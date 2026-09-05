import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { acceptAnchor, anchorEntry, appendAnchor, readAnchorLog, reconcileAgainstAnchor, verifyAnchorChain } from '../src/evidence/anchor.mjs';

/**
 * `verify` runs before collection and the anchor is written after publication, so a run whose
 * locker root is in no anchor entry dies before reaching the step that would record it.
 * Fail-closed is right and the state had no exit — worse, a run that got *past* verify and then
 * failed to push the anchor widened the gap it had just failed to close. Both were observed on
 * 2026-08-21 and it took two manual interventions to escape.
 *
 * Acceptance is the exit. These pin the two properties that decide whether it can be trusted: it
 * cannot be done silently, and it does not damage the chain it is appended to.
 */

const manifest = (over = {}) => ({
  generated_at: '2026-09-05T12:00:00.000Z',
  root_sha256: 'a'.repeat(64),
  bundle_count: 4,
  checks: [{ check_id: 'github.change.pr-review', runs: 2 }],
  ...over,
});

function log() {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-accept-'));
  return { path: join(dir, 'anchor.jsonl'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/* ------------------------------------------------- it cannot be done silently */

test('an acceptance without a reason is refused', () => {
  const l = log();
  try {
    assert.throws(() => acceptAnchor(l.path, manifest(), { by: 'susan' }), /must state why/);
    assert.equal(readAnchorLog(l.path).length, 0, 'and nothing is written');
  } finally {
    l.cleanup();
  }
});

test('an acceptance without an actor is refused', () => {
  const l = log();
  try {
    assert.throws(() => acceptAnchor(l.path, manifest(), { reason: 'checked it' }), /must name who made it/);
  } finally {
    l.cleanup();
  }
});

// Whitespace is not a reason. The sentence is the entire evidential content of a person
// overriding a control, so a blank one is the same as none.
test('whitespace does not count as a reason or an actor', () => {
  const l = log();
  try {
    assert.throws(() => acceptAnchor(l.path, manifest(), { by: '  ', reason: 'x' }), /must name who made it/);
    assert.throws(() => acceptAnchor(l.path, manifest(), { by: 'susan', reason: '   ' }), /must state why/);
  } finally {
    l.cleanup();
  }
});

/* --------------------------------------------- it is visibly not a witnessed entry */

test('an accepted entry says so, and carries who and why', () => {
  const l = log();
  try {
    const entry = acceptAnchor(l.path, manifest(), { by: 'susan', reason: 'growth traced to a demo re-run' });
    assert.equal(entry.accepted.by, 'susan');
    assert.match(entry.accepted.reason, /demo re-run/);
    assert.ok(entry.accepted.at, 'and when');
  } finally {
    l.cleanup();
  }
});

/**
 * The field is omitted rather than nulled on pipeline entries, and that is not tidiness. The
 * chain hashes every field, so writing `accepted: null` onto witnessed entries would change their
 * hash and invalidate every entry in every log that already exists.
 */
test('a witnessed entry carries no acceptance field at all', () => {
  const l = log();
  try {
    appendAnchor(l.path, manifest(), { runUri: 'https://example/run/1' });
    const [entry] = readAnchorLog(l.path);
    assert.equal('accepted' in entry, false);
    assert.equal(verifyAnchorChain([entry]).ok, true, 'and it still verifies');
  } finally {
    l.cleanup();
  }
});

test('adding the field does not change the hash of an entry without it', () => {
  const withoutField = anchorEntry(manifest(), { previousHash: null, runUri: null });
  const explicitlyNone = anchorEntry(manifest(), { previousHash: null, runUri: null, accepted: null });
  assert.equal(withoutField.entry_sha256, explicitlyNone.entry_sha256);
});

/* ------------------------------------------------ it does not damage the chain */

test('a log mixing witnessed and accepted entries verifies end to end', () => {
  const l = log();
  try {
    appendAnchor(l.path, manifest(), { runUri: 'https://example/run/1' });
    acceptAnchor(l.path, manifest({ root_sha256: 'b'.repeat(64), bundle_count: 8 }), {
      by: 'susan',
      reason: 'second collection, nothing removed',
    });
    appendAnchor(l.path, manifest({ root_sha256: 'c'.repeat(64), bundle_count: 12 }));

    const entries = readAnchorLog(l.path);
    const chain = verifyAnchorChain(entries);
    assert.equal(entries.length, 3);
    assert.equal(chain.ok, true, 'an acceptance in the middle must not break the chain after it');
    assert.equal(chain.breaks.length, 0);
    assert.deepEqual(entries.map((e) => Boolean(e.accepted)), [false, true, false]);
  } finally {
    l.cleanup();
  }
});

/**
 * The point of the whole exercise: a locker whose root was accepted reconciles, so the run that
 * was previously stuck at `root_unknown` can proceed.
 */
test('accepting a root clears root_unknown for that locker', () => {
  const l = log();
  try {
    appendAnchor(l.path, manifest());
    const grown = manifest({ root_sha256: 'b'.repeat(64), bundle_count: 8, checks: [{ check_id: 'github.change.pr-review', runs: 4 }] });

    const before = reconcileAgainstAnchor(grown, readAnchorLog(l.path));
    assert.equal(before.ok, false);
    assert.ok(before.findings.some((f) => f.kind === 'root_unknown'));

    acceptAnchor(l.path, grown, { by: 'susan', reason: 'growth accounted for' });
    const after = reconcileAgainstAnchor(grown, readAnchorLog(l.path));
    assert.equal(after.ok, true, 'the gap is closed');
    assert.deepEqual(after.findings, []);
  } finally {
    l.cleanup();
  }
});

// Acceptance closes the gap; it must not become a way to wave through deletion. A locker that
// shrank is still reported, because `shrunk` is measured against the latest entry whatever kind
// it is.
test('accepting a root does not suppress a later shrink', () => {
  const l = log();
  try {
    acceptAnchor(l.path, manifest({ checks: [{ check_id: 'x.y.z', runs: 4 }] }), {
      by: 'susan',
      reason: 'accepted at four runs',
    });
    const shrunk = manifest({ root_sha256: 'd'.repeat(64), checks: [{ check_id: 'x.y.z', runs: 1 }] });
    const result = reconcileAgainstAnchor(shrunk, readAnchorLog(l.path));
    assert.equal(result.ok, false);
    assert.ok(result.findings.some((f) => f.kind === 'shrunk'), 'evidence removed after an acceptance is still a finding');
  } finally {
    l.cleanup();
  }
});

test('the root_unknown finding names the remedy', () => {
  const l = log();
  try {
    appendAnchor(l.path, manifest());
    const grown = manifest({ root_sha256: 'e'.repeat(64) });
    const finding = reconcileAgainstAnchor(grown, readAnchorLog(l.path)).findings.find((f) => f.kind === 'root_unknown');
    assert.match(finding.detail, /ksi anchor accept/, 'a finding that names the problem and not the remedy invites improvisation');
  } finally {
    l.cleanup();
  }
});

test('the log stays one JSON object per line', () => {
  const l = log();
  try {
    appendAnchor(l.path, manifest());
    acceptAnchor(l.path, manifest({ root_sha256: 'f'.repeat(64) }), { by: 'susan', reason: 'ok' });
    const lines = readFileSync(l.path, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    for (const line of lines) assert.doesNotThrow(() => JSON.parse(line));
  } finally {
    l.cleanup();
  }
});
