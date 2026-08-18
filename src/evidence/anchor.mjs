import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * The record that says how much evidence there was supposed to be.
 *
 * Write-once storage prevents deletion. This is the other half: it makes deletion
 * *detectable*, which matters because immutability is a property of one store and evidence
 * gets copied, mirrored, restored into a working directory, and handed to assessors. The
 * copy is deletable even when the original is not.
 *
 * The mechanism is deliberately small. After each collection the manifest root, the bundle
 * count and the per-check run counts are appended to a log that lives somewhere the locker's
 * owner does not control — a different bucket, a different account, a file an assessor keeps.
 * Each entry carries the hash of the entry before it, so the log cannot be silently trimmed
 * either; and the whole point is that an attacker who truncates the locker and regenerates
 * its manifest produces a root that no anchor entry ever recorded.
 *
 * What it does not do is prove the anchor log itself is complete. Nothing self-contained can:
 * a log and its own integrity check share a fate. The anchor is worth having because it moves
 * the thing that must survive from megabytes of bundles to one append-only line per run,
 * which is small enough to put somewhere genuinely out of reach — and because the RFC 3161
 * token over each root means the timestamping authority independently saw the same value.
 */

export const ANCHOR_SCHEMA = 'ksi-harness/evidence-anchor/1';

/** One line per collection. JSON Lines, because appending must never rewrite what is there. */
export function anchorEntry(manifest, { previousHash = null, runUri = null } = {}) {
  const entry = {
    schema: ANCHOR_SCHEMA,
    anchored_at: manifest.generated_at,
    root_sha256: manifest.root_sha256,
    bundle_count: manifest.bundle_count,
    // Per-check run counts are what make truncation visible at the point it happened rather
    // than only in aggregate: a locker missing two bundles from one check still reports a
    // plausible total if another check grew.
    checks: Object.fromEntries((manifest.checks ?? []).map((c) => [c.check_id, c.runs])),
    run_uri: runUri,
    previous_sha256: previousHash,
  };
  entry.entry_sha256 = createHash('sha256').update(JSON.stringify(entry)).digest('hex');
  return entry;
}

export function readAnchorLog(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (err) {
        throw new Error(`Anchor log ${path} line ${index + 1} is not valid JSON: ${err.message}`);
      }
    });
}

/** Appends one entry, chained onto whatever is already there. */
export function appendAnchor(path, manifest, { runUri = null } = {}) {
  const existing = readAnchorLog(path);
  const previous = existing.length ? existing[existing.length - 1].entry_sha256 : null;
  const entry = anchorEntry(manifest, { previousHash: previous, runUri });
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(entry)}\n`, 'utf8');
  return entry;
}

/** Verifies the anchor log is internally consistent — that nothing was removed from it. */
export function verifyAnchorChain(entries) {
  const breaks = [];
  let previous = null;
  for (const [index, entry] of entries.entries()) {
    const { entry_sha256: stored, ...rest } = entry;
    const expected = createHash('sha256').update(JSON.stringify(rest)).digest('hex');
    if (stored !== expected) breaks.push({ index, kind: 'entry', anchored_at: entry.anchored_at });
    else if (index > 0 && entry.previous_sha256 !== previous) {
      breaks.push({ index, kind: 'chain', anchored_at: entry.anchored_at, expected: previous, stored: entry.previous_sha256 });
    }
    previous = expected;
  }
  return { ok: breaks.length === 0, breaks, length: entries.length };
}

/**
 * Compares a locker against what the anchor log says should be there.
 *
 * Three distinct findings, because they mean different things to a reader:
 *
 *   root_unknown   The locker's current root appears in no anchor entry. Either the locker
 *                  was modified after its last anchor, or it was never anchored.
 *   shrunk         A check has fewer runs than the most recent anchor recorded. This is the
 *                  finding the whole module exists for: evidence was removed.
 *   missing_check  A check the anchor knew about is absent from the locker entirely.
 *
 * Growth is not a finding. A locker with more runs than the last anchor has simply collected
 * since, which is the normal state between a collection and its anchor.
 */
export function reconcileAgainstAnchor(manifest, entries) {
  if (entries.length === 0) {
    return { ok: false, findings: [{ kind: 'no_anchor', detail: 'The anchor log is empty; nothing recorded what this locker should contain.' }] };
  }

  const findings = [];
  const chain = verifyAnchorChain(entries);
  if (!chain.ok) {
    findings.push({
      kind: 'anchor_chain_broken',
      detail: `${chain.breaks.length} break(s) in the anchor log itself, so it cannot be relied on to say what was removed.`,
      breaks: chain.breaks,
    });
  }

  const latest = entries[entries.length - 1];
  const knownRoots = new Set(entries.map((e) => e.root_sha256));
  if (!knownRoots.has(manifest.root_sha256)) {
    findings.push({
      kind: 'root_unknown',
      detail:
        `The locker's root ${manifest.root_sha256.slice(0, 12)} appears in no anchor entry. It was either ` +
        `modified after its last anchor, or never anchored.`,
    });
  }

  const current = Object.fromEntries((manifest.checks ?? []).map((c) => [c.check_id, c.runs]));
  for (const [checkId, runs] of Object.entries(latest.checks ?? {})) {
    if (!(checkId in current)) {
      findings.push({ kind: 'missing_check', check_id: checkId, detail: `${checkId} was anchored with ${runs} run(s) and is absent from the locker entirely.` });
    } else if (current[checkId] < runs) {
      findings.push({
        kind: 'shrunk',
        check_id: checkId,
        detail: `${checkId} has ${current[checkId]} run(s); the anchor at ${latest.anchored_at} recorded ${runs}. Evidence has been removed.`,
        anchored: runs,
        present: current[checkId],
      });
    }
  }

  return { ok: findings.length === 0, findings, anchored_at: latest.anchored_at, entries: entries.length };
}
