import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { appendAnchor, readAnchorLog, reconcileAgainstAnchor, verifyAnchorChain } from '../src/evidence/anchor.mjs';
import { computeManifest } from '../src/evidence/locker.mjs';
import { buildBundle, writeBundle } from '../src/evidence/bundle.mjs';
import {
  DURABILITY,
  filesystemStore,
  gcsRetentionProblems,
  isUnanswered,
  resolveStore,
  s3RetentionProblems,
} from '../src/evidence/store.mjs';

/**
 * The gap these close: everything else in this repository protects the locker against being
 * *altered*, and all of it is anchored inside the locker. Delete two-thirds of a check's
 * history, regenerate the manifest, and `verify` reported "every bundle verifies and every
 * chain is intact" — because a chain proves the consistency of what remains and can say
 * nothing about what is gone.
 */

const AT = (n) => `2026-08-1${n}T04:00:00.000Z`;

function lockerWith(runs) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-store-'));
  let previous = null;
  for (let i = 0; i < runs; i += 1) {
    const bundle = buildBundle({
      checkId: 'aws.iam.mfa-coverage',
      ksis: ['KSI-IAM-APM'],
      collectorPath: 'src/collectors/aws/iam.mjs',
      collectorVersion: '2.0.0',
      collectedAt: AT(i),
      assertion: 'test',
      scope: {},
      population: { expected: 1, source_of_truth: 's', enumerated_from: 'e' },
      items: [{ id: 'root', status: 'pass' }],
      previousHash: previous,
      chainIndex: i,
    });
    previous = bundle.integrity.content_sha256;
    writeBundle(bundle, dir);
  }
  return dir;
}

/* --------------------------------------------------------------------- the store */

// A tool cannot know an undeclared store is durable, and assuming one would be the claim
// this module exists to prevent.
test('the default store makes no durability claim, and says so', () => {
  const store = resolveStore(null, { dir: '.evidence' });
  const described = store.describe();
  assert.equal(described.kind, 'filesystem');
  assert.equal(described.durability, DURABILITY.NONE);
  assert.equal(described.immutable, false);
  assert.match(described.why, /Anything with write access can alter or delete it/);
});

test('a filesystem store refuses to claim it is write-once', async () => {
  await assert.rejects(() => filesystemStore({ dir: '/tmp/x' }).assertImmutable(), /guarantees nothing about retention/);
});

test('a declared store must name its bucket, and an unknown kind is refused', () => {
  assert.throws(() => resolveStore({ evidence: { store: { kind: 's3' } } }), /no bucket is declared/);
  assert.throws(() => resolveStore({ evidence: { store: { kind: 'gcs' } } }), /no bucket is declared/);
  assert.throws(() => resolveStore({ evidence: { store: { kind: 'ftp' } } }), /Unknown evidence\.store\.kind "ftp"/);
});

test('the s3 and gcs backends declare write-once and say what enforces it', () => {
  const s3 = resolveStore({ evidence: { store: { kind: 's3', bucket: 'b', prefix: 'p' } } }).describe();
  assert.equal(s3.durability, DURABILITY.WORM);
  assert.match(s3.why, /COMPLIANCE mode/);
  assert.equal(s3.location, 's3://b/p');

  const gcs = resolveStore({ evidence: { store: { kind: 'gcs', bucket: 'b' } } }).describe();
  assert.equal(gcs.durability, DURABILITY.WORM);
  assert.match(gcs.why, /locked bucket retention policy/);
});

/* ------------------------------------------------------------------ the refusals */

// The test above asserts the store *states* a guarantee. These assert it is *checked* —
// which is the whole difference between an evidence vault and a bucket described as one.
// A bucket with Object Lock and a bucket without are indistinguishable from the client.

const OBJECT_LOCK = (mode) => ({
  ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled', Rule: { DefaultRetention: { Mode: mode, Years: 7 } } },
});
const VERSIONED = { Status: 'Enabled' };

test('a COMPLIANCE-mode bucket with versioning is the one configuration accepted', () => {
  assert.deepEqual(s3RetentionProblems(OBJECT_LOCK('COMPLIANCE'), VERSIONED), []);
});

// The finding this module exists for. GOVERNANCE reads as "Object Lock: enabled" in the
// console, in a screenshot, and in a package — and a single permission lifts it.
test('GOVERNANCE mode is refused, because a retention an administrator can lift is not one', () => {
  const [problem] = s3RetentionProblems(OBJECT_LOCK('GOVERNANCE'), VERSIONED);
  assert.match(problem, /GOVERNANCE mode/);
  assert.match(problem, /s3:BypassGovernanceRetention/);
});

test('Object Lock without a default retention rule leaves objects deletable', () => {
  const noRule = { ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } };
  assert.match(s3RetentionProblems(noRule, VERSIONED)[0], /no default retention rule/);
});

test('a bucket with no Object Lock at all fails on every count rather than the first', () => {
  const problems = s3RetentionProblems({}, { Status: 'Suspended' });
  assert.equal(problems.length, 3, 'lock disabled, no rule, and versioning off are three separate repairs');
});

// GCS has no separate mode. An unlocked policy is the same failure wearing different words.
test('an unlocked GCS retention policy is a default, not a guarantee', () => {
  const period = String(86400 * 3650);
  assert.match(gcsRetentionProblems({ retentionPolicy: { isLocked: false, retentionPeriod: period } }, 1)[0], /not locked/);
  assert.deepEqual(gcsRetentionProblems({ retentionPolicy: { isLocked: true, retentionPeriod: period } }, 1), []);
});

test('a locked GCS policy shorter than the profile requires is still refused', () => {
  const short = { retentionPolicy: { isLocked: true, retentionPeriod: String(86400 * 30) } };
  assert.match(gcsRetentionProblems(short, 365)[0], /retention is 30 day\(s\), below the 365/);
  assert.match(gcsRetentionProblems({}, 365)[0], /no retention policy/);
});

// The same distinction the GCP collectors draw out of a 403, and it was wrong here first:
// an expired credential was reported as "this bucket has no Object Lock", which is a claim
// about the bucket made by a run that never reached it.
test('a store that could not be reached is not a store that failed its check', () => {
  assert.equal(isUnanswered('CredentialsProviderError'), true);
  assert.equal(isUnanswered('ExpiredToken'), true);
  assert.equal(isUnanswered('AccessDenied'), true, 'a denied call answered nothing about retention');
  assert.equal(isUnanswered('NetworkingError'), true);
  assert.equal(isUnanswered('ObjectLockConfigurationNotFoundError'), false, 'this one is a real answer');
  assert.equal(isUnanswered('NoSuchBucket'), false, 'so is this: the bucket is not there');
});

/* -------------------------------------------------------------------- the anchor */

test('the anchor log chains, so entries cannot be removed from it either', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-anchor-'));
  const path = join(dir, 'anchor.jsonl');
  try {
    const locker = lockerWith(1);
    try {
      for (let i = 0; i < 3; i += 1) {
        appendAnchor(path, computeManifest(locker, { generatedAt: AT(i) }));
      }
      const entries = readAnchorLog(path);
      assert.equal(entries.length, 3);
      assert.equal(verifyAnchorChain(entries).ok, true);
      assert.equal(entries[0].previous_sha256, null);
      assert.equal(entries[1].previous_sha256, entries[0].entry_sha256);

      // Remove the middle entry, as someone trimming the record would.
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
      writeFileSync(path, `${[lines[0], lines[2]].join('\n')}\n`);
      const trimmed = verifyAnchorChain(readAnchorLog(path));
      assert.equal(trimmed.ok, false);
      assert.equal(trimmed.breaks[0].kind, 'chain');
    } finally {
      rmSync(locker, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The finding the whole module exists for.
test('a locker with evidence removed is reported as shrunk, naming the check and the counts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-anchor-'));
  const path = join(dir, 'anchor.jsonl');
  const locker = lockerWith(3);
  try {
    appendAnchor(path, computeManifest(locker, { generatedAt: AT(3) }));

    // Delete two of the three bundles and regenerate the manifest, which is the attack that
    // previously reported a perfectly intact chain.
    const checkDir = join(locker, 'aws.iam.mfa-coverage');
    for (const file of readdirSync(checkDir).sort().slice(1)) unlinkSync(join(checkDir, file));

    const after = computeManifest(locker, { generatedAt: AT(4) });
    const result = reconcileAgainstAnchor(after, readAnchorLog(path));

    assert.equal(result.ok, false);
    const shrunk = result.findings.find((f) => f.kind === 'shrunk');
    assert.ok(shrunk, 'the removal is reported');
    assert.equal(shrunk.check_id, 'aws.iam.mfa-coverage');
    assert.equal(shrunk.anchored, 3);
    assert.equal(shrunk.present, 1);
    assert.match(shrunk.detail, /Evidence has been removed/);
    assert.ok(result.findings.some((f) => f.kind === 'root_unknown'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(locker, { recursive: true, force: true });
  }
});

test('a check anchored and then absent entirely is distinguished from one that shrank', () => {
  const manifest = { root_sha256: 'a'.repeat(64), bundle_count: 0, checks: [] };
  const entries = [
    {
      schema: 'ksi-harness/evidence-anchor/1',
      anchored_at: AT(1),
      root_sha256: 'b'.repeat(64),
      bundle_count: 2,
      checks: { 'aws.iam.mfa-coverage': 2 },
      run_uri: null,
      previous_sha256: null,
      entry_sha256: 'ignored',
    },
  ];
  const result = reconcileAgainstAnchor(manifest, entries);
  assert.ok(result.findings.some((f) => f.kind === 'missing_check' && f.check_id === 'aws.iam.mfa-coverage'));
});

// Growth is the normal state between a collection and its anchor, and must not be a finding.
test('a locker that has grown since its last anchor is not a finding', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-anchor-'));
  const path = join(dir, 'anchor.jsonl');
  const locker = lockerWith(2);
  try {
    appendAnchor(path, computeManifest(locker, { generatedAt: AT(2) }));
    const entries = readAnchorLog(path);
    const grown = computeManifest(locker, { generatedAt: AT(3) });
    grown.checks[0].runs = 5;

    const result = reconcileAgainstAnchor(grown, entries);
    assert.equal(result.findings.some((f) => f.kind === 'shrunk'), false, 'more runs than anchored is not removal');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(locker, { recursive: true, force: true });
  }
});

test('an empty anchor log is reported rather than treated as agreement', () => {
  const result = reconcileAgainstAnchor({ root_sha256: 'a'.repeat(64), bundle_count: 1, checks: [] }, []);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].kind, 'no_anchor');
});
