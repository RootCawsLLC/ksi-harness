import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { buildBundle, writeBundle } from '../src/evidence/bundle.mjs';
import { diffLocker } from '../src/report/diff.mjs';

/**
 * `ksi diff` answers the question a coverage report cannot: not where the boundary stands, but
 * what moved. The locker was built to be diffable from the first commit and nothing read it as
 * a series, so the artifact continuous monitoring exists to produce had to be reconstructed by
 * eye from a directory of JSON.
 *
 * The item-level comparison is the point. A check failing before and failing now shows a flat
 * result while the resource that failed may have been fixed and a different one broken, which is
 * one remediation and one new finding rather than nothing happening.
 */

const bundle = (over = {}) =>
  buildBundle({
    checkId: 'aws.network.ingress-exposure',
    ksis: ['KSI-CNA-MAT'],
    collectorPath: 'src/collectors/aws/network.mjs',
    collectorVersion: '2.0.0',
    assertion: 'No security group attached to a running resource is open beyond the declared public ports.',
    scope: {},
    population: { expected: 2, source_of_truth: 's', enumerated_from: 'e' },
    items: [
      { id: 'scope/123456789012', status: 'pass', detail: '1 security group(s) enumerated' },
      { id: 'sg/sg-aaa', status: 'pass', detail: 'No unrestricted inbound rule' },
    ],
    collectedAt: '2026-08-17T04:00:00.000Z',
    ...over,
  });

function locker(bundles) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-diff-'));
  for (const b of bundles) writeBundle(b, dir);
  return dir;
}

test('a single collection is reported as having nothing to compare, not as no change', () => {
  const dir = locker([bundle()]);
  try {
    const diff = diffLocker(dir);
    assert.equal(diff.counts.comparable, 0);
    assert.match(diff.checks[0].detail, /no interval to compare/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a resource that broke between two collections is named', () => {
  const before = bundle();
  const after = bundle({
    collectedAt: '2026-08-18T04:00:00.000Z',
    previousHash: before.integrity.content_sha256,
    chainIndex: 1,
    items: [
      { id: 'scope/123456789012', status: 'pass', detail: '1 security group(s) enumerated' },
      { id: 'sg/sg-aaa', status: 'fail', detail: 'Unrestricted inbound on TCP/5432 with 1 live attachment(s)' },
    ],
  });
  const dir = locker([before, after]);
  try {
    const diff = diffLocker(dir);
    const check = diff.checks[0];
    assert.equal(check.result_changed, true);
    assert.deepEqual(check.regressed.map((r) => r.id), ['sg/sg-aaa']);
    assert.equal(diff.counts.regressed_items, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The case a result-only diff hides completely: the verdict does not move while the subject it
// was reached over gets smaller.
test('a population that stopped being complete is reported even when the result did not move', () => {
  const before = bundle();
  const after = bundle({
    collectedAt: '2026-08-18T04:00:00.000Z',
    previousHash: before.integrity.content_sha256,
    chainIndex: 1,
    population: {
      expected: 2,
      unexamined: [{ id: 'sg/sg-aaa', reason: 'ec2:DescribeSecurityGroups denied in us-west-2' }],
      source_of_truth: 's',
      enumerated_from: 'e',
    },
    items: [{ id: 'scope/123456789012', status: 'pass', detail: '0 security group(s) enumerated' }],
  });
  const dir = locker([before, after]);
  try {
    const diff = diffLocker(dir);
    const check = diff.checks[0];
    assert.equal(check.population.completeness_lost, true);
    assert.equal(diff.counts.completeness_lost, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a fixed resource is distinguished from one that left the population', () => {
  const before = bundle({
    items: [
      { id: 'scope/123456789012', status: 'pass', detail: '2 enumerated' },
      { id: 'sg/sg-aaa', status: 'fail', detail: 'open' },
      { id: 'sg/sg-bbb', status: 'fail', detail: 'open' },
    ],
    population: { expected: 3, source_of_truth: 's', enumerated_from: 'e' },
  });
  const after = bundle({
    collectedAt: '2026-08-18T04:00:00.000Z',
    previousHash: before.integrity.content_sha256,
    chainIndex: 1,
    items: [
      { id: 'scope/123456789012', status: 'pass', detail: '1 enumerated' },
      { id: 'sg/sg-aaa', status: 'pass', detail: 'No unrestricted inbound rule' },
    ],
  });
  const dir = locker([before, after]);
  try {
    const check = diffLocker(dir).checks[0];
    assert.deepEqual(check.fixed.map((f) => f.id), ['sg/sg-aaa'], 'sg-aaa was remediated');
    assert.deepEqual(check.disappeared.map((d) => d.id), ['sg/sg-bbb'], 'sg-bbb was deleted, which is not the same thing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* -------------------------------------------------------------- the two directions */

/**
 * The default span and the alerting span answer different questions, and using one for the
 * other is silent rather than noisy.
 *
 * A report a person reads wants first-to-last: "what has changed since this locker began".
 * Alerting wants the run that just happened. A control that broke and then recovered is
 * *invisible* across the full span — both endpoints are green and everything interesting
 * happened in between — so alerting on the default would have suppressed every recovery,
 * producing a notifier that can raise and never stand down.
 *
 * Three runs, pass → fail → pass. Both views are correct; only one is useful for alerting.
 */
function threeRuns() {
  const broken = [
    { id: 'scope/123456789012', status: 'pass', detail: '1 enumerated' },
    { id: 'sg/sg-aaa', status: 'fail', detail: '0.0.0.0/0 on 22' },
  ];
  const first = bundle();
  const second = bundle({
    collectedAt: '2026-08-18T04:00:00.000Z',
    previousHash: first.integrity.content_sha256,
    chainIndex: 1,
    items: broken,
  });
  const third = bundle({
    collectedAt: '2026-08-19T04:00:00.000Z',
    previousHash: second.integrity.content_sha256,
    chainIndex: 2,
  });
  return locker([first, second, third]);
}

test('the default span reports the whole history, where a break and its repair cancel out', () => {
  const dir = threeRuns();
  try {
    const check = diffLocker(dir).checks[0];
    assert.equal(check.from.result, 'pass');
    assert.equal(check.to.result, 'pass');
    assert.equal(check.result_changed, false, 'true, and exactly why it is the wrong span for alerting');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--latest compares the two most recent runs, so the recovery is visible', () => {
  const dir = threeRuns();
  try {
    const check = diffLocker(dir, { latest: true }).checks[0];
    assert.equal(check.from.result, 'fail');
    assert.equal(check.to.result, 'pass');
    assert.equal(check.result_changed, true, 'without this, ksi notify can never stand down');
    assert.deepEqual(check.fixed.map((f) => f.id), ['sg/sg-aaa']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--latest on a single collection still reports nothing to compare rather than inventing a run', () => {
  const dir = locker([bundle()]);
  try {
    assert.equal(diffLocker(dir, { latest: true }).counts.comparable, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
