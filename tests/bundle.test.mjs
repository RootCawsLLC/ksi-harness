import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildBundle, unimplementedBundle, verifyIntegrity } from '../src/evidence/bundle.mjs';

/**
 * The bundle invariants are the load-bearing part of this repository.
 *
 * Everything downstream — coverage percentages, the SDR's implementation status, the OCR's
 * finding counts — is a projection of what these bundles say. If a bundle can report a pass it
 * has not earned, every artifact built from it inherits the lie and no amount of care in the
 * emitters recovers it. So the three invariants are tested here directly rather than through a
 * collector: result is derived and not accepted, an incomplete population cannot pass, and an
 * unexplained gap is refused outright.
 */

const AT = '2026-08-18T04:00:00.000Z';

const base = {
  checkId: 'aws.iam.mfa-coverage',
  ksis: ['KSI-IAM-APM'],
  collectorPath: 'src/collectors/aws/iam.mjs',
  collectorVersion: '1.0.0',
  collectedAt: AT,
  assertion: 'Every console-capable principal has MFA.',
  scope: { accounts: ['123456789012'] },
  population: { expected: 2, examined: 2, source_of_truth: 'IAM credential report' },
  items: [
    { id: 'alice', status: 'pass' },
    { id: 'bob', status: 'pass' },
  ],
};

const build = (overrides = {}) => buildBundle({ ...base, ...overrides });

test('result is derived from items, so a passing verdict cannot be asserted over failing evidence', () => {
  const bundle = build({
    // A caller trying to force the verdict. The field is not read.
    result: 'pass',
    items: [
      { id: 'alice', status: 'pass' },
      { id: 'bob', status: 'fail', detail: 'No MFA device' },
    ],
  });
  assert.equal(bundle.result, 'fail');
});

test('a warning item caps the result at warn', () => {
  const bundle = build({ items: [{ id: 'alice', status: 'warn' }, { id: 'bob', status: 'pass' }] });
  assert.equal(bundle.result, 'warn');
});

test('not-applicable items do not prevent a pass', () => {
  const bundle = build({
    population: { expected: 2, examined: 2, source_of_truth: 'IAM credential report' },
    items: [{ id: 'alice', status: 'pass' }, { id: 'svc', status: 'not-applicable' }],
  });
  assert.equal(bundle.result, 'pass');
});

test('an incomplete population can never pass, even when every examined item passed', () => {
  const bundle = build({
    population: {
      expected: 5,
      examined: 2,
      source_of_truth: 'IAM credential report',
      reconciliation: 'Three accounts denied iam:GenerateCredentialReport.',
    },
  });
  assert.equal(bundle.population.complete, false);
  assert.equal(bundle.result, 'warn', 'a claim verified over an unknown subset has not been verified');
});

test('an unexplained population gap is refused rather than reported', () => {
  assert.throws(
    () => build({ population: { expected: 5, examined: 2, source_of_truth: 'IAM credential report' } }),
    /population is incomplete \(2 of 5\) and no reconciliation was supplied/
  );
});

test('errors force an error result regardless of the items collected', () => {
  const bundle = build({ errors: ['AccessDenied on iam:ListUsers'] });
  assert.equal(bundle.result, 'error');
  assert.deepEqual(bundle.errors, ['AccessDenied on iam:ListUsers']);
});

test('completeness is computed, not trusted from the caller', () => {
  const bundle = build({ population: { ...base.population, complete: false } });
  assert.equal(bundle.population.complete, true);
});

/* ------------------------------------------------------- identifiers and mapping */

test('a check must declare at least one indicator, so evidence cannot map to nothing', () => {
  assert.throws(() => build({ ksis: [] }), /must declare at least one Key Security Indicator/);
});

test('a malformed indicator id is rejected before it reaches the coverage report', () => {
  assert.throws(() => build({ ksis: ['KSI-IAM'] }), /is not a KSI id/);
  assert.throws(() => build({ ksis: ['ksi-iam-apm'] }), /is not a KSI id/);
});

test('a malformed check id is rejected', () => {
  assert.throws(() => build({ checkId: 'iam' }), /Invalid check id/);
  assert.throws(() => build({ checkId: 'AWS.IAM.MFA' }), /Invalid check id/);
});

test('indicators are sorted so the hash does not depend on declaration order', () => {
  const a = build({ ksis: ['KSI-IAM-APM', 'KSI-IAM-AAM'] });
  const b = build({ ksis: ['KSI-IAM-AAM', 'KSI-IAM-APM'] });
  assert.deepEqual(a.ksis, ['KSI-IAM-AAM', 'KSI-IAM-APM']);
  assert.equal(a.integrity.content_sha256, b.integrity.content_sha256);
});

test('a timestamp is required rather than defaulted from the runner clock', () => {
  assert.throws(() => build({ collectedAt: undefined }), /collectedAt is required/);
});

/* -------------------------------------------------------------------- integrity */

test('the content hash verifies against an untouched bundle', () => {
  assert.equal(verifyIntegrity(build()).ok, true);
});

test('the content hash detects an edited verdict', () => {
  const bundle = build();
  bundle.result = 'pass';
  bundle.items = [{ id: 'alice', status: 'pass' }, { id: 'bob', status: 'pass' }];
  const check = verifyIntegrity({ ...bundle, items: [{ id: 'alice', status: 'pass' }] });
  assert.equal(check.ok, false);
});

test('the hash is stable across key insertion order', () => {
  const one = build();
  const reordered = Object.fromEntries(Object.entries({ ...one }).reverse());
  delete reordered.integrity;
  assert.equal(verifyIntegrity({ ...reordered, integrity: one.integrity }).ok, true);
});

test('two collections of identical state hash identically, so an unchanged control is diff-quiet', () => {
  assert.equal(build().integrity.content_sha256, build().integrity.content_sha256);
});

/* ---------------------------------------------------------------- unimplemented */

test('an unimplemented check reports error with no items, never a pass', () => {
  const bundle = unimplementedBundle({
    checkId: 'aws.kms.key-rotation',
    ksis: ['KSI-SVC-KYM'],
    collectorPath: 'src/collectors/aws/kms.mjs',
    collectedAt: AT,
    assertion: 'Keys rotate on schedule.',
    reason: 'Not implemented for this environment.',
  });
  assert.equal(bundle.result, 'error');
  assert.equal(bundle.items.length, 0);
  assert.equal(bundle.population.expected, 0);
});
