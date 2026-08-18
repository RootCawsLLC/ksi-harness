import assert from 'node:assert/strict';
import { test } from 'node:test';

import { grantsWildcard, trustPrincipals } from '../src/collectors/aws/iam.mjs';
import { externalReaders } from '../src/collectors/aws/logging.mjs';
import { classifyUse, extractUses } from '../src/collectors/github/supply-chain.mjs';
import { describePorts, passRate } from '../src/collectors/lib/grade.mjs';
import { ALL_CHECKS } from '../src/collectors/registry.mjs';
import { runAll } from '../src/collectors/run-all.mjs';
import { verifyIntegrity } from '../src/evidence/bundle.mjs';

const FIXTURES = 'fixtures/collectors';
const AT = '2026-08-18T04:00:00.000Z';

/* ---------------------------------------------------------------- grading helpers */

test('the pass rate excludes not-applicable items from the denominator', () => {
  assert.equal(passRate([{ status: 'pass' }, { status: 'fail' }]), 0.5);
  assert.equal(passRate([{ status: 'pass' }, { status: 'not-applicable' }]), 1);
  assert.equal(passRate([{ status: 'warn' }, { status: 'pass' }]), 0.5, 'a warning is not a pass');
});

// An empty population scoring 1.0 is only safe because the bundle's population reconciliation
// is what decides whether an empty population is acceptable. The metric must not be the thing
// carrying that judgement.
test('an empty population scores 1.0, and the population field is what qualifies it', () => {
  assert.equal(passRate([]), 1);
});

test('port ranges read the way a reviewer expects', () => {
  assert.equal(describePorts('-1', 0, 0), 'all protocols and ports');
  assert.equal(describePorts('tcp', 22, 22), 'TCP/22');
  assert.equal(describePorts('tcp', 1, 1024), 'TCP/1-1024');
  assert.equal(describePorts('tcp', null, null), 'TCP (all ports)');
});

/* ------------------------------------------------------------------- iam grading */

test('an unconditional wildcard grant is administrative', () => {
  assert.equal(grantsWildcard({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }), true);
  assert.equal(grantsWildcard({ Statement: { Effect: 'Allow', Action: ['*'], Resource: ['*'] } }), true);
  assert.equal(grantsWildcard({ Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }] }), true);
});

// A condition is how just-in-time access is expressed, so a conditioned grant is not standing
// privilege and must not be graded as though it were.
test('a conditioned wildcard grant is not standing privilege', () => {
  const doc = {
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } }],
  };
  assert.equal(grantsWildcard(doc), false);
});

test('a scoped grant and a deny are not administrative', () => {
  assert.equal(grantsWildcard({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }), false);
  assert.equal(grantsWildcard({ Statement: [{ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' }] }), false);
  assert.equal(grantsWildcard({ Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] }), false);
  assert.equal(grantsWildcard(undefined), false);
});

test('trust principals are collected across statements and shapes', () => {
  const doc = {
    Statement: [
      { Effect: 'Allow', Principal: { Service: 'ecs-tasks.amazonaws.com' } },
      { Effect: 'Allow', Principal: { AWS: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root'] } },
      { Effect: 'Deny', Principal: { AWS: 'arn:aws:iam::999999999999:root' } },
    ],
  };
  const principals = trustPrincipals(doc);
  assert.equal(principals.length, 3);
  assert.ok(principals.includes('ecs-tasks.amazonaws.com'));
  assert.ok(!principals.includes('arn:aws:iam::999999999999:root'), 'a deny does not grant trust');
});

/* --------------------------------------------------------------- logging grading */

test('a bucket policy open to everyone reports a wildcard reader', () => {
  const policy = { Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject' }] };
  assert.deepEqual(externalReaders(policy, '123456789012'), ['*']);
});

// AWS writes the logs itself through service principals. Counting those as external readers
// would make every correctly configured log bucket a finding, and a check that fires on the
// correct configuration gets switched off.
test('service principals are not external readers', () => {
  const policy = { Statement: [{ Effect: 'Allow', Principal: { Service: 'cloudtrail.amazonaws.com' } }] };
  assert.deepEqual(externalReaders(policy, '123456789012'), []);
});

test('a principal in another account is an external reader; the owning account is not', () => {
  const policy = {
    Statement: [
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } },
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:role/auditor' } },
    ],
  };
  assert.deepEqual(externalReaders(policy, '123456789012'), ['arn:aws:iam::999988887777:role/auditor']);
});

/* ---------------------------------------------------------- supply chain grading */

test('action references are extracted from workflow text with their line numbers', () => {
  const yaml = [
    'jobs:',
    '  build:',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - uses: "third/party@8f4b7c2a1d3e5f60718293a4b5c6d7e8f9012345" # v2.1.0',
    '      - name: not a use',
    '        run: echo uses: nope',
  ].join('\n');
  const uses = extractUses(yaml);
  assert.equal(uses.length, 2);
  assert.equal(uses[0].ref, 'actions/checkout@v4');
  assert.equal(uses[0].line, 4);
  assert.equal(uses[1].comment, 'v2.1.0');
});

test('a 40-character commit revision is a pass', () => {
  const verdict = classifyUse({ ref: 'third/party@8f4b7c2a1d3e5f60718293a4b5c6d7e8f9012345' });
  assert.equal(verdict.status, 'pass');
  assert.equal(verdict.kind, 'pinned');
});

test('a third-party mutable tag fails and a first-party one warns', () => {
  assert.equal(classifyUse({ ref: 'third/party@v2' }).status, 'fail');
  assert.equal(classifyUse({ ref: 'actions/checkout@v4' }).status, 'warn');
  assert.equal(classifyUse({ ref: 'github/codeql-action@v3' }).status, 'warn');
});

test('a reference with no revision at all fails', () => {
  assert.equal(classifyUse({ ref: 'third/party' }).status, 'fail');
});

// Local and container references are a different provenance question, so they stay out of the
// denominator rather than inflating the pass rate.
test('local and docker references are not applicable rather than passing', () => {
  assert.equal(classifyUse({ ref: './.github/actions/setup' }).status, 'not-applicable');
  assert.equal(classifyUse({ ref: 'docker://alpine:3.20' }).status, 'not-applicable');
});

/* ------------------------------------------------------- the full fixture run */

test('every collector runs against its fixtures and produces a valid bundle', async () => {
  const { bundles, failures } = await runAll({
    profile: { certification_class: 'c', aws: { accounts: [{ id: '123456789012', regions: ['us-east-1'] }] } },
    fixture: FIXTURES,
    collectedAt: AT,
  });

  assert.deepEqual(failures, [], 'no collector should throw against its own fixtures');
  assert.equal(bundles.length, ALL_CHECKS.length, 'each registered check produces exactly one bundle');

  for (const bundle of bundles) {
    assert.equal(verifyIntegrity(bundle).ok, true, `${bundle.check_id} hash does not verify`);
    assert.equal(bundle.collected_at, AT, `${bundle.check_id} did not use the run timestamp`);
    assert.ok(bundle.items.length > 0, `${bundle.check_id} examined nothing`);
    assert.ok(bundle.assertion?.length, `${bundle.check_id} states no assertion`);
    assert.ok(bundle.population.source_of_truth?.length, `${bundle.check_id} names no source of truth`);
  }
});

// Fixture-derived evidence must be self-identifying. A demo bundle that could be mistaken for a
// live one is the most embarrassing possible failure of a compliance tool, so the marker is
// asserted rather than assumed.
test('fixture bundles are marked as fixtures so they cannot pass for live evidence', async () => {
  const { bundles } = await runAll({ profile: {}, fixture: FIXTURES, collectedAt: AT });
  for (const bundle of bundles) {
    assert.equal(bundle.scope?.fixture, true, `${bundle.check_id} is not marked as fixture-derived`);
  }
});

test('a run is reproducible: the same fixtures and timestamp hash identically', async () => {
  const once = await runAll({ profile: {}, fixture: FIXTURES, collectedAt: AT });
  const twice = await runAll({ profile: {}, fixture: FIXTURES, collectedAt: AT });
  const hashes = (r) => r.bundles.map((b) => `${b.check_id}:${b.integrity.content_sha256}`).sort();
  assert.deepEqual(hashes(once), hashes(twice));
});

test('the fixture set exercises failure as well as success', async () => {
  const { bundles } = await runAll({ profile: {}, fixture: FIXTURES, collectedAt: AT });
  const results = new Set(bundles.map((b) => b.result));
  assert.ok(results.has('fail'), 'fixtures that only pass would not prove the grading works');
  assert.ok(results.has('pass'), 'fixtures that only fail would not prove a pass is reachable');
});

// Dogfooding, and the cheapest possible credibility check. A repository that ships a
// workflow-pinning control and does not pass it has answered the question about whether the
// control is real.
test("this repository's own workflows pass the pinning check it ships", async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const dir = '.github/workflows';
  const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));
  assert.ok(files.length > 0, 'there should be workflows to check');

  const offenders = [];
  for (const file of files) {
    for (const use of extractUses(readFileSync(`${dir}/${file}`, 'utf8'))) {
      const verdict = classifyUse(use);
      if (verdict.status === 'fail') offenders.push(`${file}:${use.line} ${use.ref}`);
    }
  }
  assert.deepEqual(offenders, [], 'pin third-party actions to a commit revision');
});

test('--only narrows the run to one provider family', async () => {
  const { bundles } = await runAll({ profile: {}, fixture: FIXTURES, collectedAt: AT, only: ['github'] });
  assert.ok(bundles.length > 0);
  for (const bundle of bundles) assert.match(bundle.check_id, /^github\./);
});
