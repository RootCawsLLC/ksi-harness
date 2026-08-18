import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { gradeMfaCoverage, gradePrivilegedAccess } from '../src/collectors/aws/iam.mjs';
import { gradeIngressExposure } from '../src/collectors/aws/network.mjs';
import { gradeBranchProtection, gradePrReview } from '../src/collectors/github/change.mjs';
import { gradeWorkflowPinning } from '../src/collectors/github/supply-chain.mjs';
import { runAll } from '../src/collectors/run-all.mjs';
import { buildBundle, verifyChain, writeBundle } from '../src/evidence/bundle.mjs';
import { readLocker } from '../src/evidence/locker.mjs';

/**
 * The population reconciliation has to be able to fail, or it is arithmetic wearing the costume
 * of evidence.
 *
 * The original collectors derived `expected` and `examined` from the same array — `items` was
 * `principals.map(...)` and `expected` was `principals.length` — so the two could never
 * disagree, `complete` was true by construction, and the invariant that a claim verified over
 * an unknown subset has not been verified could not fire on any check that mattered. These
 * tests exist to keep the denominator independent of the numerator: each one takes an
 * enumeration that names more than the grading could reach and asserts the gap survives all
 * the way into the bundle.
 */

const AT = '2026-08-18T04:00:00.000Z';
const bundle = (over = {}) =>
  buildBundle({
    checkId: 'aws.iam.privileged-access',
    ksis: ['KSI-IAM-ELP'],
    collectorPath: 'src/collectors/aws/iam.mjs',
    collectorVersion: '2.0.0',
    collectedAt: AT,
    assertion: 'test',
    scope: {},
    population: { expected: 1, source_of_truth: 's', enumerated_from: 'e' },
    items: [{ id: 'a', status: 'pass' }],
    ...over,
  });

/* ------------------------------------------------------ decided nothing is not a pass */

test('a population with nothing decidable cannot report a pass', () => {
  const b = bundle({
    population: { expected: 2, source_of_truth: 's', enumerated_from: 'e' },
    items: [
      { id: 'a', status: 'not-applicable' },
      { id: 'b', status: 'not-applicable' },
    ],
  });
  assert.equal(b.population.complete, true, 'the population is complete...');
  assert.equal(b.population.decidable, 0, '...and decided nothing');
  assert.equal(b.result, 'warn', 'tested nothing and found nothing wrong must be different results');
});

test('an empty population cannot report a pass either', () => {
  const b = bundle({ population: { expected: 0, source_of_truth: 's', enumerated_from: 'e' }, items: [] });
  assert.equal(b.result, 'warn');
  assert.equal(b.population.decidable, 0);
});

test('one decidable item among not-applicable ones is enough to reach a pass', () => {
  const b = bundle({
    population: { expected: 2, source_of_truth: 's', enumerated_from: 'e' },
    items: [
      { id: 'a', status: 'pass' },
      { id: 'b', status: 'not-applicable' },
    ],
  });
  assert.equal(b.result, 'pass');
  assert.equal(b.population.decidable, 1);
});

/* ------------------------------------------------------------- the contract itself */

test('examined is computed from the items, so a caller cannot inflate it into completeness', () => {
  const b = bundle({
    population: { expected: 5, examined: 5, reconciliation: 'claimed', source_of_truth: 's', enumerated_from: 'e' },
    items: [{ id: 'a', status: 'pass' }],
  });
  assert.equal(b.population.examined, 1, 'the caller said 5; the items say 1');
  assert.equal(b.population.complete, false);
  assert.equal(b.result, 'warn');
});

test('a denominator smaller than the numerator is refused as a disagreement about the subject', () => {
  assert.throws(
    () =>
      bundle({
        population: { expected: 1, source_of_truth: 's', enumerated_from: 'e' },
        items: [
          { id: 'a', status: 'pass' },
          { id: 'b', status: 'pass' },
        ],
      }),
    /denominator smaller than its numerator/
  );
});

test('an itemised gap composes its own reconciliation, so the honest path needs no prose', () => {
  const b = bundle({
    population: {
      expected: 2,
      unexamined: [{ id: 'account/222233334444', reason: 'denied iam:GenerateCredentialReport' }],
      source_of_truth: 's',
      enumerated_from: 'e',
    },
  });
  assert.equal(b.population.complete, false);
  assert.match(b.population.reconciliation, /account\/222233334444 \(denied iam:GenerateCredentialReport\)/);
  assert.equal(b.result, 'warn');
});

test('an unexamined entry with no reason is refused, because an unnamed gap cannot be chased', () => {
  assert.throws(
    () => bundle({ population: { expected: 2, unexamined: [{ id: 'x' }], source_of_truth: 's', enumerated_from: 'e' } }),
    /needs an id and a reason/
  );
});

/* ------------------------------------ the denominator does not move with the numerator */

test('IAM privilege: a principal that could not be described leaves the denominator alone', () => {
  const principals = [
    { type: 'user', name: 'avery', attached: [], inline: [], attachedDocuments: [], trustedPrincipals: [] },
  ];
  const graded = gradePrivilegedAccess(principals, {
    enumerated: ['user/avery', 'role/LegacyOps'],
    unexamined: [{ id: 'role/LegacyOps', reason: 'AccessDenied on iam:ListAttachedRolePolicies' }],
    accountId: '123456789012',
  });
  const b = bundle({ population: graded.population, items: graded.items });

  assert.equal(b.population.expected, 3, 'the account claim plus both enumerated principals');
  assert.equal(b.population.examined, 2, 'the account claim plus the one principal that resolved');
  assert.equal(b.population.complete, false);
  assert.equal(b.result, 'warn', 'a denied read must not pass as a clean account');
});

test('IAM MFA: the credential report is reconciled against a separate principal listing', () => {
  const rows = [
    { user: '<root_account>', mfa_active: 'true', access_key_1_active: 'false', access_key_2_active: 'false' },
    { user: 'avery', password_enabled: 'true', mfa_active: 'true' },
  ];
  // `dana` exists in IAM but the credential report is generated asynchronously and predates her.
  const graded = gradeMfaCoverage(rows, { enumeratedUsers: ['avery', 'dana'], accountId: '123456789012' });
  const b = bundle({ checkId: 'aws.iam.mfa-coverage', ksis: ['KSI-IAM-APM'], population: graded.population, items: graded.items });

  assert.equal(b.population.expected, 3);
  assert.equal(b.population.examined, 2);
  assert.equal(b.population.complete, false);
  assert.match(b.population.reconciliation, /user\/dana/);
  assert.equal(b.result, 'warn', 'a stale credential report is not a clean one');
});

test('branch protection: the denominator is what the profile declared, not what the API answered', () => {
  const graded = gradeBranchProtection(
    [{ repo: 'acme/one', branch: 'main', classic: { required_approvals: 2, dismiss_stale: true, enforce_admins: true, bypass_actors: [] } }],
    {
      declared: [{ name: 'acme/one' }, { name: 'acme/two' }],
      unexamined: [{ id: 'acme/two:main', reason: 'repository not readable (HTTP 404)' }],
    }
  );
  const b = bundle({ checkId: 'github.change.branch-protection', ksis: ['KSI-CMT-RMV'], population: graded.population, items: graded.items });

  assert.equal(b.population.expected, 2);
  assert.equal(b.population.examined, 1);
  assert.equal(b.result, 'warn', 'a repository that vanished from the boundary is not a passing one');
});

test('workflow pinning: a declared repository that never answered is a gap, not an absence', () => {
  const graded = gradeWorkflowPinning([{ repo: 'acme/one', workflows: [] }], {
    declared: [{ name: 'acme/one' }, { name: 'acme/two' }],
  });
  const b = bundle({ checkId: 'github.supply-chain.workflow-pinning', ksis: ['KSI-SCR-MIT'], population: graded.population, items: graded.items });

  assert.equal(b.population.complete, false);
  assert.match(b.population.reconciliation, /acme\/two/);
});

/* ------------------------------------------------- absence is not the same as compliance */

test('a region with no security groups warns rather than passing over nothing', () => {
  const graded = gradeIngressExposure([], { scopeId: '123456789012' });
  const b = bundle({ checkId: 'aws.network.ingress-exposure', ksis: ['KSI-CNA-MAT'], population: graded.population, items: graded.items });

  assert.equal(b.result, 'warn');
  assert.match(b.items[0].detail, /Every VPC carries a default security group/);
});

test('a period in which every commit was a merge commit warns rather than passing', () => {
  const graded = gradePrReview(
    [
      { repo: 'acme/one', branch: 'main', sha: 'aaaaaaaa11', merge_commit: true },
      { repo: 'acme/one', branch: 'main', sha: 'bbbbbbbb22', merge_commit: true },
    ],
    { scopeId: 'acme/one' }
  );
  const b = bundle({ checkId: 'github.change.pr-review', ksis: ['KSI-CMT-VTD'], population: graded.population, items: graded.items });

  assert.equal(b.population.complete, true);
  assert.equal(b.result, 'warn', 'nothing here tested whether a change was reviewed');
});

// A permission gap pointing the other way is no less wrong. Reading "the token cannot see the
// pull request" as "there was no pull request" manufactures a security finding out of a scope.
test('a commit whose review history could not be read warns rather than failing', () => {
  const graded = gradePrReview(
    [{ repo: 'acme/one', branch: 'main', sha: 'cccccccc33', merge_commit: false, pulls: [], pulls_unresolved: 'HTTP 403' }],
    { scopeId: 'acme/one' }
  );
  const item = graded.items.find((i) => i.id.includes('cccccccc'));
  assert.equal(item.status, 'warn');
  assert.match(item.detail, /could not be read/);
});

/* ---------------------------------------------------------------- every check declares one */

test('every check names an independent enumeration for its denominator', async () => {
  const { bundles } = await runAll({ profile: {}, fixture: 'fixtures/collectors', collectedAt: AT });
  for (const b of bundles) {
    assert.ok(
      b.population.enumerated_from?.length,
      `${b.check_id} does not say where its expected count came from, so its completeness claim is unreviewable`
    );
  }
});

// The bundle schema is the contract every downstream reader is written against, and it was being
// maintained by hand alongside a builder that could drift from it silently.
test('every bundle a collector produces validates against the published bundle schema', async () => {
  const { default: Ajv } = await import('ajv/dist/2020.js');
  const { default: addFormats } = await import('ajv-formats');
  const { readFileSync } = await import('node:fs');

  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(JSON.parse(readFileSync('schemas/evidence-bundle.schema.json', 'utf8')));

  const { bundles } = await runAll({ profile: {}, fixture: 'fixtures/collectors', collectedAt: AT });
  for (const b of bundles) {
    assert.ok(validate(b), `${b.check_id}: ${JSON.stringify(validate.errors)}`);
  }
});

/* --------------------------------------------------------------- history and the chain */

test('two collections in one day are both kept, so a failing run cannot be overwritten', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-locker-'));
  try {
    const morning = bundle({ collectedAt: '2026-08-18T09:00:00.000Z' });
    const afternoon = bundle({ collectedAt: '2026-08-18T15:00:00.000Z' });
    writeBundle(morning, dir);
    writeBundle(afternoon, dir);
    assert.equal(readdirSync(join(dir, 'aws.iam.privileged-access')).length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the chain catches an edited bundle whose own hash was recomputed', () => {
  const first = bundle({ collectedAt: '2026-08-17T04:00:00.000Z' });
  const second = bundle({ collectedAt: '2026-08-18T04:00:00.000Z', previousHash: first.integrity.content_sha256, chainIndex: 1 });
  assert.equal(verifyChain([first, second]).ok, true);

  // Rewrite the first bundle exactly the way someone covering their tracks would: change the
  // verdict, then recompute the content hash so `verifyIntegrity` is satisfied.
  const forged = bundle({ collectedAt: '2026-08-17T04:00:00.000Z', items: [{ id: 'a', status: 'pass', detail: 'edited' }] });
  const chain = verifyChain([forged, second]);
  assert.equal(chain.ok, false);
  assert.deepEqual(chain.breaks.map((b) => b.kind), ['chain']);
});

test('a bundle file that will not parse is reported rather than taking down the report', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-locker-'));
  try {
    writeBundle(bundle(), dir);
    mkdirSync(join(dir, 'aws.iam.privileged-access'), { recursive: true });
    writeFileSync(join(dir, 'aws.iam.privileged-access', '20260819T000000000Z-deadbeef.json'), '{ truncated');

    const locker = readLocker(dir);
    assert.equal(locker.unreadable.length, 1);
    assert.equal(locker.bundles.length, 1, 'the readable bundle still counts');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
