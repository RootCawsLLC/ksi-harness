import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildBundle } from '../src/evidence/bundle.mjs';
import { gradeProvisioning } from '../src/collectors/idp/lifecycle.mjs';
import { gradeRoster } from '../src/collectors/idp/roster.mjs';
import { normaliseRoster, resolveHrSource, resolveIdp } from '../src/collectors/lib/idp.mjs';

/**
 * The second half of KSI-IAM-AAM: whether an account should still exist.
 *
 * `idp.account.provisioning` establishes that automation created an account. It cannot establish
 * that the person is still here, because the provisioning source records how an identity was
 * made and never whether it should be kept. These tests exist to hold the line that the two are
 * independent — the first one below fails this check while passing every other check in the
 * harness, and that account is the entire reason the collector was written.
 */

const NOW = Date.parse('2026-08-19T12:00:00.000Z');
const account = (login, over = {}) => ({ login, status: 'ACTIVE', live: true, source: 'SCIM', ...over });

const roster = (workers, over = {}) =>
  normaliseRoster({ as_of: '2026-08-18T06:00:00Z', system: 'workday', workers, ...over });

const bundleOf = (graded) =>
  buildBundle({
    checkId: 'idp.account.roster',
    ksis: ['KSI-IAM-AAM'],
    collectorPath: 'src/collectors/idp/roster.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-19T12:00:00.000Z',
    assertion: 'test',
    scope: {},
    ...graded,
  });

const itemFor = (graded, login) => graded.items.find((i) => i.id === `account/${login}`);

/* --------------------------------------------------------------- the finding */

/**
 * The whole argument for this collector in one test.
 *
 * The same account, graded by both halves of the indicator: automation created it, so the
 * lifecycle check passes it, and nothing about that is wrong. The person left in March. If this
 * ever starts passing both, the harness has gone back to reporting a mechanism as an outcome.
 */
test('an account automation provisioned perfectly still fails if its worker record ended', () => {
  const leaver = account('j.lindqvist@x', { source: 'ACTIVE_DIRECTORY' });

  const provisioning = gradeProvisioning([leaver], { automatedSources: new Set(['ACTIVE_DIRECTORY']) });
  assert.equal(provisioning.items[0].status, 'pass', 'provisioning was automated, and that much is true');

  const graded = gradeRoster([leaver], roster([{ email: 'j.lindqvist@x', status: 'terminated', termination_date: '2026-03-14' }]), { now: NOW });
  const item = itemFor(graded, 'j.lindqvist@x');
  assert.equal(item.status, 'fail');
  assert.equal(item.observed.days_since, 158, 'the age of the gap is reported, not just its existence');
  assert.match(item.detail, /Provisioning was automated; deprovisioning was not/);
});

// Unattributable rather than proven orphaned, and the detail has to say which, because the two
// call for different remedies: one is a deprovisioning failure, the other a missing declaration.
test('an account with no worker record fails as unattributable, distinctly from a leaver', () => {
  const graded = gradeRoster([account('break-glass@x')], roster([]), { now: NOW });
  const item = itemFor(graded, 'break-glass@x');
  assert.equal(item.status, 'fail');
  assert.equal(item.observed.attribution, 'none');
  assert.match(item.detail, /not declared in idp.non_human_accounts/);
  assert.doesNotMatch(item.detail, /terminated/);
});

/* ------------------------------------------------- exclusions, and their price */

test('a declared non-human identity leaves the denominator rather than passing', () => {
  const graded = gradeRoster([account('svc-transcode@x')], roster([]), {
    nonHumanAccounts: new Set(['svc-transcode@x']),
    now: NOW,
  });
  assert.equal(itemFor(graded, 'svc-transcode@x').status, 'not-applicable');
  assert.equal(bundleOf(graded).population.decidable, 1, 'only the roster freshness item was decidable');
});

/**
 * The reason the exclusion is a list and not a prefix.
 *
 * An estate that could exclude accounts by naming them `svc-` would be granting itself the
 * exclusion, and an orphaned account is exactly the thing that can be renamed. The identical
 * login fails without the declaration and is excluded with it, so the profile is doing the work.
 */
test('the same service-shaped login fails when the profile has not declared it', () => {
  const graded = gradeRoster([account('svc-transcode@x')], roster([]), { now: NOW });
  assert.equal(itemFor(graded, 'svc-transcode@x').status, 'fail');
});

test('a deprovisioned account is not-applicable: who it belonged to is no longer a live question', () => {
  const graded = gradeRoster([account('gone@x', { live: false, status: 'DEPROVISIONED' })], roster([]), { now: NOW });
  assert.equal(itemFor(graded, 'gone@x').status, 'not-applicable');
});

/* --------------------------------------------------------------- worker state */

// Suspending a parental-leave account may be correct policy. It is not this indicator's question,
// and a finding here would be wrong in the one direction this repository cannot afford.
test('a worker on leave still works here and their account passes', () => {
  const graded = gradeRoster([account('t.varga@x')], roster([{ email: 't.varga@x', status: 'leave' }]), { now: NOW });
  assert.equal(itemFor(graded, 't.varga@x').status, 'pass');
});

test('a worker state the harness does not map warns rather than resolving into a guess', () => {
  const graded = gradeRoster([account('r.okafor@x')], roster([{ email: 'r.okafor@x', status: 'contingent-worker' }]), { now: NOW });
  const item = itemFor(graded, 'r.okafor@x');
  assert.equal(item.status, 'warn');
  assert.equal(item.observed.worker_status, 'contingent-worker');
  assert.equal(bundleOf(graded).result, 'warn', 'and it cannot be absorbed into a passing bundle');
});

test('accounts and roster rows are matched case-insensitively, and login aliases email', () => {
  const graded = gradeRoster([account('Amara.Osei@X')], normaliseRoster({
    as_of: '2026-08-18T06:00:00Z',
    system: 'workday',
    workers: [{ login: 'amara.osei@x', status: 'active' }],
  }), { now: NOW });
  assert.equal(itemFor(graded, 'Amara.Osei@X').status, 'pass');
});

/* ------------------------------------------------------------------ freshness */

/**
 * The failure mode that would otherwise read clean forever.
 *
 * Every account matches a currently-employed worker, so without a freshness item this bundle
 * passes — over a roster exported before any of the terminations it is supposed to reveal. The
 * premise having expired has to be visible in the same population as the findings.
 */
test('a stale roster cannot produce a clean bundle even when every account matches', () => {
  const graded = gradeRoster([account('a@x')], roster([{ email: 'a@x', status: 'active' }], { as_of: '2026-06-01T00:00:00Z' }), { maxAgeDays: 7, now: NOW });

  assert.equal(itemFor(graded, 'a@x').status, 'pass', 'the account itself reconciles');
  const freshness = graded.items.find((i) => i.id === 'roster/as-of');
  assert.equal(freshness.status, 'fail');
  assert.equal(freshness.observed.age_days, 79.5);
  assert.equal(bundleOf(graded).result, 'fail');
});

test('an undated roster fails, because nothing establishes it is current', () => {
  const graded = gradeRoster([account('a@x')], roster([{ email: 'a@x', status: 'active' }], { as_of: null }), { now: NOW });
  const freshness = graded.items.find((i) => i.id === 'roster/as-of');
  assert.equal(freshness.status, 'fail');
  assert.match(freshness.detail, /no as_of/);
});

test('the roster snapshot is a member of the population, not a precondition of it', () => {
  const graded = gradeRoster([account('a@x'), account('b@x')], roster([]), { now: NOW });
  assert.equal(graded.population.expected, 3, 'two accounts plus the roster itself');
  assert.equal(bundleOf(graded).population.complete, true);
});

/* ------------------------------------------------- the boundary with no roster */

/**
 * Why an undeclared roster produces a bundle instead of an exception.
 *
 * A collector that threw here would leave the route with a missing bundle, and a route with a
 * missing bundle reports `no-evidence` for the whole indicator — which would hide the findings
 * the other two checks did make. Reporting the accounts as unexamined says the true thing: the
 * population is known, none of it was tested, and here is why.
 */
test('no declared roster is an unexamined population, not an empty one and not a pass', () => {
  const graded = gradeRoster([account('a@x'), account('b@x')], null, { now: NOW });
  const bundle = bundleOf(graded);

  assert.deepEqual(graded.items, []);
  assert.equal(bundle.population.expected, 2);
  assert.equal(bundle.population.examined, 0);
  assert.equal(bundle.result, 'warn', 'the ceiling on a population nothing examined');
  assert.match(bundle.population.reconciliation, /no HR roster is declared/);
});

// A zero would plot as an estate where no account is attributable to anybody, which is a much
// worse claim than the true one: nothing was measured.
test('an unmeasured population reports no metric rather than a metric of zero', () => {
  const bundle = bundleOf(gradeRoster([account('a@x')], null, { now: NOW }));
  assert.equal(bundle.metric, undefined);
  assert.equal(JSON.parse(JSON.stringify(bundle)).metric, undefined, 'and it is absent from the written bundle');
});

/* ----------------------------------------------------------------- the profile */

test('the roster is declared, never discovered, and an unknown kind is refused', () => {
  assert.equal(resolveHrSource(null), null, 'absence is absence, not a default');
  assert.throws(() => resolveHrSource({ kind: 'workday-api', path: 'x' }), /Unknown idp.hr_source.kind/);
  assert.throws(() => resolveHrSource({ kind: 'file' }), /path is required/);
  assert.equal(resolveHrSource({ path: './hr/roster.json' }).maxAgeDays, 7, 'a default shorter than any notice period');
});

test('the profile carries the roster and the non-human declarations through to the collector', () => {
  const idp = resolveIdp({
    idp: {
      provider: 'okta',
      domain: 'x.okta.com',
      hr_source: { kind: 'file', path: './hr/roster.json', max_age_days: 2 },
      non_human_accounts: ['SVC-Transcode@X'],
    },
  });
  assert.equal(idp.hrSource.maxAgeDays, 2);
  assert.equal(idp.nonHumanAccounts.has('svc-transcode@x'), true, 'normalised, so a declaration is not case-sensitive');
});
