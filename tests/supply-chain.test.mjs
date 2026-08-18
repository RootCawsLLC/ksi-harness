import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DEFAULT_SLA_DAYS, gradeDependencyAlerts } from '../src/collectors/github/dependencies.mjs';
import { gradeRegister, registerFrom } from '../src/collectors/thirdparty/register.mjs';
import { buildBundle } from '../src/evidence/bundle.mjs';

/**
 * Supply chain, split the way the indicators actually split it.
 *
 * KSI-SCR-MON is narrower than "supply chain risk": it asks whether third-party *software*
 * is automatically monitored for upstream vulnerabilities. The register — who the third
 * parties are, who owns them, whether a non-certified one has a resolution — is KSI-SCR-MIT,
 * which asks to identify, review and mitigate. Routing one check at both would have been the
 * convenient reading and the wrong one.
 */

const NOW = Date.parse('2026-08-18T04:00:00.000Z');
const bundle = (graded, checkId, ksis) =>
  buildBundle({
    checkId,
    ksis,
    collectorPath: 'src/collectors/x.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-18T04:00:00.000Z',
    assertion: 'test',
    scope: {},
    items: graded.items,
    population: graded.population,
  });

/* ----------------------------------------------------- upstream vulnerabilities */

// The first-order question, and the one a count of open alerts cannot answer: a repository
// with alerting off and no alerts looks identical to one with alerting on and nothing wrong.
test('a repository with alerting disabled fails, however empty its alert list is', () => {
  const graded = gradeDependencyAlerts([{ repo: 'a/b', alerts_enabled: false, alerts: [] }], { now: NOW });
  const item = graded.items.find((i) => i.id === 'monitoring/a/b');
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /absence of monitoring rather than an absence of vulnerabilities/);
  assert.equal(bundle(graded, 'github.supply-chain.dependency-alerts', ['KSI-SCR-MON']).result, 'fail');
});

test('monitoring state is its own population member, so enabling it is evidenced separately from the queue', () => {
  const graded = gradeDependencyAlerts([{ repo: 'a/b', alerts_enabled: true, alerts: [] }], { now: NOW });
  assert.deepEqual(graded.items.map((i) => i.id), ['monitoring/a/b']);
  assert.equal(bundle(graded, 'github.supply-chain.dependency-alerts', ['KSI-SCR-MON']).result, 'pass');
});

// An alert open for two days and one open for two hundred are not the same fact.
test('an open alert is aged against the window its severity declares', () => {
  const repos = [
    {
      repo: 'a/b',
      alerts_enabled: true,
      alerts: [
        { number: 1, severity: 'critical', package: 'jinja2', created_at: '2026-07-08T00:00:00Z' },
        { number: 2, severity: 'high', package: 'lodash', created_at: '2026-08-10T00:00:00Z' },
      ],
    },
  ];
  const graded = gradeDependencyAlerts(repos, { slaDays: DEFAULT_SLA_DAYS, now: NOW });

  const overdue = graded.items.find((i) => i.id === 'alert/a/b#1');
  assert.equal(overdue.status, 'fail', 'a 41-day critical against a 7-day window');
  assert.match(overdue.detail, /past the 7-day window/);

  const within = graded.items.find((i) => i.id === 'alert/a/b#2');
  assert.equal(within.status, 'warn', 'within its window is neither a failure nor evidence of a fix');
  assert.match(within.detail, /within the 30-day window/);
});

test('a severity with no declared window warns rather than being silently accepted', () => {
  const graded = gradeDependencyAlerts(
    [{ repo: 'a/b', alerts_enabled: true, alerts: [{ number: 3, severity: 'moderate', package: 'x', created_at: '2020-01-01T00:00:00Z' }] }],
    { now: NOW }
  );
  assert.match(graded.items.find((i) => i.id === 'alert/a/b#3').detail, /no remediation window is declared/);
});

test('a repository whose alert state could not be read is unverifiable, not compliant', () => {
  const graded = gradeDependencyAlerts([{ repo: 'a/b', unverifiable: 'Token lacks permission' }], { now: NOW });
  assert.equal(graded.items[0].status, 'warn');
});

test('the denominator is the declared repositories plus the alerts they reported', () => {
  const graded = gradeDependencyAlerts(
    [
      { repo: 'a/b', alerts_enabled: true, alerts: [{ number: 1, severity: 'low', package: 'x', created_at: '2026-08-17T00:00:00Z' }] },
      { repo: 'a/c', alerts_enabled: true, alerts: [] },
    ],
    { now: NOW, unexamined: [{ id: 'a/d', reason: 'PERMISSION_DENIED' }] }
  );
  const b = bundle(graded, 'github.supply-chain.dependency-alerts', ['KSI-SCR-MON']);
  assert.equal(b.population.expected, 4, '2 repositories + 1 alert + 1 unexamined');
  assert.equal(b.population.complete, false);
});

/* ------------------------------------------------------------ the register */

const OWNED = { name: 'Atlas', provider: 'MongoDB', certified: false, owner: 'Data lead' };

test('a dependency nobody owns fails before anything else is considered', () => {
  const graded = gradeRegister([{ ...OWNED, owner: null, resolution: { plan: 'x', target_date: '2027-01-01' } }], [], { now: NOW });
  assert.equal(graded.items[0].status, 'fail');
  assert.match(graded.items[0].detail, /nobody will answer for/);
});

// The FedRAMP case: not automatically a failure, but a question that fails when it goes stale.
test('a non-certified dependency is a question, and fails when its resolution is overdue', () => {
  const future = gradeRegister([{ ...OWNED, resolution: { plan: 'Migrate to Gov tier', target_date: '2027-03-31' } }], [], { now: NOW });
  assert.equal(future.items[0].status, 'warn', 'owned, dated and in the future is a known gap being worked');

  const overdue = gradeRegister([{ ...OWNED, resolution: { plan: 'Migrate to Gov tier', target_date: '2026-07-31' } }], [], { now: NOW });
  assert.equal(overdue.items[0].status, 'fail');
  assert.match(overdue.items[0].detail, /was due 2026-07-31 and has passed/);

  const undated = gradeRegister([{ ...OWNED, resolution: { plan: 'Assess' } }], [], { now: NOW });
  assert.match(undated.items[0].detail, /cannot go overdue and will not be chased/);

  const none = gradeRegister([{ ...OWNED }], [], { now: NOW });
  assert.match(none.items[0].detail, /no resolution is stated/);
});

test('a certified dependency with a lapsed attestation is not evidence of a current authorization', () => {
  const current = gradeRegister(
    [{ name: 'GCP', certified: true, fedramp_id: 'FR1', owner: 'Platform', attestation: { date: '2026-06-01', refresh_days: 365 } }],
    [],
    { now: NOW }
  );
  assert.equal(current.items[0].status, 'pass');

  const lapsed = gradeRegister(
    [{ name: 'Datadog', certified: true, fedramp_id: 'FR2', owner: 'Obs', attestation: { date: '2024-02-01', refresh_days: 365 } }],
    [],
    { now: NOW }
  );
  assert.equal(lapsed.items[0].status, 'fail');
  assert.match(lapsed.items[0].detail, /lapsed attestation is not evidence/);
});

// The finding the reconciliation exists for. A register checked only against itself confirms
// that a document says what it says.
test('an observed integration matching no register entry is an undeclared dependency', () => {
  const graded = gradeRegister(
    [{ name: 'Datadog', certified: true, fedramp_id: 'FR2', owner: 'Obs', attestation: { date: '2026-06-01' }, hosts: ['datadoghq.com'] }],
    [
      { source: 'a/b', host: 'hooks.datadoghq.com' },
      { source: 'a/b', host: 'sentry.io' },
    ],
    { now: NOW }
  );
  assert.equal(graded.items.find((i) => i.id.includes('datadoghq')).status, 'pass', 'a subdomain of a declared host matches');
  const undeclared = graded.items.find((i) => i.id.includes('sentry.io'));
  assert.equal(undeclared.status, 'fail');
  assert.match(undeclared.detail, /no register entry mentions it/);
});

test('the denominator spans both the declaration and the observation', () => {
  const graded = gradeRegister(
    [{ name: 'A', certified: false, owner: 'o', resolution: { plan: 'p', target_date: '2027-01-01' } }],
    [{ source: 'a/b', host: 'x.example' }],
    { now: NOW, unexamined: [{ id: 'webhooks/a/c', reason: 'PERMISSION_DENIED' }] }
  );
  const b = bundle(graded, 'thirdparty.register.review', ['KSI-SCR-MIT']);
  assert.equal(b.population.expected, 3, '1 declared + 1 observed + 1 unexamined');
  assert.match(b.population.enumerated_from, /would only confirm that a document says what it says/);
});

// One declaration, not two. The overview states these dependencies to FedRAMP under
// MAS-CSO-TPR, and a register that could drift from what was filed is worse than none.
test('the register is read from the same certification block the overview emits', () => {
  const profile = {
    certification: {
      third_party: {
        certified: [{ id: 'FR1', name: 'GCP', use_case: 'compute', owner: 'Platform', attestation: { date: '2026-06-01' } }],
        non_certified: [{ name: 'Atlas', provider: 'MongoDB', use_case: 'metadata', owner: 'Data' }],
      },
    },
  };
  const register = registerFrom(profile);
  assert.equal(register.length, 2);
  assert.equal(register[0].certified, true);
  assert.equal(register[0].fedramp_id, 'FR1');
  assert.equal(register[1].certified, false);
  assert.equal(register[1].owner, 'Data');
});
