import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { runAll } from '../src/collectors/run-all.mjs';
import { writeBundle } from '../src/evidence/bundle.mjs';
import { readLocker } from '../src/evidence/locker.mjs';
import { assessCadence, buildState, openFindings } from '../src/evidence/state.mjs';

/**
 * The control state is where the harness decides what it is willing to say, so these tests are
 * mostly about what it refuses to say.
 *
 * The important one: a route can declare a check and a cadence, and the state must not treat that
 * declaration as evidence. Missing evidence reads as `no-evidence`, stale evidence fails the
 * cadence, and an incomplete population degrades rather than passes. Every one of those is a
 * place where a self-assessment would round up.
 */

const AT = '2026-08-18T04:00:00.000Z';
const NOW = Date.parse(AT) + 6 * 60 * 60 * 1000;
const temporary = [];

after(() => {
  for (const dir of temporary) rmSync(dir, { recursive: true, force: true });
});

async function locker({ collectedAt = AT } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-state-'));
  temporary.push(dir);
  const { bundles } = await runAll({ profile: {}, fixture: 'fixtures/collectors', collectedAt });
  for (const bundle of bundles) writeBundle(bundle, dir);
  return dir;
}

/* ------------------------------------------------------------------------ cadence */

const check = (overrides = {}) => ({ check_id: 'x.y.z', present: true, age_days: 0.5, observed_interval_days: null, ...overrides });

test('an event-driven cadence is exempt rather than passed, since nothing was due', () => {
  const verdict = assessCadence({ cadence: 'per-incident' }, [check()], NOW);
  assert.equal(verdict.verifiable, false);
  assert.equal(verdict.met, null);
});

test('a claimed schedule with no evidence in the locker fails', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [check({ present: false, age_days: Infinity })], NOW);
  assert.equal(verdict.met, false);
  assert.match(verdict.detail, /holds no evidence/);
});

test('a route with a cadence but no checks cannot have one verified', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [], NOW);
  assert.equal(verdict.verifiable, false);
  assert.equal(verdict.met, null);
});

// A daily job that ran 35 hours ago is not a broken control, and flagging it would make the
// report noisy enough that a real staleness would be skipped over.
test('one period of tolerance is allowed before staleness is a finding', () => {
  assert.equal(assessCadence({ cadence: 'daily' }, [check({ age_days: 1.5 })], NOW).met, true);
  assert.equal(assessCadence({ cadence: 'daily' }, [check({ age_days: 9 })], NOW).met, false);
});

test('stale evidence against a claimed schedule reports the age it observed', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [check({ age_days: 42 })], NOW);
  assert.equal(verdict.met, false);
  assert.match(verdict.detail, /42\.0 days old/);
});

test('an observed interval longer than the claim fails even when the latest run is fresh', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [check({ age_days: 0.2, observed_interval_days: 30 })], NOW);
  assert.equal(verdict.met, false);
  assert.match(verdict.detail, /observed interval is 30\.0 days/);
});

test('the stalest check governs, not the freshest', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [check({ age_days: 0.1 }), check({ age_days: 60 })], NOW);
  assert.equal(verdict.met, false);
});

test('a single run reports that the interval is not yet established rather than implying one', () => {
  const verdict = assessCadence({ cadence: 'daily' }, [check({ age_days: 0.3 })], NOW);
  assert.equal(verdict.met, true);
  assert.match(verdict.detail, /not yet established/);
});

/* -------------------------------------------------------------------------- state */

test('the state resolves every applicable indicator and never claims one is met', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });

  assert.equal(state.routes_valid, true);
  assert.deepEqual(state.route_errors, []);
  assert.equal(state.indicators.length, state.counts.total);

  const serialised = JSON.stringify(state);
  assert.ok(!/"met_status"|"compliant":true/.test(serialised), 'the state must not assert an indicator is met');

  for (const indicator of state.indicators.filter((i) => i.applicable)) {
    assert.ok(indicator.coverage, `${indicator.id} has no coverage level`);
    assert.ok(indicator.evidence_state, `${indicator.id} has no evidence state`);
  }
});

test('the ruleset provenance travels with the state, so a report identifies what it reasoned about', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  assert.match(state.ruleset.sha256, /^[0-9a-f]{64}$/);
  assert.ok(state.ruleset.version);
});

test('fixture-derived evidence is counted and reported as such', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  assert.equal(state.evidence.fixture_bundles, state.evidence.bundle_count);
  assert.ok(state.evidence.bundle_count > 0);
});

test('an empty locker yields no-evidence rather than a clean bill of health', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-empty-'));
  temporary.push(dir);
  const state = buildState({ evidenceDir: dir, klass: 'c', now: NOW });

  assert.equal(state.evidence.bundle_count, 0);
  const automated = state.indicators.filter((i) => ['automated', 'partial'].includes(i.coverage));
  assert.ok(automated.length > 0);
  for (const indicator of automated) {
    assert.equal(indicator.evidence_state, 'no-evidence', `${indicator.id} claimed a state without evidence`);
  }
  assert.equal(state.counts.evidence_state['satisfied-in-part'], 0);
});

test('manual and unaddressed routes are stated as such rather than folded into the automated tally', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  for (const indicator of state.indicators.filter((i) => i.coverage === 'manual')) {
    assert.equal(indicator.evidence_state, 'manual-attested');
    assert.ok(indicator.manual_evidence?.owner, `${indicator.id} is manual with no owner`);
  }
  for (const indicator of state.indicators.filter((i) => i.coverage === 'unaddressed')) {
    assert.equal(indicator.evidence_state, 'not-evidenced');
    assert.ok(indicator.next, `${indicator.id} is unaddressed with no next step`);
  }
});

test('partial coverage always carries a stated gap into the state', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  for (const indicator of state.indicators.filter((i) => i.coverage === 'partial')) {
    assert.ok(indicator.unautomated.length > 0, `${indicator.id} is partial with no gap stated`);
  }
});

test('stale evidence is reported as a cadence failure rather than accepted', async () => {
  const dir = await locker({ collectedAt: '2026-01-01T00:00:00.000Z' });
  const state = buildState({ evidenceDir: dir, klass: 'c', now: NOW });
  assert.ok(state.counts.cadence_unmet > 0, 'evidence from eight months ago cannot satisfy a daily claim');
});

test('open findings name the failing checks and exclude indicators that claim no automation', async () => {
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  const findings = openFindings(state);
  assert.ok(findings.length > 0, 'the fixtures include failures, so findings must be reported');
  for (const finding of findings) {
    assert.ok(finding.checks.length > 0, `${finding.indicator} is a finding with no failing check named`);
    const indicator = state.indicators.find((i) => i.id === finding.indicator);
    assert.ok(['automated', 'partial'].includes(indicator.coverage));
  }
});

/* ------------------------------------------------------------------------ report */

// The scheduled monitoring workflow reads findings out of the JSON report to decide whether to
// raise an issue. A finding that only exists in the rendered Markdown is a finding nobody is
// paged for, so the machine-readable path is part of the contract.
test('the JSON coverage report carries the findings a monitoring run acts on', async () => {
  const { coverageJson, coverageMarkdown } = await import('../src/report/coverage.mjs');
  const state = buildState({ evidenceDir: await locker(), klass: 'c', now: NOW });
  const report = coverageJson(state);

  assert.ok(Array.isArray(report.findings));
  assert.deepEqual(report.findings, openFindings(state));
  for (const finding of report.findings) {
    assert.ok(finding.indicator && finding.evidence_state);
    assert.ok(finding.checks.length > 0);
  }

  // Both renderings must agree about how many findings there are.
  const markdown = coverageMarkdown(state);
  for (const finding of report.findings) {
    assert.ok(markdown.includes(finding.indicator), `${finding.indicator} is missing from the Markdown report`);
  }
});

test('the report states plainly when its evidence came from fixtures', async () => {
  const { coverageMarkdown } = await import('../src/report/coverage.mjs');
  const markdown = coverageMarkdown(buildState({ evidenceDir: await locker(), klass: 'c', now: NOW }));
  assert.match(markdown, /came from fixtures/);
  assert.match(markdown, /not a production environment/);
});

/* ------------------------------------------------------------------------ locker */

test('the locker verifies bundle integrity and reports tampering rather than dropping it', async () => {
  const dir = await locker();
  const before = readLocker(dir);
  assert.deepEqual(before.tampered, []);
  assert.ok(before.bundles.length > 0);
  assert.ok(before.checks.size > 0);
});
