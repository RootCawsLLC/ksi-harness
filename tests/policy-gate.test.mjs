import assert from 'node:assert/strict';
import { test } from 'node:test';

import { findIacFiles, gradeGate, ksisInMessage } from '../src/collectors/pipeline/policy-gate.mjs';
import { buildBundle } from '../src/evidence/bundle.mjs';

/**
 * The population reconciliation is the whole reason this collector exists rather than a CI step
 * that echoes an exit code.
 *
 * A gate reports on the files it was given. If a file never reaches the gate — a bad --policy
 * path, an ignore rule, a directory nobody added to the workflow — it does not appear in the
 * report, and a collector that counted the report's own entries would call that a clean pass
 * over a shrinking denominator. Enumerating the working tree independently is what turns "every
 * file was evaluated" into a claim that can be falsified.
 *
 * The split these tests now assume: grading declares the denominator and itemises what it could
 * not reach, and the bundle contract is what turns that into `examined`, `complete` and a
 * reconciliation. A grade function that computed its own completeness could disagree with the
 * bundle built from it, which is one authority too many for the field everything else relies on.
 */

const bundleFrom = (graded) =>
  buildBundle({
    checkId: 'pipeline.iac.policy-gate',
    ksis: ['KSI-CMT-VTD'],
    collectorPath: 'src/collectors/pipeline/policy-gate.mjs',
    collectorVersion: '2.0.0',
    collectedAt: '2026-08-18T04:00:00.000Z',
    assertion: 'Every Terraform file in a gated root was evaluated by the policy gate.',
    scope: {},
    items: graded.items,
    population: graded.population,
  });

const report = (filename, { failures = [], warnings = [], successes = 5 } = {}) => ({
  filename,
  namespace: 'main',
  successes,
  warnings: warnings.map((msg) => ({ msg })),
  failures: failures.map((msg) => ({ msg })),
});

test('a file evaluated with no findings passes', () => {
  const graded = gradeGate({ report: [report('infra/main.tf')], expectedFiles: ['infra/main.tf'] });
  assert.equal(graded.items[0].status, 'pass');
  assert.equal(graded.population.expected, 1);
  assert.deepEqual(graded.population.unexamined, []);

  const bundle = bundleFrom(graded);
  assert.equal(bundle.population.examined, 1);
  assert.equal(bundle.population.complete, true);
  assert.equal(bundle.result, 'pass');
});

test('a denied finding fails the file', () => {
  const graded = gradeGate({
    report: [report('infra/main.tf', { failures: ['KSI-SVC-SIN: unencrypted volume'] })],
    expectedFiles: ['infra/main.tf'],
  });
  assert.equal(graded.items[0].status, 'fail');
});

// Advisory and blocking findings are different claims and collapsing them into one exit code
// loses the distinction the policy author deliberately made.
test('an advisory-only finding warns rather than failing', () => {
  const graded = gradeGate({
    report: [report('infra/main.tf', { warnings: ['KSI-MLA-LET: single-region trail'] })],
    expectedFiles: ['infra/main.tf'],
  });
  assert.equal(graded.items[0].status, 'warn');
});

test('a file present in a gated root but absent from the report is reported, not assumed to pass', () => {
  const graded = gradeGate({
    report: [report('infra/main.tf')],
    expectedFiles: ['infra/main.tf', 'infra/forgotten.tf'],
  });

  // The unevaluated file is a hole in the population rather than a member of it. Carrying it
  // as an examined warning would have let the denominator absorb the very gap it exists to
  // expose, and `complete` would have been true over a file nothing ever looked at.
  assert.deepEqual(graded.items.map((i) => i.id), ['infra/main.tf']);
  const forgotten = graded.population.unexamined.find((u) => u.id === 'infra/forgotten.tf');
  assert.ok(forgotten, 'the unevaluated file is itemised');
  assert.match(forgotten.reason, /never evaluated/);
  assert.equal(graded.population.expected, 2);

  const bundle = bundleFrom(graded);
  assert.equal(bundle.population.examined, 1, 'an unevaluated file is not examined');
  assert.equal(bundle.population.complete, false);
  assert.match(bundle.population.reconciliation, /infra\/forgotten\.tf/);
  assert.equal(bundle.result, 'warn', 'an incomplete population cannot report a pass');
});

test('an unevaluated file is excluded from examined so the bundle cannot report a complete population', () => {
  const graded = gradeGate({ report: [], expectedFiles: ['infra/a.tf', 'infra/b.tf'] });
  assert.equal(graded.population.unexamined.length, 2);

  const bundle = bundleFrom(graded);
  assert.equal(bundle.population.examined, 0);
  assert.equal(bundle.population.complete, false);
  assert.ok(bundle.population.reconciliation, 'a gap with no explanation would be refused by buildBundle');
  assert.equal(bundle.result, 'warn');
});

test('a file the report covers but no root declares is surfaced rather than dropped', () => {
  const graded = gradeGate({
    report: [report('infra/main.tf'), report('scratch/experiment.tf')],
    expectedFiles: ['infra/main.tf'],
  });
  assert.deepEqual(graded.unexpected, ['scratch/experiment.tf']);
});

test('separator style does not change the result, because reports and globs disagree on it', () => {
  const graded = gradeGate({
    report: [report('infra\\modules\\main.tf')],
    expectedFiles: ['infra/modules/main.tf'],
  });
  assert.equal(graded.items[0].status, 'pass');
  assert.deepEqual(graded.population.unexamined, []);
});

test('findings for the same file across namespaces are merged into one verdict', () => {
  const graded = gradeGate({
    report: [
      report('infra/main.tf', { failures: ['KSI-SVC-SIN: unencrypted'] }),
      report('infra/main.tf', { warnings: ['KSI-MLA-LET: single region'] }),
    ],
    expectedFiles: ['infra/main.tf'],
  });
  assert.equal(graded.items.length, 1);
  assert.equal(graded.items[0].status, 'fail');
  assert.equal(bundleFrom(graded).population.examined, 1);
});

/* ------------------------------------------------------- indicators from findings */

test('indicator ids are recovered from finding text, linking a gate rule to a KSI', () => {
  assert.deepEqual(ksisInMessage('KSI-CNA-RNT / KSI-CNA-MAT: too open'), ['KSI-CNA-MAT', 'KSI-CNA-RNT']);
  assert.deepEqual(ksisInMessage('KSI-SVC-SIN: KSI-SVC-SIN again'), ['KSI-SVC-SIN']);
  assert.deepEqual(ksisInMessage('no indicator here'), []);
});

test('the graded result reports every indicator the gate flagged', () => {
  const graded = gradeGate({
    report: [
      report('infra/a.tf', { failures: ['KSI-CNA-RNT / KSI-CNA-MAT: open'] }),
      report('infra/b.tf', { warnings: ['KSI-MLA-LET: single region'] }),
    ],
    expectedFiles: ['infra/a.tf', 'infra/b.tf'],
  });
  assert.deepEqual(graded.indicatorsFlagged, ['KSI-CNA-MAT', 'KSI-CNA-RNT', 'KSI-MLA-LET']);
});

/* ------------------------------------------------------------- file enumeration */

test('the gated roots in this repository enumerate the Terraform under them', () => {
  const compliant = findIacFiles('policy/terraform/compliant');
  assert.deepEqual(compliant, ['main.tf']);
  assert.ok(findIacFiles('policy/terraform/violations').includes('main.tf'));
});

test('provider and module caches are excluded, since nobody can action a finding in them', () => {
  const files = findIacFiles('policy/terraform');
  assert.deepEqual(files.filter((f) => f.includes('.terraform')), []);
});

test('a root that does not exist enumerates empty rather than throwing', () => {
  assert.deepEqual(findIacFiles('policy/terraform/does-not-exist'), []);
});

test('the metric counts the pass rate over evaluated files', () => {
  const graded = gradeGate({
    report: [report('infra/a.tf'), report('infra/b.tf', { failures: ['KSI-SVC-SIN: no'] })],
    expectedFiles: ['infra/a.tf', 'infra/b.tf'],
  });
  assert.equal(graded.metric.metric_id, 'pipeline.iac.gate_pass_rate');
  assert.equal(graded.metric.value, 0.5);
});
