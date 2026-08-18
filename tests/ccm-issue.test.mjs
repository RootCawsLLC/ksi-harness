// Escalation is a control, so the interesting cases are the ones that are awkward to trigger by
// hand: the second identical run that must stay silent, and the recovery that must stand the alert
// down. An alert that cannot close itself is only half a control.

import test from 'node:test';
import assert from 'node:assert/strict';

import { alertable, decide, fingerprint, readFingerprint, renderBody } from '../scripts/ccm-issue.mjs';

const finding = (indicator, checks) => ({
  indicator,
  name: `${indicator} name`,
  evidence_state: 'no-evidence',
  checks,
});

const failing = (id, items = 1) => ({ check_id: id, result: 'fail', failing_items: items });
const absent = (id) => ({ check_id: id, result: 'absent', failing_items: 0 });

const FAILING = [
  finding('KSI-CMT-LMC', [absent('aws.logging.trail-integrity'), failing('github.change.pr-review', 6)]),
  finding('KSI-CNA-DFP', [absent('aws.iam.privileged-access')]),
];

// The distinction the whole escalation rests on: a check that ran and failed is a control problem,
// a check that never ran is a coverage gap, and paging on the second buries the first.
test('only checks that ran and failed are escalated', () => {
  const open = alertable(FAILING);

  assert.equal(open.length, 1);
  assert.equal(open[0].indicator, 'KSI-CMT-LMC');
});

test('a finding set with nothing failing escalates nothing', () => {
  assert.deepEqual(alertable([finding('KSI-CNA-DFP', [absent('aws.iam.privileged-access')])]), []);
});

test('no failing controls and no open issue does nothing', () => {
  const { action } = decide({ findings: [finding('KSI-CNA-DFP', [absent('a.b.c')])], existing: null });

  assert.equal(action, 'none');
});

test('failing controls with no open issue opens one', () => {
  const { action } = decide({ findings: FAILING, existing: null });

  assert.equal(action, 'create');
});

// The bug this replaces: a dated title and no lookup, so a standing finding opened a fresh issue
// every day. The same finding set on a later run has to be silent.
test('the same failing controls on a later run stay silent', () => {
  const body = renderBody({ findings: FAILING, mode: 'github-live', profile: 'p.yaml' });
  const { action } = decide({ findings: FAILING, existing: { number: 7, body } });

  assert.equal(action, 'none');
});

test('a changed set of failing controls updates the open issue', () => {
  const body = renderBody({ findings: FAILING, mode: 'github-live', profile: 'p.yaml' });
  const worse = [...FAILING, finding('KSI-SVC-CFG', [failing('aws.config.recorder-state')])];

  assert.equal(decide({ findings: worse, existing: { number: 7, body } }).action, 'update');
});

// Recovery. An escalation that cannot stand down trains people to ignore it.
test('recovery closes the open issue', () => {
  const body = renderBody({ findings: FAILING, mode: 'github-live', profile: 'p.yaml' });
  const { action, reason } = decide({ findings: [], existing: { number: 7, body } });

  assert.equal(action, 'close');
  assert.match(reason, /supporting it/);
});

test('a body with no fingerprint is treated as changed rather than matching', () => {
  const { action } = decide({ findings: FAILING, existing: { number: 7, body: 'hand-edited' } });

  assert.equal(action, 'update');
  assert.equal(readFingerprint('hand-edited'), null);
});

// Failing-item counts move as commits land. Rewriting the issue for that would be noise, and the
// thing worth reacting to is a control changing state.
test('the fingerprint ignores failing-item counts but tracks which checks fail', () => {
  const fewer = [finding('KSI-CMT-LMC', [failing('github.change.pr-review', 2)])];
  const more = [finding('KSI-CMT-LMC', [failing('github.change.pr-review', 99)])];
  const other = [finding('KSI-CMT-LMC', [failing('github.change.branch-protection', 2)])];

  assert.equal(fingerprint(fewer), fingerprint(more));
  assert.notEqual(fingerprint(fewer), fingerprint(other));
});

test('the fingerprint is order-independent', () => {
  const a = [finding('KSI-A', [failing('x.y')]), finding('KSI-B', [failing('p.q')])];

  assert.equal(fingerprint(a), fingerprint([...a].reverse()));
});

test('the body names the failing checks and carries a readable fingerprint', () => {
  const body = renderBody({
    findings: FAILING,
    mode: 'github-live',
    profile: 'examples/self.profile.yaml',
    runUrl: 'https://example/run/1',
    generatedAt: '2026-08-18T13:00:00.000Z',
  });

  assert.match(body, /github\.change\.pr-review/);
  assert.match(body, /examples\/self\.profile\.yaml/);
  assert.match(body, /github-live/);
  assert.equal(readFingerprint(body), fingerprint(FAILING));
  // The coverage gap is explained rather than silently dropped.
  assert.match(body, /coverage gap rather than a\s*\n?failing control/);
  // An indicator with only absent checks must not appear as a failing row.
  assert.doesNotMatch(body, /\| KSI-CNA-DFP \|/);
});
