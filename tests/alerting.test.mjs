import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';

import { buildNotification, SEVERITY, transitions } from '../src/alert/notification.mjs';
import { redact, resolveSink, shouldDeliver, stdoutSink, webhookSink } from '../src/alert/sinks.mjs';

/**
 * The rule this module exists to enforce: notify on transition, not on state.
 *
 * A control that has been failing for forty days is one piece of news and thirty-nine reasons
 * to stop reading, and a channel people have muted is alerting that looks present and does
 * nothing — the same shape as every other silent-success failure this repository hunts.
 */

const failing = (indicator, checkId) => ({
  indicator,
  name: indicator,
  evidence_state: 'failing',
  checks: [{ check_id: checkId, result: 'fail', failing_items: 1 }],
});

const diffWith = (checks) => ({ checks });
const changed = (checkId, from, to) => ({ check_id: checkId, comparable: true, result_changed: from !== to, from: { result: from }, to: { result: to } });

const BY_CHECK = new Map([
  ['aws.config.recorder-state', ['KSI-CNA-EIS', 'KSI-SVC-ACM']],
  ['aws.iam.mfa-coverage', ['KSI-IAM-APM']],
]);

/* --------------------------------------------------------------------- transitions */

test('a check that started failing opens every indicator that claims it', () => {
  const { opened, closed } = transitions(diffWith([changed('aws.config.recorder-state', 'pass', 'fail')]), BY_CHECK);
  assert.deepEqual([...opened.keys()], ['KSI-CNA-EIS', 'KSI-SVC-ACM']);
  assert.equal(closed.size, 0);
});

test('a check that started passing closes them again', () => {
  const { opened, closed } = transitions(diffWith([changed('aws.config.recorder-state', 'fail', 'pass')]), BY_CHECK);
  assert.deepEqual([...closed.keys()], ['KSI-CNA-EIS', 'KSI-SVC-ACM']);
  assert.equal(opened.size, 0);
});

// warn → fail is a transition into failure; fail → warn is out of it. Neither is a no-op.
test('transitions through warn are still transitions', () => {
  assert.equal(transitions(diffWith([changed('aws.iam.mfa-coverage', 'warn', 'fail')]), BY_CHECK).opened.size, 1);
  assert.equal(transitions(diffWith([changed('aws.iam.mfa-coverage', 'fail', 'warn')]), BY_CHECK).closed.size, 1);
});

test('a check whose result did not move produces nothing', () => {
  const { opened, closed } = transitions(diffWith([changed('aws.iam.mfa-coverage', 'fail', 'fail')]), BY_CHECK);
  assert.equal(opened.size + closed.size, 0);
});

/* ------------------------------------------------------------------- notification */

test('the notification separates what moved from what was already reported', () => {
  const notification = buildNotification({
    findings: [failing('KSI-CNA-EIS', 'aws.config.recorder-state'), failing('KSI-IAM-APM', 'aws.iam.mfa-coverage')],
    diff: diffWith([changed('aws.config.recorder-state', 'pass', 'fail')]),
    indicatorsByCheck: BY_CHECK,
  });

  assert.equal(notification.severity, SEVERITY.FAILING);
  assert.equal(notification.changed, true);
  assert.match(notification.summary, /Newly failing:[\s\S]*KSI-CNA-EIS/);
  assert.match(notification.summary, /Still failing \(reported when they started\): KSI-IAM-APM/);
});

test('a recovery is its own severity, so standing down is reported as news', () => {
  const notification = buildNotification({
    findings: [],
    diff: diffWith([changed('aws.config.recorder-state', 'fail', 'pass')]),
    indicatorsByCheck: BY_CHECK,
  });
  assert.equal(notification.severity, SEVERITY.RECOVERED);
  assert.equal(notification.changed, true);
  assert.match(notification.summary, /Recovered:[\s\S]*now passes/);
});

test('failing controls that did not move leave the notification unchanged', () => {
  const notification = buildNotification({
    findings: [failing('KSI-IAM-APM', 'aws.iam.mfa-coverage')],
    diff: diffWith([changed('aws.iam.mfa-coverage', 'fail', 'fail')]),
    indicatorsByCheck: BY_CHECK,
  });
  assert.equal(notification.severity, SEVERITY.FAILING, 'they are still failing');
  assert.equal(notification.changed, false, 'and that is not news');
});

/* --------------------------------------------------------------------- delivery */

// The distinction that decides the behaviour. A stateless sink can only append, so it fires
// on transitions. A stateful one can revise, so it must hear about quiet runs to close things.
test('a stateless sink stays silent when nothing transitioned', () => {
  const quiet = buildNotification({
    findings: [failing('KSI-IAM-APM', 'aws.iam.mfa-coverage')],
    diff: diffWith([changed('aws.iam.mfa-coverage', 'fail', 'fail')]),
    indicatorsByCheck: BY_CHECK,
  });
  assert.equal(shouldDeliver(quiet, stdoutSink()), false);
  assert.equal(shouldDeliver(quiet, stdoutSink(), { always: true }), true, '--always overrides');
});

test('a stateful sink always hears, because only it can close something', () => {
  const quiet = buildNotification({ findings: [], diff: diffWith([]), indicatorsByCheck: BY_CHECK });
  assert.equal(shouldDeliver(quiet, { stateful: true }), true);
});

test('a transition is delivered to a stateless sink', () => {
  const moved = buildNotification({
    findings: [failing('KSI-CNA-EIS', 'aws.config.recorder-state')],
    diff: diffWith([changed('aws.config.recorder-state', 'pass', 'fail')]),
    indicatorsByCheck: BY_CHECK,
  });
  assert.equal(shouldDeliver(moved, stdoutSink()), true);
});

/* ------------------------------------------------------------------------ sinks */

// Where compliance findings go is a decision about who sees an inventory of a boundary's
// weakest points. A tool that guessed would be making it for somebody.
test('no sink is defaulted, and the refusal says why', () => {
  assert.throws(() => resolveSink(null), /No alerting sink is declared/);
  assert.throws(() => resolveSink({ alerting: { sink: { kind: 'carrier-pigeon' } } }), /Unknown alerting\.sink\.kind/);
});

test('a webhook sink refuses without a URL rather than posting nowhere', () => {
  assert.throws(() => resolveSink({ alerting: { sink: { kind: 'webhook', url_env: 'KSI_NOT_SET_HERE' } } }), /neither KSI_NOT_SET_HERE nor alerting\.sink\.url/);
});

// Most webhook URLs are credentials.
test('a webhook URL is redacted everywhere it is printed', () => {
  assert.equal(redact('https://hooks.example.com/services/T000/B000/SECRETTOKEN'), 'https://hooks.example.com/…');
  assert.equal(redact('not a url'), '(unparseable url)');
  assert.match(webhookSink({ url: 'https://h.example/abc/secret' }).describe().target, /^https:\/\/h\.example\/…$/);
});

test('the webhook sink posts the notification and fails loudly on a non-2xx', async () => {
  const received = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received.push(JSON.parse(Buffer.concat(chunks).toString()));
    res.writeHead(received.length === 1 ? 200 : 500);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, resolve));

  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const sink = webhookSink({ url });
    const notification = buildNotification({
      findings: [failing('KSI-CNA-EIS', 'aws.config.recorder-state')],
      diff: diffWith([changed('aws.config.recorder-state', 'pass', 'fail')]),
      indicatorsByCheck: BY_CHECK,
    });

    const result = await sink.deliver(notification);
    assert.equal(result.delivered, true);
    assert.equal(received[0].severity, 'failing');
    assert.equal(received[0].opened[0].indicator, 'KSI-CNA-EIS');

    // A monitoring run that cannot escalate must not report success.
    await assert.rejects(() => sink.deliver(notification), /returned HTTP 500/);
  } finally {
    server.close();
  }
});
