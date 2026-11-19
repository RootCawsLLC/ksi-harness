import test from 'node:test';
import assert from 'node:assert/strict';
import { CREDENTIAL_REPORT_PENDING } from '../src/collectors/aws/iam.mjs';
import { errorReason } from '../src/collectors/lib/aws.mjs';

// The IAM fetch path never runs offline, so a wrong error name there passes every fixture test and
// shows up only on a live run, as an account nobody examined. These check the names against the
// installed SDK instead: no network and no stubs, just the classes the real client throws.

async function iamOrSkip(t) {
  try {
    return await import('@aws-sdk/client-iam');
  } catch {
    t.skip('@aws-sdk/client-iam is not installed (an optional dependency), so there is nothing to check against');
    return null;
  }
}

test('every credential-report pending name is an error the IAM SDK actually throws', async (t) => {
  const sdk = await iamOrSkip(t);
  if (!sdk) return;
  // A name nothing throws makes optional() rethrow on a missing report, and the whole account
  // goes unexamined unless a report happened to exist already.
  for (const name of CREDENTIAL_REPORT_PENDING) {
    assert.equal(typeof sdk[name], 'function', `${name} is not exported by @aws-sdk/client-iam`);
    assert.ok(sdk[name].prototype instanceof sdk.IAMServiceException, `${name} is not an IAM service error`);
    assert.equal(new sdk[name]({ $metadata: {}, message: 'x' }).name, name, `${name} would not appear as err.name`);
  }
});

test('every modeled credential-report error means "generate and wait", including an expired report', async (t) => {
  const sdk = await iamOrSkip(t);
  if (!sdk) return;
  const modeled = Object.keys(sdk).filter((k) => /^CredentialReport\w+Exception$/.test(k)).sort();
  assert.deepEqual([...CREDENTIAL_REPORT_PENDING].sort(), modeled);
});

test('an unexamined reason names the error when the message alone says nothing', () => {
  const modeled = Object.assign(new Error('Unknown'), { name: 'CredentialReportNotPresentException' });
  assert.equal(errorReason(modeled), 'CredentialReportNotPresentException: Unknown');
});

test('an unexamined reason does not repeat a name the message already carries, or name a plain Error', () => {
  const named = Object.assign(new Error('AccessDenied: not authorized'), { name: 'AccessDenied' });
  assert.equal(errorReason(named), 'AccessDenied: not authorized');
  assert.equal(errorReason(new Error('socket hang up')), 'socket hang up');
  assert.equal(errorReason('a string'), 'a string');
});
