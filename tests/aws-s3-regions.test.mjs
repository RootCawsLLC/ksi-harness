import test from 'node:test';
import assert from 'node:assert/strict';
import { service } from '../src/collectors/lib/aws.mjs';

// The S3 fetch paths never run offline, so a missing client option passes every fixture test and
// shows up only on a live run. This checks the client the collectors actually build: no network,
// no stubs.

test('the S3 client follows region redirects, so a bucket in another region is examined', async (t) => {
  try {
    await import('@aws-sdk/client-s3');
  } catch {
    t.skip('@aws-sdk/client-s3 is not installed (an optional dependency), so there is nothing to check against');
    return;
  }
  // Without this, every bucket outside the client's region answers 301 PermanentRedirect and
  // leaves the encryption, TLS and log-access populations with it as unexamined.
  const { client } = await service('s3', 'us-west-2');
  assert.equal(client.config.followRegionRedirects, true);
  assert.equal(await client.config.region(), 'us-west-2', 'the option must not displace the region passed in');
});

test('only S3 gets the redirect option; other clients are built as before', async (t) => {
  try {
    await import('@aws-sdk/client-iam');
  } catch {
    t.skip('@aws-sdk/client-iam is not installed (an optional dependency), so there is nothing to check against');
    return;
  }
  const { client } = await service('iam', 'us-west-2');
  assert.notEqual(client.config.followRegionRedirects, true);
});
