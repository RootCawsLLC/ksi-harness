import test from 'node:test';
import assert from 'node:assert/strict';
import { gradeEncryptionAtRest } from '../src/collectors/aws/data.mjs';
import { gradeLogAccess } from '../src/collectors/aws/logging.mjs';
import { gradeTlsEnforcement } from '../src/collectors/aws/transit.mjs';
import { listBuckets, service } from '../src/collectors/lib/aws.mjs';

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

/* ------------------------------------------------------------- bucket region */

// With redirects followed, a bucket is read wherever it lives, so the item has to say where that
// was. Every bucket item carries observed.region, passing or failing, and null when the region was
// not stated, never the client's region filled in as a guess.
function bucketRegions(items) {
  return Object.fromEntries(items.filter((i) => i.id.startsWith('bucket/')).map((i) => [i.id, i.observed?.region]));
}

test('encryption at rest records each bucket region, on passes and failures alike', () => {
  const graded = gradeEncryptionAtRest({
    buckets: [
      { name: 'east', region: 'us-east-1', encryption: { type: 'AES256', key_id: null } },
      { name: 'west', region: 'us-west-1', encryption: null },
      { name: 'unstated', encryption: { type: 'AES256', key_id: null } },
    ],
    volumes: [],
    ebs_encryption_by_default: true,
  });
  assert.deepEqual(bucketRegions(graded.items), {
    'bucket/east': 'us-east-1',
    'bucket/west': 'us-west-1',
    'bucket/unstated': null,
  });
});

test('TLS enforcement records each bucket region, on passes and failures alike', () => {
  const graded = gradeTlsEnforcement(
    {
      listeners: [],
      buckets: [
        { name: 'denies', region: 'us-east-1', policy_present: true, denies_insecure_transport: true },
        { name: 'allows', region: 'us-west-1', policy_present: false, denies_insecure_transport: false },
        { name: 'unstated', policy_present: false, denies_insecure_transport: false },
      ],
    },
    { minTlsVersion: '1.2' }
  );
  assert.deepEqual(bucketRegions(graded.items), {
    'bucket/denies': 'us-east-1',
    'bucket/allows': 'us-west-1',
    'bucket/unstated': null,
  });
});

test('log access records each trail bucket region, and null for one this account did not list', () => {
  const graded = gradeLogAccess(
    [
      { name: 'clean', region: 'us-east-1', blockPublicAccess: true, policy: null, publicAcl: false },
      { name: 'exposed', region: 'us-west-1', blockPublicAccess: false, policy: null, publicAcl: false },
      { name: 'archive-elsewhere', region: null, blockPublicAccess: true, policy: null, publicAcl: false },
    ],
    '123456789012',
    true
  );
  assert.deepEqual(bucketRegions(graded.items), {
    'bucket/clean': 'us-east-1',
    'bucket/exposed': 'us-west-1',
    'bucket/archive-elsewhere': null,
  });
});

// listBuckets is a thin wrapper over one SDK call, and what it guards (S3 returning BucketRegion
// only when MaxBuckets is set, and continuation tokens) cannot be exercised without a live account
// holding more buckets than a page. So the client is stubbed at the SDK boundary, and the test
// asserts on the requests we build and the fields we read from real ListBucketsCommand inputs.
test('listBuckets asks for the paginated form, follows every page, and does not invent a region', async (t) => {
  let sdk;
  try {
    sdk = await import('@aws-sdk/client-s3');
  } catch {
    t.skip('@aws-sdk/client-s3 is not installed (an optional dependency), so there is nothing to check against');
    return;
  }
  const pagesOut = [
    { Buckets: [{ Name: 'a', BucketRegion: 'us-east-1' }], ContinuationToken: 'next' },
    { Buckets: [{ Name: 'b', BucketRegion: 'us-west-1' }, { Name: 'c' }] },
  ];
  const sent = [];
  const client = {
    send: async (command) => {
      assert.ok(command instanceof sdk.ListBucketsCommand);
      sent.push(command.input);
      return pagesOut[sent.length - 1];
    },
  };
  const buckets = await listBuckets(client, sdk);
  // Without MaxBuckets, S3 answers with the legacy unpaginated listing: no BucketRegion, and a
  // population that stops at the account quota.
  assert.ok(sent.every((input) => input.MaxBuckets > 0), 'every request must set MaxBuckets');
  assert.equal(sent[1].ContinuationToken, 'next');
  assert.deepEqual(buckets, [
    { name: 'a', region: 'us-east-1' },
    { name: 'b', region: 'us-west-1' },
    { name: 'c', region: null },
  ]);
});
