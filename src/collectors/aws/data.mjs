import { buildBundle } from '../../evidence/bundle.mjs';
import { callerIdentity, fixtureScope, loadFixture, optional, pages, passRate, resolveAccounts, service } from '../lib/aws.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/aws/data.mjs';

export const CHECKS = [
  {
    id: 'aws.data.encryption-at-rest',
    ksis: ['KSI-SVC-SIN'],
    fixture: 'aws-storage',
    assertion:
      'Every bucket and block volume in scope is encrypted at rest, and the account default for new volumes is ' +
      'encryption on.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades encryption at rest, and deliberately does not treat provider-managed keys as a
 * failure.
 *
 * SSE-S3 and an AWS-managed KMS key are both real encryption. Painting a permanent warning
 * over an acceptable configuration trains people to ignore the report, which costs more than
 * the distinction is worth at this level. What the item *does* record is the key custody,
 * because a federal customer's question is not "is it encrypted" but "who holds the key" —
 * and that is exactly the gap the route for KSI-SVC-SIN names as unautomated.
 */
export function gradeEncryptionAtRest(storage) {
  const items = [];

  for (const bucket of storage.buckets ?? []) {
    if (!bucket.encryption) {
      items.push({ id: `bucket/${bucket.name}`, status: 'fail', detail: 'No default encryption configured' });
      continue;
    }
    const customerManaged = bucket.encryption.type === 'aws:kms' && Boolean(bucket.encryption.key_id);
    items.push({
      id: `bucket/${bucket.name}`,
      status: 'pass',
      detail: customerManaged
        ? `Encrypted with a customer-managed key (${bucket.encryption.key_id})`
        : `Encrypted with ${bucket.encryption.type}, provider-held key`,
      observed: { algorithm: bucket.encryption.type, customer_managed_key: customerManaged },
    });
  }

  for (const volume of storage.volumes ?? []) {
    items.push(
      volume.encrypted
        ? {
            id: `volume/${volume.id}`,
            status: 'pass',
            detail: volume.kms_key_id ? 'Encrypted with a named KMS key' : 'Encrypted',
            observed: { customer_managed_key: Boolean(volume.kms_key_id) },
          }
        : { id: `volume/${volume.id}`, status: 'fail', detail: 'Block volume is not encrypted' }
    );
  }

  items.unshift(
    storage.ebs_encryption_by_default
      ? { id: 'account/ebs-default-encryption', status: 'pass', detail: 'New block volumes are encrypted by default' }
      : {
          id: 'account/ebs-default-encryption',
          status: 'fail',
          detail:
            'Default encryption for new block volumes is off, so the next volume created can be unencrypted without ' +
            'any change to the resources listed here',
        }
  );

  const expected = (storage.buckets?.length ?? 0) + (storage.volumes?.length ?? 0) + 1;
  return {
    items,
    population: {
      expected,
      examined: items.length,
      source_of_truth:
        's3:ListBuckets with s3:GetBucketEncryption per bucket, ec2:DescribeVolumes, plus one account-level claim ' +
        'from ec2:GetEbsEncryptionByDefault',
    },
    metric: { metric_id: 'aws.storage.encrypted_at_rest', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchStorage(region) {
  const { client: s3, sdk: s3sdk } = await service('s3', region);
  const listed = await s3.send(new s3sdk.ListBucketsCommand({}));

  const buckets = [];
  for (const bucket of listed.Buckets ?? []) {
    const got = await optional(s3.send(new s3sdk.GetBucketEncryptionCommand({ Bucket: bucket.Name })), [
      'ServerSideEncryptionConfigurationNotFoundError',
    ]);
    const rule = got?.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault;
    buckets.push({
      name: bucket.Name,
      encryption: rule ? { type: rule.SSEAlgorithm, key_id: rule.KMSMasterKeyID ?? null } : null,
    });
  }

  const { client: ec2, sdk: ec2sdk } = await service('ec2', region);
  const volumes = (await pages(ec2, ec2sdk.DescribeVolumesCommand, {}, (r) => r.Volumes)).map((v) => ({
    id: v.VolumeId,
    encrypted: v.Encrypted,
    kms_key_id: v.KmsKeyId ?? null,
  }));
  const byDefault = await ec2.send(new ec2sdk.GetEbsEncryptionByDefaultCommand({}));

  return { buckets, volumes, ebs_encryption_by_default: byDefault.EbsEncryptionByDefault };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };

  if (fixture) {
    const data = loadFixture(fixture, 'aws-storage');
    return [
      buildBundle({
        ...common,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-storage'),
        ...gradeEncryptionAtRest(data),
      }),
    ];
  }

  const accounts = resolveAccounts(profile);
  const region = accounts[0].regions?.[0] ?? 'us-east-1';
  const identity = await callerIdentity(region);

  return [
    buildBundle({
      ...common,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: { account: identity.account, credential_arn: identity.arn, region },
      ...gradeEncryptionAtRest(await fetchStorage(region)),
    }),
  ];
}
