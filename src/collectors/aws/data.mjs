import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture, mergeGraded, optional, pages, passRate, perAccount, service } from '../lib/aws.mjs';

export const VERSION = '2.0.0';
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
export function gradeEncryptionAtRest(storage, { scopeId = 'account', unexamined = [] } = {}) {
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
      ? { id: `account/${scopeId}/ebs-default-encryption`, status: 'pass', detail: 'New block volumes are encrypted by default' }
      : {
          id: `account/${scopeId}/ebs-default-encryption`,
          status: 'fail',
          detail:
            'Default encryption for new block volumes is off, so the next volume created can be unencrypted without ' +
            'any change to the resources listed here',
        }
  );

  const enumerated = (storage.buckets?.length ?? 0) + (storage.volumes?.length ?? 0);
  return {
    items,
    population: {
      expected: 1 + enumerated + unexamined.length,
      unexamined,
      source_of_truth:
        's3:ListBuckets with s3:GetBucketEncryption per bucket, ec2:DescribeVolumes, plus one account-level claim ' +
        'from ec2:GetEbsEncryptionByDefault',
      enumerated_from: 's3:ListBuckets and ec2:DescribeVolumes, counted before any encryption configuration was read',
    },
    metric: { metric_id: 'aws.storage.encrypted_at_rest', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchStorage(region, credentials) {
  const { client: s3, sdk: s3sdk } = await service('s3', region, credentials);
  const listed = await s3.send(new s3sdk.ListBucketsCommand({}));

  const buckets = [];
  const unexamined = [];
  for (const bucket of listed.Buckets ?? []) {
    try {
      const got = await optional(s3.send(new s3sdk.GetBucketEncryptionCommand({ Bucket: bucket.Name })), [
        'ServerSideEncryptionConfigurationNotFoundError',
      ]);
      const rule = got?.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault;
      buckets.push({
        name: bucket.Name,
        encryption: rule ? { type: rule.SSEAlgorithm, key_id: rule.KMSMasterKeyID ?? null } : null,
      });
    } catch (err) {
      // A bucket in another region, or one this credential cannot read, is a gap rather than
      // an unencrypted bucket. Grading it as a failure would manufacture a finding out of a
      // permission, which is the mirror image of the bug this harness is built to avoid.
      unexamined.push({ id: `bucket/${bucket.Name}`, reason: err.message });
    }
  }

  const { client: ec2, sdk: ec2sdk } = await service('ec2', region, credentials);
  const volumes = (await pages(ec2, ec2sdk.DescribeVolumesCommand, {}, (r) => r.Volumes)).map((v) => ({
    id: v.VolumeId,
    encrypted: v.Encrypted,
    kms_key_id: v.KmsKeyId ?? null,
  }));
  const byDefault = await ec2.send(new ec2sdk.GetEbsEncryptionByDefaultCommand({}));

  return { buckets, volumes, ebs_encryption_by_default: byDefault.EbsEncryptionByDefault, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chain = {
    previousHash: previousHashes.get(CHECKS[0].id)?.hash ?? null,
    chainIndex: previousHashes.get(CHECKS[0].id)?.index ?? 0,
  };

  if (fixture) {
    const data = loadFixture(fixture, 'aws-storage');
    return [
      buildBundle({
        ...common,
        ...chain,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-storage'),
        ...gradeEncryptionAtRest(data, { scopeId: data.account ?? 'fixture', unexamined: data.unexamined ?? [] }),
      }),
    ];
  }

  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, region, credentials }) => {
    const storage = await fetchStorage(region, credentials);
    return gradeEncryptionAtRest(storage, { scopeId: account.id, unexamined: storage.unexamined });
  });

  return [
    buildBundle({
      ...common,
      ...chain,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: { accounts: accounts.map((a) => a.id), collector_role: profile?.aws?.collector_role ?? null },
      ...mergeGraded(parts, {
        sourceOfTruth: 's3:ListBuckets and ec2:DescribeVolumes in each declared account',
        enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'aws.storage.encrypted_at_rest', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
