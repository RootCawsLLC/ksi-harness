import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture, mergeGraded, optional, passRate, perAccount, service } from '../lib/aws.mjs';

export const VERSION = '2.0.0';
export const PATH = 'src/collectors/aws/logging.mjs';

export const CHECKS = [
  {
    id: 'aws.logging.trail-integrity',
    ksis: ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM'],
    fixture: 'aws-cloudtrail',
    assertion:
      'The account has at least one enabled multi-region audit trail with log file validation on, and every ' +
      'configured trail is actively delivering.',
  },
  {
    id: 'aws.logging.log-access',
    ksis: ['KSI-MLA-ALA'],
    fixture: 'aws-log-storage',
    assertion:
      'Every bucket holding audit log data blocks public access and grants read access to no principal outside ' +
      'the account.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades trail configuration.
 *
 * The account-level item is the reason this does not report a vacuous pass. With no trails
 * configured, a population of the trails themselves is empty, complete, and free of
 * failures — which the bundle contract would correctly derive as a pass over nothing. So the
 * account-level claim is carried as its own population member and the denominator is
 * `trails + 1`. Any check whose subject is "the account has at least one X" needs this
 * shape; without it, absence reads as compliance.
 */
export function gradeTrailIntegrity(trails, accountId, { unexamined = [] } = {}) {
  const items = trails.map((trail) => {
    const problems = [];
    if (!trail.IsLogging) problems.push('not currently logging');
    if (!trail.LogFileValidationEnabled) problems.push('log file validation disabled');
    if (trail.LatestDeliveryError) problems.push(`delivery error: ${trail.LatestDeliveryError}`);

    if (problems.length) {
      return {
        id: `trail/${trail.Name}`,
        status: 'fail',
        detail: problems.join('; '),
        observed: {
          is_logging: trail.IsLogging,
          log_file_validation: trail.LogFileValidationEnabled,
          multi_region: trail.IsMultiRegionTrail,
          kms_encrypted: Boolean(trail.KmsKeyId),
        },
      };
    }
    return {
      id: `trail/${trail.Name}`,
      status: trail.KmsKeyId ? 'pass' : 'warn',
      detail: trail.KmsKeyId
        ? 'Logging, validated, encrypted with a customer-managed key'
        : 'Logging and validated, but encrypted with the default key rather than a customer-managed one',
      observed: { multi_region: trail.IsMultiRegionTrail, kms_encrypted: Boolean(trail.KmsKeyId) },
    };
  });

  const compliant = trails.filter((t) => t.IsLogging && t.IsMultiRegionTrail && t.LogFileValidationEnabled);
  items.unshift(
    compliant.length
      ? {
          id: `account/${accountId}`,
          status: 'pass',
          detail: `${compliant.length} enabled multi-region trail(s) with log file validation`,
        }
      : {
          id: `account/${accountId}`,
          status: 'fail',
          detail:
            trails.length === 0
              ? 'No audit trail configured in this account'
              : `${trails.length} trail(s) configured but none is simultaneously enabled, multi-region and validated`,
        }
  );

  return {
    items,
    population: {
      expected: 1 + trails.length + unexamined.length,
      unexamined,
      source_of_truth:
        'cloudtrail:DescribeTrails with cloudtrail:GetTrailStatus per trail, plus one account-level claim',
      enumerated_from: 'cloudtrail:DescribeTrails, counted before any trail status was fetched',
    },
    metric: {
      metric_id: 'aws.cloudtrail.compliant_trails',
      value: compliant.length,
      unit: 'count',
    },
  };
}

/** A bucket policy statement that names a principal outside this account, or `*`. */
export function externalReaders(policy, accountId) {
  const out = new Set();
  for (const s of [].concat(policy?.Statement ?? [])) {
    if (s.Effect !== 'Allow') continue;
    const principals = s.Principal === '*' ? ['*'] : Object.values(s.Principal ?? {}).flatMap((v) => [].concat(v));
    for (const p of principals) {
      if (p === '*') {
        out.add('*');
        continue;
      }
      // Service principals are how AWS itself writes the logs; they are not external readers.
      if (typeof p === 'string' && p.endsWith('.amazonaws.com')) continue;
      if (typeof p === 'string' && !p.includes(accountId)) out.add(p);
    }
  }
  return [...out];
}

export function gradeLogAccess(buckets, accountId, accountBlockPublicAccess, { unexamined = [] } = {}) {
  const items = buckets.map((bucket) => {
    const problems = [];
    if (!bucket.blockPublicAccess) problems.push('bucket-level block public access is not fully enabled');
    const external = externalReaders(bucket.policy, accountId);
    if (external.length) problems.push(`policy grants access to ${external.join(', ')}`);
    if (bucket.publicAcl) problems.push('ACL grants access to a public grantee');

    return problems.length
      ? { id: `bucket/${bucket.name}`, status: 'fail', detail: problems.join('; '), observed: { external_principals: external } }
      : { id: `bucket/${bucket.name}`, status: 'pass', detail: 'Public access blocked, no external reader in the policy' };
  });

  items.unshift(
    accountBlockPublicAccess
      ? { id: `account/${accountId}`, status: 'pass', detail: 'Account-level S3 Block Public Access is fully enabled' }
      : {
          id: `account/${accountId}`,
          status: 'fail',
          detail:
            'Account-level S3 Block Public Access is not fully enabled, so a future bucket can be made public without ' +
            'changing any check in this list',
        }
  );

  return {
    items,
    population: {
      expected: 1 + buckets.length + unexamined.length,
      unexamined,
      source_of_truth:
        'Destination buckets named by cloudtrail:DescribeTrails, plus one account-level claim from s3control:GetPublicAccessBlock',
      enumerated_from:
        'the distinct S3 destinations named by cloudtrail:DescribeTrails, counted before any bucket configuration was read',
    },
    metric: { metric_id: 'aws.s3.log_buckets_without_external_read', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchTrails(region, credentials) {
  const { client, sdk } = await service('cloudtrail', region, credentials);
  // includeShadowTrails false: a multi-region trail is reported in every region, and counting
  // the shadows would inflate the population with copies of one trail.
  const described = await client.send(new sdk.DescribeTrailsCommand({ includeShadowTrails: false }));
  const trails = [];
  for (const trail of described.trailList ?? []) {
    const status = await client.send(new sdk.GetTrailStatusCommand({ Name: trail.TrailARN }));
    trails.push({
      Name: trail.Name,
      TrailARN: trail.TrailARN,
      IsMultiRegionTrail: trail.IsMultiRegionTrail,
      LogFileValidationEnabled: trail.LogFileValidationEnabled,
      KmsKeyId: trail.KmsKeyId,
      S3BucketName: trail.S3BucketName,
      IsLogging: status.IsLogging,
      LatestDeliveryError: status.LatestDeliveryError,
    });
  }
  return trails;
}

async function fetchLogStorage(region, trails, accountId, credentials) {
  const { client, sdk } = await service('s3', region, credentials);
  const names = [...new Set(trails.map((t) => t.S3BucketName).filter(Boolean))];

  const buckets = [];
  const unexamined = [];
  for (const name of names) {
    try {
      const bpa = await optional(client.send(new sdk.GetPublicAccessBlockCommand({ Bucket: name })), [
        'NoSuchPublicAccessBlockConfiguration',
      ]);
      const cfg = bpa?.PublicAccessBlockConfiguration;
      const policyRaw = await optional(client.send(new sdk.GetBucketPolicyCommand({ Bucket: name })), [
        'NoSuchBucketPolicy',
      ]);
      const acl = await client.send(new sdk.GetBucketAclCommand({ Bucket: name }));
      const publicAcl = (acl.Grants ?? []).some((g) =>
        String(g.Grantee?.URI ?? '').includes('acs.amazonaws.com/groups/global')
      );

      buckets.push({
        name,
        blockPublicAccess: Boolean(
          cfg?.BlockPublicAcls && cfg?.BlockPublicPolicy && cfg?.IgnorePublicAcls && cfg?.RestrictPublicBuckets
        ),
        policy: policyRaw?.Policy ? JSON.parse(policyRaw.Policy) : null,
        publicAcl,
      });
    } catch (err) {
      // A log destination this credential cannot read is a gap in the population. Grading it
      // as an exposed bucket would invent a finding from a permission; dropping it would
      // report clean over a destination nobody looked at.
      unexamined.push({ id: `bucket/${name}`, reason: err.message });
    }
  }

  return { buckets, accountId, unexamined };
}

async function fetchAccountBlockPublicAccess(region, accountId, credentials) {
  // s3control is a separate client; treated as optional so a missing configuration is
  // distinguishable from a denied call. A denial propagates.
  let sdk;
  try {
    sdk = await import('@aws-sdk/client-s3-control');
  } catch {
    return null;
  }
  const client = new sdk.S3ControlClient({ region, credentials });
  const got = await optional(client.send(new sdk.GetPublicAccessBlockCommand({ AccountId: accountId })), [
    'NoSuchPublicAccessBlockConfiguration',
  ]);
  const cfg = got?.PublicAccessBlockConfiguration;
  return Boolean(cfg?.BlockPublicAcls && cfg?.BlockPublicPolicy && cfg?.IgnorePublicAcls && cfg?.RestrictPublicBuckets);
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chainOf = (checkId) => ({
    previousHash: previousHashes.get(checkId)?.hash ?? null,
    chainIndex: previousHashes.get(checkId)?.index ?? 0,
  });

  if (fixture) {
    const trailFixture = loadFixture(fixture, 'aws-cloudtrail');
    const storage = loadFixture(fixture, 'aws-log-storage');
    return [
      buildBundle({
        ...common,
        ...chainOf(CHECKS[0].id),
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-cloudtrail'),
        ...gradeTrailIntegrity(trailFixture.trails, trailFixture.account, { unexamined: trailFixture.unexamined ?? [] }),
      }),
      buildBundle({
        ...common,
        ...chainOf(CHECKS[1].id),
        checkId: CHECKS[1].id,
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'aws-log-storage'),
        ...gradeLogAccess(storage.buckets, storage.account, storage.account_block_public_access, {
          unexamined: storage.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, region, credentials }) => {
    const trails = await fetchTrails(region, credentials);
    const storage = await fetchLogStorage(region, trails, account.id, credentials);
    const accountBpa = await fetchAccountBlockPublicAccess(region, account.id, credentials);
    return {
      trails: gradeTrailIntegrity(trails, account.id),
      access: gradeLogAccess(storage.buckets, account.id, accountBpa === null ? false : accountBpa, {
        unexamined: storage.unexamined,
      }),
    };
  });

  const scope = { accounts: accounts.map((a) => a.id), collector_role: profile?.aws?.collector_role ?? null };

  return [
    buildBundle({
      ...common,
      ...chainOf(CHECKS[0].id),
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope,
      ...mergeGraded(
        parts.map((p) => ({ scope: p.scope, graded: p.graded.trails })),
        {
          sourceOfTruth: 'cloudtrail:DescribeTrails with cloudtrail:GetTrailStatus per trail, in each declared account',
          enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
          metric: { metric_id: 'aws.cloudtrail.compliant_trails', unit: 'count' },
          unexamined,
        }
      ),
    }),
    buildBundle({
      ...common,
      ...chainOf(CHECKS[1].id),
      checkId: CHECKS[1].id,
      ksis: CHECKS[1].ksis,
      assertion: CHECKS[1].assertion,
      scope,
      ...mergeGraded(
        parts.map((p) => ({ scope: p.scope, graded: p.graded.access })),
        {
          sourceOfTruth: 'S3 destinations named by cloudtrail:DescribeTrails, plus the account-level public access block',
          enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
          metric: { metric_id: 'aws.s3.log_buckets_without_external_read', unit: 'ratio' },
          unexamined,
        }
      ),
    }),
  ];
}
