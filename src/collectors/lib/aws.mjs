export { fixtureScope, loadFixture } from './fixtures.mjs';
export { accountItem, describePorts, mergeGraded, passRate } from './grade.mjs';

/**
 * Shared plumbing for the AWS checks.
 *
 * Carried over from RootCawsLLC/grc-wizard, where each of these behaviors was arrived at
 * by a live run producing wrong evidence. Four jobs, all about keeping checks honest
 * rather than convenient:
 *
 *  - Lazy SDK loading, so the repository installs and tests without the AWS SDK present.
 *    Only a real collection needs it.
 *  - Full pagination, because a first-page answer over a truncated population is the
 *    quietest way to report a pass that is not one.
 *  - A hard line between "this resource has no such configuration" and "I was not allowed
 *    to look", which `optional()` enforces.
 *  - Cross-account collection over the accounts the profile declares, with every account
 *    that could not be reached itemized rather than dropped. A real authorization boundary
 *    is almost never one account, and a harness that silently reports the account it
 *    happens to be standing in has redefined the boundary.
 */

const CLIENT_MODULES = {
  cloudtrail: ['@aws-sdk/client-cloudtrail', 'CloudTrailClient'],
  config: ['@aws-sdk/client-config-service', 'ConfigServiceClient'],
  ec2: ['@aws-sdk/client-ec2', 'EC2Client'],
  elbv2: ['@aws-sdk/client-elastic-load-balancing-v2', 'ElasticLoadBalancingV2Client'],
  iam: ['@aws-sdk/client-iam', 'IAMClient'],
  kms: ['@aws-sdk/client-kms', 'KMSClient'],
  logs: ['@aws-sdk/client-cloudwatch-logs', 'CloudWatchLogsClient'],
  s3: ['@aws-sdk/client-s3', 'S3Client'],
  secretsmanager: ['@aws-sdk/client-secrets-manager', 'SecretsManagerClient'],
  sts: ['@aws-sdk/client-sts', 'STSClient'],
};

/**
 * Returns `{ client, sdk }` for a service in a region.
 *
 * The whole module comes back alongside the client so a check can name the commands it
 * needs without a static import list that would break installation when the optional SDK is
 * absent.
 *
 * `credentials` is undefined rather than null when unset, deliberately: passing
 * `credentials: undefined` leaves the SDK's own provider chain intact, which is what makes
 * the ambient-credential case behave as though cross-account support were not there.
 */
export async function service(name, region, credentials = undefined) {
  const entry = CLIENT_MODULES[name];
  if (!entry) throw new Error(`Unknown AWS service "${name}". Known: ${Object.keys(CLIENT_MODULES).join(', ')}`);
  const [moduleName, className] = entry;

  let sdk;
  try {
    sdk = await import(moduleName);
  } catch {
    throw new Error(
      `${moduleName} is not installed. It is an optional dependency because the repository must ` +
        `install and test without it. Run: npm install ${moduleName}`
    );
  }
  return { client: new sdk[className]({ region, credentials }), sdk };
}

/**
 * Collects every page of a paginated call into one array.
 *
 * The repeated-token guard is not hypothetical politeness: a service that echoes the token
 * it was given turns this into an infinite loop that never returns and never errors, which
 * in a scheduled collection reads as a hung job rather than as a broken call.
 */
export async function pages(client, CommandClass, input, extract, tokenIn = 'NextToken', tokenOut = 'NextToken') {
  const out = [];
  const seen = new Set();
  let token;
  do {
    const response = await client.send(new CommandClass({ ...input, [tokenIn]: token }));
    out.push(...(extract(response) ?? []));
    const next = response[tokenOut];
    if (next && seen.has(next)) {
      throw new Error(`${CommandClass.name} returned a pagination token it had already issued; refusing to loop.`);
    }
    if (next) seen.add(next);
    token = next;
  } while (token);
  return out;
}

/**
 * Swallows the "this resource has no such configuration" errors that AWS reports as
 * exceptions rather than empty responses, and only those.
 *
 * Any other failure propagates, because a permission error must not be
 * indistinguishable from an absent configuration. That confusion is precisely how a
 * collector comes to report a clean pass over data it was never allowed to read.
 */
export async function optional(promise, absentErrorNames) {
  try {
    return await promise;
  } catch (err) {
    if (absentErrorNames.includes(err.name) || absentErrorNames.includes(err.Code)) return null;
    throw err;
  }
}

/** Who the ambient credential actually is. Recorded in scope so evidence names its own source. */
export async function callerIdentity(region = 'us-east-1', credentials = undefined) {
  const { client, sdk } = await service('sts', region, credentials);
  const out = await client.send(new sdk.GetCallerIdentityCommand({}));
  return { account: out.Account, arn: out.Arn, user_id: out.UserId };
}

/**
 * The population denominator comes from the profile, deliberately.
 *
 * Refusing an empty list matters: a run over zero accounts would otherwise report every
 * check as a vacuous pass. Discovering scope from the environment instead would mean the
 * evidence silently redefines what was in the boundary, which is the one thing a
 * certification boundary may not do.
 */
export function resolveAccounts(profile) {
  const accounts = profile?.aws?.accounts ?? [];
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error(
      'No AWS accounts in the profile (aws.accounts). Scope is declared, never discovered: a check ' +
        'over an empty population would report a pass having examined nothing.'
    );
  }
  return accounts.map((a) => (typeof a === 'string' ? { id: a, regions: profile.aws.regions ?? ['us-east-1'] } : a));
}

/** The role ARN this harness assumes into a member account. */
export function collectorRoleArn(profile, accountId) {
  const declared = profile?.aws?.collector_role;
  if (!declared) return null;
  if (declared.startsWith('arn:')) return declared.replace('{account}', accountId).replace('{account_id}', accountId);
  return `arn:aws:iam::${accountId}:role/${declared}`;
}

/**
 * Assumes the declared read-only collector role in one account.
 *
 * Deliberately short-lived and read-only by convention rather than by enforcement here —
 * the trust policy on the role is the control, and this harness is not in a position to
 * verify it. What it can do is name the role it used in the bundle's scope, so a reviewer
 * asking "with what privilege was this collected" has an answer in the evidence rather than
 * in a runbook.
 */
export async function assumeRole(roleArn, region, sessionName = 'ksi-harness') {
  const { client, sdk } = await service('sts', region);
  const out = await client.send(
    new sdk.AssumeRoleCommand({ RoleArn: roleArn, RoleSessionName: sessionName, DurationSeconds: 3600 })
  );
  const c = out.Credentials;
  return {
    accessKeyId: c.AccessKeyId,
    secretAccessKey: c.SecretAccessKey,
    sessionToken: c.SessionToken,
    expiration: c.Expiration,
  };
}

/**
 * Runs one grading function against every account the profile declares.
 *
 * Returns `{ parts, unexamined }` shaped for `mergeGraded`. An account that cannot be
 * assumed into, or whose listing calls fail, becomes an `unexamined` entry rather than an
 * absence — which is the difference between a population of three accounts reported as
 * incomplete, and a population of two accounts reported as clean.
 *
 * A single-account profile with no declared role runs on the ambient credential, so the
 * common local case needs no role at all. More than one account without a declared role is
 * refused: running them all on one credential would report the same account's evidence
 * several times under several names, which is worse than not running.
 */
export async function perAccount(profile, fn, { sessionName = 'ksi-harness' } = {}) {
  const accounts = resolveAccounts(profile);
  const parts = [];
  const unexamined = [];

  if (accounts.length > 1 && !profile?.aws?.collector_role) {
    throw new Error(
      `${accounts.length} accounts are in scope but the profile declares no aws.collector_role. Running them ` +
        `all on one credential would file one account's evidence under every account id. Declare a role name ` +
        `this harness can assume in each account, or reduce the profile to the account these credentials hold.`
    );
  }

  for (const account of accounts) {
    const region = account.regions?.[0] ?? profile?.aws?.regions?.[0] ?? 'us-east-1';
    const roleArn = collectorRoleArn(profile, account.id);

    let credentials;
    if (roleArn) {
      try {
        credentials = await assumeRole(roleArn, region, sessionName);
      } catch (err) {
        unexamined.push({ id: `account/${account.id}`, reason: `could not assume ${roleArn}: ${err.message}` });
        continue;
      }
    }

    try {
      const graded = await fn({ account, region, regions: account.regions ?? [region], credentials, roleArn });
      parts.push({ scope: account.id, graded });
    } catch (err) {
      unexamined.push({ id: `account/${account.id}`, reason: err.message });
    }
  }

  return { parts, unexamined, accounts };
}
