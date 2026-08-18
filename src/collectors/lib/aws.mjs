export { fixtureScope, loadFixture } from './fixtures.mjs';
export { describePorts, passRate } from './grade.mjs';

/**
 * Shared plumbing for the AWS checks.
 *
 * Carried over from RootCawsLLC/grc-wizard, where each of these behaviours was arrived at
 * by a live run producing wrong evidence. Three jobs, all about keeping checks honest
 * rather than convenient:
 *
 *  - Lazy SDK loading, so the repository installs and tests without the AWS SDK present.
 *    Only a real collection needs it.
 *  - Full pagination, because a first-page answer over a truncated population is the
 *    quietest way to report a pass that is not one.
 *  - A hard line between "this resource has no such configuration" and "I was not allowed
 *    to look", which `optional()` enforces.
 */

const CLIENT_MODULES = {
  cloudtrail: ['@aws-sdk/client-cloudtrail', 'CloudTrailClient'],
  config: ['@aws-sdk/client-config-service', 'ConfigServiceClient'],
  ec2: ['@aws-sdk/client-ec2', 'EC2Client'],
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

/** Collects every page of a paginated call into one array. */
export async function pages(client, CommandClass, input, extract, tokenIn = 'NextToken', tokenOut = 'NextToken') {
  const out = [];
  let token;
  do {
    const response = await client.send(new CommandClass({ ...input, [tokenIn]: token }));
    out.push(...(extract(response) ?? []));
    token = response[tokenOut];
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
export async function callerIdentity(region = 'us-east-1') {
  const { client, sdk } = await service('sts', region);
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
