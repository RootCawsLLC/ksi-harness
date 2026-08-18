import { buildBundle } from '../../evidence/bundle.mjs';
import { callerIdentity, fixtureScope, loadFixture, optional, pages, passRate, resolveAccounts, service } from '../lib/aws.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/aws/iam.mjs';

export const CHECKS = [
  {
    id: 'aws.iam.mfa-coverage',
    ksis: ['KSI-IAM-APM'],
    fixture: 'aws-iam-credential-report',
    assertion:
      'Every principal in the account with console access has an MFA device attached, and the root user has ' +
      'MFA attached with no active access keys.',
  },
  {
    id: 'aws.iam.privileged-access',
    ksis: ['KSI-CNA-DFP', 'KSI-IAM-ELP', 'KSI-IAM-JIT'],
    fixture: 'aws-iam-principals',
    assertion:
      'No long-lived IAM user holds an administrative grant, and every role that does is enumerated with the ' +
      'principals permitted to assume it.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * The credential report is a CSV, and two of its columns lie if read naively.
 *
 * `password_enabled` is the literal string `not_supported` for the root user rather than
 * `true`, so filtering on `=== 'true'` drops root from the population — the one principal
 * whose MFA state matters most. `password_last_used` carries `no_information` and
 * `not_supported` as data, not as absence.
 */
export function parseCredentialReport(csv) {
  const [header, ...lines] = csv.trim().split(/\r?\n/);
  const cols = header.split(',');
  return lines
    .filter((l) => l.trim())
    .map((line) => {
      const cells = line.split(',');
      return Object.fromEntries(cols.map((c, i) => [c, cells[i]]));
    });
}

export const ROOT = '<root_account>';

export function gradeMfaCoverage(rows) {
  const inScope = rows.filter((r) => r.user === ROOT || r.password_enabled === 'true');
  const items = inScope.map((row) => {
    const mfa = row.mfa_active === 'true';
    if (row.user === ROOT) {
      const keys = ['access_key_1_active', 'access_key_2_active'].filter((k) => row[k] === 'true');
      if (!mfa) {
        return { id: 'root', status: 'fail', detail: 'Root user has no MFA device attached', observed: { mfa_active: row.mfa_active } };
      }
      if (keys.length) {
        return {
          id: 'root',
          status: 'fail',
          detail: `Root user has ${keys.length} active access key(s); root should hold no programmatic credential`,
          observed: { active_keys: keys },
        };
      }
      return { id: 'root', status: 'pass', detail: 'MFA attached, no active access keys' };
    }
    return mfa
      ? { id: row.user, status: 'pass', detail: 'Console access with MFA' }
      : { id: row.user, status: 'fail', detail: 'Console access without MFA' };
  });

  return {
    items,
    population: {
      expected: inScope.length,
      examined: items.length,
      source_of_truth: 'iam:GetCredentialReport - every principal with console access, plus root',
    },
    metric: { metric_id: 'aws.iam.mfa_coverage', value: passRate(items), unit: 'ratio' },
  };
}

const ADMIN_MANAGED = new Set(['AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess']);

/** True when a policy document allows any action on any resource without a condition. */
export function grantsWildcard(document) {
  const statements = [].concat(document?.Statement ?? []);
  return statements.some((s) => {
    if (s.Effect !== 'Allow' || s.Condition) return false;
    const actions = [].concat(s.Action ?? s.NotAction ?? []);
    const resources = [].concat(s.Resource ?? []);
    return actions.some((a) => a === '*' || a === 'iam:*') && resources.some((r) => r === '*');
  });
}

/**
 * Grades administrative privilege over IAM users and roles.
 *
 * A user with an administrative grant fails: an IAM user is a long-lived identity, so admin
 * on it is standing privilege by construction, which is what KSI-IAM-JIT rules out. A role
 * with an administrative grant warns rather than fails — a break-glass admin role is
 * legitimate and its trust policy is the control — but it is always surfaced, because the
 * indicator asks for the model to be *persistently reviewed* and an unenumerated admin role
 * is one nobody reviewed.
 */
export function gradePrivilegedAccess(principals) {
  const items = principals.map((p) => {
    const adminBy = [
      ...p.attached.filter((name) => ADMIN_MANAGED.has(name)).map((name) => `managed policy ${name}`),
      ...p.inline.filter((pol) => grantsWildcard(pol.document)).map((pol) => `inline policy ${pol.name}`),
      ...p.attachedDocuments.filter((pol) => grantsWildcard(pol.document)).map((pol) => `customer policy ${pol.name}`),
    ];

    if (adminBy.length === 0) {
      return { id: `${p.type}/${p.name}`, status: 'pass', detail: 'No administrative grant' };
    }
    if (p.type === 'user') {
      return {
        id: `user/${p.name}`,
        status: 'fail',
        detail: `Standing administrative privilege on a long-lived identity via ${adminBy.join(', ')}`,
        observed: { granted_by: adminBy },
      };
    }
    return {
      id: `role/${p.name}`,
      status: 'warn',
      detail: `Administrative role, assumable by ${p.trustedPrincipals.join(', ') || 'no principal'} — review that elevation is time-bound`,
      observed: { granted_by: adminBy, trusted_principals: p.trustedPrincipals },
    };
  });

  return {
    items,
    population: {
      expected: principals.length,
      examined: items.length,
      source_of_truth: 'iam:ListUsers + iam:ListRoles with attached and inline policies resolved for each',
    },
    metric: {
      metric_id: 'aws.iam.principals_without_standing_admin',
      value: items.length ? items.filter((i) => i.status === 'pass').length / items.length : 1,
      unit: 'ratio',
    },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchCredentialReport(region, credentials) {
  const { client, sdk } = await service('iam', region, credentials);
  // The report is generated asynchronously. GenerateCredentialReport is idempotent and
  // returns STARTED or COMPLETE; GetCredentialReport throws until one exists.
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const got = await optional(client.send(new sdk.GetCredentialReportCommand({})), [
      'ReportNotPresentException',
      'ReportInProgressException',
    ]);
    if (got?.Content) return Buffer.from(got.Content).toString('utf8');
    await client.send(new sdk.GenerateCredentialReportCommand({}));
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error('iam:GetCredentialReport did not produce a report after 10 attempts');
}

async function fetchPrincipals(region, credentials) {
  const { client, sdk } = await service('iam', region, credentials);

  const users = await pages(client, sdk.ListUsersCommand, {}, (r) => r.Users, 'Marker', 'Marker');
  const roles = await pages(client, sdk.ListRolesCommand, {}, (r) => r.Roles, 'Marker', 'Marker');

  const policyCache = new Map();
  async function resolveCustomerPolicy(arn, name) {
    if (policyCache.has(arn)) return policyCache.get(arn);
    const meta = await client.send(new sdk.GetPolicyCommand({ PolicyArn: arn }));
    const version = await client.send(
      new sdk.GetPolicyVersionCommand({ PolicyArn: arn, VersionId: meta.Policy.DefaultVersionId })
    );
    const document = JSON.parse(decodeURIComponent(version.PolicyVersion.Document));
    const entry = { name, document };
    policyCache.set(arn, entry);
    return entry;
  }

  async function describe(type, name, trustDocument) {
    const AttachedCmd = type === 'user' ? sdk.ListAttachedUserPoliciesCommand : sdk.ListAttachedRolePoliciesCommand;
    const InlineCmd = type === 'user' ? sdk.ListUserPoliciesCommand : sdk.ListRolePoliciesCommand;
    const GetInlineCmd = type === 'user' ? sdk.GetUserPolicyCommand : sdk.GetRolePolicyCommand;
    const key = type === 'user' ? 'UserName' : 'RoleName';

    const attachedRaw = await pages(
      client,
      AttachedCmd,
      { [key]: name },
      (r) => r.AttachedPolicies,
      'Marker',
      'Marker'
    );
    const inlineNames = await pages(client, InlineCmd, { [key]: name }, (r) => r.PolicyNames, 'Marker', 'Marker');

    const inline = [];
    for (const policyName of inlineNames) {
      const got = await client.send(new GetInlineCmd({ [key]: name, PolicyName: policyName }));
      inline.push({ name: policyName, document: JSON.parse(decodeURIComponent(got.PolicyDocument)) });
    }

    // Only customer-managed policies need their document read; AWS-managed administrative
    // policies are recognised by name, and reading every AWS-managed document would be a
    // large number of calls for no additional signal.
    const attachedDocuments = [];
    for (const policy of attachedRaw) {
      if (policy.PolicyArn?.startsWith('arn:aws:iam::aws:policy/')) continue;
      attachedDocuments.push(await resolveCustomerPolicy(policy.PolicyArn, policy.PolicyName));
    }

    return {
      type,
      name,
      attached: attachedRaw.map((p) => p.PolicyName),
      inline,
      attachedDocuments,
      trustedPrincipals: trustPrincipals(trustDocument),
    };
  }

  const out = [];
  for (const user of users) out.push(await describe('user', user.UserName, null));
  for (const role of roles) {
    // Service-linked roles are AWS-controlled and cannot be modified, so grading them adds
    // noise without adding a decision anyone can act on.
    if (role.Path?.startsWith('/aws-service-role/')) continue;
    const trust = role.AssumeRolePolicyDocument
      ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument))
      : null;
    out.push(await describe('role', role.RoleName, trust));
  }
  return out;
}

export function trustPrincipals(trustDocument) {
  const statements = [].concat(trustDocument?.Statement ?? []);
  const out = new Set();
  for (const s of statements) {
    if (s.Effect !== 'Allow') continue;
    for (const value of Object.values(s.Principal ?? {})) {
      for (const p of [].concat(value)) out.add(p);
    }
  }
  return [...out];
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit }) {
  const bundles = [];
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };

  if (fixture) {
    const report = loadFixture(fixture, 'aws-iam-credential-report', { json: false });
    const mfa = gradeMfaCoverage(parseCredentialReport(report));
    bundles.push(
      buildBundle({
        ...common,
        checkId: 'aws.iam.mfa-coverage',
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-iam-credential-report'),
        ...mfa,
      })
    );

    const priv = gradePrivilegedAccess(loadFixture(fixture, 'aws-iam-principals'));
    bundles.push(
      buildBundle({
        ...common,
        checkId: 'aws.iam.privileged-access',
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'aws-iam-principals'),
        ...priv,
      })
    );
    return bundles;
  }

  const accounts = resolveAccounts(profile);
  if (accounts.length > 1) {
    throw new Error(
      `${accounts.length} accounts in scope but cross-account role assumption is not implemented here. ` +
        `Refusing rather than reporting one account's evidence ${accounts.length} times.`
    );
  }
  // IAM is global; the region only selects an endpoint.
  const region = accounts[0].regions?.[0] ?? 'us-east-1';
  const identity = await callerIdentity(region);
  const scope = { account: identity.account, credential_arn: identity.arn, service: 'iam', global: true };

  const mfa = gradeMfaCoverage(parseCredentialReport(await fetchCredentialReport(region)));
  bundles.push(
    buildBundle({ ...common, checkId: 'aws.iam.mfa-coverage', ksis: CHECKS[0].ksis, assertion: CHECKS[0].assertion, scope, ...mfa })
  );

  const priv = gradePrivilegedAccess(await fetchPrincipals(region));
  bundles.push(
    buildBundle({ ...common, checkId: 'aws.iam.privileged-access', ksis: CHECKS[1].ksis, assertion: CHECKS[1].assertion, scope, ...priv })
  );

  return bundles;
}
