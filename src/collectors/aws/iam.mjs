import { buildBundle } from '../../evidence/bundle.mjs';
import {
  fixtureScope,
  loadFixture,
  mergeGraded,
  optional,
  pages,
  passRate,
  perAccount,
  service,
} from '../lib/aws.mjs';

export const VERSION = '2.0.0';
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

/**
 * Grades MFA coverage, reconciling the credential report against a separate principal listing.
 *
 * The denominator comes from `iam:ListUsers` and the numerator from `iam:GetCredentialReport`,
 * which is the point: the credential report is generated asynchronously and can be stale, so a
 * user created since the last generation is absent from it. Deriving both ends from the report
 * would make the reconciliation arithmetic that cannot fail, and a check whose completeness
 * test can never fail is not testing completeness.
 *
 * A principal with no console access is `not-applicable` rather than excluded: dropping it
 * from the population would make the denominator disagree with the listing for a reason the
 * bundle never records.
 */
export function gradeMfaCoverage(rows, { enumeratedUsers = null, accountId = 'unknown' } = {}) {
  const items = rows.map((row) => {
    if (row.user === ROOT) {
      const mfa = row.mfa_active === 'true';
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

    if (row.password_enabled !== 'true') {
      return {
        id: row.user,
        status: 'not-applicable',
        detail: 'No console access, so a console MFA device is not the applicable control',
        observed: { password_enabled: row.password_enabled },
      };
    }
    return row.mfa_active === 'true'
      ? { id: row.user, status: 'pass', detail: 'Console access with MFA' }
      : { id: row.user, status: 'fail', detail: 'Console access without MFA' };
  });

  // Every principal the listing knows about but the report does not mention. A stale or
  // truncated report is the failure this reconciliation exists to surface, and it is
  // invisible if the report is allowed to define its own denominator.
  const reported = new Set(rows.map((r) => r.user));
  const unexamined = (enumeratedUsers ?? [])
    .filter((name) => !reported.has(name))
    .map((name) => ({
      id: `user/${name}`,
      reason: 'listed by iam:ListUsers but absent from the credential report, which is generated asynchronously',
    }));

  const expected = enumeratedUsers ? enumeratedUsers.length + 1 : rows.length;

  return {
    items,
    population: {
      expected,
      unexamined,
      source_of_truth: 'iam:GetCredentialReport - one row per principal, plus root',
      enumerated_from: enumeratedUsers
        ? 'iam:ListUsers, plus the root account, taken before the credential report was read'
        : `credential report rows for account ${accountId}`,
    },
    metric: { metric_id: 'aws.iam.mfa_coverage', value: passRate(items), unit: 'ratio' },
  };
}

const ADMIN_MANAGED = new Set(['AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess']);

/**
 * Condition keys that genuinely remove standing privilege rather than merely narrowing where
 * it can be used from.
 *
 * This distinction was wrong in the first version and wrong in the direction that matters. A
 * condition of any kind was treated as removing the grant, so `aws:RequestedRegion` — which
 * constrains nothing about who holds administrative access or for how long — disqualified a
 * wildcard admin statement entirely. Elevation-bound and session-bound conditions are how
 * just-in-time access is actually expressed; a tag or a source address is not.
 */
const ELEVATION_CONDITION_KEYS = [
  'aws:multifactorauthpresent',
  'aws:multifactorauthage',
  'aws:tokenissuetime',
];

/**
 * Actions that are administrative in effect without being administrative in text.
 *
 * Each of these on `Resource: "*"` is a documented path from limited privilege to full
 * privilege — rewrite a policy version, attach a policy to yourself, mint a login profile,
 * pass a role to a service that will run as it. A check that only matches `Action: "*"`
 * reports these as unprivileged, which is the most useful kind of false negative to an
 * attacker and the reason KSI-IAM-ELP is about effect rather than syntax.
 */
const ESCALATION_ACTIONS = [
  'iam:createpolicyversion',
  'iam:setdefaultpolicyversion',
  'iam:attachuserpolicy',
  'iam:attachrolepolicy',
  'iam:attachgrouppolicy',
  'iam:putuserpolicy',
  'iam:putrolepolicy',
  'iam:putgrouppolicy',
  'iam:createaccesskey',
  'iam:createloginprofile',
  'iam:updateloginprofile',
  'iam:updateassumerolepolicy',
  'iam:passrole',
];

/** Matches an action pattern from a policy (which may contain `*`) against a literal action. */
function actionMatches(pattern, literal) {
  const p = String(pattern).toLowerCase();
  if (p === '*') return true;
  if (!p.includes('*')) return p === literal;
  const rx = new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
  return rx.test(literal);
}

function conditionKeys(condition) {
  return Object.values(condition ?? {})
    .flatMap((operands) => Object.keys(operands ?? {}))
    .map((k) => k.toLowerCase());
}

/**
 * Describes what a policy document grants, rather than answering one boolean about it.
 *
 * Returns `{ admin, via, constrained, conditions }`. `constrained` means the grant is bound
 * to an elevation event, so it is privilege that has to be acquired rather than privilege
 * that is simply held — which is the distinction KSI-IAM-JIT turns on.
 */
export function adminGrant(document) {
  const statements = [].concat(document?.Statement ?? []);
  const via = [];
  const conditions = [];
  let constrained = false;

  for (const s of statements) {
    if (s.Effect !== 'Allow') continue;
    const resources = [].concat(s.Resource ?? []);
    if (!resources.some((r) => r === '*')) continue;

    const keys = conditionKeys(s.Condition);
    const elevationBound = keys.some((k) => ELEVATION_CONDITION_KEYS.includes(k));
    const matched = [];

    if (s.NotAction !== undefined) {
      // Allow everything except a named few, on every resource. Administrative by
      // construction, and completely invisible to a test that only reads `Action`.
      const excluded = [].concat(s.NotAction);
      matched.push(`NotAction grant excluding only ${excluded.join(', ')}`);
    } else {
      const actions = [].concat(s.Action ?? []);
      if (actions.some((a) => a === '*' || a === 'iam:*')) {
        matched.push(`wildcard action grant (${actions.join(', ')})`);
      } else {
        const escalations = ESCALATION_ACTIONS.filter((e) => actions.some((a) => actionMatches(a, e)));
        if (escalations.length) matched.push(`privilege-escalation actions on every resource (${escalations.join(', ')})`);
      }
    }

    if (matched.length === 0) continue;
    via.push(...matched);
    if (keys.length) conditions.push(...keys);
    if (elevationBound) constrained = true;
  }

  return { admin: via.length > 0, via, constrained, conditions: [...new Set(conditions)] };
}

/**
 * True when a policy document confers standing administrative privilege.
 *
 * Kept as a boolean for the callers and tests that only need the verdict; `adminGrant`
 * carries the reasoning.
 */
export function grantsWildcard(document) {
  const grant = adminGrant(document);
  return grant.admin && !grant.constrained;
}

/**
 * Grades administrative privilege over IAM users and roles.
 *
 * A user with an unconditioned administrative grant fails: an IAM user is a long-lived
 * identity, so admin on it is standing privilege by construction, which is what KSI-IAM-JIT
 * rules out. A role with an administrative grant warns rather than fails — a break-glass
 * admin role is legitimate and its trust policy is the control — but it is always surfaced,
 * because the indicator asks for the model to be *persistently reviewed* and an unenumerated
 * admin role is one nobody reviewed.
 *
 * A permissions boundary downgrades a user finding to a warning rather than clearing it. The
 * boundary is a real constraint and reporting the user as a standing administrator would be
 * wrong; it is also a second document that has to be read to know the effective privilege,
 * and this check has not read it.
 */
export function gradePrivilegedAccess(principals, { enumerated = null, unexamined = [], accountId = 'unknown' } = {}) {
  const items = principals.map((p) => {
    const grants = [
      ...p.attached.filter((name) => ADMIN_MANAGED.has(name)).map((name) => ({ via: [`managed policy ${name}`], constrained: false, conditions: [] })),
      ...p.inline.map((pol) => ({ ...adminGrant(pol.document), label: `inline policy ${pol.name}` })),
      ...p.attachedDocuments.map((pol) => ({ ...adminGrant(pol.document), label: `customer policy ${pol.name}` })),
    ].filter((g) => g.via?.length);

    const adminBy = grants.flatMap((g) => (g.label ? g.via.map((v) => `${g.label}: ${v}`) : g.via));
    const conditions = [...new Set(grants.flatMap((g) => g.conditions ?? []))];
    const everyGrantConstrained = grants.length > 0 && grants.every((g) => g.constrained);

    if (adminBy.length === 0) {
      return { id: `${p.type}/${p.name}`, status: 'pass', detail: 'No administrative grant' };
    }

    if (everyGrantConstrained) {
      return {
        id: `${p.type}/${p.name}`,
        status: 'pass',
        detail: `Administrative grant, bound to an elevation condition (${conditions.join(', ')}) rather than standing`,
        observed: { granted_by: adminBy, conditions },
      };
    }

    if (p.type === 'user') {
      if (p.permissionsBoundary) {
        return {
          id: `user/${p.name}`,
          status: 'warn',
          detail:
            `Administrative grant via ${adminBy.join(', ')}, capped by permissions boundary ` +
            `${p.permissionsBoundary}. Effective privilege depends on that boundary, which this check does not read.`,
          observed: { granted_by: adminBy, permissions_boundary: p.permissionsBoundary, conditions },
        };
      }
      return {
        id: `user/${p.name}`,
        status: 'fail',
        detail: `Standing administrative privilege on a long-lived identity via ${adminBy.join(', ')}`,
        observed: { granted_by: adminBy, conditions },
      };
    }

    return {
      id: `role/${p.name}`,
      status: 'warn',
      detail: `Administrative role, assumable by ${p.trustedPrincipals.join(', ') || 'no principal'} — review that elevation is time-bound`,
      observed: { granted_by: adminBy, trusted_principals: p.trustedPrincipals, conditions },
    };
  });

  // Without this, an account whose listing returned nothing produces an empty, complete,
  // failure-free population. The bundle contract now caps that at warn on its own, but an
  // item that says which account was empty is a better report than a bare warning.
  const enumeratedCount = enumerated ? enumerated.length : principals.length;
  items.unshift(
    enumeratedCount > 0
      ? {
          id: `account/${accountId}`,
          status: 'pass',
          detail: `${enumeratedCount} IAM principal(s) enumerated for assessment`,
        }
      : {
          id: `account/${accountId}`,
          status: 'warn',
          detail:
            'No IAM principals were enumerated in this account. Nothing here distinguishes an account that ' +
            'genuinely holds none from a listing that was filtered or truncated.',
        }
  );

  return {
    items,
    population: {
      // The account item plus every principal the listing named, whether or not its policies
      // could be read. `enumerated` already includes the principals that failed to resolve,
      // so they are counted here once and itemised in `unexamined`.
      expected: 1 + enumeratedCount,
      unexamined,
      source_of_truth: 'iam:ListUsers + iam:ListRoles with attached and inline policies resolved for each',
      enumerated_from: 'iam:ListUsers + iam:ListRoles, counted before any policy document was fetched',
    },
    metric: {
      metric_id: 'aws.iam.principals_without_standing_admin',
      value: passRate(items),
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

  // Service-linked roles are AWS-controlled and cannot be modified, so grading them adds
  // noise without adding a decision anyone can act on. They leave the denominator entirely
  // rather than becoming an unexplained gap.
  const gradableRoles = roles.filter((r) => !r.Path?.startsWith('/aws-service-role/'));
  const enumerated = [
    ...users.map((u) => `user/${u.UserName}`),
    ...gradableRoles.map((r) => `role/${r.RoleName}`),
  ];

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

  async function describe(type, name, trustDocument, permissionsBoundary) {
    const AttachedCmd = type === 'user' ? sdk.ListAttachedUserPoliciesCommand : sdk.ListAttachedRolePoliciesCommand;
    const InlineCmd = type === 'user' ? sdk.ListUserPoliciesCommand : sdk.ListRolePoliciesCommand;
    const GetInlineCmd = type === 'user' ? sdk.GetUserPolicyCommand : sdk.GetRolePolicyCommand;
    const key = type === 'user' ? 'UserName' : 'RoleName';

    const attachedRaw = await pages(client, AttachedCmd, { [key]: name }, (r) => r.AttachedPolicies, 'Marker', 'Marker');
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
      permissionsBoundary: permissionsBoundary ?? null,
      trustedPrincipals: trustPrincipals(trustDocument),
    };
  }

  const principals = [];
  const unexamined = [];

  // One principal whose policies cannot be read is a gap in the population, not a reason to
  // abandon the account. Letting the error propagate meant a single denied GetPolicy call
  // discarded every other principal's evidence along with it.
  for (const user of users) {
    try {
      principals.push(await describe('user', user.UserName, null, user.PermissionsBoundary?.PermissionsBoundaryArn));
    } catch (err) {
      unexamined.push({ id: `user/${user.UserName}`, reason: err.message });
    }
  }
  for (const role of gradableRoles) {
    try {
      const trust = role.AssumeRolePolicyDocument ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : null;
      principals.push(await describe('role', role.RoleName, trust, role.PermissionsBoundary?.PermissionsBoundaryArn));
    } catch (err) {
      unexamined.push({ id: `role/${role.RoleName}`, reason: err.message });
    }
  }

  return { principals, enumerated, unexamined, userNames: users.map((u) => u.UserName) };
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

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chainOf = (checkId) => ({
    previousHash: previousHashes.get(checkId)?.hash ?? null,
    chainIndex: previousHashes.get(checkId)?.index ?? 0,
  });

  if (fixture) {
    const principalData = loadFixture(fixture, 'aws-iam-principals');
    const report = loadFixture(fixture, 'aws-iam-credential-report', { json: false });

    const mfa = gradeMfaCoverage(parseCredentialReport(report), {
      enumeratedUsers: principalData.enumerated_users ?? null,
      accountId: principalData.account ?? 'fixture',
    });
    const priv = gradePrivilegedAccess(principalData.principals ?? principalData, {
      enumerated: principalData.enumerated ?? null,
      unexamined: principalData.unexamined ?? [],
      accountId: principalData.account ?? 'fixture',
    });

    return [
      buildBundle({
        ...common,
        ...chainOf('aws.iam.mfa-coverage'),
        checkId: 'aws.iam.mfa-coverage',
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-iam-credential-report'),
        ...mfa,
      }),
      buildBundle({
        ...common,
        ...chainOf('aws.iam.privileged-access'),
        checkId: 'aws.iam.privileged-access',
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'aws-iam-principals'),
        ...priv,
      }),
    ];
  }

  // IAM is global; the region only selects an endpoint.
  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, region, credentials }) => {
    const fetched = await fetchPrincipals(region, credentials);
    const report = parseCredentialReport(await fetchCredentialReport(region, credentials));
    return {
      mfa: gradeMfaCoverage(report, { enumeratedUsers: fetched.userNames, accountId: account.id }),
      priv: gradePrivilegedAccess(fetched.principals, {
        enumerated: fetched.enumerated,
        unexamined: fetched.unexamined,
        accountId: account.id,
      }),
    };
  });

  const scope = {
    accounts: accounts.map((a) => a.id),
    collector_role: profile?.aws?.collector_role ?? null,
    service: 'iam',
    global: true,
  };

  const mfa = mergeGraded(
    parts.map((p) => ({ scope: p.scope, graded: p.graded.mfa })),
    {
      sourceOfTruth: 'iam:GetCredentialReport in each declared account',
      enumeratedFrom: 'iam:ListUsers per account, plus root, taken before the credential report was read',
      metric: { metric_id: 'aws.iam.mfa_coverage', unit: 'ratio' },
      unexamined,
    }
  );
  const priv = mergeGraded(
    parts.map((p) => ({ scope: p.scope, graded: p.graded.priv })),
    {
      sourceOfTruth: 'iam:ListUsers + iam:ListRoles in each declared account, with policies resolved per principal',
      enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
      metric: { metric_id: 'aws.iam.principals_without_standing_admin', unit: 'ratio' },
      unexamined,
    }
  );

  return [
    buildBundle({
      ...common,
      ...chainOf('aws.iam.mfa-coverage'),
      checkId: 'aws.iam.mfa-coverage',
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope,
      ...mfa,
    }),
    buildBundle({
      ...common,
      ...chainOf('aws.iam.privileged-access'),
      checkId: 'aws.iam.privileged-access',
      ksis: CHECKS[1].ksis,
      assertion: CHECKS[1].assertion,
      scope,
      ...priv,
    }),
  ];
}
