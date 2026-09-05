import { buildBundle } from '../../evidence/bundle.mjs';
import { api, endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/iam.mjs';

export const CHECKS = [
  {
    id: 'gcp.iam.service-account-keys',
    // Deliberately not KSI-SVC-ASM. A downloaded key is a secret, so the temptation is to
    // claim "Automating Secret Management" here — but that indicator is about the secret
    // management system: rotation configuration, vault usage, secret age. This check reads
    // none of those. Claiming it would be the coverage inflation the routing model exists
    // to prevent, so SVC-ASM stays unaddressed until something actually reads a vault.
    ksis: ['KSI-IAM-SNU'],
    fixture: 'gcp-service-accounts',
    assertion:
      'No service account in the project holds a user-managed key, and the organization policy that prevents ' +
      'their creation is enforced.',
  },
  {
    id: 'gcp.iam.privileged-access',
    ksis: ['KSI-CNA-DFP', 'KSI-IAM-ELP', 'KSI-IAM-JIT'],
    fixture: 'gcp-iam-policy',
    assertion:
      'No principal holds a primitive role on the project, and every binding that confers broad privilege is ' +
      'enumerated with the members it grants it to.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades service account key posture.
 *
 * A user-managed key is a private key someone downloaded, and once downloaded it lives
 * wherever it was put — a laptop, a CI secret, an email thread. It is the most
 * characteristic GCP finding there is, and it fails rather than warns because there is no
 * configuration that makes a downloaded key safe. Google-rotated `SYSTEM_MANAGED` keys are
 * a different object entirely and leave the population as not-applicable.
 *
 * The project-level item carries the preventive half. `iam.disableServiceAccountKeyCreation`
 * is enforced by Org Policy at the API, so a project with the constraint on cannot acquire
 * this finding tomorrow, and one without it can. A check that only counted today's keys
 * would report those two projects identically.
 */
export function gradeServiceAccountKeys(serviceAccounts, { projectId, keyCreationDisabled = null, unexamined = [] } = {}) {
  const items = serviceAccounts.map((sa) => {
    const userManaged = (sa.keys ?? []).filter((k) => k.keyType === 'USER_MANAGED');
    if (userManaged.length === 0) {
      return {
        id: `serviceAccount/${sa.email}`,
        status: 'pass',
        detail: 'No user-managed key; authentication is via workload identity or a Google-rotated key',
      };
    }
    return {
      id: `serviceAccount/${sa.email}`,
      status: 'fail',
      detail:
        `${userManaged.length} user-managed key(s) — private key material has been downloaded and exists ` +
        `outside Google's control`,
      observed: { keys: userManaged.map((k) => ({ name: k.name?.split('/').pop(), created: k.validAfterTime })) },
    };
  });

  items.unshift(
    keyCreationDisabled === null
      ? {
          id: `project/${projectId}`,
          status: 'warn',
          detail:
            'Could not read the organization policy for iam.disableServiceAccountKeyCreation, so nothing here ' +
            'establishes whether a new downloaded key could be created tomorrow.',
        }
      : keyCreationDisabled
        ? {
            id: `project/${projectId}`,
            status: 'pass',
            detail: 'iam.disableServiceAccountKeyCreation is enforced, so new user-managed keys are rejected at the API',
          }
        : {
            id: `project/${projectId}`,
            status: 'fail',
            detail:
              'iam.disableServiceAccountKeyCreation is not enforced. Any principal who can administer a service ' +
              'account can create a downloadable key without changing anything in the list above.',
          }
  );

  return {
    items,
    population: {
      expected: 1 + serviceAccounts.length + unexamined.length,
      unexamined,
      source_of_truth: 'iam:serviceAccounts.list with keys.list per account, plus one project-level policy claim',
      enumerated_from:
        'iam.serviceAccounts.list for the project, counted before any key listing was made; the project-level ' +
        'constraint is read separately from the Organization Policy API',
    },
    metric: { metric_id: 'gcp.iam.accounts_without_downloaded_keys', value: passRate(items), unit: 'ratio' },
  };
}

/** Roles that confer broad, standing privilege over everything in a project. */
export const PRIMITIVE_ROLES = new Set(['roles/owner', 'roles/editor']);

/** Roles that are administrative in effect without being primitive in name. */
export const ADMIN_EQUIVALENT = new Set([
  'roles/iam.securityAdmin',
  'roles/iam.serviceAccountKeyAdmin',
  'roles/iam.serviceAccountTokenCreator',
  'roles/resourcemanager.projectIamAdmin',
  'roles/orgpolicy.policyAdmin',
]);

/** A member string that is a human identity rather than a workload. */
export function isHumanMember(member) {
  return member.startsWith('user:') || member.startsWith('group:') || member.startsWith('domain:');
}

/**
 * Grades project IAM bindings.
 *
 * A primitive role held by a human is standing administrative privilege on a long-lived
 * identity, which is what KSI-IAM-JIT rules out, so it fails. The same role held by a
 * service account warns instead: a build or deploy identity with broad rights is a real
 * risk and a common one, but the control is the workload identity binding rather than the
 * role, and this check has not read it. Both are always surfaced, because the indicator
 * asks for the model to be persistently reviewed and an unenumerated owner is one nobody
 * reviewed.
 *
 * A condition on the binding is recorded but does not clear it. Conditions on GCP bindings
 * are commonly resource- or time-scoped, and only the time-scoped ones bear on standing
 * privilege — which is a judgment this check surfaces rather than makes.
 */
export function gradePrivilegedAccess(bindings, { projectId, unexamined = [] } = {}) {
  const items = [];

  // Counted from the policy before any grading happens, so the denominator is a property of
  // the source rather than a tally of whatever the loop below managed to produce. Deriving
  // it from `items` afterwards would make the completeness test unable to fail.
  const privilegedMembers = bindings
    .filter((b) => PRIMITIVE_ROLES.has(b.role) || ADMIN_EQUIVALENT.has(b.role))
    .reduce((n, b) => n + (b.members?.length ?? 0), 0);

  for (const binding of bindings) {
    const primitive = PRIMITIVE_ROLES.has(binding.role);
    const adminEquivalent = ADMIN_EQUIVALENT.has(binding.role);
    if (!primitive && !adminEquivalent) continue;

    for (const member of binding.members ?? []) {
      const id = `binding/${binding.role}/${member}`;
      const why = primitive ? `primitive role ${binding.role}` : `administrative role ${binding.role}`;
      const conditioned = binding.condition ? ` (condition: ${binding.condition.title ?? 'unnamed'})` : '';

      if (member.startsWith('deleted:')) {
        items.push({
          id,
          status: 'fail',
          detail: `${why} is still bound to a deleted principal, which is a binding nobody owns${conditioned}`,
        });
        continue;
      }
      items.push({
        id,
        status: isHumanMember(member) ? 'fail' : 'warn',
        detail: isHumanMember(member)
          ? `Standing ${why} on a human identity${conditioned}`
          : `${why} on a workload identity${conditioned} — review that the trust binding is the real control`,
        observed: { role: binding.role, member, condition: binding.condition ?? null },
      });
    }
  }

  // Without this, a project whose IAM policy contains no privileged binding produces an
  // empty, complete, failure-free population — which reads as compliance rather than as the
  // genuinely good state it usually is. Naming the project makes the pass legible.
  const total = bindings.reduce((n, b) => n + (b.members?.length ?? 0), 0);
  items.unshift(
    total > 0
      ? {
          id: `project/${projectId}`,
          status: 'pass',
          detail: `${bindings.length} role binding(s) covering ${total} member(s) enumerated for assessment`,
        }
      : {
          id: `project/${projectId}`,
          status: 'warn',
          detail:
            'The project IAM policy returned no bindings at all. A project with no access policy is a project ' +
            'nobody can use, so this describes the collection rather than the project.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + privilegedMembers + unexamined.length,
      unexamined,
      source_of_truth: 'cloudresourcemanager:projects.getIamPolicy, every binding conferring primitive or admin-equivalent privilege',
      enumerated_from:
        'the project IAM policy read in full, with privileged member-bindings counted before grading; bindings ' +
        'outside the privileged set leave the population rather than being counted as passes',
    },
    metric: { metric_id: 'gcp.iam.bindings_without_standing_privilege', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchServiceAccounts(projectId, token) {
  const listed = await paginate(endpoint('iam', `/projects/${projectId}/serviceAccounts`), 'accounts', { token });
  if (!listed.ok) {
    throw new Error(listed.classification?.detail ?? `iam.serviceAccounts.list failed with HTTP ${listed.status}`);
  }

  const serviceAccounts = [];
  const unexamined = [];
  for (const sa of listed.items) {
    const keys = await api(endpoint('iam', `/projects/${projectId}/serviceAccounts/${sa.email}/keys`), { token });
    if (!keys.ok) {
      // A key listing this credential cannot read is a gap, not an account without keys.
      unexamined.push({
        id: `serviceAccount/${sa.email}`,
        reason: keys.classification?.detail ?? `keys.list failed with HTTP ${keys.status}`,
      });
      continue;
    }
    serviceAccounts.push({ email: sa.email, displayName: sa.displayName, keys: keys.body?.keys ?? [] });
  }
  return { serviceAccounts, unexamined };
}

/** Whether an Org Policy boolean constraint is enforced for this project. */
async function fetchBooleanConstraint(projectId, constraint, token) {
  const res = await api(endpoint('orgpolicy', `/projects/${projectId}/policies/${constraint}:getEffectivePolicy`), { token });
  if (!res.ok) return null;
  const rules = res.body?.spec?.rules ?? [];
  return rules.some((r) => r.enforce === true);
}

async function fetchIamPolicy(projectId, token) {
  const res = await api(endpoint('crm', `/projects/${projectId}:getIamPolicy`), { token, method: 'POST' });
  if (!res.ok) {
    throw new Error(res.classification?.detail ?? `projects.getIamPolicy failed with HTTP ${res.status}`);
  }
  return res.body?.bindings ?? [];
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chainOf = (checkId) => ({
    previousHash: previousHashes.get(checkId)?.hash ?? null,
    chainIndex: previousHashes.get(checkId)?.index ?? 0,
  });

  if (fixture) {
    const sa = loadFixture(fixture, 'gcp-service-accounts');
    const policy = loadFixture(fixture, 'gcp-iam-policy');
    return [
      buildBundle({
        ...common,
        ...chainOf(CHECKS[0].id),
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'gcp-service-accounts'),
        ...gradeServiceAccountKeys(sa.service_accounts, {
          projectId: sa.project,
          keyCreationDisabled: sa.key_creation_disabled ?? null,
          unexamined: sa.unexamined ?? [],
        }),
      }),
      buildBundle({
        ...common,
        ...chainOf(CHECKS[1].id),
        checkId: CHECKS[1].id,
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'gcp-iam-policy'),
        ...gradePrivilegedAccess(policy.bindings, { projectId: policy.project, unexamined: policy.unexamined ?? [] }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const { serviceAccounts, unexamined: keyGaps } = await fetchServiceAccounts(project.id, token);
    const keyCreationDisabled = await fetchBooleanConstraint(project.id, 'iam.disableServiceAccountKeyCreation', token);
    return {
      keys: gradeServiceAccountKeys(serviceAccounts, { projectId: project.id, keyCreationDisabled, unexamined: keyGaps }),
      priv: gradePrivilegedAccess(await fetchIamPolicy(project.id, token), { projectId: project.id }),
    };
  });

  const scope = { projects: projects.map((p) => p.id), organization_id: profile?.gcp?.organization_id ?? null };

  return [
    buildBundle({
      ...common,
      ...chainOf(CHECKS[0].id),
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope,
      ...mergeGraded(
        parts.map((p) => ({ scope: p.scope, graded: p.graded.keys })),
        {
          sourceOfTruth: 'iam.serviceAccounts.list with keys.list per account, in each declared project',
          enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
          metric: { metric_id: 'gcp.iam.accounts_without_downloaded_keys', unit: 'ratio' },
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
        parts.map((p) => ({ scope: p.scope, graded: p.graded.priv })),
        {
          sourceOfTruth: 'cloudresourcemanager projects.getIamPolicy in each declared project',
          enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
          metric: { metric_id: 'gcp.iam.bindings_without_standing_privilege', unit: 'ratio' },
          unexamined,
        }
      ),
    }),
  ];
}
