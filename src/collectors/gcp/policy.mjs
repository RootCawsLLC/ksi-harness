import { buildBundle } from '../../evidence/bundle.mjs';
import { api, endpoint, fixtureScope, loadFixture, mergeGraded, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/policy.mjs';

export const CHECKS = [
  {
    id: 'gcp.policy.org-constraints',
    ksis: ['KSI-CNA-EIS', 'KSI-SVC-ACM'],
    fixture: 'gcp-org-policy',
    assertion:
      'Every Organization Policy constraint the profile declares as required is enforced on the project, with no ' +
      'project-level exception weakening it.',
  },
];

/**
 * The preventive half of the GCP family, and the reason it is worth having separately from
 * the detective collectors.
 *
 * Organization Policy is evaluated when the API call is made rather than after the fact, so
 * a constraint that is enforced does not merely describe today's state — it decides what
 * tomorrow's can be. `iam.disableServiceAccountKeyCreation` on a project with no downloaded
 * keys is a different fact from the same project without it, and only one of those two
 * projects can acquire the finding overnight.
 *
 * That makes this the GCP counterpart to the Terraform policy gate: a gate cannot see a
 * change made in the console, and a collector reading deployed state cannot stop one. Org
 * Policy is the rare control that does both, which is why KSI-CNA-EIS asks for automated
 * services that *enforce* intended state rather than only assess it. See ADR 0005.
 */

/** Constraints treated as the baseline when the profile declares none. */
export const DEFAULT_CONSTRAINTS = Object.freeze([
  { id: 'iam.disableServiceAccountKeyCreation', why: 'prevents downloadable service account keys being created at all' },
  { id: 'storage.publicAccessPrevention', why: 'prevents a bucket being made public regardless of its own IAM' },
  { id: 'sql.restrictPublicIp', why: 'prevents a database being given a public address' },
  { id: 'compute.requireOsLogin', why: 'forces SSH through IAM rather than metadata-distributed keys' },
  { id: 'compute.vmExternalIpAccess', why: 'restricts which VMs may hold an external address' },
  { id: 'iam.allowedPolicyMemberDomains', why: 'prevents sharing with identities outside the organization' },
]);

/* ------------------------------------------------------------------- grading */

export function gradeOrgConstraints(effective, { projectId, required = DEFAULT_CONSTRAINTS, unexamined = [] } = {}) {
  const byId = new Map(effective.map((e) => [e.constraint, e]));

  const items = required.map(({ id, why }) => {
    const state = byId.get(id);
    if (!state) {
      return {
        id: `constraint/${id}`,
        status: 'fail',
        detail: `Not enforced anywhere in the hierarchy above this project — ${why}`,
      };
    }
    if (!state.enforced) {
      return {
        id: `constraint/${id}`,
        status: 'fail',
        detail: `Present but not enforced${state.source ? ` (inherited from ${state.source})` : ''} — ${why}`,
        observed: { source: state.source ?? null },
      };
    }
    // An enforced constraint carrying exceptions is the case that reads as compliant on a
    // dashboard and is not: the constraint applies to everything except the thing somebody
    // needed it not to apply to, and nothing in the enforced flag says so.
    if (state.exceptions?.length) {
      return {
        id: `constraint/${id}`,
        status: 'warn',
        detail: `Enforced with ${state.exceptions.length} exception(s): ${state.exceptions.join(', ')} — ${why}`,
        observed: { exceptions: state.exceptions, source: state.source ?? null },
      };
    }
    return {
      id: `constraint/${id}`,
      status: 'pass',
      detail: `Enforced${state.source ? ` from ${state.source}` : ''} with no exception`,
    };
  });

  const enforcedCount = items.filter((i) => i.status === 'pass').length;
  items.unshift({
    id: `project/${projectId}`,
    status: enforcedCount > 0 ? 'pass' : 'fail',
    detail:
      enforcedCount > 0
        ? `${enforcedCount} of ${required.length} declared constraint(s) enforced without exception`
        : 'No declared Organization Policy constraint is enforced on this project, so nothing prevents the ' +
          'configurations the detective checks look for from being created again tomorrow',
  });

  return {
    items,
    population: {
      expected: 1 + required.length + unexamined.length,
      unexamined,
      source_of_truth: 'orgpolicy:policies.getEffectivePolicy per declared constraint, resolved through the hierarchy',
      enumerated_from:
        'the constraints the profile declares as required, counted before any policy was read — the required set ' +
        'is a declaration of intended state rather than a reading of the current one',
    },
    metric: { metric_id: 'gcp.policy.constraints_enforced', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchEffectivePolicies(projectId, required, token) {
  const effective = [];
  const unexamined = [];

  for (const { id } of required) {
    const res = await api(endpoint('orgpolicy', `/projects/${projectId}/policies/${id}:getEffectivePolicy`), { token });
    if (!res.ok) {
      if (res.classification?.kind === 'absent') {
        effective.push({ constraint: id, enforced: false, source: null, exceptions: [] });
        continue;
      }
      unexamined.push({ id: `constraint/${id}`, reason: res.classification?.detail ?? `HTTP ${res.status}` });
      continue;
    }
    const rules = res.body?.spec?.rules ?? [];
    const enforced = rules.some((r) => r.enforce === true) || rules.some((r) => r.allowAll === false);
    const exceptions = rules.flatMap((r) => r.values?.deniedValues ?? []).filter(Boolean);
    effective.push({ constraint: id, enforced, source: res.body?.spec?.inheritFromParent ? 'parent' : null, exceptions });
  }
  return { effective, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const check = CHECKS[0];
  const common = {
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
    previousHash: previousHashes.get(check.id)?.hash ?? null,
    chainIndex: previousHashes.get(check.id)?.index ?? 0,
  };
  const required = profile?.gcp?.required_constraints ?? DEFAULT_CONSTRAINTS;

  if (fixture) {
    const data = loadFixture(fixture, 'gcp-org-policy');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'gcp-org-policy', { required_constraints: data.required.map((r) => r.id) }),
        ...gradeOrgConstraints(data.effective, {
          projectId: data.project,
          required: data.required,
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const { effective, unexamined: gaps } = await fetchEffectivePolicies(project.id, required, token);
    return gradeOrgConstraints(effective, { projectId: project.id, required, unexamined: gaps });
  });

  return [
    buildBundle({
      ...common,
      scope: {
        projects: projects.map((p) => p.id),
        organization_id: profile?.gcp?.organization_id ?? null,
        required_constraints: required.map((r) => r.id),
      },
      ...mergeGraded(parts, {
        sourceOfTruth: 'the effective Organization Policy for each declared constraint, in each declared project',
        enumeratedFrom: 'the constraints and projects declared in the profile, counted before any was read',
        metric: { metric_id: 'gcp.policy.constraints_enforced', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
