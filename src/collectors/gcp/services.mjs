import { buildBundle } from '../../evidence/bundle.mjs';
import { endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/services.mjs';

export const CHECKS = [
  {
    id: 'gcp.service.surface',
    ksis: ['KSI-CNA-DFP', 'KSI-CNA-MAT'],
    fixture: 'gcp-enabled-services',
    assertion:
      'Every service API enabled on a declared project appears in the intended service surface the profile ' +
      'declares, and every intended service is enabled.',
  },
];

/**
 * The functionality half of "functionality and privileges are strictly defined".
 *
 * The privilege half was already checked: `gcp.iam.privileged-access` asserts that no principal
 * holds a primitive role and that every binding conferring broad privilege is *enumerated with the
 * members it grants it to*. Enumeration is what "strictly defined" means, and that check performs
 * it for privileges. Nothing performed it for functionality, so `KSI-CNA-DFP` sat at `partial`
 * with a gap reading "needs an authoritative architecture inventory and there is not one yet".
 *
 * There is one. `serviceusage.googleapis.com` reports exactly which service APIs are enabled on a
 * project, which is the surface through which anything can be done to it at all — an API that is
 * not enabled cannot be called, by an attacker or by anyone else. Comparing that enumeration
 * against a surface the profile declares makes "strictly defined" falsifiable in the direction
 * that matters: a service nobody declared is functionality nobody defined.
 *
 * Both directions are graded, and the second is the one usually skipped:
 *
 *   enabled but not declared    functionality outside the definition — fails
 *   declared but not enabled    the definition describes an estate that does not exist — warns
 *
 * The second is a warning rather than a failure because a declared-and-absent service is a stale
 * profile rather than an exposure, and treating a documentation lag as a security finding is how
 * a report trains its readers to skim. It is not silent, though: a definition that has drifted
 * from reality is no longer a definition of anything.
 *
 * ## Why the denominator is honest here
 *
 * The population is enumerated from the API, never from the declaration. That ordering is the
 * whole point (ADR 0003): counting only the services the profile mentions would make the check
 * unfalsifiable, because the one failure it exists to catch — an enabled service nobody declared —
 * is precisely the case that would be missing from a declaration-derived denominator.
 *
 * ## Why this is GCP-only, and why that is stated rather than worked around
 *
 * AWS has no equivalent. Services are not "enabled" there; they are callable in any region unless
 * an SCP forbids it, so there is no authoritative enumeration of an account's service surface to
 * compare a declaration against. Approximating one from CloudTrail usage would measure what has
 * been *used*, not what is *available*, and an unused-but-reachable service is exactly the surface
 * this indicator is about.
 *
 * That asymmetry is why `KSI-CNA-DFP` declares its sufficiency conditionally: the argument holds
 * for a boundary whose providers can enumerate their own service surface, and does not hold for
 * one that cannot. See `src/routes/sufficiency.mjs`.
 */

/** Services present on every project and not meaningfully "surface" — enabling them is not a choice. */
const BASELINE = new Set([
  'serviceusage.googleapis.com',
  'cloudapis.googleapis.com',
  'storage-component.googleapis.com',
  'storage-api.googleapis.com',
  'monitoring.googleapis.com',
  'logging.googleapis.com',
  'cloudtrace.googleapis.com',
  'datastore.googleapis.com',
  'bigquerystorage.googleapis.com',
  'sql-component.googleapis.com',
  'servicemanagement.googleapis.com',
]);

/**
 * Grades one project's enabled services against the intended surface.
 *
 * `intended` is the profile's declaration. `enabled` is what the API said. Neither is trusted to
 * stand in for the other.
 */
export function gradeServiceSurface(enabled, { projectId, intended, unexamined = [] }) {
  const declared = new Set(intended);
  const live = enabled.filter((s) => !BASELINE.has(s));
  const items = [];

  for (const service of live.sort()) {
    if (declared.has(service)) {
      items.push({ id: `project/${projectId}/service/${service}`, status: 'pass', detail: 'Enabled and declared' });
    } else {
      items.push({
        id: `project/${projectId}/service/${service}`,
        status: 'fail',
        detail:
          `${service} is enabled on ${projectId} and appears in no declared service surface. Functionality ` +
          'nobody declared has not been strictly defined.',
      });
    }
  }

  // The other direction. A definition that names services the estate does not run has drifted from
  // the thing it claims to define, which is worth saying even though it exposes nothing.
  const enabledSet = new Set(live);
  for (const service of [...declared].filter((s) => !enabledSet.has(s) && !BASELINE.has(s)).sort()) {
    items.push({
      id: `project/${projectId}/declared/${service}`,
      status: 'warn',
      detail: `${service} is declared for ${projectId} and is not enabled. The declaration describes an estate that is not running.`,
    });
  }

  return {
    items,
    population: {
      // Enumerated from the API plus the declaration's own unmatched entries, so neither side can
      // shrink the denominator by omission.
      expected: live.length + [...declared].filter((s) => !enabledSet.has(s) && !BASELINE.has(s)).length + unexamined.length,
      source_of_truth: 'serviceusage.googleapis.com services.list, filtered to state:ENABLED',
      enumerated_from:
        'The enabled-service list returned by the API, never the profile declaration — a declaration-derived ' +
        'denominator could not contain the undeclared service this check exists to find.',
    },
    unexamined,
    metric: { metric_id: 'gcp.services.within_declared_surface', value: passRate(items), unit: 'ratio' },
  };
}

async function fetchEnabledServices(projectId, token) {
  const services = await paginate(
    `${endpoint('serviceusage', `/projects/${projectId}/services`)}?filter=state:ENABLED&pageSize=200`,
    'services',
    { token }
  );
  return services.map((s) => s.config?.name ?? s.name?.split('/services/')[1]).filter(Boolean);
}

/** The intended surface for a project: its own declaration, else the profile-wide one. */
export function intendedFor(profile, projectId) {
  const project = (profile?.gcp?.projects ?? []).find((p) => p.id === projectId);
  return project?.intended_services ?? profile?.gcp?.intended_services ?? null;
}

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

  if (fixture) {
    const data = loadFixture(fixture, 'gcp-enabled-services');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'gcp-enabled-services', { projects: [data.project] }),
        ...gradeServiceSurface(data.enabled, {
          projectId: data.project,
          intended: data.intended,
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const intended = intendedFor(profile, project.id);

    // A project with no declared surface is not graded against an empty one. "Nothing is declared"
    // and "nothing should be enabled" are different claims, and inventing the second from the
    // first would fail every service on the project for a profile that simply has not been filled
    // in — a finding about the document, reported as a finding about the estate.
    if (!intended) {
      return {
        items: [],
        population: {
          expected: 1,
          source_of_truth: 'profile declaration',
          enumerated_from: 'The declared projects.',
        },
        unexamined: [
          {
            id: `project/${project.id}`,
            reason:
              'No intended_services declared for this project, so there is nothing to compare the enabled ' +
              'surface against. Declare it under gcp.projects[].intended_services or gcp.intended_services.',
          },
        ],
        metric: { metric_id: 'gcp.services.within_declared_surface', unit: 'ratio' },
      };
    }

    const enabled = await fetchEnabledServices(project.id, token);
    return gradeServiceSurface(enabled, { projectId: project.id, intended, unexamined: [] });
  });

  return [
    buildBundle({
      ...common,
      scope: { projects: projects.map((p) => p.id) },
      ...mergeGraded(parts, { unexamined }),
    }),
  ];
}
