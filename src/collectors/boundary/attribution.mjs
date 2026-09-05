import { loadBoundary, partition } from '../../boundary/boundary.mjs';
import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture } from '../lib/fixtures.mjs';
import { passRate } from '../lib/grade.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/boundary/attribution.mjs';

export const CHECKS = [
  {
    id: 'boundary.scope.attribution',
    ksis: ['KSI-PIY-GIV'],
    fixture: 'boundary-inventory',
    assertion:
      'Every enumerated resource carries a boundary selector placing it inside or outside the authorization ' +
      'boundary, and every capability the profile declares out of scope has a named attester.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades boundary attribution across the enumerated estate.
 *
 * This is the inventory KSI-PIY-GIV asks for — authoritative sources used to automatically
 * generate a real-time inventory of information resources — with the twist that an inventory
 * of a capability-scoped boundary has to answer *membership*, not just existence. Listing
 * every bucket in the organization is not an inventory of the authorization boundary; it is
 * an inventory of the organization, and the difference is the whole assessment surface.
 *
 * An unattributed resource fails. Not warns. A boundary drawn around a product mode is only
 * as good as the attribution on the resources that serve it, and a resource nobody has
 * placed is a resource that is in the boundary or out of it depending on who is asked — which
 * is the condition an authorization exists to remove. It is also the failure that grows
 * silently: nobody adds a label to a resource they forgot they created.
 */
export function gradeAttribution(resources, boundary, { unexamined = [] } = {}) {
  const parts = partition(resources, boundary);
  const items = [];

  // The declared capabilities come first, because they are the claim the resources are
  // evidence for. A boundary that names three capabilities and shows resources for two has
  // a gap that no per-resource item would surface.
  const represented = new Set(parts.in.map((r) => r.capability).filter(Boolean));
  for (const capability of boundary.inScope) {
    items.push(
      represented.has(capability.id)
        ? {
            id: `capability/${capability.id}`,
            status: 'pass',
            detail:
              `In scope${capability.condition ? ` (${capability.condition})` : ''}; ` +
              `${parts.in.filter((r) => r.capability === capability.id).length} attributed resource(s)`,
          }
        : {
            id: `capability/${capability.id}`,
            status: 'fail',
            detail:
              `Declared in scope${capability.condition ? ` (${capability.condition})` : ''} but no enumerated ` +
              `resource is attributed to it. Either the capability runs on resources nobody labeled, or the ` +
              `declaration names something the boundary does not actually contain.`,
          }
    );
  }

  // Out-of-scope capabilities cannot be verified from infrastructure, so they are recorded
  // with their attester rather than graded. Marking them not-applicable keeps them out of the
  // pass rate instead of inflating it with claims nothing tested.
  for (const capability of boundary.outOfScope) {
    items.push({
      id: `capability/${capability.id}`,
      status: 'not-applicable',
      detail:
        `Declared out of scope: ${capability.excluded_by} Attested by ${capability.attested_by}. ` +
        `No infrastructure signal can confirm a capability is disabled, so this is a stated exclusion ` +
        `rather than a tested one.`,
      observed: { excluded_by: capability.excluded_by, attested_by: capability.attested_by },
    });
  }

  for (const resource of parts.in) {
    items.push({
      id: `resource/${resource.id}`,
      status: 'pass',
      detail: `Attributed to the boundary${resource.capability ? ` under ${resource.capability}` : ''}`,
      observed: { selector: resource.attribution.value, capability: resource.capability ?? null },
    });
  }
  for (const resource of parts.out) {
    items.push({
      id: `resource/${resource.id}`,
      status: 'not-applicable',
      detail: 'Attributed outside the boundary; graded by nothing here and excluded from the assessment surface',
      observed: { selector: resource.attribution.value },
    });
  }
  for (const resource of parts.unattributed) {
    items.push({
      id: `resource/${resource.id}`,
      status: 'fail',
      detail:
        `Unattributed — ${resource.attribution.reason}. Its boundary membership depends on who is asked, ` +
        `which is the condition an authorization exists to remove.`,
      observed: { selector: resource.attribution.value, provider: resource.provider ?? null },
    });
  }

  return {
    items,
    population: {
      expected: boundary.inScope.length + boundary.outOfScope.length + resources.length + unexamined.length,
      unexamined,
      source_of_truth:
        'every resource enumerated by the collectors in this run, partitioned by the boundary selector the ' +
        'profile declares, plus one item per declared capability',
      enumerated_from:
        'the capabilities declared in boundary.in_scope and boundary.out_of_scope, plus the resource inventory ' +
        'returned by the provider APIs — counted before any attribution was resolved',
    },
    metric: { metric_id: 'boundary.attributed_resources', value: passRate(items), unit: 'ratio' },
  };
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

  if (fixture) {
    const data = loadFixture(fixture, 'boundary-inventory');
    const boundary = loadBoundary({ boundary: data.boundary });
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'boundary-inventory', { boundary: boundary.description }),
        ...gradeAttribution(data.resources, boundary, { unexamined: data.unexamined ?? [] }),
      }),
    ];
  }

  const boundary = loadBoundary(profile);
  if (!boundary) {
    throw new Error(
      'boundary.scope.attribution needs a boundary declaration in the profile. If the authorization boundary ' +
        'is a product mode rather than a set of accounts, it has to be declared before anything can be ' +
        'attributed to it. See examples/northwind.profile.yaml.'
    );
  }

  // The live inventory is assembled by the provider collectors and handed here through the
  // profile's declared resource sources. Until a provider-side inventory feed is wired, a
  // live run refuses rather than grading an empty estate as a clean boundary.
  const inventory = profile?.boundary?.inventory ?? null;
  if (!inventory) {
    throw new Error(
      'No boundary.inventory source is configured. Attributing a boundary requires an enumerated estate, and ' +
        'grading zero resources would report a perfectly attributed boundary containing nothing.'
    );
  }

  return [
    buildBundle({
      ...common,
      scope: { boundary: boundary.description, selector: boundary.selector },
      ...gradeAttribution(inventory, boundary),
    }),
  ];
}
