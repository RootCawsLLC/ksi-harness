/**
 * The authorization boundary, when it is a product mode rather than a network perimeter.
 *
 * Every scope construct in this harness so far has been an infrastructure one: accounts,
 * projects, regions, repositories. That works when the boundary is drawn around resources.
 * It does not work when the boundary is drawn around a *capability* — "text to speech,
 * speech to text and agents, in zero-retention mode only, with third-party model and
 * telephony integrations out of scope and off by default". That boundary moves when a
 * feature flag moves, and a harness that enumerates infrastructure will not notice.
 *
 * Two failure modes follow, and they pull in opposite directions. Enumerate everything and
 * the report describes systems outside the authorization, which overstates the assessment
 * surface and buries real findings in noise. Filter to a hand-maintained list and the report
 * silently omits whatever nobody remembered to add, which is the more dangerous one because
 * it looks clean.
 *
 * So membership is declared as a selector — a label on GCP, a tag on AWS — and every
 * enumerated resource is partitioned into exactly one of three states:
 *
 *   in            carries the selector with an in-scope value
 *   out           carries it with an out-of-scope value
 *   unattributed  carries neither
 *
 * The third state is the whole point. A resource nobody has attributed is not evidence of
 * anything, in either direction: it is a resource whose boundary membership is unknown, and
 * an authorization boundary with unknown members is not a boundary. It is graded as a
 * finding rather than quietly excluded, for the same reason an unexplained population gap
 * throws rather than shrinking the denominator.
 *
 * What this module deliberately cannot do is verify that an out-of-scope capability is
 * actually switched off. "Third-party LLM integrations are off by default" is a claim about
 * product configuration, not about infrastructure, and no cloud API answers it. Those
 * entries therefore require a named attester, which is the same discipline the `manual`
 * coverage level applies to indicators.
 */

export const ATTRIBUTION = Object.freeze(['in', 'out', 'unattributed']);

const DEFAULT_IN_VALUES = ['true', 'in', 'in-scope'];
const DEFAULT_OUT_VALUES = ['false', 'out', 'out-of-scope'];

/**
 * Reads and validates the boundary declaration from a profile.
 *
 * Refuses rather than defaulting when the declaration is incomplete. A boundary the harness
 * guessed at is worse than no boundary, because every population downstream inherits the
 * guess without anyone having decided it.
 */
export function loadBoundary(profile) {
  const declared = profile?.boundary;
  if (!declared) return null;

  if (!declared.description) {
    throw new Error(
      'boundary.description is required: state in prose what the authorization covers. Every artifact ' +
        'this harness emits quotes it, and a boundary nobody can describe is one nobody agreed.'
    );
  }
  const selector = declared.selector ?? {};
  if (!selector.gcp_label && !selector.aws_tag) {
    throw new Error(
      'boundary.selector needs at least one of gcp_label or aws_tag. Membership has to be readable from the ' +
        'resource itself; a boundary maintained as a list somewhere else drifts silently.'
    );
  }
  if (!Array.isArray(declared.in_scope) || declared.in_scope.length === 0) {
    throw new Error('boundary.in_scope must name at least one capability the authorization covers.');
  }

  for (const capability of declared.in_scope) {
    if (!capability.id || !capability.name) throw new Error('Every boundary.in_scope entry needs an id and a name.');
  }
  for (const capability of declared.out_of_scope ?? []) {
    if (!capability.id || !capability.name) throw new Error('Every boundary.out_of_scope entry needs an id and a name.');
    // Whether a capability is switched off is a product fact, not an infrastructure one, and
    // nothing here can read it. Naming who attests to it is the honest substitute.
    if (!capability.excluded_by || !capability.attested_by) {
      throw new Error(
        `boundary.out_of_scope "${capability.id}" needs excluded_by and attested_by. No cloud API can confirm ` +
          `that a capability is off by default, so an exclusion without a named attester is an assertion ` +
          `nobody owns.`
      );
    }
  }

  return {
    description: declared.description,
    selector: {
      gcpLabel: selector.gcp_label ?? null,
      awsTag: selector.aws_tag ?? null,
      inValues: (selector.in_values ?? DEFAULT_IN_VALUES).map((v) => String(v).toLowerCase()),
      outValues: (selector.out_values ?? DEFAULT_OUT_VALUES).map((v) => String(v).toLowerCase()),
    },
    inScope: declared.in_scope,
    outOfScope: declared.out_of_scope ?? [],
  };
}

/** The selector value carried by a resource, whichever provider it came from. */
export function selectorValue(resource, boundary) {
  const { gcpLabel, awsTag } = boundary.selector;
  const labels = resource.labels ?? {};
  const tags = resource.tags ?? {};
  const raw = (gcpLabel ? labels[gcpLabel] : undefined) ?? (awsTag ? tags[awsTag] : undefined);
  return raw === undefined || raw === null ? null : String(raw).toLowerCase();
}

/**
 * Places one resource in exactly one of the three attribution states.
 *
 * A value present but recognized as neither in nor out is `unattributed` rather than an
 * error: somebody has labeled the resource, they have simply used a value the profile does
 * not define, and that is the same "nobody has decided this" problem wearing a typo.
 */
export function attribute(resource, boundary) {
  const value = selectorValue(resource, boundary);
  if (value === null) return { state: 'unattributed', value: null, reason: 'carries no boundary selector' };
  if (boundary.selector.inValues.includes(value)) return { state: 'in', value };
  if (boundary.selector.outValues.includes(value)) return { state: 'out', value };
  return {
    state: 'unattributed',
    value,
    reason: `selector value "${value}" is not one the profile defines as in-scope or out-of-scope`,
  };
}

/** Partitions an enumerated resource set by attribution. */
export function partition(resources, boundary) {
  const out = { in: [], out: [], unattributed: [] };
  for (const resource of resources) {
    const verdict = attribute(resource, boundary);
    out[verdict.state].push({ ...resource, attribution: verdict });
  }
  return out;
}

/**
 * Filters a resource set to the boundary, for collectors that grade infrastructure.
 *
 * Returns the in-scope resources plus the unattributed ones, deliberately. Dropping the
 * unattributed set here would hide it, and the collector that enumerated them is often the
 * only thing that will ever see them — so they travel downstream and are reported by
 * `boundary.attribution` rather than being silently discarded at the filter.
 */
export function withinBoundary(resources, boundary) {
  if (!boundary) return { graded: resources, excluded: [], unattributed: [] };
  const parts = partition(resources, boundary);
  return { graded: [...parts.in, ...parts.unattributed], excluded: parts.out, unattributed: parts.unattributed };
}
