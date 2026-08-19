/**
 * Whether an indicator's sufficiency argument holds for the boundary actually being assessed.
 *
 * `automated` means the declared checks settle the indicator with nothing material left over
 * (ADR 0002). Writing that argument turned out to be impossible for every indicator in the
 * catalog, and the reason was not that the evidence was too weak. It was that the question is
 * malformed: **sufficiency is a property of a boundary, and the routing map declared it as a
 * property of an indicator.**
 *
 * `KSI-CNA-DFP` is the worked example. "Functionality and privileges are strictly defined" is
 * settled for a boundary whose providers can enumerate their own service surface, because the
 * privilege half is already checked and the functionality half becomes a comparison between an
 * authoritative enumeration and a declared one. GCP exposes exactly that. AWS does not — services
 * are not "enabled" there — so the same checks that settle the claim for one estate leave a real
 * gap in another. Declared globally, the honest answer has to be `partial`, and it is `partial`
 * for everybody including the boundaries where it is demonstrably false.
 *
 * So an `automated` route declares the condition its argument depends on, and this resolves that
 * condition against the loaded profile. Three outcomes, and the third is the one that matters:
 *
 *   holds        the boundary satisfies the condition; the route is automated here
 *   fails        the boundary does not; the route falls back to partial, with its stated gap
 *   unresolved   no profile was supplied, so the condition could not be evaluated
 *
 * Unresolved falls back to partial too. A coverage report that credited automation it could not
 * confirm applies would be making exactly the unverified claim this repository exists to refuse —
 * the same rule as `ksi store` reporting UNVERIFIED rather than a guarantee it never checked.
 */

/** Condition kinds a sufficiency argument may depend on. Deliberately few. */
export const CONDITIONS = Object.freeze(['providers_within']);

/**
 * The providers a profile actually declares.
 *
 * From the declaration rather than from collected evidence, because the boundary is declared and
 * never discovered (ADR 0004). A provider the profile names but the run could not reach is a
 * population gap, which is a separate finding and must not quietly shrink the boundary instead.
 */
export function declaredProviders(profile) {
  if (!profile) return null;
  const providers = new Set();
  if (profile.aws?.accounts?.length || profile.aws?.account_id) providers.add('aws');
  if (profile.gcp?.projects?.length || profile.gcp?.organization_id) providers.add('gcp');
  if (profile.github?.repositories?.length || profile.github?.org) providers.add('github');
  return providers;
}

/**
 * Resolves one route's sufficiency condition against a profile.
 *
 * @returns {{ status: 'holds'|'fails'|'unresolved'|'not-applicable', detail: string|null,
 *             coverage: string }}
 *          `coverage` is the level the route resolves to here, which is what a report should show.
 */
export function resolveSufficiency(route, profile) {
  if (route?.coverage !== 'automated') {
    return { status: 'not-applicable', detail: null, coverage: route?.coverage ?? 'unaddressed' };
  }

  const condition = route.sufficiency?.holds_when;
  if (!condition) {
    // An unconditional claim of sufficiency. The validator refuses these, so reaching here means
    // the route bypassed validation; report it rather than honouring it.
    return {
      status: 'unresolved',
      detail: 'The route claims automated coverage without stating the boundary its argument holds for.',
      coverage: 'partial',
    };
  }

  const declared = declaredProviders(profile);
  if (!declared) {
    return {
      status: 'unresolved',
      detail:
        'No profile was supplied, so the boundary this argument depends on could not be checked. ' +
        'Reported as partial: coverage that cannot be confirmed to apply is not coverage. ' +
        'Pass --profile to resolve it.',
      coverage: 'partial',
    };
  }

  const allowed = new Set(condition.providers_within ?? []);
  const outside = [...declared].filter((p) => !allowed.has(p)).sort();

  if (outside.length) {
    return {
      status: 'fails',
      detail:
        `The argument holds for a boundary declaring only ${[...allowed].sort().join(', ')}; this one also ` +
        `declares ${outside.join(', ')}. Reported as partial, with the stated gap.`,
      coverage: 'partial',
    };
  }

  // An empty boundary satisfies "declares nothing outside the set" vacuously, and vacuous truth is
  // not evidence. The bundle contract already refuses a pass over zero decidable items; the same
  // reasoning applies one level up.
  if (declared.size === 0) {
    return {
      status: 'fails',
      detail:
        'The profile declares no provider at all, so the condition is satisfied only vacuously. ' +
        'An indicator evidenced over an empty boundary has not been evidenced.',
      coverage: 'partial',
    };
  }

  return {
    status: 'holds',
    detail: `The boundary declares only ${[...declared].sort().join(', ')}, which the argument covers.`,
    coverage: 'automated',
  };
}
