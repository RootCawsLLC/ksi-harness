/**
 * What a profile's sections say about which collectors run, and how their absence is graded.
 *
 * A collector family whose section is missing does not run: there is nothing declared for it to
 * read, and running it only produced a refusal that failed the collection. What differs is what
 * the missing section means for grading, and that difference is the whole of this module.
 *
 *   SCOPED_PROVIDERS   Infrastructure a service may or may not run on. No section means the
 *                      provider is outside the boundary, so its checks leave each indicator's
 *                      check list. Left in, they read as absent, and absent outranks failing:
 *                      an AWS-only service could never show a failing AWS check, because the
 *                      absent GCP check beside it turned the indicator into `no-evidence`.
 *
 *   OPTIONAL_SOURCES   Evidence sources a service may not have, such as an identity provider or
 *                      an IaC policy gate. The indicators they serve still apply, so no section
 *                      means the checks stay in the indicator and stay absent, with the reason
 *                      named. A service with no IdP has not evidenced automated account
 *                      management, and must not look as if the question was out of scope.
 *
 *   ALWAYS_REQUIRED    Declarations every service must make. Their collectors always run, and
 *                      refuse a missing section.
 *
 * Presence of the key is the declaration, not presence of content inside it. `gcp:` with nothing
 * under it is someone saying the service runs on GCP and has not finished writing down where;
 * that collector runs and refuses the missing projects, which is the visible outcome it should
 * have. Reading an empty section as "not used" would let a half-written profile shrink the
 * boundary without anyone deciding to.
 *
 * Profile-defined rather than discovered (ADR 0004): a provider the profile names but the run
 * could not reach is a population gap, which is a separate finding and must not quietly shrink
 * the boundary instead.
 */
export const SCOPED_PROVIDERS = Object.freeze(['aws', 'gcp', 'github']);

/** Each optional source, keyed by its family and profile section, with what its absence means. */
export const OPTIONAL_SOURCES = Object.freeze({
  boundary: 'no product-mode boundary declared in the profile',
  idp: 'no identity provider declared in the profile',
  pipeline: 'no IaC policy gate declared in the profile',
});

/**
 * Listed so that every collector family is placed in exactly one group, and a test fails until a
 * new one is. A new infrastructure provider left unclassified would always be expected, which
 * re-creates the masking SCOPED_PROVIDERS exists to stop.
 */
export const ALWAYS_REQUIRED = Object.freeze(['thirdparty']);

/** The scoped providers a profile declares, or `null` when there is no profile at all. */
export function declaredProviders(profile) {
  if (!profile) return null;
  return new Set(SCOPED_PROVIDERS.filter((p) => Object.hasOwn(profile, p)));
}

/**
 * Whether a family is a provider outside the profile's boundary.
 *
 * `false` with no profile: nothing was declared, so nothing can be excluded, and every check is
 * expected. That keeps a profile-less coverage report as strict as it has always been.
 */
export function outOfScope(family, profile) {
  const declared = declaredProviders(profile);
  return Boolean(declared) && SCOPED_PROVIDERS.includes(family) && !declared.has(family);
}

/** Why an optional source's checks have no evidence, or `null` when it is declared or there is no profile. */
export function undeclaredSource(family, profile) {
  if (!profile || !Object.hasOwn(OPTIONAL_SOURCES, family) || Object.hasOwn(profile, family)) return null;
  return OPTIONAL_SOURCES[family];
}

/** Whether a family's collectors should run for this profile. */
export function collected(family, profile) {
  return !outOfScope(family, profile) && !undeclaredSource(family, profile);
}

/** The partition a report states, so a reader can see what was left out and not only what ran. */
export function providerScope(profile) {
  const declared = declaredProviders(profile);
  if (!declared) return null;
  return {
    in_scope: SCOPED_PROVIDERS.filter((p) => declared.has(p)),
    out_of_scope: SCOPED_PROVIDERS.filter((p) => !declared.has(p)),
    undeclared_sources: Object.keys(OPTIONAL_SOURCES).filter((family) => undeclaredSource(family, profile)),
  };
}
