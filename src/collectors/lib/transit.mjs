/**
 * Transport security, and the one number this repository cannot resolve from the ruleset.
 *
 * `KSI-SVC-SIN` carries sc-8 and sc-8.1 (transmission confidentiality and integrity) and sc-13
 * (cryptographic protection). Every other parameterized judgment in this harness is resolved from
 * the pinned FedRAMP ruleset, because a hand-copied rule is one that goes stale while reading as
 * current. **A TLS version floor is not available there.** The vendored `CTL` entry for SC-13 says
 * to follow the FedRAMP Cryptographic Module Use rules and carries no version number, so there is
 * nothing to pin to.
 *
 * The honest response is a declaration rather than a constant. The profile states the floor, it is
 * carried into the bundle's scope so evidence names the standard it was graded against, and the
 * route says plainly that the number came from the organization and not from the ruleset. Writing
 * `1.2` into this file would have been restating rule content the ruleset does not actually state
 * — the failure mode `AGENTS.md` names first.
 *
 * ## What a version floor does and does not establish
 *
 * It is necessary and not sufficient. sc-13 is about validated cryptographic modules, and a
 * listener negotiating TLS 1.2 with a non-validated module satisfies this check and not the
 * control. Nothing reachable from a describe call distinguishes the two, so the check grades the
 * half it can see and the route states the half it cannot.
 */

/** Parses "1.2", "TLS_1_2", "TLSv1.2" into a comparable [major, minor]. Null when unrecognised. */
export function parseTlsVersion(value) {
  if (value == null) return null;
  const match = /(\d)[._](\d)/.exec(String(value));
  return match ? [Number(match[1]), Number(match[2])] : null;
}

/** Negative when `a` is older than `b`. Null when either could not be parsed. */
export function compareTlsVersion(a, b) {
  const left = parseTlsVersion(a);
  const right = parseTlsVersion(b);
  if (!left || !right) return null;
  return left[0] - right[0] || left[1] - right[1];
}

/**
 * The floor the boundary declares, defaulting to 1.2.
 *
 * The default is a working one rather than a claim about what FedRAMP requires — a boundary that
 * declares nothing is graded against the number every current federal baseline has converged on,
 * and the bundle records which floor was used either way so the reader is never guessing.
 */
export function resolveMinTlsVersion(profile) {
  const declared = profile?.transit?.min_tls_version ?? null;
  const version = declared == null ? '1.2' : String(declared);
  if (!parseTlsVersion(version)) {
    throw new Error(
      `transit.min_tls_version "${declared}" is not a TLS version this harness can compare. Use a string like ` +
        '"1.2".'
    );
  }
  return { version, declared: declared != null };
}

/** Resources the profile declares as machine-to-machine paths, for one provider. */
export function resolveMutualAuthRequired(profile, provider) {
  const declared = profile?.transit?.mutual_auth_required?.[provider] ?? [];
  if (!Array.isArray(declared)) {
    throw new Error(`transit.mutual_auth_required.${provider} must be a list of resource names.`);
  }
  return declared;
}

/**
 * The TLS floor an AWS predefined security policy permits, read out of its name.
 *
 * AWS encodes the floor in the policy name and exposes no API that returns it as a field, so this
 * is the only way to grade a listener without a hand-maintained copy of every policy AWS has ever
 * published. The parse handles the two families that carry the version — `TLS-1-2-...`,
 * `TLS13-1-2-...`, `FS-1-2-Res-...` — and the legacy names that predate the convention.
 *
 * **An unrecognised name returns null and the caller must warn rather than pass.** AWS adds
 * policies; a check that resolved an unknown name to "probably fine" would go quietly wrong for
 * exactly the newest configurations, which is the wrong direction to be wrong in. A warning is a
 * prompt to extend this function, and it is visible in the report until somebody does.
 */
export function elbPolicyFloor(policyName) {
  if (!policyName) return null;

  // Named before AWS put the version in the name. All three permit TLS 1.0.
  if (/^ELBSecurityPolicy-(2015-05|2016-08|FS-2018-06|TLS-1-0-2015-04)$/.test(policyName)) return '1.0';

  const match = /-1-([0-3])(?:-|$)/.exec(policyName);
  return match ? `1.${match[1]}` : null;
}
