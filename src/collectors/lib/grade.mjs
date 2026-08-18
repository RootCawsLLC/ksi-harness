/**
 * Grading helpers shared by every collector family.
 *
 * Kept separate from the provider libraries so a GitHub check and an AWS check compute a
 * coverage ratio the same way. Two collectors that each define "pass rate" slightly
 * differently produce metrics that cannot be compared or trended, which defeats the point of
 * having them.
 */

/**
 * Share of items that passed.
 *
 * `not-applicable` items leave the denominator entirely rather than counting as passes. A
 * repository with no workflows should not improve the pinning ratio, and a resource the check
 * does not apply to should not dilute a real failure.
 *
 * An empty population returns 1 rather than 0 or NaN. That is safe only because the bundle
 * contract handles emptiness separately: a check whose subject is "at least one X exists"
 * carries an explicit account-level item, so a metric of 1 over no items never travels
 * alongside a passing result derived from nothing.
 */
export function passRate(items) {
  const counted = items.filter((i) => i.status !== 'not-applicable');
  if (counted.length === 0) return 1;
  return counted.filter((i) => i.status === 'pass').length / counted.length;
}

/** Human-readable port range for a finding's detail text. */
export function describePorts(protocol, fromPort, toPort) {
  if (protocol === '-1' || protocol === -1) return 'all protocols and ports';
  const proto = String(protocol).toUpperCase();
  if (fromPort == null) return `${proto} (all ports)`;
  return fromPort === toPort ? `${proto}/${fromPort}` : `${proto}/${fromPort}-${toPort}`;
}
