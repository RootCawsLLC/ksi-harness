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
 * An empty population returns 1 rather than 0 or NaN, and that is safe only because the
 * bundle contract now refuses to derive a `pass` from a population with nothing decidable in
 * it. The metric is a trend line; it is not the thing carrying the judgement.
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

/**
 * An explicit population member for a claim about the container rather than its contents.
 *
 * Any check whose subject is "the account has at least one X" needs one of these, because a
 * population of the Xs themselves is empty, complete and free of failures when there are no
 * Xs at all. The bundle contract catches that case now and caps it at `warn`, but a warning
 * that says "nothing was decidable" is a worse report than an item that says "this account
 * has no audit trail" — so the checks that can say the second thing should.
 */
export function accountItem(id, ok, detail, observed = undefined) {
  return { id, status: ok ? 'pass' : 'fail', detail, ...(observed ? { observed } : {}) };
}

/**
 * Merges graded results collected across several scopes — accounts, regions, repositories —
 * into the single population one bundle reports.
 *
 * Item ids are namespaced by scope when there is more than one, because `sg/sg-0123` means
 * two different resources in two different accounts and a locker that cannot tell them apart
 * will report a fixed finding that simply moved.
 *
 * `unexamined` accumulates across scopes and is what makes the population reconciliation
 * load-bearing here: a boundary of three accounts where one refuses the call yields
 * `expected` three and `examined` two, so the ceiling is `warn` and the report names the
 * account. Summing only what came back would report a clean pass over two-thirds of a
 * boundary.
 */
export function mergeGraded(parts, { sourceOfTruth, enumeratedFrom, metric = null, unexamined = [] }) {
  const namespaced = parts.length > 1;
  const items = [];
  const gaps = [...unexamined];
  let expected = 0;

  for (const { scope, graded } of parts) {
    for (const item of graded.items) {
      items.push(namespaced ? { ...item, id: `${scope}:${item.id}` } : item);
    }
    for (const gap of graded.population?.unexamined ?? []) {
      gaps.push(namespaced ? { ...gap, id: `${scope}:${gap.id}` } : gap);
    }
    expected += graded.population?.expected ?? graded.items.length;
  }

  // Scopes that were never reached contributed no items and no expected count of their own,
  // so each one adds exactly one to the denominator: the scope itself, unexamined.
  expected += unexamined.length;

  const resolved = {
    items,
    population: {
      expected,
      unexamined: gaps,
      source_of_truth: sourceOfTruth,
      enumerated_from: enumeratedFrom,
    },
  };

  if (metric) {
    resolved.metric =
      metric.unit === 'count'
        ? { ...metric, value: parts.reduce((sum, p) => sum + (p.graded.metric?.value ?? 0), 0) }
        : { ...metric, value: passRate(items) };
  }
  return resolved;
}
