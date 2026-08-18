import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Evidence bundle construction.
 *
 * The contract is carried over from RootCawsLLC/grc-wizard, where it was built against a
 * SOC 2 control set and verified in live runs. Five properties are enforced here rather
 * than left to each check, because a check that gets any of them wrong produces evidence
 * that looks fine and is not:
 *
 *  1. `result` is derived from `items`, never passed in. A check cannot assert a pass while
 *     carrying failing items.
 *  2. An incomplete population can never be a pass — the ceiling is `warn`. A claim
 *     verified over an unknown subset has not been verified.
 *  3. An unexplained population gap is refused outright.
 *  4. A population that decided nothing can never be a pass. Zero decidable items means the
 *     assertion was never tested, and "tested nothing" and "found nothing wrong" have to be
 *     different results or an empty listing reads as compliance.
 *  5. `examined` is computed from `items` rather than accepted from the caller, so the only
 *     number a collector supplies is `expected` — which has to come from an enumeration
 *     made before grading. A collector deriving both ends from the same array cannot ever
 *     produce a gap, and its reconciliation is decoration. `enumerated_from` names the
 *     independent source so that claim is reviewable rather than implied.
 *
 * What changed for FedRAMP 20x: the bundle is keyed by `check_id` and carries the set of
 * Key Security Indicators it contributes to, rather than a single control id. That is not
 * cosmetic. A KSI is a capability claim broad enough that no single check settles it, so
 * the many-to-many edge has to be first-class or the coverage report will overstate. The
 * indicator-level judgement is assembled in ../routes and ../evidence/state.mjs, and it is
 * deliberately not something a check can make about itself.
 */

/** Deterministic key order, so the hash of unchanged evidence does not change. */
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, k) => {
        if (value[k] !== undefined) acc[k] = canonicalize(value[k]);
        return acc;
      }, {});
  }
  return value;
}

/** Items that actually tested the assertion. A `not-applicable` item decided nothing. */
export function decidableItems(items) {
  return items.filter((i) => i.status !== 'not-applicable');
}

function deriveResult(items, population, errors) {
  if (errors.length) return 'error';
  if (items.some((i) => i.status === 'fail')) return 'fail';
  if (!population.complete) return 'warn';
  if (items.some((i) => i.status === 'warn')) return 'warn';
  // Invariant 4. A population containing nothing the check could decide has not evidenced
  // its assertion, and reporting `pass` is how an empty API listing — a scoping mistake, a
  // filtered query, a region with nothing in it, a token that can see no repositories —
  // becomes a green tick. The ceiling is `warn` rather than `error` because the collection
  // itself worked; what is missing is a subject, and the report says so plainly instead of
  // failing a build over it.
  if (population.decidable === 0) return 'warn';
  return 'pass';
}

const CHECK_ID = /^[a-z0-9]+(\.[a-z0-9-]+){2,}$/;
const KSI_ID = /^KSI-[A-Z]{3}-[A-Z]{3}$/;

/**
 * Resolves the population, which is the only place a completeness claim is made.
 *
 * `expected` is the caller's single input and has to come from an enumeration performed
 * before grading — the principals the API listed, the repositories the profile declares,
 * the files on disk. `examined` is computed here. When the two differ, either an itemised
 * `unexamined` list or a written `reconciliation` is required, and `unexamined` is
 * preferred: "three accounts denied the call" is a list rather than a sentence, and a list
 * can be counted, diffed and escalated.
 */
function resolvePopulation(checkId, population, items) {
  const examined = items.length;
  const unexamined = population.unexamined ?? [];

  if (!Array.isArray(unexamined)) {
    throw new Error(`${checkId}: population.unexamined must be an array of { id, reason }.`);
  }
  for (const entry of unexamined) {
    if (!entry?.id || !entry?.reason) {
      throw new Error(`${checkId}: every unexamined entry needs an id and a reason. An unnamed gap cannot be chased.`);
    }
  }

  // A collector that itemises what it could not reach should not also have to do the
  // arithmetic. Supplying both is allowed; disagreeing about them is not.
  const expected = population.expected ?? examined + unexamined.length;
  if (!Number.isInteger(expected) || expected < 0) {
    throw new Error(`${checkId}: population.expected must be a non-negative integer, got ${population.expected}.`);
  }
  if (expected < examined) {
    throw new Error(
      `${checkId}: population declares ${expected} expected but ${examined} were examined. A denominator ` +
        `smaller than its numerator means the enumeration and the grading disagree about the subject.`
    );
  }
  if (unexamined.length && expected !== examined + unexamined.length) {
    throw new Error(
      `${checkId}: population declares ${expected} expected with ${examined} examined and ` +
        `${unexamined.length} itemised as unexamined, which does not add up.`
    );
  }

  const complete = examined === expected;
  const reconciliation =
    population.reconciliation ??
    (unexamined.length
      ? `${unexamined.length} of ${expected} could not be examined: ` +
        unexamined.map((u) => `${u.id} (${u.reason})`).join('; ')
      : undefined);

  if (!complete && !reconciliation) {
    throw new Error(
      `${checkId}: population is incomplete (${examined} of ${expected}) ` +
        `and no reconciliation was supplied. An unexplained gap is not evidence.`
    );
  }

  return {
    expected,
    examined,
    complete,
    decidable: decidableItems(items).length,
    unexamined: unexamined.length ? unexamined : undefined,
    reconciliation,
    source_of_truth: population.source_of_truth,
    enumerated_from: population.enumerated_from,
  };
}

/**
 * Builds a bundle conforming to schemas/evidence-bundle.schema.json.
 *
 * `collectedAt` is a required argument rather than defaulting to `Date.now()` on purpose:
 * the executing runner's clock is not an acceptable evidence timestamp, and making the
 * caller pass it keeps that decision visible instead of hiding it behind a default.
 *
 * `previousHash` links this bundle to the last one written for the same check, and it sits
 * in the hashed body rather than in the `integrity` block. That placement is the point. A
 * hash stored beside the data it covers detects careless edits and nothing else, because
 * whoever edits the bundle recomputes it in the same motion. A chain means editing one
 * bundle invalidates every bundle after it, so concealing a change means rewriting the
 * locker all the way to a head that was published elsewhere — see `writeManifest` and the
 * signing step in ccm.yml.
 */
export function buildBundle({
  checkId,
  ksis,
  collectorPath,
  collectorVersion,
  sourceCommit,
  collectedAt,
  assertion,
  scope,
  population,
  items,
  metric,
  errors = [],
  previousHash = null,
  chainIndex = 0,
}) {
  if (!collectedAt) throw new Error('collectedAt is required; pass a timestamp from a trusted source');
  if (!CHECK_ID.test(checkId ?? '')) {
    throw new Error(`Invalid check id "${checkId}". Expected provider.domain.slug, e.g. aws.iam.mfa-coverage.`);
  }
  if (!Array.isArray(ksis) || ksis.length === 0) {
    throw new Error(
      `${checkId}: a check must declare at least one Key Security Indicator it contributes to. ` +
        `Evidence that maps to nothing cannot be reported and should not be collected.`
    );
  }
  for (const ksi of ksis) {
    if (!KSI_ID.test(ksi)) throw new Error(`${checkId}: "${ksi}" is not a KSI id (expected KSI-XXX-YYY).`);
  }

  const resolvedPopulation = resolvePopulation(checkId, population, items);
  const bundle = {
    check_id: checkId,
    ksis: [...ksis].sort(),
    collector: { path: collectorPath, version: collectorVersion, source_commit: sourceCommit },
    collected_at: collectedAt,
    scope,
    population: resolvedPopulation,
    result: deriveResult(items, resolvedPopulation, errors),
    assertion,
    items,
    metric,
    errors: errors.length ? errors : undefined,
    chain: { previous_sha256: previousHash, index: chainIndex },
  };

  const hash = createHash('sha256').update(JSON.stringify(canonicalize(bundle))).digest('hex');
  bundle.integrity = { content_sha256: hash, signed: false };
  return bundle;
}

/**
 * One directory per check, one file per collection.
 *
 * The filename carries the full timestamp and a hash prefix rather than the date alone.
 * Naming by date meant a second collection on the same day silently overwrote the first, so
 * a failing morning run disappeared behind a passing afternoon one with nothing left to
 * show it had happened — in a locker whose entire premise is that the history *is* the
 * evidence. Sub-daily collection is also the only way a `continuous` cadence claim can ever
 * be distinguished from a `daily` one.
 */
export function writeBundle(bundle, outDir) {
  const stamp = bundle.collected_at.replace(/[-:.]/g, '');
  const dir = join(outDir, bundle.check_id);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${stamp}-${bundle.integrity.content_sha256.slice(0, 8)}.json`);
  writeFileSync(path, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
  return path;
}

/**
 * A bundle for a check that has not been implemented for this environment.
 *
 * This exists so an unwritten check cannot be mistaken for a passing one. It reports
 * `error` with a zero-item population, which is exactly what it is: no evidence.
 * Generating a silent pass here would be the single most damaging bug this tool could have,
 * and it is the specific failure mode that makes a programme's 100% pass rate meaningless.
 */
export function unimplementedBundle({ checkId, ksis, collectorPath, collectedAt, assertion, reason }) {
  return buildBundle({
    checkId,
    ksis,
    collectorPath,
    collectorVersion: '0.0.0-unimplemented',
    collectedAt,
    assertion,
    scope: {},
    population: { expected: 0, source_of_truth: 'none', enumerated_from: 'none' },
    items: [],
    errors: [reason],
  });
}

/** Recomputes the content hash, so a stored bundle can be checked for accidental corruption. */
export function verifyIntegrity(bundle) {
  const { integrity, ...rest } = bundle;
  const expected = createHash('sha256').update(JSON.stringify(canonicalize(rest))).digest('hex');
  return { ok: integrity?.content_sha256 === expected, expected, stored: integrity?.content_sha256 ?? null };
}

/**
 * Verifies the hash chain over one check's history, oldest first.
 *
 * This is the thing `verifyIntegrity` on its own cannot do. An edited bundle whose hash was
 * recomputed passes integrity and breaks here, because the bundle after it still carries the
 * hash the edited one used to have. The chain is only ever as good as its head, which is why
 * the head goes into the manifest and the manifest is signed outside this process.
 */
export function verifyChain(history) {
  const breaks = [];
  let previous = null;
  for (const [index, bundle] of history.entries()) {
    const integrity = verifyIntegrity(bundle);
    if (!integrity.ok) {
      breaks.push({ index, collected_at: bundle.collected_at, kind: 'content', ...integrity });
    }
    const declared = bundle.chain?.previous_sha256 ?? null;
    if (index > 0 && declared !== previous) {
      breaks.push({ index, collected_at: bundle.collected_at, kind: 'chain', expected: previous, stored: declared });
    }
    previous = integrity.expected;
  }
  return { ok: breaks.length === 0, breaks, head: previous, length: history.length };
}
