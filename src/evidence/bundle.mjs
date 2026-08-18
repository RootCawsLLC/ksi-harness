import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Evidence bundle construction.
 *
 * The contract is carried over from RootCawsLLC/grc-wizard, where it was built against a
 * SOC 2 control set and verified in live runs. Three properties are enforced here rather
 * than left to each check, because a check that gets any of them wrong produces evidence
 * that looks fine and is not:
 *
 *  1. `result` is derived from `items`, never passed in. A check cannot assert a pass while
 *     carrying failing items.
 *  2. An incomplete population can never be a pass — the ceiling is `warn`. A claim
 *     verified over an unknown subset has not been verified.
 *  3. An unexplained population gap is refused outright.
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

function deriveResult(items, population, errors) {
  if (errors.length) return 'error';
  if (items.some((i) => i.status === 'fail')) return 'fail';
  if (!population.complete) return 'warn';
  if (items.some((i) => i.status === 'warn')) return 'warn';
  return 'pass';
}

const CHECK_ID = /^[a-z0-9]+(\.[a-z0-9-]+){2,}$/;
const KSI_ID = /^KSI-[A-Z]{3}-[A-Z]{3}$/;

/**
 * Builds a bundle conforming to schemas/evidence-bundle.schema.json.
 *
 * `collectedAt` is a required argument rather than defaulting to `Date.now()` on purpose:
 * the executing runner's clock is not an acceptable evidence timestamp, and making the
 * caller pass it keeps that decision visible instead of hiding it behind a default.
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

  const complete = population.examined === population.expected;
  if (!complete && !population.reconciliation) {
    throw new Error(
      `${checkId}: population is incomplete (${population.examined} of ${population.expected}) ` +
        `and no reconciliation was supplied. An unexplained gap is not evidence.`
    );
  }

  const resolvedPopulation = { ...population, complete };
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
  };

  const hash = createHash('sha256').update(JSON.stringify(canonicalize(bundle))).digest('hex');
  bundle.integrity = { content_sha256: hash, signed: false };
  return bundle;
}

/** One directory per check, one file per collection, named by UTC date. */
export function writeBundle(bundle, outDir) {
  const day = bundle.collected_at.slice(0, 10);
  const dir = join(outDir, bundle.check_id);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${day}.json`);
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
    population: { expected: 0, examined: 0, source_of_truth: 'none' },
    items: [],
    errors: [reason],
  });
}

/** Recomputes the content hash, so a stored bundle can be checked for tampering. */
export function verifyIntegrity(bundle) {
  const { integrity, ...rest } = bundle;
  const expected = createHash('sha256').update(JSON.stringify(canonicalize(rest))).digest('hex');
  return { ok: integrity?.content_sha256 === expected, expected, stored: integrity?.content_sha256 ?? null };
}
