import { writeBundle } from '../evidence/bundle.mjs';
import { chainHeads, writeManifest } from '../evidence/locker.mjs';
import { COLLECTORS, providerOf } from './registry.mjs';

/**
 * Runs every collector and writes the bundles.
 *
 * One collector failing does not stop the run: the remaining evidence is still worth having,
 * and a partial locker with a named failure is more useful than no locker. What the run must
 * never do is let a failure look like a success, so a collector that throws is reported in
 * `failures` and the caller decides the exit code.
 *
 * `collectedAt` is fixed once for the whole run rather than per collector, so every bundle in
 * one collection shares a timestamp and a reviewer can tell one collection from the next.
 *
 * Each bundle is chained onto the last one written for the same check, which is why the
 * existing locker is read before anything is collected. A run against an empty locker starts
 * fresh chains, and that is exactly what a pipeline which discards its locker between runs
 * does every time — see the persistence steps in ccm.yml.
 */
export async function runAll({
  profile,
  collectedAt = new Date().toISOString(),
  fixture,
  sourceCommit,
  outDir,
  only = null,
  log = () => {},
  manifest = true,
  runUri = null,
}) {
  const bundles = [];
  const failures = [];
  const written = [];
  const previousHashes = outDir ? chainHeads(outDir) : new Map();

  for (const collector of COLLECTORS) {
    const checks = collector.CHECKS.filter((c) => !only || only.includes(c.id) || only.includes(providerOf(c.id)));
    if (checks.length === 0) continue;

    try {
      const produced = await collector.collect({ profile, collectedAt, fixture, sourceCommit, previousHashes });
      const kept = produced.filter((b) => !only || only.includes(b.check_id) || only.includes(providerOf(b.check_id)));
      bundles.push(...kept);
      for (const bundle of kept) {
        const gap = bundle.population.complete
          ? ''
          : `  [${bundle.population.examined}/${bundle.population.expected} examined]`;
        log(`  ${bundle.result.padEnd(5)} ${bundle.check_id}  (${bundle.items.length} item(s))${gap}`);
        if (outDir) written.push(writeBundle(bundle, outDir));
      }
    } catch (err) {
      // The collector produced nothing, so there is no bundle to mark. Recording the failure
      // here keeps it visible; the coverage report reads a missing bundle as missing evidence
      // rather than as a pass, which is what makes this safe to continue past.
      failures.push({ collector: collector.PATH, checks: checks.map((c) => c.id), error: err.message });
      log(`  ERROR ${collector.PATH}: ${err.message}`);
    }
  }

  // The manifest pins each chain head at a point in time, so a locker rewritten end to end —
  // which produces a perfectly consistent chain — is still detectable against a manifest that
  // was signed when the old head was current.
  let manifestResult = null;
  if (outDir && manifest && bundles.length) {
    manifestResult = writeManifest(outDir, { generatedAt: collectedAt, runUri });
  }

  return { bundles, failures, written, collectedAt, manifest: manifestResult };
}
