import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import { verifyChain, verifyIntegrity } from './bundle.mjs';

/**
 * Reading the evidence locker.
 *
 * The locker is a directory of `<check-id>/<timestamp>-<hash8>.json`, persisted between
 * runs. Two consequences that are the whole reason for the layout:
 *
 *  - Control state is diffable. A `git log` over the locker, or `ksi diff` over two of its
 *    points, is the change history of the security posture — the artifact continuous
 *    reporting actually needs and the one a screenshot-based programme can never produce.
 *  - History is the evidence of recurrence. Twenty-six indicators require activity that is
 *    "persistent" in FedRAMP's sense, and a run that happened is only demonstrable if the
 *    previous runs are still there. Retention is therefore a compliance property, not
 *    housekeeping, and a pipeline that starts from an empty locker every morning cannot
 *    evidence a cadence no matter how reliably it runs. See the persistence steps in
 *    ccm.yml, which exist for exactly this reason.
 */

export function readLocker(dir) {
  if (!existsSync(dir)) {
    return { dir, checks: new Map(), bundles: [], tampered: [], unreadable: [], chains: new Map() };
  }

  const checks = new Map();
  const bundles = [];
  const tampered = [];
  const unreadable = [];
  const chains = new Map();

  for (const checkId of readdirSync(dir)) {
    const checkDir = join(dir, checkId);
    if (!existsSync(checkDir) || !statSync(checkDir).isDirectory()) continue;

    const history = [];
    for (const file of readdirSync(checkDir).sort()) {
      if (!file.endsWith('.json')) continue;
      let bundle;
      try {
        bundle = JSON.parse(readFileSync(join(checkDir, file), 'utf8'));
      } catch (err) {
        // A bundle that will not parse is reported, not thrown. One corrupt file used to
        // take down the whole report, which meant the failure mode of a truncated write was
        // "no coverage report at all" rather than "one check is unreadable".
        unreadable.push({ check_id: checkId, file, error: err.message });
        continue;
      }
      const integrity = verifyIntegrity(bundle);
      if (!integrity.ok) tampered.push({ check_id: checkId, file, ...integrity });
      history.push(bundle);
      bundles.push(bundle);
    }

    if (history.length) {
      history.sort((a, b) => a.collected_at.localeCompare(b.collected_at));
      checks.set(checkId, { latest: history[history.length - 1], history });
      chains.set(checkId, verifyChain(history));
    }
  }

  return { dir, checks, bundles, tampered, unreadable, chains };
}

/** The content hash of the most recent bundle for each check, for chaining the next one onto. */
export function chainHeads(dir) {
  const heads = new Map();
  const locker = readLocker(dir);
  for (const [checkId, { history }] of locker.checks) {
    const latest = history[history.length - 1];
    heads.set(checkId, { hash: latest.integrity?.content_sha256 ?? null, index: (latest.chain?.index ?? 0) + 1 });
  }
  return heads;
}

/** Every chain break in the locker, flattened for reporting. */
export function chainBreaks(locker) {
  const out = [];
  for (const [checkId, chain] of locker.chains ?? []) {
    for (const brk of chain.breaks) out.push({ check_id: checkId, ...brk });
  }
  return out;
}

/**
 * Writes a manifest naming every bundle in the locker and each check's chain head.
 *
 * This is what makes the chain worth having. A chain proves internal consistency, and an
 * attacker who rewrites every bundle from the edit forward produces a consistent chain with
 * a different head. The manifest pins the heads at a point in time so that rewrite is
 * detectable, and the manifest itself is signed outside this process — keyless cosign in
 * ccm.yml — because a signature this code could forge would prove nothing about this code.
 */
export function computeManifest(dir, { generatedAt, runUri = null } = {}) {
  const locker = readLocker(dir);
  const entries = [];

  for (const [checkId, { history }] of [...locker.checks].sort(([a], [b]) => a.localeCompare(b))) {
    const chain = locker.chains.get(checkId);
    entries.push({
      check_id: checkId,
      runs: history.length,
      first_collected_at: history[0].collected_at,
      last_collected_at: history[history.length - 1].collected_at,
      chain_head_sha256: chain.head,
      chain_ok: chain.ok,
      bundles: history.map((b) => ({ collected_at: b.collected_at, content_sha256: b.integrity?.content_sha256 ?? null })),
    });
  }

  const manifest = {
    schema: 'ksi-harness/evidence-manifest/1',
    generated_at: generatedAt ?? new Date().toISOString(),
    run_uri: runUri,
    locker: dir,
    bundle_count: locker.bundles.length,
    unreadable: locker.unreadable,
    tampered: locker.tampered.map((t) => ({ check_id: t.check_id, file: t.file })),
    checks: entries,
  };
  // A digest over the entries so a verifier has one value to compare rather than a tree.
  manifest.root_sha256 = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
  return manifest;
}

/**
 * Computes the manifest and writes it into the locker.
 *
 * Kept separate from `computeManifest` because verification must not write. A verifier that
 * regenerated the manifest in place would overwrite the very artifact it was asked to check,
 * so the second run of `ksi verify` would compare the locker against a manifest the first run
 * had already replaced — and would agree with itself no matter what had happened in between.
 */
export function writeManifest(dir, options = {}) {
  const manifest = computeManifest(dir, options);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'MANIFEST.json');
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { path, manifest };
}

/**
 * Observed collection interval, in days, from the run history.
 *
 * The median rather than the mean, because one long gap — a holiday, an outage, a
 * credentials expiry — should not be able to make a daily job look weekly, nor a burst of
 * catch-up runs make a weekly job look daily. Fewer than two runs yields null: a single
 * bundle is a collection, not a cadence, and claiming otherwise from one data point is the
 * error this function exists to avoid.
 */
export function observedIntervalDays(history) {
  if (!history || history.length < 2) return null;
  const times = history.map((b) => Date.parse(b.collected_at)).sort((a, b) => a - b);
  const gaps = times.slice(1).map((t, i) => (t - times[i]) / 86400000);
  gaps.sort((a, b) => a - b);
  const mid = Math.floor(gaps.length / 2);
  return gaps.length % 2 ? gaps[mid] : (gaps[mid - 1] + gaps[mid]) / 2;
}

export function ageInDays(bundle, now = Date.now()) {
  return (now - Date.parse(bundle.collected_at)) / 86400000;
}
