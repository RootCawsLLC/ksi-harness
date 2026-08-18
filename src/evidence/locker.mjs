import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { verifyIntegrity } from './bundle.mjs';

/**
 * Reading the evidence locker.
 *
 * The locker is a directory of `<check-id>/<YYYY-MM-DD>.json`, kept in git. Two consequences
 * that are the whole reason for the layout:
 *
 *  - Control state is diffable. `git log` over the locker is the change history of the
 *    security posture, which is the artifact continuous reporting actually needs and the one
 *    a screenshot-based programme can never produce.
 *  - History is the evidence of recurrence. Twenty-six indicators require activity that is
 *    "persistent" in FedRAMP's sense, and a run that happened is only demonstrable if the
 *    previous runs are still there. Retention is therefore a compliance property, not
 *    housekeeping.
 */

export function readLocker(dir) {
  if (!existsSync(dir)) return { dir, checks: new Map(), bundles: [], tampered: [] };

  const checks = new Map();
  const bundles = [];
  const tampered = [];

  for (const checkId of readdirSync(dir)) {
    const checkDir = join(dir, checkId);
    if (!statSync(checkDir).isDirectory()) continue;

    const history = [];
    for (const file of readdirSync(checkDir).sort()) {
      if (!file.endsWith('.json')) continue;
      const bundle = JSON.parse(readFileSync(join(checkDir, file), 'utf8'));
      const integrity = verifyIntegrity(bundle);
      if (!integrity.ok) {
        tampered.push({ check_id: checkId, file, ...integrity });
      }
      history.push(bundle);
      bundles.push(bundle);
    }
    if (history.length) {
      history.sort((a, b) => a.collected_at.localeCompare(b.collected_at));
      checks.set(checkId, { latest: history[history.length - 1], history });
    }
  }

  return { dir, checks, bundles, tampered };
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
