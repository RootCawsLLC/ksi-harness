import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { catalog, resolveIndicator } from '../catalog/ksi.mjs';
import { CHECK_IDS } from '../collectors/registry.mjs';

/**
 * Loading and validation of the KSI routing map.
 *
 * The validator is the point of this module. A coverage report is only worth reading if the
 * declarations behind it cannot quietly drift into optimism, so the rules below are
 * deliberately strict about the two ways that happens: claiming a check that does not
 * exist, and claiming a coverage level without the argument that level requires.
 */

const ROUTES_PATH = join(dirname(fileURLToPath(import.meta.url)), 'routes.yaml');

export const COVERAGE_LEVELS = Object.freeze(['automated', 'partial', 'manual', 'unaddressed']);

/**
 * Cadence vocabulary, with the interval used to test a claim against evidence history.
 *
 * `null` means the cadence is event-driven and cannot be verified from a schedule — a
 * per-incident review is not late because no incident happened. Those routes are exempt
 * from the staleness check rather than silently passing it.
 */
export const CADENCES = Object.freeze({
  // `continuous` was an alias for `daily`, which made the two indistinguishable in both
  // directions: a claim of continuous collection was satisfied by a daily job, and the locker
  // could not have shown otherwise because bundles were named by date and a second collection
  // on the same day silently overwrote the first. Bundles now carry a full timestamp, so
  // sub-daily collection is observable and the distinction is worth drawing.
  continuous: 0.25,
  daily: 1,
  weekly: 7,
  monthly: 31,
  quarterly: 93,
  annual: 366,
  'per-incident': null,
  'per-change': null,
  'per-request': null,
  'ad-hoc': null,
});

export function loadRoutes({ path = ROUTES_PATH } = {}) {
  const parsed = parse(readFileSync(path, 'utf8')) ?? {};
  return Object.fromEntries(
    Object.entries(parsed).map(([id, route]) => [
      id,
      { id, checks: [], unautomated: [], ...route },
    ])
  );
}

/**
 * Validates the routing map against the catalog and the collector registry.
 *
 * Returns `{ ok, errors, warnings }` rather than throwing so the CLI can print every
 * problem at once; a validator that stops at the first error turns one fix into ten runs.
 */
export function validateRoutes({ routes = loadRoutes(), klass = 'c' } = {}) {
  const errors = [];
  const warnings = [];
  const indicators = catalog({ klass }).indicators;
  const applicable = indicators.filter((i) => i.applicable);
  const known = new Set(indicators.map((i) => i.id));

  for (const indicator of applicable) {
    if (!routes[indicator.id]) {
      errors.push(
        `${indicator.id} (${indicator.name}) applies at Class ${klass.toUpperCase()} but has no route. ` +
          `Every applicable indicator needs one, even if the route is "unaddressed" — an absent route ` +
          `is indistinguishable from a forgotten one.`
      );
    }
  }

  for (const [id, route] of Object.entries(routes)) {
    if (!known.has(id)) {
      errors.push(`Route "${id}" is not an indicator in the pinned ruleset. Check the id, or the ruleset moved.`);
      continue;
    }

    const indicator = resolveIndicator(id, { klass });
    if (!indicator.applicable) {
      warnings.push(`${id} has a route but does not apply at Class ${klass.toUpperCase()}; it will be ignored.`);
    }

    if (!COVERAGE_LEVELS.includes(route.coverage)) {
      errors.push(`${id}: coverage "${route.coverage}" is not one of ${COVERAGE_LEVELS.join(', ')}.`);
      continue;
    }

    if (route.cadence !== undefined && !(route.cadence in CADENCES)) {
      errors.push(`${id}: cadence "${route.cadence}" is not one of ${Object.keys(CADENCES).join(', ')}.`);
    }

    const hasChecks = route.checks.length > 0;

    for (const check of route.checks) {
      if (!CHECK_IDS.has(check)) {
        errors.push(
          `${id}: declares check "${check}", which no collector implements. This is the check that stops ` +
            `the coverage report from crediting automation that does not exist.`
        );
      }
    }

    switch (route.coverage) {
      case 'automated':
        if (!hasChecks) errors.push(`${id}: coverage "automated" with no checks.`);
        if (!route.sufficiency) {
          errors.push(
            `${id}: coverage "automated" requires a "sufficiency" argument stating why the declared checks ` +
              `settle the indicator with nothing material left over. If that argument cannot be written, the ` +
              `honest level is "partial".`
          );
        }
        if (!route.cadence) errors.push(`${id}: coverage "automated" requires a cadence.`);
        break;

      case 'partial':
        if (!hasChecks) {
          errors.push(`${id}: coverage "partial" with no checks. With nothing automated the level is "unaddressed".`);
        }
        if (!route.unautomated?.length) {
          errors.push(
            `${id}: coverage "partial" requires "unautomated" naming what the checks do not establish. ` +
              `Partial coverage without a stated gap reads as full coverage to anyone scanning the report.`
          );
        }
        if (!route.cadence) errors.push(`${id}: coverage "partial" requires a cadence.`);
        break;

      case 'manual':
        if (hasChecks) {
          errors.push(`${id}: coverage "manual" but checks are declared. Use "partial" when automation contributes.`);
        }
        for (const field of ['owner', 'artifact', 'why_not_automated']) {
          if (!route.manual_evidence?.[field]) {
            errors.push(
              `${id}: coverage "manual" requires manual_evidence.${field}. Manual is a decision that needs an ` +
                `owner and a reason, otherwise it is "unaddressed" wearing a better label.`
            );
          }
        }
        if (!route.cadence) errors.push(`${id}: coverage "manual" requires a cadence.`);
        break;

      case 'unaddressed':
        if (hasChecks) errors.push(`${id}: coverage "unaddressed" but checks are declared.`);
        if (!route.reason) errors.push(`${id}: coverage "unaddressed" requires a "reason".`);
        if (!route.next) {
          errors.push(`${id}: coverage "unaddressed" requires "next" — a gap with no named next step is a gap nobody owns.`);
        }
        break;
    }
  }

  // A check that no route claims is evidence being collected for nothing. Not an error —
  // it may be deliberately supporting — but it should never be silent.
  const claimed = new Set(Object.values(routes).flatMap((r) => r.checks));
  for (const check of CHECK_IDS) {
    if (!claimed.has(check)) warnings.push(`Check "${check}" is implemented but no route claims it.`);
  }

  return { ok: errors.length === 0, errors, warnings };
}

/** Reverse index: check id -> the indicators that claim it. */
export function checkToIndicators(routes = loadRoutes()) {
  const out = new Map();
  for (const route of Object.values(routes)) {
    for (const check of route.checks) {
      if (!out.has(check)) out.set(check, []);
      out.get(check).push(route.id);
    }
  }
  return out;
}
