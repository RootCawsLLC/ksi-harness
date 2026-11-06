import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { REVIEW_FIELDS, reviewFingerprints } from '../catalog/fingerprint.mjs';
import { catalog, resolveIndicator } from '../catalog/ksi.mjs';
import { CHECK_IDS } from '../collectors/registry.mjs';
import { CONDITIONS } from './sufficiency.mjs';

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
export function validateRoutes({ routes = loadRoutes(), klass = 'c', fingerprints = reviewFingerprints() } = {}) {
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

    errors.push(...reviewErrors(id, route, fingerprints.get(id)));

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
        if (!route.cadence) errors.push(`${id}: coverage "automated" requires a cadence.`);

        if (!route.sufficiency) {
          errors.push(
            `${id}: coverage "automated" requires a "sufficiency" argument stating why the declared checks ` +
              `settle the indicator with nothing material left over. If that argument cannot be written, the ` +
              `honest level is "partial".`
          );
          break;
        }
        if (typeof route.sufficiency === 'string') {
          errors.push(
            `${id}: "sufficiency" must be a mapping with "holds_when" and "argument", not prose alone. ` +
              `Sufficiency is a property of a boundary rather than of an indicator — the same checks that ` +
              `settle a claim for one estate can leave a real gap in another — so the argument has to say ` +
              `which boundary it is an argument about.`
          );
          break;
        }
        if (!route.sufficiency.argument) {
          errors.push(`${id}: "sufficiency" requires an "argument". The prose is the bar; the condition only scopes it.`);
        }
        {
          const holds = route.sufficiency.holds_when;
          const kinds = holds ? Object.keys(holds) : [];
          if (!kinds.length) {
            errors.push(
              `${id}: "sufficiency.holds_when" must name the boundary the argument holds for. ` +
                `Known condition(s): ${CONDITIONS.join(', ')}.`
            );
          }
          for (const kind of kinds) {
            if (!CONDITIONS.includes(kind)) {
              errors.push(`${id}: unknown sufficiency condition "${kind}". Known: ${CONDITIONS.join(', ')}.`);
            }
          }
          if (holds?.providers_within && !holds.providers_within.length) {
            errors.push(`${id}: "providers_within" is empty, which no boundary satisfies except an empty one.`);
          }
        }
        // The same route has to be honest in both worlds. Where the condition does not hold it
        // resolves to `partial`, and a partial level with no stated gap reads as full coverage to
        // anyone scanning a table — so the gap is required here for exactly the reason it is there.
        if (!route.unautomated?.length) {
          errors.push(
            `${id}: coverage "automated" requires "unautomated" as well, naming what the checks fail to ` +
              `establish on a boundary the sufficiency condition does not cover. The route resolves to ` +
              `"partial" there, and would otherwise report a partial with no gap.`
          );
        }
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

const STALE = {
  text:
    'the indicator\'s statement, its cited terms, or what one of those terms means changed since this ' +
    'route was reviewed. The reasoning below was written against the old wording and may no longer hold.',
  controls:
    'the indicator\'s 800-53 mappings, or FedRAMP\'s CTL values for them, changed since this route was ' +
    'reviewed. Emitted SDR and OSCAL results credit this route\'s evidence to those controls, and any ' +
    'reasoning or Rev5 material that relies on their values may no longer hold.',
};

/**
 * The route stamp: which version of the indicator the route's reasoning was reviewed against.
 *
 * Required wherever the route claims something. An `unaddressed` route claims nothing a reword
 * could inflate, and the generated baseline is entirely unaddressed and must validate on day
 * one, so there the stamp is optional, but a stamp that is present is always checked: a stale
 * one is a stale claim of review, at any level.
 *
 * There is deliberately no way to renew a stamp in bulk. Renewing is the review; a command that
 * renewed everything would be the bypass this exists to prevent.
 */
function reviewErrors(id, route, current) {
  const stamp = route.reviewed;
  const renew = (fields) => `ksi routes reviewed ${id} --fields ${fields.join(',')}`;

  if (stamp === undefined) {
    if (route.coverage === 'unaddressed') return [];
    return [
      `${id}: coverage "${route.coverage}" requires "reviewed", the fingerprint of the indicator its reasoning ` +
        `was written against. Without it a reworded indicator cannot be told apart from the one the route ` +
        `describes. Read the route against \`ksi explain ${id}\`, then: ${renew(REVIEW_FIELDS)}`,
    ];
  }
  if (stamp === null || typeof stamp !== 'object' || Array.isArray(stamp)) {
    return [`${id}: "reviewed" must be a mapping of ${REVIEW_FIELDS.join(' and ')}. Write it with: ${renew(REVIEW_FIELDS)}`];
  }

  const errors = [];
  for (const key of Object.keys(stamp)) {
    if (!REVIEW_FIELDS.includes(key)) errors.push(`${id}: "reviewed.${key}" is not a review field (${REVIEW_FIELDS.join(', ')}).`);
  }
  for (const field of REVIEW_FIELDS) {
    if (!stamp[field]) {
      errors.push(`${id}: "reviewed.${field}" is missing, so this route was never reviewed against it. ${renew([field])}`);
    } else if (stamp[field] !== current[field]) {
      errors.push(
        `${id}: ${STALE[field]} (reviewed.${field} ${stamp[field]}, pinned ${current[field]}.) ` +
          `See what moved with \`ksi drift --base <ref before the bump>\`, re-read the route, then: ${renew([field])}`
      );
    }
  }
  return errors;
}

/**
 * Renews the review stamp on named routes, in place.
 *
 * An edit to the one line rather than a YAML round trip: re-serializing would rewrap every folded
 * argument in the file, and a diff that touches all the prose hides the one line a reviewer
 * should be looking at. The stamp is written as a flow mapping directly under the route key so
 * the edit stays a single line. The result is re-parsed and compared before anything is written,
 * so a layout this cannot handle fails loudly instead of writing a stamp it did not mean to.
 */
export function stampReviewed({ ids, fields, path = ROUTES_PATH, fingerprints = reviewFingerprints() }) {
  if (!ids.length) throw new Error('Name the routes you reviewed. There is no "all": renewing is the review.');
  if (!fields.length || fields.some((f) => !REVIEW_FIELDS.includes(f))) {
    throw new Error(`--fields must name one or more of ${REVIEW_FIELDS.join(', ')}.`);
  }

  const lines = readFileSync(path, 'utf8').split('\n');
  const expected = {};

  for (const id of ids) {
    const current = fingerprints.get(id);
    if (!current) throw new Error(`${id} is not an indicator in the pinned ruleset.`);

    const header = lines.findIndex((l) => l === `${id}:` || l.startsWith(`${id}: `) || l.startsWith(`${id}:\t`));
    if (header === -1) throw new Error(`${id} has no route in ${path}.`);
    let end = header + 1;
    while (end < lines.length && (lines[end] === '' || /^\s/.test(lines[end]))) end += 1;

    const existing = loadRoutes({ path })[id]?.reviewed;
    const at = lines.slice(header + 1, end).findIndex((l) => /^\s+reviewed:/.test(l));
    if (at !== -1 && !/^ {2}reviewed: \{[^}]*\}\s*$/.test(lines[header + 1 + at])) {
      throw new Error(`${id}: "reviewed" is not a one-line flow mapping; fix it by hand rather than have this guess.`);
    }

    const stamp = { ...(existing && typeof existing === 'object' ? existing : {}) };
    for (const field of fields) stamp[field] = current[field];
    // Quoted, because a hex digest is not always a YAML string: all digits reads as an integer
    // and `123e4567...` as a float, and a stamp parsed as a number never matches anything.
    const ordered = REVIEW_FIELDS.filter((f) => stamp[f]).map((f) => `${f}: "${stamp[f]}"`);
    const line = `  reviewed: { ${ordered.join(', ')} }`;

    if (at === -1) lines.splice(header + 1, 0, line);
    else lines[header + 1 + at] = line;
    expected[id] = Object.fromEntries(REVIEW_FIELDS.filter((f) => stamp[f]).map((f) => [f, stamp[f]]));
  }

  const text = lines.join('\n');
  const reparsed = parse(text);
  for (const [id, stamp] of Object.entries(expected)) {
    if (JSON.stringify(reparsed[id]?.reviewed) !== JSON.stringify(stamp)) {
      throw new Error(`${id}: the stamp did not land where intended; nothing was written.`);
    }
  }
  writeFileSync(path, text, 'utf8');
  return expected;
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
