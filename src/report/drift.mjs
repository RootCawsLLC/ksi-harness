import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ctlIndex, reviewFingerprints } from '../catalog/fingerprint.mjs';
import { normaliseControlId } from '../catalog/ksi.mjs';
import { loadRules } from '../catalog/rules.mjs';
import { loadRoutes } from '../routes/routes.mjs';

/**
 * Ruleset drift: what changed upstream, and which of our routes it invalidates.
 *
 * The problem this solves is specific. FedRAMP maintains the Consolidated Rules as a live
 * document — the pinned copy (see vendor/fedramp/PINNED.json) is already past the 25.11A KSI
 * standard that most published analysis cites — and a KSI catalog that silently tracks upstream
 * is worse than one that is pinned, because the routing reasoning was written against
 * particular indicator text. If a statement changes, the argument in the route for why the
 * automation is or is not sufficient may no longer hold, and nothing about a passing check
 * would reveal that.
 *
 * So: pin the ruleset, and make the bump a reviewable event that names the routes it puts in
 * question. A CI job runs this weekly against upstream. After `vendor:sync` the pin *is*
 * upstream and that comparison goes quiet, which is exactly when a reviewer needs it, so
 * `--base REF` compares the ruleset committed at a git ref against the current pin instead.
 * The gate that forces the review is the route stamp (src/catalog/fingerprint.mjs); this is the
 * report that says what to read.
 */

function indexIndicators(rules) {
  const review = reviewFingerprints(rules);
  const ctl = ctlIndex(rules);
  const out = new Map();
  for (const [theme, node] of Object.entries(rules.KSI ?? {})) {
    for (const [id, indicator] of Object.entries(node.indicators ?? {})) {
      out.set(id, {
        id,
        theme,
        name: indicator.name,
        statement: JSON.stringify(indicator.statement ?? null),
        varies: JSON.stringify(indicator.varies_by_class ?? null),
        controls: [...(indicator.controls ?? [])].sort(),
        terms: [...(indicator.terms ?? [])].sort(),
        review: review.get(id),
        parameters: Object.fromEntries(
          (indicator.controls ?? []).map((c) => [c, JSON.stringify(ctl.get(normaliseControlId(c)) ?? null)])
        ),
      });
    }
  }
  return out;
}

const RULES_URL = 'https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const RULES_PATH = 'vendor/fedramp/fedramp-consolidated-rules.json';

export async function fetchUpstreamRules(url = RULES_URL) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status} ${res.statusText}`);
  return res.json();
}

/**
 * Compares two rulesets and attributes each change to the routes it affects.
 *
 * A changed statement is reported as `review` rather than `error`: the text moved, and whether
 * that breaks the route's reasoning is a judgment. A new or removed indicator is structural
 * and reported as `error`, because route validation will already be failing.
 *
 * `stale` names the route stamp fields the change invalidates. It comes from the same
 * fingerprint the validator checks, not from the field list beside it, so the report cannot
 * call an indicator changed while the gate lets it through, or the reverse.
 */
export function diffRulesets({ from, to, routes = loadRoutes(), labels = { from: 'pinned', to: 'upstream' } }) {
  const before = indexIndicators(from);
  const after = indexIndicators(to);

  const added = [];
  const removed = [];
  const changed = [];

  for (const [id, next] of after) {
    const prev = before.get(id);
    if (!prev) {
      added.push({ id, theme: next.theme, name: next.name, severity: 'error', impact: 'No route exists for this indicator; route validation will fail until one is added.' });
      continue;
    }
    const fields = [];
    if (prev.statement !== next.statement) fields.push('statement');
    if (prev.varies !== next.varies) fields.push('class variance');
    if (prev.name !== next.name) fields.push('name');
    if (JSON.stringify(prev.controls) !== JSON.stringify(next.controls)) fields.push('800-53 mappings');
    if (JSON.stringify(prev.terms) !== JSON.stringify(next.terms)) fields.push('cited terms');
    const stale = Object.keys(next.review).filter((k) => prev.review[k] !== next.review[k]);
    // A term redefined or a CTL value moved changes nothing on the indicator itself, so the field
    // comparisons above cannot see it. The fingerprint can, and an indicator it calls stale must
    // never be skipped here: that is the report calling clean what the gate refuses.
    if (stale.includes('text') && !fields.some((f) => ['statement', 'class variance', 'cited terms'].includes(f))) {
      fields.push('term definitions');
    }
    // Only controls mapped on both sides: a newly mapped control's values arrive with the mapping
    // change, and reporting them twice is the noise the shared field exists to avoid.
    if (Object.keys(next.parameters).some((c) => c in prev.parameters && prev.parameters[c] !== next.parameters[c])) {
      fields.push('parameter values');
    }
    if (fields.length === 0) continue;

    const route = routes[id];
    changed.push({
      id,
      theme: next.theme,
      name: next.name,
      fields,
      stale,
      severity: 'review',
      route_coverage: route?.coverage ?? null,
      impact: route
        ? fields.includes('statement') || fields.includes('term definitions')
          ? `The indicator text, or what a term it cites means, changed and the route is "${route.coverage}". ` +
            'Re-read the sufficiency or gap reasoning: it was written against the previous wording.'
          : `Route is "${route.coverage}"; ${fields.join(' and ')} changed.`
        : 'No route for this indicator.',
      controls_added: next.controls.filter((c) => !prev.controls.includes(c)),
      controls_removed: prev.controls.filter((c) => !next.controls.includes(c)),
      terms_added: next.terms.filter((t) => !prev.terms.includes(t)),
      terms_removed: prev.terms.filter((t) => !next.terms.includes(t)),
    });
  }

  for (const [id, prev] of before) {
    if (after.has(id)) continue;
    removed.push({
      id,
      theme: prev.theme,
      name: prev.name,
      severity: 'error',
      impact: routes[id]
        ? 'A route still claims this indicator; route validation will fail until it is deleted.'
        : 'No route claimed it.',
    });
  }

  const themesBefore = new Set(Object.keys(from.KSI ?? {}));
  const themesAfter = new Set(Object.keys(to.KSI ?? {}));

  return {
    labels,
    from_version: from.info?.version ?? null,
    to_version: to.info?.version ?? null,
    version_changed: from.info?.version !== to.info?.version,
    counts: { before: before.size, after: after.size, added: added.length, removed: removed.length, changed: changed.length },
    themes: {
      added: [...themesAfter].filter((t) => !themesBefore.has(t)),
      removed: [...themesBefore].filter((t) => !themesAfter.has(t)),
    },
    added,
    removed,
    changed,
    ok: added.length === 0 && removed.length === 0 && changed.length === 0,
  };
}

/** The ruleset as committed at a git ref. A ref that does not resolve throws; it is not an empty ruleset. */
export function rulesAtRef(ref) {
  // A ref beginning with `-` would reach git as an option; `--end-of-options` already stops that,
  // and refusing it here makes the failure say what was wrong instead of git's own complaint.
  if (typeof ref !== 'string' || !ref || ref.startsWith('-')) {
    throw new Error(`--base needs a git ref such as main or a commit; got ${JSON.stringify(ref)}.`);
  }
  const text = execFileSync('git', ['show', '--end-of-options', `${ref}:${RULES_PATH}`], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return JSON.parse(text);
}

/**
 * Without `base`: pinned against upstream, the weekly question of whether to bump.
 * With `base`: the ruleset at that ref against the pin, the reviewer's question after bumping.
 */
export async function checkDrift({ routes = loadRoutes(), url, base } = {}) {
  if (base) {
    return diffRulesets({ from: rulesAtRef(base), to: loadRules(), routes, labels: { from: base, to: 'pinned' } });
  }
  return diffRulesets({ from: loadRules(), to: await fetchUpstreamRules(url), routes });
}

export function driftMarkdown(diff) {
  const lines = ['# FedRAMP ruleset drift', ''];
  lines.push(`${diff.labels.from} \`${diff.from_version}\` → ${diff.labels.to} \`${diff.to_version}\``);
  lines.push('');

  if (diff.ok) {
    lines.push(`No indicator changes. ${diff.counts.after} indicators, unchanged.`);
    return `${lines.join('\n')}\n`;
  }

  lines.push(
    `${diff.counts.added} added · ${diff.counts.removed} removed · ${diff.counts.changed} changed ` +
      `(${diff.counts.before} → ${diff.counts.after} indicators)`
  );
  lines.push('');
  if (diff.themes.added.length) lines.push(`New themes: ${diff.themes.added.join(', ')}`);
  if (diff.themes.removed.length) lines.push(`Removed themes: ${diff.themes.removed.join(', ')}`);
  if (diff.themes.added.length || diff.themes.removed.length) lines.push('');

  for (const [heading, rows] of [
    ['Added — a route is required before validation passes', diff.added],
    ['Removed — the route must be deleted', diff.removed],
    ['Changed — the route reasoning needs re-reading', diff.changed],
  ]) {
    if (!rows.length) continue;
    lines.push(`## ${heading}`);
    lines.push('');
    for (const row of rows) {
      lines.push(`- **${row.id}** (${row.name})${row.fields ? ` — ${row.fields.join(', ')}` : ''}`);
      lines.push(`  ${row.impact}`);
      if (row.controls_added?.length) lines.push(`  Controls added: ${row.controls_added.join(', ')}`);
      if (row.controls_removed?.length) lines.push(`  Controls removed: ${row.controls_removed.join(', ')}`);
      if (row.terms_added?.length) lines.push(`  Terms added: ${row.terms_added.join(', ')}`);
      if (row.terms_removed?.length) lines.push(`  Terms removed: ${row.terms_removed.join(', ')}`);
      if (row.stale?.length) lines.push(`  Route stamp to renew after review: ${row.stale.join(', ')}`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(
    diff.labels.to === 'pinned'
      ? 'To adopt: re-read each route above, then `ksi routes reviewed <ids> --fields <stale fields>` and `npm run routes:validate`.'
      : 'To adopt: `npm run vendor:sync`, then `ksi drift --base HEAD` and review each route it names.'
  );
  return `${lines.join('\n')}\n`;
}
