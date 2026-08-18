import { createHash } from 'node:crypto';

import { loadRules } from '../catalog/rules.mjs';
import { loadRoutes } from '../routes/routes.mjs';

/**
 * Ruleset drift: what changed upstream, and which of our routes it invalidates.
 *
 * The problem this solves is specific. FedRAMP maintains the Consolidated Rules as a live
 * document — the pinned copy here is version 2026.07.14.01, already past the 25.11A KSI
 * standard that most published analysis cites — and a KSI catalog that silently tracks upstream
 * is worse than one that is pinned, because the routing reasoning was written against
 * particular indicator text. If a statement changes, the argument in the route for why the
 * automation is or is not sufficient may no longer hold, and nothing about a passing check
 * would reveal that.
 *
 * So: pin the ruleset, and make the bump a reviewable event that names the routes it puts in
 * question. A CI job runs this weekly.
 */

const hash = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);

function indexIndicators(rules) {
  const out = new Map();
  for (const [theme, node] of Object.entries(rules.KSI ?? {})) {
    for (const [id, indicator] of Object.entries(node.indicators ?? {})) {
      out.set(id, {
        id,
        theme,
        name: indicator.name,
        statement_hash: hash(indicator.statement ?? null),
        varies_hash: hash(indicator.varies_by_class ?? null),
        controls: [...(indicator.controls ?? [])].sort(),
        terms: [...(indicator.terms ?? [])].sort(),
      });
    }
  }
  return out;
}

const RULES_URL = 'https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json';

export async function fetchUpstreamRules(url = RULES_URL) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status} ${res.statusText}`);
  return res.json();
}

/**
 * Compares two rulesets and attributes each change to the routes it affects.
 *
 * A changed statement is reported as `review` rather than `error`: the text moved, and whether
 * that breaks the route's reasoning is a judgement. A new or removed indicator is structural
 * and reported as `error`, because route validation will already be failing.
 */
export function diffRulesets({ pinned, upstream, routes = loadRoutes() }) {
  const before = indexIndicators(pinned);
  const after = indexIndicators(upstream);

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
    if (prev.statement_hash !== next.statement_hash) fields.push('statement');
    if (prev.varies_hash !== next.varies_hash) fields.push('class variance');
    if (prev.name !== next.name) fields.push('name');
    if (JSON.stringify(prev.controls) !== JSON.stringify(next.controls)) fields.push('800-53 mappings');
    if (JSON.stringify(prev.terms) !== JSON.stringify(next.terms)) fields.push('cited terms');
    if (fields.length === 0) continue;

    const route = routes[id];
    changed.push({
      id,
      theme: next.theme,
      name: next.name,
      fields,
      severity: 'review',
      route_coverage: route?.coverage ?? null,
      impact: route
        ? fields.includes('statement')
          ? `The indicator text changed and the route is "${route.coverage}". Re-read the sufficiency or gap ` +
            'reasoning: it was written against the previous wording.'
          : `Route is "${route.coverage}"; ${fields.join(' and ')} changed.`
        : 'No route for this indicator.',
      controls_added: next.controls.filter((c) => !prev.controls.includes(c)),
      controls_removed: prev.controls.filter((c) => !next.controls.includes(c)),
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

  const themesBefore = new Set(Object.keys(pinned.KSI ?? {}));
  const themesAfter = new Set(Object.keys(upstream.KSI ?? {}));

  return {
    pinned_version: pinned.info?.version ?? null,
    upstream_version: upstream.info?.version ?? null,
    version_changed: pinned.info?.version !== upstream.info?.version,
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

export async function checkDrift({ routes = loadRoutes(), url } = {}) {
  const pinned = loadRules();
  const upstream = await fetchUpstreamRules(url);
  return diffRulesets({ pinned, upstream, routes });
}

export function driftMarkdown(diff) {
  const lines = ['# FedRAMP ruleset drift', ''];
  lines.push(`Pinned \`${diff.pinned_version}\` → upstream \`${diff.upstream_version}\``);
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
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push('To adopt: `npm run vendor:sync`, update `src/routes/routes.yaml`, then `npm run routes:validate`.');
  return `${lines.join('\n')}\n`;
}
