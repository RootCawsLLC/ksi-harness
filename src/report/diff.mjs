import { checkToIndicators } from '../routes/routes.mjs';
import { readLocker } from '../evidence/locker.mjs';

/**
 * What changed in the evidence between two points in the locker.
 *
 * The locker was built to be diffable and nothing read it as a series, so the one artifact
 * continuous monitoring is actually for — what regressed, what got fixed, when — had to be
 * reconstructed by eye from a directory of JSON. A coverage report answers "where does this
 * boundary stand"; this answers "what moved", which is the question an assessor asks on the
 * second visit and the one a weekly review exists to have an answer to.
 *
 * Item-level rather than result-level, deliberately. A check that was failing before and is
 * failing now shows no change in its result while the specific resource that failed may have
 * been fixed and a different one broken — which is two findings and one remediation, not a
 * flat line.
 */

/** The bundle in `history` closest to, but not after, `at`. Falls back to the earliest. */
function bundleAt(history, at) {
  if (!at) return null;
  const cutoff = Date.parse(at);
  const eligible = history.filter((b) => Date.parse(b.collected_at) <= cutoff);
  return eligible.length ? eligible[eligible.length - 1] : null;
}

function itemMap(bundle) {
  return new Map((bundle?.items ?? []).map((i) => [i.id, i]));
}

export function diffLocker(evidenceDir, { from = null, to = null } = {}) {
  const locker = readLocker(evidenceDir);
  const routes = checkToIndicators();
  const checks = [];

  for (const [checkId, { history }] of [...locker.checks].sort(([a], [b]) => a.localeCompare(b))) {
    const before = from ? bundleAt(history, from) : history[0];
    const after = to ? bundleAt(history, to) : history[history.length - 1];

    // One run is a collection, not a trend. Saying so is more useful than rendering a diff
    // against itself and letting the reader assume nothing changed.
    if (!before || !after || before === after) {
      checks.push({
        check_id: checkId,
        indicators: routes.get(checkId) ?? [],
        runs: history.length,
        comparable: false,
        detail:
          history.length < 2
            ? 'Only one collection in the locker, so there is no interval to compare across'
            : 'No two collections fall on either side of the requested window',
      });
      continue;
    }

    const beforeItems = itemMap(before);
    const afterItems = itemMap(after);
    const regressed = [];
    const fixed = [];
    const appeared = [];
    const disappeared = [];

    const rank = { pass: 0, 'not-applicable': 0, warn: 1, fail: 2 };
    for (const [id, item] of afterItems) {
      const was = beforeItems.get(id);
      if (!was) {
        if (rank[item.status] > 0) appeared.push({ id, status: item.status, detail: item.detail });
        continue;
      }
      if (rank[item.status] > rank[was.status]) {
        regressed.push({ id, from: was.status, to: item.status, detail: item.detail });
      } else if (rank[item.status] < rank[was.status]) {
        fixed.push({ id, from: was.status, to: item.status });
      }
    }
    for (const [id, item] of beforeItems) {
      if (!afterItems.has(id)) disappeared.push({ id, status: item.status });
    }

    checks.push({
      check_id: checkId,
      indicators: routes.get(checkId) ?? [],
      comparable: true,
      runs: history.length,
      from: { collected_at: before.collected_at, result: before.result, metric: before.metric?.value ?? null },
      to: { collected_at: after.collected_at, result: after.result, metric: after.metric?.value ?? null },
      result_changed: before.result !== after.result,
      // A population that was complete and is not any more is a regression in the evidence
      // rather than in the environment, and it is the one a result-only diff hides entirely:
      // the check can go on reporting the same verdict over a shrinking denominator.
      population: {
        from: { examined: before.population.examined, expected: before.population.expected, complete: before.population.complete },
        to: { examined: after.population.examined, expected: after.population.expected, complete: after.population.complete },
        completeness_lost: before.population.complete === true && after.population.complete === false,
      },
      regressed,
      fixed,
      appeared,
      disappeared,
    });
  }

  const comparable = checks.filter((c) => c.comparable);
  return {
    evidence_dir: evidenceDir,
    from,
    to,
    counts: {
      checks: checks.length,
      comparable: comparable.length,
      result_changed: comparable.filter((c) => c.result_changed).length,
      regressed_items: comparable.reduce((n, c) => n + c.regressed.length + c.appeared.length, 0),
      fixed_items: comparable.reduce((n, c) => n + c.fixed.length, 0),
      completeness_lost: comparable.filter((c) => c.population.completeness_lost).length,
    },
    checks,
  };
}

const arrow = (a, b) => (a === b ? a : `${a} → ${b}`);

export function diffMarkdown(diff) {
  const lines = ['# Evidence change report', ''];
  lines.push(
    `Locker \`${diff.evidence_dir}\` · ${diff.counts.comparable} of ${diff.counts.checks} check(s) had two ` +
      `collections to compare` +
      (diff.from || diff.to ? ` · window ${diff.from ?? 'first run'} to ${diff.to ?? 'latest run'}` : '')
  );
  lines.push('');

  if (diff.counts.comparable === 0) {
    lines.push(
      '> **Nothing to compare.** Every check has a single collection in the locker. A locker that is discarded ' +
        'between runs will always look like this, and a cadence claim tested against it can never fail — which ' +
        'is a property of the pipeline, not of the environment.'
    );
    lines.push('');
    return `${lines.join('\n')}\n`;
  }

  lines.push(
    `**${diff.counts.regressed_items} regression(s)** · **${diff.counts.fixed_items} fixed** · ` +
      `${diff.counts.result_changed} check result(s) changed · ${diff.counts.completeness_lost} lost population completeness`
  );
  lines.push('');

  for (const check of diff.checks) {
    if (!check.comparable) continue;
    const interesting =
      check.result_changed ||
      check.population.completeness_lost ||
      check.regressed.length ||
      check.fixed.length ||
      check.appeared.length ||
      check.disappeared.length;
    if (!interesting) continue;

    lines.push(`## \`${check.check_id}\``);
    lines.push('');
    lines.push(
      `${check.indicators.join(', ') || 'claimed by no route'} · ` +
        `${check.from.collected_at} → ${check.to.collected_at} · result ${arrow(check.from.result, check.to.result)}`
    );
    lines.push('');

    if (check.population.completeness_lost) {
      lines.push(
        `- **Population completeness lost** — ${check.population.from.examined}/${check.population.from.expected} ` +
          `became ${check.population.to.examined}/${check.population.to.expected}. The verdict below is over a ` +
          'smaller subject than it was.'
      );
    }
    for (const r of check.regressed) lines.push(`- **Regressed** \`${r.id}\` ${arrow(r.from, r.to)} — ${r.detail ?? ''}`);
    for (const a of check.appeared) lines.push(`- **New finding** \`${a.id}\` (${a.status}) — ${a.detail ?? ''}`);
    for (const f of check.fixed) lines.push(`- Fixed \`${f.id}\` ${arrow(f.from, f.to)}`);
    for (const d of check.disappeared) lines.push(`- Gone from the population \`${d.id}\` (was ${d.status})`);
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

/** Terminal summary. */
export function diffText(diff) {
  const c = diff.counts;
  if (c.comparable === 0) {
    return `No check in ${diff.evidence_dir} has two collections to compare. Nothing has been observed to change.`;
  }
  return [
    `${c.comparable} of ${c.checks} check(s) compared`,
    `regressions   ${String(c.regressed_items).padStart(3)}`,
    `fixed         ${String(c.fixed_items).padStart(3)}`,
    `result moved  ${String(c.result_changed).padStart(3)}`,
    `completeness lost ${c.completeness_lost}`,
  ].join('\n');
}
