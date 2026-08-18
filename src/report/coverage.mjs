import { openFindings } from '../evidence/state.mjs';

/**
 * The coverage report.
 *
 * Written to be read by someone sceptical. Two conventions do most of that work:
 *
 *  - Automated coverage and evidence outcome are separate columns. "Passing" and "sufficient"
 *    are different claims, and a single status column forces them into one — which is how a
 *    report comes to show green for an indicator whose automation was never argued to settle it.
 *  - Every gap is printed with its stated reason. The route file already requires one, so the
 *    report has no excuse to summarise a gap as a number.
 */

const COVERAGE_ORDER = ['automated', 'partial', 'manual', 'unaddressed', 'unrouted'];

const SYMBOL = {
  'satisfied-in-part': 'pass',
  failing: 'FAIL',
  degraded: 'warn',
  'no-evidence': 'none',
  'manual-attested': 'manual',
  'not-evidenced': '—',
};

export function coverageJson(state) {
  return {
    generated_at: state.generated_at,
    class: state.klass,
    ruleset: state.ruleset,
    counts: state.counts,
    routes_valid: state.routes_valid,
    route_errors: state.route_errors,
    evidence: state.evidence,
    // The same list the Markdown report prints under "Open findings". Carried in the JSON so a
    // scheduled monitoring run can act on it — raise an issue, fail a build — without parsing
    // prose. A finding that only exists in a rendered report is a finding nobody is paged for.
    findings: openFindings(state),
    indicators: state.indicators.map((i) => ({
      id: i.id,
      theme: i.theme,
      name: i.name,
      applicable: i.applicable,
      optional: i.optional,
      coverage: i.coverage,
      evidence_state: i.evidence_state,
      cadence: i.cadence,
      checks: i.checks.map((c) => ({
        check_id: c.check_id,
        present: c.present,
        result: c.result,
        age_days: Number.isFinite(c.age_days) ? Number(c.age_days.toFixed(2)) : null,
        run_count: c.run_count ?? 0,
        population: c.population ?? null,
        metric: c.metric,
        fixture: Boolean(c.fixture),
      })),
      controls: i.controls,
      unautomated: i.unautomated,
      reason: i.reason,
      next: i.next,
    })),
  };
}

function bar(counts, total) {
  return COVERAGE_ORDER.filter((k) => counts[k])
    .map((k) => `${k} ${counts[k]}`)
    .join('  ·  ')
    .concat(`  (of ${total} applicable)`);
}

export function coverageMarkdown(state) {
  const lines = [];
  const c = state.counts;

  lines.push(`# Key Security Indicator coverage`);
  lines.push('');
  lines.push(
    `Class **${state.klass.toUpperCase()}** · FedRAMP Consolidated Rules \`${state.ruleset.version}\` ` +
      `(updated ${state.ruleset.last_updated}, \`sha256:${state.ruleset.sha256.slice(0, 16)}\`) · ` +
      `generated ${state.generated_at}`
  );
  lines.push('');

  if (!state.routes_valid) {
    lines.push('> **The routing map does not validate.** The numbers below are not trustworthy until it does.');
    lines.push('>');
    for (const err of state.route_errors) lines.push(`> - ${err}`);
    lines.push('');
  }

  if (state.evidence.fixture_bundles > 0) {
    lines.push(
      `> **${state.evidence.fixture_bundles} of ${state.evidence.bundle_count} evidence bundles came from fixtures.** ` +
        'This report describes the harness, not a production environment.'
    );
    lines.push('');
  }
  if (state.evidence.tampered.length) {
    lines.push(`> **${state.evidence.tampered.length} bundle(s) failed content-hash verification.**`);
    lines.push('');
  }

  lines.push(`**Automated coverage** — ${bar(c.coverage, c.applicable)}`);
  lines.push('');
  lines.push(
    `**Evidence outcome** — ` +
      Object.entries(c.evidence_state)
        .filter(([, n]) => n)
        .map(([k, n]) => `${k} ${n}`)
        .join('  ·  ')
  );
  lines.push('');
  lines.push(
    `Nothing is reported as fully automated. That is a finding about this harness, not a rendering artifact: ` +
      `an indicator only reaches \`automated\` when someone writes the argument that its checks leave nothing ` +
      `material out, and no such argument has been written yet. See \`docs/adr/0002-coverage-honesty.md\`.`
  );
  lines.push('');

  lines.push('## By theme');
  lines.push('');
  lines.push('| Theme | Indicators | Automated or partial | Manual | Unaddressed |');
  lines.push('|---|---:|---:|---:|---:|');
  for (const theme of state.themes) {
    const inTheme = state.indicators.filter((i) => i.theme === theme.short && i.applicable);
    if (inTheme.length === 0) continue;
    lines.push(
      `| ${theme.short} — ${theme.name} | ${inTheme.length} ` +
        `| ${inTheme.filter((i) => ['automated', 'partial'].includes(i.coverage)).length} ` +
        `| ${inTheme.filter((i) => i.coverage === 'manual').length} ` +
        `| ${inTheme.filter((i) => i.coverage === 'unaddressed').length} |`
    );
  }
  lines.push('');

  lines.push('## Every applicable indicator');
  lines.push('');
  lines.push('| Indicator | Coverage | Evidence | Cadence | Checks | 800-53 |');
  lines.push('|---|---|---|---|---|---:|');
  for (const i of state.indicators) {
    if (!i.applicable) continue;
    const cadence = i.cadence?.claimed
      ? `${i.cadence.claimed}${i.cadence.met === false ? ' ✗' : i.cadence.met === true ? ' ✓' : ''}`
      : '—';
    const checks = i.checks.length ? i.checks.map((ch) => `\`${ch.check_id}\``).join('<br>') : '—';
    lines.push(
      `| **${i.id}**<br>${i.name}${i.optional ? ' *(optional at this class)*' : ''} ` +
        `| ${i.coverage} | ${SYMBOL[i.evidence_state] ?? i.evidence_state} | ${cadence} | ${checks} | ${i.controls.length} |`
    );
  }
  lines.push('');

  const findings = openFindings(state);
  if (findings.length) {
    lines.push('## Open findings');
    lines.push('');
    lines.push('Indicators with automated coverage whose evidence is failing, degraded or absent.');
    lines.push('');
    for (const finding of findings) {
      lines.push(
        `- **${finding.indicator}** (${finding.name}) — ${finding.evidence_state}: ` +
          finding.checks.map((ch) => `\`${ch.check_id}\` ${ch.result}${ch.failing_items ? ` (${ch.failing_items} failing)` : ''}`).join(', ')
      );
    }
    lines.push('');
  }

  const gaps = state.indicators.filter((i) => i.applicable && i.coverage === 'unaddressed');
  if (gaps.length) {
    lines.push('## Unaddressed, with reasons');
    lines.push('');
    for (const gap of gaps) {
      lines.push(`### ${gap.id} — ${gap.name}`);
      lines.push('');
      lines.push(gap.reason.trim().replace(/\s+/g, ' '));
      lines.push('');
      lines.push(`**Next:** ${gap.next.trim().replace(/\s+/g, ' ')}`);
      lines.push('');
    }
  }

  const partial = state.indicators.filter((i) => i.applicable && i.coverage === 'partial');
  if (partial.length) {
    lines.push('## What the automation does not establish');
    lines.push('');
    lines.push(
      'Each of these indicators has real automated evidence that does not settle the capability claim. ' +
        'Stated here so a reviewer does not have to find it.'
    );
    lines.push('');
    for (const i of partial) {
      lines.push(`### ${i.id} — ${i.name}`);
      lines.push('');
      for (const gap of i.unautomated) lines.push(`- ${gap.trim().replace(/\s+/g, ' ')}`);
      lines.push('');
    }
  }

  return `${lines.join('\n')}\n`;
}

/** Terminal summary for a CI log or a demo. */
export function coverageText(state) {
  const c = state.counts;
  const rows = [
    `FedRAMP Consolidated Rules ${state.ruleset.version}  ·  Class ${state.klass.toUpperCase()}`,
    `${c.applicable} applicable indicators of ${c.total} in the ruleset` +
      (c.optional ? `  (${c.optional} optional at this class)` : ''),
    '',
    `automated    ${String(c.coverage.automated).padStart(3)}`,
    `partial      ${String(c.coverage.partial).padStart(3)}`,
    `manual       ${String(c.coverage.manual).padStart(3)}`,
    `unaddressed  ${String(c.coverage.unaddressed).padStart(3)}`,
    '',
    `evidence: ${Object.entries(c.evidence_state)
      .filter(([, n]) => n)
      .map(([k, n]) => `${k} ${n}`)
      .join(', ')}`,
    `bundles: ${state.evidence.bundle_count}` +
      (state.evidence.fixture_bundles ? `  (${state.evidence.fixture_bundles} from fixtures — NOT REAL EVIDENCE)` : ''),
  ];
  if (state.counts.cadence_unmet) rows.push(`cadence unmet: ${state.counts.cadence_unmet}`);
  if (!state.routes_valid) rows.push(`ROUTES INVALID: ${state.route_errors.length} error(s)`);
  return rows.join('\n');
}
