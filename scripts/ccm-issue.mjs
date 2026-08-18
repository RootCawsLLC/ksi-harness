// Escalation for a scheduled monitoring run: one living issue, opened when a control is
// demonstrably not working and closed when it recovers.
//
// Two bugs in the first version of this are worth naming, because both are the same shape as the
// checkov failure elsewhere in this repo — a control that reports success while doing nothing.
//
//   1. It ran `gh issue create --label ccm || true` against a repository with no `ccm` label. The
//      command failed, `|| true` swallowed it, and the step stayed green. The entire escalation
//      path was dead and the run looked fine.
//   2. The title carried the date, and nothing looked for an existing issue. A standing finding
//      would therefore open a new issue every single day — around 365 a year for one unresolved
//      problem, which is how alerting becomes something people filter to a folder.
//
// So: a stable title, a fingerprint of the finding set embedded in the body, and an update only
// when that fingerprint changes. Silence between changes is the goal, not a side effect.
//
// What gets escalated is narrower than what gets reported, deliberately. An indicator with no
// evidence is a real gap, but on a run whose profile declares no cloud scope it is simply a
// statement that the operator already knows — and burying one failing control under fourteen
// "never collected" lines is how a real finding gets missed. Absence stays visible in every
// coverage artifact; the issue is reserved for a check that ran and failed.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { argv, env } from 'node:process';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const TITLE = 'CCM: evidence does not support declared coverage';
export const LABEL = 'ccm';
const MARKER = 'ksi-fingerprint';

/** Findings carrying at least one check that ran and failed. */
export const alertable = (findings = []) =>
  findings.filter((finding) => (finding.checks ?? []).some((check) => check.result === 'fail'));

/**
 * A stable identity for the finding set.
 *
 * Deliberately excludes failing-item counts. A count that drifts as commits land would rewrite the
 * issue daily without telling anyone anything new, and the thing worth reacting to is a control
 * changing state, not a tally moving.
 */
export const fingerprint = (findings) => {
  const canonical = alertable(findings)
    .map((finding) => {
      const checks = (finding.checks ?? [])
        .filter((check) => check.result === 'fail')
        .map((check) => check.check_id)
        .sort();
      return `${finding.indicator}:${checks.join(',')}`;
    })
    .sort()
    .join('|');
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
};

export const readFingerprint = (body = '') =>
  new RegExp(`<!--\\s*${MARKER}:\\s*([0-9a-f]+)\\s*-->`).exec(body)?.[1] ?? null;

export const renderBody = ({ findings, mode, profile, runUrl, generatedAt }) => {
  const open = alertable(findings);
  const lines = [
    'A scheduled monitoring run found controls whose evidence no longer supports the coverage this',
    'repository declares for them.',
    '',
    `- **Collection mode:** ${mode}`,
    `- **Profile:** \`${profile}\``,
    generatedAt ? `- **Generated:** ${generatedAt}` : null,
    runUrl ? `- **Run:** ${runUrl}` : null,
    '',
    '## Failing controls',
    '',
    '| Indicator | Name | Evidence state | Failing checks |',
    '|---|---|---|---|',
  ].filter((line) => line !== null);

  for (const finding of open) {
    const checks = (finding.checks ?? [])
      .filter((check) => check.result === 'fail')
      .map((check) => `\`${check.check_id}\` (${check.failing_items} item(s))`)
      .join('<br>');
    lines.push(`| ${finding.indicator} | ${finding.name} | ${finding.evidence_state} | ${checks} |`);
  }

  lines.push(
    '',
    'Indicators with no evidence at all are not listed here. They are a coverage gap rather than a',
    'failing control, they are reported in full in the coverage artifact attached to the run, and',
    'listing them daily alongside real failures is how a real failure gets missed.',
    '',
    'This issue is updated in place when the set of failing controls changes, and closed',
    'automatically when the evidence supports the declared coverage again.',
    '',
    `<!-- ${MARKER}: ${fingerprint(findings)} -->`,
  );

  return lines.join('\n');
};

/**
 * What to do about the current findings, given the issue that already exists.
 *
 * Pure so the interesting cases are testable without a network: the recovery path in particular is
 * the one nobody exercises by hand, and an escalation that cannot stand down is only half a control.
 */
export const decide = ({ findings = [], existing = null }) => {
  const open = alertable(findings);

  if (open.length === 0) {
    return existing
      ? { action: 'close', reason: 'every previously failing control now has evidence supporting it' }
      : { action: 'none', reason: 'no failing controls, and no issue open' };
  }
  if (!existing) return { action: 'create', reason: `${open.length} failing control(s)` };

  const current = fingerprint(findings);
  return readFingerprint(existing.body) === current
    ? { action: 'none', reason: 'the same controls are still failing, and the issue is already open' }
    : { action: 'update', reason: 'the set of failing controls changed' };
};

/* --------------------------------------------------------------------------- command */

const gh = (args, { allowFailure = false } = {}) => {
  try {
    return execFileSync('gh', args, { encoding: 'utf8' });
  } catch (err) {
    if (allowFailure) return null;
    // Never swallowed. A monitoring run that cannot escalate has to fail loudly, or it becomes a
    // green tick asserting that nothing was wrong.
    throw new Error(`gh ${args.join(' ')} failed: ${err.stderr?.trim() || err.message}`);
  }
};

const ensureLabel = () => {
  const existing = gh(['label', 'list', '--json', 'name'], { allowFailure: true });
  const names = existing ? JSON.parse(existing).map((l) => l.name) : [];
  if (names.includes(LABEL)) return;
  gh(['label', 'create', LABEL, '--description', 'Raised by a scheduled control monitoring run', '--color', 'B60205']);
  console.log(`created the '${LABEL}' label`);
};

const findExisting = () => {
  const raw = gh(['issue', 'list', '--label', LABEL, '--state', 'open', '--json', 'number,body', '--limit', '1']);
  const [issue] = JSON.parse(raw || '[]');
  return issue ?? null;
};

const main = () => {
  const coveragePath = argv[2] ?? 'out/coverage.json';
  const coverage = JSON.parse(readFileSync(coveragePath, 'utf8'));
  const findings = coverage.findings ?? [];

  ensureLabel();
  const existing = findExisting();
  const { action, reason } = decide({ findings, existing });

  const body = renderBody({
    findings,
    mode: env.KSI_MODE ?? 'unknown',
    profile: env.KSI_PROFILE ?? 'unknown',
    runUrl: env.KSI_RUN_URL,
    generatedAt: coverage.generated_at,
  });

  console.log(`${alertable(findings).length} failing control(s) of ${findings.length} finding(s); ${action}: ${reason}`);

  if (action === 'create') {
    const url = gh(['issue', 'create', '--title', TITLE, '--body', body, '--label', LABEL]);
    console.log(`opened ${url.trim()}`);
  } else if (action === 'update') {
    gh(['issue', 'edit', String(existing.number), '--body', body]);
    gh(['issue', 'comment', String(existing.number), '--body', `The set of failing controls changed.\n\n${reason}.`]);
    console.log(`updated issue #${existing.number}`);
  } else if (action === 'close') {
    gh(['issue', 'close', String(existing.number), '--comment', `Closing: ${reason}.`]);
    console.log(`closed issue #${existing.number}`);
  }
};

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) main();
