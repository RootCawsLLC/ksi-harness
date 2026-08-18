import { alertable, fingerprint } from '../../scripts/ccm-issue.mjs';

/**
 * What a monitoring run has to say, and whether it is worth saying.
 *
 * The escalation this repository already had was sound in the part that is usually wrong: it
 * narrows to controls that *ran and failed* rather than everything the report lists, and it
 * suppresses repeats by fingerprinting the finding set. Both of those survive here unchanged,
 * because the failure mode they avoid — a daily message that is 90% "still not collected" —
 * is the one that gets a channel muted, after which the alerting is decorative.
 *
 * What it could not do was say *what changed*. "The set of failing controls changed" is true
 * and nearly useless: the reader still has to diff two tables by eye to find the one control
 * that started failing. `ksi diff` already computes exactly that, so a notification is built
 * from both — the current findings for authority, the diff for narrative.
 *
 * The rule this module exists to enforce: **notify on transition, not on state.** A control
 * that has been failing for forty days is not forty pieces of news. It is one piece of news
 * and thirty-nine reasons to stop reading.
 */

export const SEVERITY = Object.freeze({
  FAILING: 'failing',
  RECOVERED: 'recovered',
  CLEAN: 'clean',
});

/**
 * Which indicators newly acquired a failing check, and which lost their last one.
 *
 * Derived from the locker diff rather than from a stored copy of the previous report, so no
 * additional state has to be kept correct. A check whose result moved is mapped back to the
 * indicators that claim it.
 */
export function transitions(diff, indicatorsByCheck) {
  const opened = new Map();
  const closed = new Map();

  for (const check of diff?.checks ?? []) {
    if (!check.comparable || !check.result_changed) continue;
    const indicators = indicatorsByCheck.get(check.check_id) ?? [];
    const became = check.to?.result;
    const was = check.from?.result;

    for (const indicator of indicators) {
      if (became === 'fail' && was !== 'fail') opened.set(indicator, check.check_id);
      if (was === 'fail' && became !== 'fail') closed.set(indicator, check.check_id);
    }
  }
  return { opened, closed };
}

/**
 * Builds the notification, and decides whether there is anything to deliver.
 *
 * `changed` is the field a stateless sink keys on. A stateful sink — one that owns a living
 * issue it can update in place — additionally compares the fingerprint, because it has to
 * reconcile with whatever it left behind last time.
 */
export function buildNotification({
  findings = [],
  diff = null,
  indicatorsByCheck = new Map(),
  mode = 'unknown',
  profile = 'unknown',
  runUrl = null,
  generatedAt = null,
} = {}) {
  const open = alertable(findings);
  const { opened, closed } = transitions(diff, indicatorsByCheck);

  const severity = open.length > 0 ? SEVERITY.FAILING : closed.size > 0 ? SEVERITY.RECOVERED : SEVERITY.CLEAN;

  // Something transitioned, in either direction. A run where nothing moved has nothing to
  // report however many controls are failing — those were reported when they started failing.
  const changed = opened.size > 0 || closed.size > 0;

  const title =
    severity === SEVERITY.FAILING
      ? `${open.length} control(s) failing`
      : severity === SEVERITY.RECOVERED
        ? `${closed.size} control(s) recovered`
        : 'No failing controls';

  const lines = [];
  if (opened.size) {
    lines.push('Newly failing:');
    for (const [indicator, checkId] of opened) lines.push(`  ${indicator} — ${checkId} started failing`);
  }
  if (closed.size) {
    lines.push('Recovered:');
    for (const [indicator, checkId] of closed) lines.push(`  ${indicator} — ${checkId} now passes`);
  }
  const continuing = open.filter((f) => !opened.has(f.indicator));
  if (continuing.length) {
    lines.push(
      `Still failing (reported when they started): ${continuing.map((f) => f.indicator).join(', ')}`
    );
  }

  return {
    severity,
    changed,
    fingerprint: fingerprint(findings),
    title,
    summary: lines.join('\n') || 'Nothing changed since the previous collection.',
    counts: { failing: open.length, opened: opened.size, closed: closed.size },
    opened: [...opened].map(([indicator, check]) => ({ indicator, check })),
    closed: [...closed].map(([indicator, check]) => ({ indicator, check })),
    findings: open,
    context: { mode, profile, runUrl, generatedAt },
  };
}
