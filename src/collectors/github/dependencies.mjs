import { buildBundle } from '../../evidence/bundle.mjs';
import { api, fixtureScope, loadFixture, paginate, passRate, resolveRepos } from '../lib/github.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/github/dependencies.mjs';

export const CHECKS = [
  {
    id: 'github.supply-chain.dependency-alerts',
    ksis: ['KSI-SCR-MON'],
    fixture: 'github-dependency-alerts',
    assertion:
      'Every declared repository has automated upstream vulnerability monitoring enabled, and no open alert has ' +
      'been outstanding longer than the remediation window its severity declares.',
  },
];

/* ------------------------------------------------------------------- grading */

/** Days a severity may remain open before it is a finding rather than a queue. */
export const DEFAULT_SLA_DAYS = Object.freeze({ critical: 7, high: 30, medium: 90, low: 180 });

/**
 * Grades upstream vulnerability monitoring.
 *
 * KSI-SCR-MON asks whether third-party software resources are *automatically monitored* for
 * upstream vulnerabilities. So the first-order question is not how many alerts are open — it
 * is whether anything is watching at all, and a repository with alerting switched off and
 * zero alerts looks identical in a count to one with alerting on and nothing wrong. That is
 * why monitoring state is its own population member per repository and fails on its own
 * terms: no mechanism is a worse position than a known backlog, and it is the position that
 * produces reassuring numbers.
 *
 * Open alerts are then graded against the remediation window their severity declares in the
 * profile rather than against a fixed threshold. A critical open for two days and a critical
 * open for two hundred are not the same fact, and collapsing them into "3 open criticals"
 * loses the only part an assessor can act on.
 */
export function gradeDependencyAlerts(repos, { slaDays = DEFAULT_SLA_DAYS, now = Date.now(), unexamined = [] } = {}) {
  const items = [];

  for (const repo of repos) {
    if (repo.unverifiable) {
      items.push({
        id: `monitoring/${repo.repo}`,
        status: 'warn',
        detail: repo.unverifiable,
        observed: { reason: 'permission' },
      });
      continue;
    }

    items.push(
      repo.alerts_enabled
        ? {
            id: `monitoring/${repo.repo}`,
            status: 'pass',
            detail: 'Automated upstream vulnerability alerting is enabled',
          }
        : {
            id: `monitoring/${repo.repo}`,
            status: 'fail',
            detail:
              'Automated upstream vulnerability alerting is disabled. Nothing is watching this repository, so ' +
              'an empty alert list here is an absence of monitoring rather than an absence of vulnerabilities.',
          }
    );

    for (const alert of repo.alerts ?? []) {
      const severity = String(alert.severity ?? 'unknown').toLowerCase();
      const ageDays = (now - Date.parse(alert.created_at)) / 86400000;
      const window = slaDays[severity];
      const id = `alert/${repo.repo}#${alert.number}`;
      const what = `${severity} in ${alert.package} (${alert.advisory ?? 'no advisory id'}), open ${ageDays.toFixed(0)} day(s)`;

      if (window === undefined) {
        items.push({ id, status: 'warn', detail: `${what}; no remediation window is declared for "${severity}"` });
        continue;
      }
      items.push(
        ageDays > window
          ? {
              id,
              status: 'fail',
              detail: `${what}, past the ${window}-day window declared for ${severity}`,
              observed: { severity, age_days: Math.round(ageDays), window_days: window, package: alert.package },
            }
          : {
              id,
              status: 'warn',
              detail: `${what}, within the ${window}-day window declared for ${severity}`,
              observed: { severity, age_days: Math.round(ageDays), window_days: window, package: alert.package },
            }
      );
    }
  }

  const enumerated = repos.length + repos.reduce((n, r) => n + (r.alerts?.length ?? 0), 0);
  return {
    items,
    population: {
      expected: enumerated + unexamined.length,
      unexamined,
      source_of_truth:
        'the vulnerability-alerting state of each declared repository, plus every open dependency alert it reports',
      enumerated_from:
        'the repositories declared in the profile, counted before any alert listing was made; each repository ' +
        'contributes one monitoring-state member whether or not it reports any alert',
    },
    metric: { metric_id: 'github.supply_chain.alerts_within_window', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchAlertState(repos) {
  const out = [];
  const unexamined = [];

  for (const repo of repos) {
    const record = { repo: repo.name, alerts_enabled: false, alerts: [] };

    // 204 means enabled, 404 means disabled. Anything else is a fact about the token.
    const enabled = await api(`/repos/${repo.name}/vulnerability-alerts`);
    if (enabled.ok) record.alerts_enabled = true;
    else if (enabled.classification?.kind === 'absent') record.alerts_enabled = false;
    else {
      record.unverifiable = enabled.classification?.detail ?? `HTTP ${enabled.status}`;
      out.push(record);
      continue;
    }

    const alerts = await paginate(`/repos/${repo.name}/dependabot/alerts?state=open&per_page=100`);
    if (!alerts.ok) {
      // Reading alerts needs a scope reading the flag does not. Knowing monitoring is on
      // while being unable to read the queue is a real and reportable half-answer.
      record.unverifiable = `alerting is ${record.alerts_enabled ? 'enabled' : 'disabled'} but the alert list could not be read: ${
        alerts.classification?.detail ?? `HTTP ${alerts.status}`
      }`;
      out.push(record);
      continue;
    }

    record.alerts = alerts.items.map((a) => ({
      number: a.number,
      severity: a.security_advisory?.severity ?? a.security_vulnerability?.severity ?? 'unknown',
      package: a.dependency?.package?.name ?? 'unknown',
      advisory: a.security_advisory?.ghsa_id ?? null,
      created_at: a.created_at,
    }));
    out.push(record);
  }
  return { repos: out, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const check = CHECKS[0];
  const common = {
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
    previousHash: previousHashes.get(check.id)?.hash ?? null,
    chainIndex: previousHashes.get(check.id)?.index ?? 0,
  };
  const slaDays = { ...DEFAULT_SLA_DAYS, ...(profile?.github?.vulnerability_sla_days ?? {}) };

  if (fixture) {
    const data = loadFixture(fixture, 'github-dependency-alerts');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'github-dependency-alerts', { remediation_windows_days: slaDays }),
        ...gradeDependencyAlerts(data.repositories, {
          slaDays: data.sla_days ?? slaDays,
          now: Date.parse(collectedAt),
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const declared = resolveRepos(profile);
  const { repos, unexamined } = await fetchAlertState(declared);

  return [
    buildBundle({
      ...common,
      scope: { repositories: declared.map((r) => r.name), remediation_windows_days: slaDays },
      ...gradeDependencyAlerts(repos, { slaDays, now: Date.parse(collectedAt), unexamined }),
    }),
  ];
}
