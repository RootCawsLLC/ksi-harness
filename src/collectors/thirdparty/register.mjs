import { buildBundle } from '../../evidence/bundle.mjs';
import { api, resolveRepos } from '../lib/github.mjs';
import { fixtureScope, loadFixture } from '../lib/fixtures.mjs';
import { passRate } from '../lib/grade.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/thirdparty/register.mjs';

export const CHECKS = [
  {
    id: 'thirdparty.register.review',
    ksis: ['KSI-SCR-MIT'],
    fixture: 'thirdparty-register',
    assertion:
      'Every third-party dependency inside the assessment scope is declared with an owner and a current ' +
      'attestation, every non-certified one carries a resolution that has not gone stale, and every outbound ' +
      'integration observed in the estate corresponds to a declared entry.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades the third-party register, and — crucially — what the estate says back.
 *
 * A register check that only reads the register is close to tautological: it confirms that a
 * document says what it says. The finding that matters is the dependency nobody wrote down,
 * and that can only come from somewhere else. So the declared entries are reconciled against
 * outbound integrations actually observed — repository webhooks, whose destination hosts are
 * third parties receiving data by definition — and a destination matching no declared entry
 * is graded as an undeclared dependency rather than ignored.
 *
 * This is the same shape as the boundary attribution check: a declaration, an observation,
 * and the gap between them treated as the finding rather than as noise.
 *
 * The certified/non-certified split is the part with teeth for a FedRAMP package. A
 * non-certified dependency inside a boundary targeting certification is not automatically a
 * failure — it is a question, and it becomes a failure when nobody owns the answer. So an
 * entry with a stated resolution, a named owner and a target date in the future warns; one
 * whose date has passed, or that names no owner, fails. A resolution that has quietly gone
 * stale is exactly what surfaces late and expensively.
 */
export function gradeRegister(register, observed, { now = Date.now(), unexamined = [] } = {}) {
  const items = [];

  for (const entry of register) {
    const id = `dependency/${entry.name}`;

    if (!entry.owner) {
      items.push({
        id,
        status: 'fail',
        detail: `No owner. A dependency nobody owns is one nobody will answer for when an assessor asks.`,
      });
      continue;
    }

    if (entry.certified) {
      const attestedAt = entry.attestation?.date ? Date.parse(entry.attestation.date) : null;
      const refreshDays = entry.attestation?.refresh_days ?? 365;
      if (!attestedAt) {
        items.push({
          id,
          status: 'fail',
          detail: `Declared FedRAMP certified (${entry.fedramp_id ?? 'no id'}) with no attestation date, so nothing here says the authorization is current.`,
        });
        continue;
      }
      const ageDays = (now - attestedAt) / 86400000;
      items.push(
        ageDays > refreshDays
          ? {
              id,
              status: 'fail',
              detail: `Attestation is ${ageDays.toFixed(0)} days old against a ${refreshDays}-day refresh; a lapsed attestation is not evidence of a current authorization`,
              observed: { fedramp_id: entry.fedramp_id ?? null, age_days: Math.round(ageDays) },
            }
          : {
              id,
              status: 'pass',
              detail: `FedRAMP certified (${entry.fedramp_id ?? 'no id'}), attested ${entry.attestation.date}, owned by ${entry.owner}`,
              observed: { fedramp_id: entry.fedramp_id ?? null, age_days: Math.round(ageDays) },
            }
      );
      continue;
    }

    // Non-certified, inside a package targeting certification.
    const resolution = entry.resolution;
    if (!resolution?.plan) {
      items.push({
        id,
        status: 'fail',
        detail:
          `Not FedRAMP certified and no resolution is stated. Inside a boundary targeting certification this is ` +
          `a question somebody has to answer — move it in-boundary, move to a certified tier, or scope it out.`,
        observed: { provider: entry.provider, use_case: entry.use_case },
      });
      continue;
    }
    const target = resolution.target_date ? Date.parse(resolution.target_date) : null;
    if (!target) {
      items.push({
        id,
        status: 'fail',
        detail: `Not certified, resolution stated ("${resolution.plan}") but with no target date, so it cannot go overdue and will not be chased.`,
      });
      continue;
    }
    items.push(
      target < now
        ? {
            id,
            status: 'fail',
            detail: `Not certified; the resolution "${resolution.plan}" was due ${resolution.target_date} and has passed. Owned by ${entry.owner}.`,
            observed: { provider: entry.provider, target_date: resolution.target_date, overdue: true },
          }
        : {
            id,
            status: 'warn',
            detail: `Not certified, but owned by ${entry.owner} with "${resolution.plan}" due ${resolution.target_date}`,
            observed: { provider: entry.provider, target_date: resolution.target_date, overdue: false },
          }
    );
  }

  // The observed side. A destination the register does not mention is a third party
  // receiving data that nobody assessed.
  const declaredHosts = new Set(
    register.flatMap((e) => [e.name?.toLowerCase(), ...(e.hosts ?? []).map((h) => h.toLowerCase())]).filter(Boolean)
  );
  for (const integration of observed) {
    const host = String(integration.host ?? '').toLowerCase();
    const matched = [...declaredHosts].some((declared) => host === declared || host.endsWith(`.${declared}`) || host.includes(declared));
    items.push(
      matched
        ? {
            id: `integration/${integration.source}/${host}`,
            status: 'pass',
            detail: `Outbound integration to ${host}, which the register declares`,
          }
        : {
            id: `integration/${integration.source}/${host}`,
            status: 'fail',
            detail:
              `Outbound integration to ${host} from ${integration.source}, and no register entry mentions it. ` +
              `A third party receiving data that nobody assessed is the finding this reconciliation exists for.`,
            observed: integration,
          }
    );
  }

  return {
    items,
    population: {
      expected: register.length + observed.length + unexamined.length,
      unexamined,
      source_of_truth:
        'the third-party register declared in the profile, reconciled against outbound integrations observed in ' +
        'the estate',
      enumerated_from:
        'the register declared in the profile plus the integrations enumerated from the declared repositories, ' +
        'counted before either was graded — the register alone would only confirm that a document says what it says',
    },
    metric: { metric_id: 'thirdparty.declared_and_owned', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

/**
 * Outbound integrations observable with a repository-scoped token.
 *
 * Webhooks are the reachable surface: every one names an external host receiving repository
 * events, which makes it a third-party data flow by definition. Installed GitHub Apps would
 * be the richer signal and need organisation-admin scope, so their absence is a stated gap
 * on the route rather than a silent one.
 */
async function fetchIntegrations(repos) {
  const observed = [];
  const unexamined = [];

  for (const repo of repos) {
    const hooks = await api(`/repos/${repo.name}/hooks`);
    if (!hooks.ok) {
      unexamined.push({
        id: `webhooks/${repo.name}`,
        reason: hooks.classification?.detail ?? `HTTP ${hooks.status}`,
      });
      continue;
    }
    for (const hook of hooks.body ?? []) {
      const url = hook.config?.url;
      if (!url) continue;
      try {
        observed.push({ source: repo.name, host: new URL(url).hostname, events: hook.events ?? [], active: Boolean(hook.active) });
      } catch {
        unexamined.push({ id: `webhook/${repo.name}/${hook.id}`, reason: `configured URL is not parseable` });
      }
    }
  }
  return { observed, unexamined };
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

  if (fixture) {
    const data = loadFixture(fixture, 'thirdparty-register');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'thirdparty-register', { declared: data.register.length }),
        ...gradeRegister(data.register, data.observed ?? [], {
          now: Date.parse(collectedAt),
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const register = registerFrom(profile);
  if (register.length === 0) {
    throw new Error(
      'No third-party register is declared. Add certification.third_party to the profile — an assessment scope ' +
        'with no declared third parties is a claim, and this check has nothing to reconcile against.'
    );
  }

  const repos = resolveRepos(profile);
  const { observed, unexamined } = await fetchIntegrations(repos);

  return [
    buildBundle({
      ...common,
      scope: { declared: register.length, repositories: repos.map((r) => r.name) },
      ...gradeRegister(register, observed, { now: Date.parse(collectedAt), unexamined }),
    }),
  ];
}

/**
 * Reads the register from the certification block the overview emitter already uses.
 *
 * Deliberately the same declaration rather than a second one. The overview states these
 * dependencies to FedRAMP under MAS-CSO-TPR; a register that could drift from what was filed
 * would be worse than no register.
 */
export function registerFrom(profile) {
  const third = profile?.certification?.third_party ?? {};
  const owners = profile?.certification?.third_party_owners ?? {};

  return [
    ...(third.certified ?? []).map((r) => ({
      name: r.name ?? r.id,
      provider: r.provider ?? null,
      use_case: r.use_case,
      certified: true,
      fedramp_id: r.id,
      owner: r.owner ?? owners[r.name ?? r.id] ?? null,
      attestation: r.attestation ?? null,
      hosts: r.hosts ?? [],
    })),
    ...(third.non_certified ?? []).map((r) => ({
      name: r.name,
      provider: r.provider,
      use_case: r.use_case,
      certified: false,
      owner: r.owner ?? owners[r.name] ?? null,
      resolution: r.resolution ?? null,
      hosts: r.hosts ?? [],
    })),
  ];
}
