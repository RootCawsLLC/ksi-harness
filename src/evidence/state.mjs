import { catalog } from '../catalog/ksi.mjs';
import { rulesProvenance } from '../catalog/rules.mjs';
import { CADENCES, loadRoutes, validateRoutes } from '../routes/routes.mjs';
import { ageInDays, chainBreaks, observedIntervalDays, readLocker } from './locker.mjs';

/**
 * Folding the catalog, the routing map and the evidence locker into one control state.
 *
 * This is the single input every emitter reads. Adding a new output format means writing a
 * new emitter against this structure, not another traversal of the locker — which is the
 * whole of the "machine-readable first, format-pluggable" argument in
 * docs/adr/0001-format-strategy.md, made concrete.
 *
 * The boundary this module refuses to cross: it never reports that an indicator is *met*.
 * It reports what the declared coverage is, what the evidence says, and whether the claimed
 * cadence is borne out — and it stops there. Whether a capability claim is satisfied is a
 * judgement a person signs, and a harness that rendered it as a green tick would be
 * manufacturing exactly the false confidence the coverage model exists to prevent.
 */

export const EVIDENCE_STATES = Object.freeze([
  'satisfied-in-part', // every declared check passed; coverage level says how much that settles
  'failing', // at least one declared check found a failure
  'degraded', // warnings, or a population that could not be completed
  'no-evidence', // checks are declared but the locker has nothing, or collection errored
  'manual-attested', // no automation by decision; an owner and artifact are named
  'not-evidenced', // nothing yet, by admission
]);

function stateFromChecks(checkStates) {
  if (checkStates.length === 0) return 'no-evidence';
  if (checkStates.some((c) => !c.present || c.result === 'error')) return 'no-evidence';
  if (checkStates.some((c) => c.result === 'fail')) return 'failing';
  if (checkStates.some((c) => c.result === 'warn' || !c.population_complete)) return 'degraded';
  return 'satisfied-in-part';
}

/**
 * Tests a route's cadence claim against the locker.
 *
 * A route claiming daily collection while the locker holds one bundle from six weeks ago is
 * making an aspirational statement, and an aspirational cadence on an indicator whose text
 * says "persistently" is the kind of gap a reviewer finds and a self-assessment does not.
 * Event-driven cadences are exempt rather than passed: a per-incident review is not overdue
 * because no incident happened.
 */
export function assessCadence(route, checkStates, now) {
  const claimed = route.cadence ?? null;
  const allowed = claimed ? CADENCES[claimed] : undefined;

  if (!claimed) return { claimed: null, verifiable: false, met: null, detail: 'No cadence declared' };
  if (allowed === null) {
    return { claimed, verifiable: false, met: null, detail: `${claimed} is event-driven and cannot be verified from a schedule` };
  }
  if (checkStates.length === 0) {
    return { claimed, verifiable: false, met: null, detail: 'No automated checks to observe a cadence from' };
  }

  const present = checkStates.filter((c) => c.present);
  if (present.length === 0) {
    return { claimed, verifiable: true, met: false, detail: 'Claimed a schedule but the locker holds no evidence' };
  }

  const stalest = Math.max(...present.map((c) => c.age_days));
  const intervals = present.map((c) => c.observed_interval_days).filter((v) => v != null);
  const observed = intervals.length ? Math.max(...intervals) : null;

  // Tolerance of one period: a daily job that ran 35 hours ago is not a broken cadence, and
  // flagging it would make the report noisy enough to be ignored.
  const tolerance = allowed * 2;
  if (stalest > tolerance) {
    return {
      claimed,
      verifiable: true,
      met: false,
      observed_interval_days: observed,
      detail: `Claims ${claimed} but the freshest evidence is ${stalest.toFixed(1)} days old`,
    };
  }
  if (observed != null && observed > tolerance) {
    return {
      claimed,
      verifiable: true,
      met: false,
      observed_interval_days: observed,
      detail: `Claims ${claimed} but the observed interval is ${observed.toFixed(1)} days`,
    };
  }
  return {
    claimed,
    verifiable: true,
    met: true,
    observed_interval_days: observed,
    detail:
      observed == null
        ? `Fresh (${stalest.toFixed(1)} days old); only one run so far, so the interval is not yet established`
        : `Observed interval ${observed.toFixed(1)} days against a claimed ${claimed}`,
  };
}

export function buildState({ evidenceDir, klass = 'c', routes = loadRoutes(), now = Date.now(), profile = null } = {}) {
  const validation = validateRoutes({ routes, klass });
  const locker = readLocker(evidenceDir);
  const { indicators, counts, themes } = catalog({ klass });

  const resolved = indicators.map((indicator) => {
    const route = routes[indicator.id];
    if (!indicator.applicable) {
      return { ...indicator, coverage: 'not-applicable', evidence_state: 'not-evidenced', checks: [], cadence: null };
    }
    if (!route) {
      return { ...indicator, coverage: 'unrouted', evidence_state: 'not-evidenced', checks: [], cadence: null };
    }

    const checkStates = (route.checks ?? []).map((checkId) => {
      const entry = locker.checks.get(checkId);
      if (!entry) {
        return { check_id: checkId, present: false, result: null, population_complete: false, age_days: Infinity };
      }
      const { latest, history } = entry;
      return {
        check_id: checkId,
        present: true,
        result: latest.result,
        assertion: latest.assertion,
        collected_at: latest.collected_at,
        age_days: ageInDays(latest, now),
        observed_interval_days: observedIntervalDays(history),
        run_count: history.length,
        population: latest.population,
        population_complete: Boolean(latest.population?.complete),
        metric: latest.metric ?? null,
        failing_items: (latest.items ?? []).filter((i) => i.status === 'fail').length,
        fixture: Boolean(latest.scope?.fixture),
      };
    });

    let evidenceState;
    if (route.coverage === 'manual') evidenceState = 'manual-attested';
    else if (route.coverage === 'unaddressed') evidenceState = 'not-evidenced';
    else evidenceState = stateFromChecks(checkStates);

    return {
      ...indicator,
      coverage: route.coverage,
      sufficiency: route.sufficiency ?? null,
      unautomated: route.unautomated ?? [],
      manual_evidence: route.manual_evidence ?? null,
      reason: route.reason ?? null,
      next: route.next ?? null,
      note: route.note ?? null,
      checks: checkStates,
      cadence: assessCadence(route, checkStates, now),
      evidence_state: evidenceState,
    };
  });

  const applicable = resolved.filter((i) => i.applicable);
  const tally = (field, value) => applicable.filter((i) => i[field] === value).length;

  return {
    generated_at: new Date(now).toISOString(),
    klass,
    profile: profile ? { service_name: profile.service_name ?? null, provider: profile.provider ?? null } : null,
    ruleset: rulesProvenance(),
    routes_valid: validation.ok,
    route_errors: validation.errors,
    route_warnings: validation.warnings,
    evidence: {
      dir: evidenceDir,
      bundle_count: locker.bundles.length,
      // A tampered bundle is reported rather than dropped. Silently discarding it would hide
      // the one event the content hash exists to detect.
      tampered: locker.tampered,
      // A break in a check's hash chain is the stronger signal, and the one an edited bundle
      // cannot avoid by recomputing its own hash. Reported separately because the two mean
      // different things: a content mismatch is usually corruption, a chain mismatch is not.
      chain_breaks: chainBreaks(locker),
      unreadable: locker.unreadable,
      fixture_bundles: locker.bundles.filter((b) => b.scope?.fixture).length,
    },
    counts: {
      ...counts,
      coverage: {
        automated: tally('coverage', 'automated'),
        partial: tally('coverage', 'partial'),
        manual: tally('coverage', 'manual'),
        unaddressed: tally('coverage', 'unaddressed'),
        unrouted: tally('coverage', 'unrouted'),
      },
      evidence_state: Object.fromEntries(EVIDENCE_STATES.map((s) => [s, tally('evidence_state', s)])),
      cadence_unmet: applicable.filter((i) => i.cadence?.met === false).length,
    },
    themes,
    indicators: resolved,
  };
}

/** Indicators with an automated claim that the evidence does not currently support. */
export function openFindings(state) {
  return state.indicators
    .filter((i) => i.applicable && ['failing', 'degraded', 'no-evidence'].includes(i.evidence_state))
    .filter((i) => ['automated', 'partial'].includes(i.coverage))
    .map((i) => ({
      indicator: i.id,
      name: i.name,
      evidence_state: i.evidence_state,
      checks: i.checks.filter((c) => !c.present || c.result !== 'pass').map((c) => ({
        check_id: c.check_id,
        result: c.present ? c.result : 'absent',
        failing_items: c.failing_items ?? 0,
      })),
    }));
}
