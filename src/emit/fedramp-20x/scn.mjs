import { assertValid } from '../validate.mjs';

/**
 * Emits a FedRAMP 20x Significant Change Notification.
 *
 * The schema was already vendored and already registered in the ajv resolver; there was
 * simply no emitter behind it, so the one artifact a provider files repeatedly over the life
 * of an authorization was the one this harness could not produce.
 *
 * The division of labour is the same one the SDR emitter draws, for the same reason. An SCN
 * is a statement about an *intended* change — its type, its rationale, its timeline — and
 * none of that is observable in configuration. Generating it from evidence drift would be
 * inventing prose about a decision no collector watched anyone make, which is precisely what
 * `sdr.mjs` refuses to do for the narrative sections.
 *
 * So the human authors the change record and this emitter fills in the part that is tedious,
 * mechanical and easy to get wrong: which indicators the change touches, which 800-53
 * controls those indicators carry, and what the evidence currently says about each of them.
 * Answering "if I change the ingress path, which controls do I have to speak to" by hand
 * means reading the crosswalk and missing one; it is resolved from the pinned ruleset here.
 *
 * The evidence position is appended to the impact analysis rather than substituted for it.
 * A change proposed while the indicators it touches are already failing is a materially
 * different filing from the same change proposed from a clean baseline, and the reviewer
 * should not have to open a second document to find that out.
 */

export const kind = 'scn';

const CHANGE_TYPES = new Set(['Adaptive', 'Transformative']);

function requireChange(change) {
  if (!change) {
    throw new Error(
      'ksi emit scn needs --change FILE, a change record declaring what is being changed and why. See ' +
        'examples/change.scn.yaml. The type, rationale and timeline of a change are not observable in ' +
        'configuration, and generating them would be inventing a decision nobody made.'
    );
  }
  for (const field of ['change_type', 'description']) {
    if (!change[field]) throw new Error(`The change record needs "${field}".`);
  }
  if (!CHANGE_TYPES.has(change.change_type)) {
    throw new Error(
      `change_type "${change.change_type}" is not one of ${[...CHANGE_TYPES].join(', ')}. Routine recurring ` +
        `changes (SCN-RTR) do not require a notification at all.`
    );
  }
  if (!Array.isArray(change.indicators) || change.indicators.length === 0) {
    throw new Error(
      'The change record needs "indicators": the Key Security Indicators this change touches. A significant ' +
        'change that bears on no indicator is either not significant or not understood.'
    );
  }
}

/** The indicators named by the change, resolved against the state, with their controls. */
export function impactedFrom(state, ids) {
  const byId = new Map(state.indicators.map((i) => [i.id, i]));
  return ids.map((id) => {
    const indicator = byId.get(id);
    if (!indicator) {
      throw new Error(`${id} is not an indicator in the pinned ruleset (${state.ruleset.version}). Check the id.`);
    }
    return indicator;
  });
}

/**
 * States, per impacted indicator, what the evidence says today.
 *
 * Deliberately not a verdict on the change. It is the baseline a reviewer needs in order to
 * read the plan: an indicator that is already degraded is a different starting point from one
 * that is passing, and the plan's verification steps should say which it is.
 */
export function baselineNarrative(indicators) {
  const lines = indicators.map((indicator) => {
    const checks = indicator.checks ?? [];
    const evidence = checks.length
      ? checks
          .map((c) => `${c.check_id} ${c.present ? c.result : 'absent'}${c.population_complete === false ? ' (population incomplete)' : ''}`)
          .join(', ')
      : 'no automated checks';
    const gaps = indicator.unautomated?.length
      ? ` Not established by automation: ${indicator.unautomated.map((u) => u.trim().replace(/\s+/g, ' ')).join(' ')}`
      : '';
    return (
      `- ${indicator.id} (${indicator.name}): coverage ${indicator.coverage}, evidence ${indicator.evidence_state} ` +
      `[${evidence}].${gaps}`
    );
  });
  return `Evidence baseline at the time of this notification:\n${lines.join('\n')}`;
}

export function emit(state, { overviewUri, change = null } = {}) {
  requireChange(change);
  if (!overviewUri) {
    throw new Error('ksi emit scn requires --overview-uri, the URI of the Certification Package Overview.');
  }

  const indicators = impactedFrom(state, change.indicators);
  const controls = [...new Set(indicators.flatMap((i) => i.controls))].sort();

  const document = {
    certificationPackageOverviewUri: overviewUri,
    changeType: change.change_type,
    changeDescription: change.description,
  };

  if (change.change_type_explanation) document.changeTypeExplanation = change.change_type_explanation;
  if (change.reason) document.reason = change.reason;
  if (change.customer_impact) document.customerImpact = change.customer_impact;
  if (change.assessor_name) document.assessorName = change.assessor_name;
  if (change.related_vulnerability) document.relatedVulnerability = change.related_vulnerability;

  // Both the indicators and the controls they carry. A reviewer working from the 20x side
  // wants the first and one working from a Rev5 crosswalk wants the second, and resolving the
  // mapping by hand is where a filing quietly omits a control.
  document.impactedControls = [...indicators.map((i) => i.id), ...controls];

  const analysis = [change.impact_analysis?.trim(), baselineNarrative(indicators)].filter(Boolean);
  document.impactAnalysis = analysis.join('\n\n');

  if (change.plan?.summary) {
    document.planAndTimeline = { summary: change.plan.summary.trim() };
    if (change.plan.planned_start) document.planAndTimeline.plannedStart = change.plan.planned_start;
    if (change.plan.planned_completion) document.planAndTimeline.plannedCompletion = change.plan.planned_completion;
    if (change.plan.milestones?.length) {
      document.planAndTimeline.milestones = change.plan.milestones.map((m) => ({
        milestoneDescription: m.description,
        ...(m.target_date ? { targetDate: m.target_date } : {}),
      }));
    }
  }

  return assertValid('scn', document);
}
