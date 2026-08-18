import { createHash } from 'node:crypto';

/**
 * Emits OSCAL Assessment Results from the same control state the 20x emitters read.
 *
 * This exists to make an argument rather than to serve a submission. FedRAMP 20x does not use
 * OSCAL — it uses FedRAMP's own lightweight JSON schemas, and RFC-0024's machine-readable
 * requirement applies to Rev5 only. So the recommendation this repository implements is
 * "machine-readable first, format-pluggable": model control state internally, treat every
 * output format as a projection of it, and never author in any of them by hand.
 *
 * Assessment Results is the right OSCAL model to demonstrate that with, and the choice is
 * itself the point. An SSP or a Component Definition would require a complete interlocking
 * object graph before any of it is valid — Greg Elin's "there is no valid partial OSCAL", which
 * is the practical reason most teams that tried OSCAL produced nothing. Assessment Results is
 * the one model that maps naturally onto observations and findings a machine actually has, so
 * it can be generated incrementally from real evidence.
 *
 * The output is deliberately not validated against the OSCAL schema here: NIST's schema is not
 * vendored, and adding a 2 MB dependency to support a format this repository argues against
 * leading with would be the wrong trade. `oscal-cli validate` is the right tool, and the
 * workflow in .github/workflows runs it on the emitted file so the claim is checked rather
 * than asserted.
 */

const OSCAL_VERSION = '1.1.3';

/** Stable UUIDs from stable inputs, so re-emitting unchanged state produces an identical file. */
function stableUuid(...parts) {
  const hex = createHash('sha256').update(parts.join('|')).digest('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    `4${hex.slice(13, 16)}`,
    ((parseInt(hex.slice(16, 17), 16) & 0x3) | 0x8).toString(16) + hex.slice(17, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * OSCAL has no vocabulary for "the automation is real but does not settle the claim", which is
 * the state 20 of 46 indicators are in. `satisfied` / `not-satisfied` is the whole enum, so
 * partial coverage is emitted as `not-satisfied` with the sufficiency gap in the description
 * rather than rounded up to `satisfied`.
 *
 * Rounding up would be the tempting move and it is exactly the failure mode that makes
 * generated compliance artifacts untrustworthy: the target format's coarser vocabulary
 * silently upgrades a qualified claim into an unqualified one.
 */
function targetStatus(indicator) {
  if (indicator.coverage === 'automated' && indicator.evidence_state === 'satisfied-in-part') {
    return { state: 'satisfied' };
  }
  return {
    state: 'not-satisfied',
    remarks:
      indicator.coverage === 'partial'
        ? 'Automated evidence is present and passing but the route does not claim sufficiency; see the gap ' +
          'statements in this finding\u2019s description. OSCAL offers no intermediate status, so this is reported ' +
          'as not-satisfied rather than rounded up.'
        : undefined,
  };
}

function observations(state) {
  const out = [];
  const seen = new Set();

  for (const indicator of state.indicators) {
    for (const check of indicator.checks) {
      if (!check.present || seen.has(check.check_id)) continue;
      seen.add(check.check_id);
      out.push({
        uuid: stableUuid('observation', check.check_id, check.collected_at),
        title: check.check_id,
        description: check.assertion ?? check.check_id,
        methods: ['TEST'],
        types: ['control-objective'],
        props: [
          { name: 'result', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: check.result },
          { name: 'population-expected', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: String(check.population?.expected ?? 0) },
          { name: 'population-examined', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: String(check.population?.examined ?? 0) },
          { name: 'population-complete', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: String(Boolean(check.population?.complete)) },
          ...(check.fixture
            ? [{ name: 'fixture', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: 'true' }]
            : []),
        ],
        collected: check.collected_at,
        remarks:
          `Population: ${check.population?.examined ?? 0} of ${check.population?.expected ?? 0} examined from ` +
          `${check.population?.source_of_truth ?? 'unrecorded source'}.` +
          (check.population?.complete ? '' : ` INCOMPLETE: ${check.population?.reconciliation ?? 'no reconciliation'}`),
      });
    }
  }
  return out;
}

function findings(state) {
  return state.indicators
    .filter((i) => i.applicable)
    .map((indicator) => {
      const status = targetStatus(indicator);
      const description = [
        indicator.statement,
        `Coverage: ${indicator.coverage}. Evidence state: ${indicator.evidence_state}.`,
        ...(indicator.unautomated?.length
          ? [`Not established by automation:\n${indicator.unautomated.map((u) => `- ${u.trim()}`).join('\n')}`]
          : []),
        ...(indicator.reason ? [`Reason unaddressed: ${indicator.reason.trim()}`] : []),
        ...(indicator.manual_evidence
          ? [`Manual evidence owned by ${indicator.manual_evidence.owner}: ${indicator.manual_evidence.artifact}.`]
          : []),
      ].join('\n\n');

      return {
        uuid: stableUuid('finding', indicator.id, state.ruleset.sha256),
        title: `${indicator.id} — ${indicator.name}`,
        description,
        target: {
          type: 'objective-id',
          'target-id': indicator.id,
          description: `FedRAMP Key Security Indicator ${indicator.id}, theme ${indicator.theme} (${indicator.theme_name}).`,
          status,
        },
        // The 800-53 controls each indicator maps to, carried through so a control-keyed
        // consumer can reuse this evidence without re-deriving the crosswalk.
        props: indicator.controls.map((control) => ({
          name: 'related-control',
          ns: 'https://github.com/RootCawsLLC/ksi-harness/ns',
          value: control,
        })),
        'related-observations': indicator.checks
          .filter((c) => c.present)
          .map((c) => ({ 'observation-uuid': stableUuid('observation', c.check_id, c.collected_at) })),
      };
    });
}

export const kind = 'oscal-assessment-results';

export function emit(state, { title, sspUri = 'https://example.com/ssp.json', uuid = null } = {}) {
  const start = state.indicators
    .flatMap((i) => i.checks.filter((c) => c.present).map((c) => c.collected_at))
    .sort()[0];

  return {
    'assessment-results': {
      uuid: uuid ?? stableUuid('assessment-results', state.ruleset.sha256, state.generated_at),
      metadata: {
        title: title ?? `Key Security Indicator assessment results — ${state.profile?.service_name ?? 'unnamed service'}`,
        'last-modified': state.generated_at,
        version: state.ruleset.version,
        'oscal-version': OSCAL_VERSION,
        props: [
          { name: 'fedramp-ruleset-version', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: state.ruleset.version },
          { name: 'fedramp-ruleset-sha256', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: state.ruleset.sha256 },
          { name: 'certification-class', ns: 'https://github.com/RootCawsLLC/ksi-harness/ns', value: state.klass },
        ],
        remarks:
          'Generated by ksi-harness from the same control state that produces its FedRAMP 20x artifacts. FedRAMP 20x ' +
          'does not consume OSCAL; this output exists to demonstrate that control state is modelled independently of ' +
          'its serialisation, and to serve Rev5 or customer requests that do want OSCAL.',
      },
      'import-ap': { href: sspUri },
      results: [
        {
          uuid: stableUuid('result', state.generated_at, state.ruleset.sha256),
          title: `Continuous control monitoring, Class ${state.klass.toUpperCase()}`,
          description:
            `${state.counts.applicable} applicable Key Security Indicators assessed from ${state.evidence.bundle_count} ` +
            'evidence bundle(s). Coverage levels and their sufficiency gaps are carried in each finding.',
          start: start ?? state.generated_at,
          end: state.generated_at,
          'reviewed-controls': {
            'control-selections': [
              {
                description:
                  'NIST 800-53 Rev 5 controls reached transitively through Key Security Indicator mappings in the ' +
                  'pinned FedRAMP ruleset.',
                'include-controls': [
                  ...new Set(state.indicators.filter((i) => i.applicable).flatMap((i) => i.controls)),
                ]
                  .sort()
                  .map((id) => ({ 'control-id': id })),
              },
            ],
          },
          observations: observations(state),
          findings: findings(state),
        },
      ],
    },
  };
}
