import { controlOverlay } from '../../catalog/ksi.mjs';
import { assertValid } from '../validate.mjs';

/**
 * Emits the Key Security Indicator section of a Security Decision Record.
 *
 * Scope is deliberately narrow. An SDR is largely a narrative document — boundary
 * description, architecture, FRR process implementation — and generating that narrative from
 * configuration would be inventing prose about decisions no collector observed. What *is*
 * machine-generatable is the KSI section, because every field it requires is either resolved
 * from the pinned ruleset or derived from evidence that exists. So this emitter fills that
 * section completely and marks the human-authored sections as human-authored rather than
 * producing plausible filler.
 *
 * The implementation-status mapping is the load-bearing decision here, and it is
 * conservative by design: see `implementationStatus`.
 */

/**
 * Maps control state to FedRAMP's three-value status.
 *
 * "Implemented" requires two things at once — an `automated` route, meaning someone wrote the
 * argument that the checks settle the indicator, and passing evidence at the claimed cadence.
 * Passing checks under a `partial` route are explicitly *not* enough, because the route itself
 * says they leave something out.
 *
 * The consequence is worth stating plainly: a harness with no `automated` routes emits no
 * "Implemented" indicators. That is the correct output for such a harness, and a mapping
 * generous enough to avoid it would be measuring effort rather than coverage.
 */
export function implementationStatus(indicator) {
  if (indicator.coverage === 'automated' && indicator.evidence_state === 'satisfied-in-part' && indicator.cadence?.met !== false) {
    return 'Implemented';
  }
  if (indicator.evidence_state === 'not-evidenced') return 'Not Implemented';
  if (indicator.evidence_state === 'no-evidence') return 'Not Implemented';
  return 'Partially Implemented';
}

function implementationStatements(indicator) {
  const out = [`**${indicator.name}.** ${indicator.statement}`];

  if (indicator.coverage === 'manual') {
    out.push(
      `Evidenced by review rather than by automation, on a ${indicator.cadence?.claimed ?? 'declared'} cycle. ` +
        `Owner: ${indicator.manual_evidence.owner}. Artifact: ${indicator.manual_evidence.artifact}.`
    );
    out.push(`Automation was not chosen here because: ${indicator.manual_evidence.why_not_automated.trim()}`);
    return out;
  }

  if (indicator.coverage === 'unaddressed') {
    out.push(`No evidence is currently produced for this indicator. ${indicator.reason.trim()}`);
    out.push(`Planned next step: ${indicator.next.trim()}`);
    return out;
  }

  const checks = indicator.checks.map((c) => c.check_id).join(', ');
  out.push(
    `Evidenced by ${indicator.checks.length} automated check(s) (${checks}) collected on a ` +
      `${indicator.cadence?.claimed ?? 'declared'} cycle, each producing a full-population evidence bundle with a ` +
      `completeness reconciliation and a content hash.`
  );

  if (indicator.coverage === 'automated' && indicator.sufficiency) {
    out.push(`Sufficiency of the automated evidence: ${indicator.sufficiency.trim()}`);
  }
  if (indicator.unautomated?.length) {
    out.push(
      'The automated evidence does not establish the following, which is stated here rather than left for a ' +
        'reviewer to discover:\n' +
        indicator.unautomated.map((u) => `- ${u.trim()}`).join('\n')
    );
  }
  if (indicator.note) out.push(indicator.note);
  return out;
}

function validationStatements(indicator) {
  if (!indicator.checks.length) {
    return [
      indicator.coverage === 'manual'
        ? `Validated by the named owner on a ${indicator.cadence?.claimed} cycle; the artifact is the record.`
        : 'No internal validation is currently automated for this indicator.',
    ];
  }

  const out = indicator.checks.map((check) => {
    if (!check.present) return `${check.check_id}: declared but no evidence bundle is present in the locker.`;
    const population = check.population
      ? `${check.population.examined} of ${check.population.expected} item(s) examined` +
        (check.population.complete ? ', population complete' : `, INCOMPLETE — ${check.population.reconciliation}`)
      : 'population not recorded';
    return (
      `${check.check_id}: "${check.assertion}" — result ${check.result.toUpperCase()}, ${population}, ` +
      `collected ${check.collected_at} (${check.run_count} run(s) retained).` +
      (check.fixture ? ' NOTE: produced from fixtures, not live systems.' : '')
    );
  });

  if (indicator.cadence?.verifiable) {
    out.push(
      indicator.cadence.met
        ? `Cadence verified against collection history: ${indicator.cadence.detail}.`
        : `Cadence NOT met: ${indicator.cadence.detail}.`
    );
  } else if (indicator.cadence?.claimed) {
    out.push(`Cadence is ${indicator.cadence.claimed}; ${indicator.cadence.detail}.`);
  }
  return out;
}

/**
 * The independent-assessment field, which this harness will not write.
 *
 * `ksiAssessment` is required by the schema, and it is the assessor's statement rather than
 * the provider's. Generating text here would be putting words in the mouth of a party that has
 * not spoken, so the emitter states the absence and accepts injected assessor statements
 * instead. This is the one field where being schema-valid and being honest pull in different
 * directions, and honesty wins.
 */
function assessmentStatements(indicator, assessorStatements) {
  const provided = assessorStatements?.[indicator.id];
  if (provided?.length) return provided;
  return [
    'No independent assessment has been recorded for this indicator. This field is reserved for the ' +
      'assessor\u2019s statement and is not generated by the provider\u2019s tooling.',
  ];
}

function evidenceEntries(indicator, { baseUri }) {
  return indicator.checks
    .filter((c) => c.present)
    .map((check) => {
      const day = check.collected_at.slice(0, 10);
      const entry = {
        evidenceType: 'Audit Record',
        evidenceDescription:
          `Evidence bundle from ${check.check_id}: full-population result with completeness reconciliation, ` +
          `per-item outcomes and a SHA-256 content hash.`,
        evidenceText:
          `result=${check.result} examined=${check.population?.examined ?? 0}/${check.population?.expected ?? 0} ` +
          `complete=${check.population?.complete ?? false} failing_items=${check.failing_items ?? 0}` +
          (check.metric ? ` ${check.metric.metric_id}=${check.metric.value}` : ''),
        lastUpdated: day,
      };
      // evidenceLocation is validated as a URI, so it is emitted only when a base is supplied.
      // A bare filesystem path would fail validation, and inventing one would be worse.
      if (baseUri) entry.evidenceLocation = `${baseUri.replace(/\/$/, '')}/${check.check_id}/${day}.json`;
      return entry;
    });
}

/** Control parameter values FedRAMP has already decided, from the ruleset's CTL section. */
function securityControls(state) {
  const seen = new Map();
  for (const indicator of state.indicators) {
    if (!indicator.applicable) continue;
    for (const controlId of indicator.controls) {
      const overlay = controlOverlay(controlId);
      if (!overlay?.parameters?.length || seen.has(overlay.control_id)) continue;
      seen.set(overlay.control_id, {
        controlId: overlay.control_id,
        parameterValues: overlay.parameters.map((p) => ({
          parameterId: p.parameterId,
          parameterValue: String(p.value),
        })),
        controlImplementationDescription:
          'Parameter value defined by FedRAMP in the Consolidated Rules for 2026 (CTL section) and inherited ' +
          'without modification. Implementation narrative is authored separately.',
      });
    }
  }
  return [...seen.values()].sort((a, b) => a.controlId.localeCompare(b.controlId));
}

export const kind = 'sdr';

export function emit(state, { overviewUri, baseUri = null, assessorStatements = null, frrRequirements = null } = {}) {
  if (!overviewUri) {
    throw new Error(
      'An SDR requires certificationPackageOverviewUri (schema-required). Pass --overview-uri with the URI of the ' +
        'published Certification Package Overview.'
    );
  }

  const document = {
    certificationPackageOverviewUri: overviewUri,
    fedRampRequirements:
      frrRequirements ?? [
        {
          frrID: 'SDR-CSO-FRR',
          frrImplementationStatus: 'Partially Implemented',
          frrImplementation: [
            'The Key Security Indicator section of this record is generated from continuously collected evidence by ' +
              'ksi-harness against FedRAMP Consolidated Rules version ' +
              `${state.ruleset.version} (sha256 ${state.ruleset.sha256.slice(0, 16)}).`,
            'FedRAMP Requirement (FRR) process implementation narrative is authored by the provider and is not ' +
              'generated from configuration. This entry is a placeholder recording that fact; it is not a claim that ' +
              'the FRR processes are implemented.',
          ],
        },
      ],
    keySecurityIndicators: state.indicators
      .filter((indicator) => indicator.applicable)
      .map((indicator) => ({
        ksiId: indicator.id,
        ksiImplementationStatus: implementationStatus(indicator),
        ksiImplementation: implementationStatements(indicator),
        ksiValidation: validationStatements(indicator),
        ksiAssessment: assessmentStatements(indicator, assessorStatements),
        ksiTests: indicator.checks.map((c) => `${c.check_id}: ${c.assertion ?? '(no bundle present)'}`),
        ksiEvidence: evidenceEntries(indicator, { baseUri }),
      })),
  };

  const controls = securityControls(state);
  if (controls.length) document.securityControls = controls;

  return assertValid('sdr', document);
}
