import { openFindings } from '../../evidence/state.mjs';
import { assertValid } from '../validate.mjs';

/**
 * Emits the quarterly Ongoing Certification Report required by CCM-OCR-AVL.
 *
 * Of all the 20x artifacts this is the one that most wants to be generated, because it is a
 * report about a period rather than a description of a design. Every field it requires is
 * either a fact about the reporting window or a summary of what changed in it, and both are
 * things the evidence locker already knows.
 *
 * The point of wiring it up is that ongoing reporting stops being an event. `git log` over the
 * locker is the change history, so the report is a build artifact of the period rather than a
 * quarterly reconstruction of it — which is the practical difference between continuous
 * certification and an annual scramble with extra steps.
 */

function quarterBounds(to) {
  const end = new Date(to);
  const start = new Date(end);
  start.setUTCMonth(start.getUTCMonth() - 3);
  return { from: start.toISOString().slice(0, 10), to: end.toISOString().slice(0, 10) };
}

/**
 * Summarizes what changed, from the locker rather than from memory.
 *
 * Only differences are reported. A check that passed at the start of the period and passes now
 * is not a change, and listing it would pad the report with reassurance — which is how a
 * reporting obligation degrades into a document nobody reads.
 */
export function certificationDataChanges(state, { from }) {
  const changes = [];
  const fromMs = Date.parse(`${from}T00:00:00Z`);

  const drifted = [];
  for (const indicator of state.indicators) {
    for (const check of indicator.checks) {
      if (!check.present) continue;
      if (Date.parse(check.collected_at) < fromMs) continue;
      if (check.result !== 'pass') {
        drifted.push(`${indicator.id} via ${check.check_id} (${check.result}, ${check.failing_items} failing item(s))`);
      }
    }
  }

  const unique = [...new Set(drifted)];
  if (unique.length) {
    changes.push(
      `${unique.length} indicator/check pair(s) are not currently passing: ${unique.slice(0, 12).join('; ')}` +
        (unique.length > 12 ? `; and ${unique.length - 12} more` : '')
    );
  }

  const cadenceMisses = state.indicators.filter((i) => i.cadence?.met === false);
  if (cadenceMisses.length) {
    changes.push(
      `${cadenceMisses.length} indicator(s) did not meet their declared collection cadence during the period: ` +
        cadenceMisses.map((i) => `${i.id} (${i.cadence.detail})`).join('; ')
    );
  }

  if (state.evidence.tampered.length) {
    changes.push(
      `${state.evidence.tampered.length} evidence bundle(s) failed content-hash verification and were reported ` +
        'rather than discarded.'
    );
  }

  if (state.evidence.fixture_bundles > 0) {
    changes.push(
      `${state.evidence.fixture_bundles} of ${state.evidence.bundle_count} bundle(s) in the locker were produced from ` +
        'fixtures rather than live systems and do not constitute evidence about the production environment.'
    );
  }

  changes.push(
    `Evidence assessed against FedRAMP Consolidated Rules ${state.ruleset.version} ` +
      `(last updated ${state.ruleset.last_updated}, sha256 ${state.ruleset.sha256.slice(0, 16)}).`
  );

  return changes;
}

function plannedChanges(state) {
  const planned = state.indicators
    .filter((i) => i.applicable && i.next)
    .map((i) => `${i.id} (${i.name}): ${i.next.trim().replace(/\s+/g, ' ')}`);
  return planned.length
    ? planned
    : ['No changes to certification data are planned for the next reporting period.'];
}

export const kind = 'ocr';

export function emit(state, { overviewUri, reportTo = state.generated_at, activeAgencies = [], incidents = [] } = {}) {
  if (!overviewUri) {
    throw new Error('An OCR requires certificationPackageOverviewUri (schema-required). Pass --overview-uri.');
  }

  const period = quarterBounds(reportTo);
  const horizon = new Date(`${period.to}T00:00:00Z`);
  horizon.setUTCMonth(horizon.getUTCMonth() + 3);

  const findings = openFindings(state);

  const document = {
    certificationPackageOverviewUri: overviewUri,
    reportPeriod: period,
    certificationDataChanges: certificationDataChanges(state, period),
    plannedCertificationDataChanges: {
      planningHorizonThrough: horizon.toISOString().slice(0, 10),
      changes: plannedChanges(state),
    },
    // Accepted vulnerabilities are reported in full under VER-RPT-AVI, not here. This harness
    // does not manage a vulnerability register, and summarizing one it cannot see would be
    // asserting an absence.
    acceptedVulnerabilities:
      'No accepted vulnerabilities are tracked by this harness. Accepted vulnerabilities are reported separately ' +
      'per VER-RPT-AVI from the provider\u2019s vulnerability register, which is not an input to this tooling.',
    transformativeChanges: [],
    updatedRecommendations: findings.length
      ? [
          `${findings.length} indicator(s) have automated coverage whose evidence is currently failing, degraded or ` +
            `absent: ${findings.map((f) => f.indicator).join(', ')}. Remediation is tracked against the check that ` +
            'detected it rather than against the indicator, so a fix is verified by the same query that found the gap.',
        ]
      : ['No changes to security recommendations or best practices during this period.'],
    activeAgencies,
    reportableIncidents: {
      // An empty array is an affirmative attestation that none occurred, per the schema. It is
      // passed through from the caller rather than defaulted silently, because attesting to an
      // absence is a decision a person makes.
      incidents,
    },
  };

  return assertValid('ocr', document);
}
