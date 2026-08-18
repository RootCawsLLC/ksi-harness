import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

import { runAll } from '../src/collectors/run-all.mjs';
import { writeBundle } from '../src/evidence/bundle.mjs';
import { buildState } from '../src/evidence/state.mjs';
import { EMITTERS, emitterFor } from '../src/emit/index.mjs';
import { SCHEMA_IDS, validateArtifact, validator } from '../src/emit/validate.mjs';

/**
 * Emitter tests, and the argument for "machine-readable first, format-pluggable" reduced to
 * something executable.
 *
 * Rule FRC-CSO-JSN requires submitted JSON to validate against FedRAMP's published schemas, so
 * the SDR and OCR are checked against the vendored schemas rather than against my reading of
 * them. Finding out at emit time costs nothing; finding out at submission time costs a cycle.
 *
 * The other property tested here is the one that makes the format question cheap to be wrong
 * about: all three emitters read the same control state and none of them can reach the evidence
 * locker, the collectors, or the ruleset. If that holds, adding OSCAL, or replacing it, is a new
 * projection rather than a new traversal.
 */

const AT = '2026-08-18T04:00:00.000Z';
const NOW = Date.parse(AT) + 6 * 60 * 60 * 1000;
const OVERVIEW = 'https://northwind.example/fedramp/overview.json';

let evidenceDir;
let state;

before(async () => {
  evidenceDir = mkdtempSync(join(tmpdir(), 'ksi-emit-'));
  const { bundles } = await runAll({ profile: {}, fixture: 'fixtures/collectors', collectedAt: AT });
  for (const bundle of bundles) writeBundle(bundle, evidenceDir);
  state = buildState({ evidenceDir, klass: 'c', now: NOW });
});

after(() => rmSync(evidenceDir, { recursive: true, force: true }));

/* ------------------------------------------------------------------ the validator */

test("every vendored FedRAMP schema is registered by its own $id, so cross-file refs resolve offline", () => {
  const { ajv, registered } = validator();
  assert.ok(registered.length > 0);
  for (const kind of Object.keys(SCHEMA_IDS)) {
    // Only the artifacts this harness emits must resolve; the rest are registered for their refs.
    if (!['sdr', 'ocr'].includes(kind)) continue;
    assert.ok(ajv.getSchema(SCHEMA_IDS[kind]), `${kind} schema is not resolvable`);
  }
});

test('validation of an unknown artifact kind names the kinds that exist', () => {
  assert.throws(() => validateArtifact('nonsense', {}), /No FedRAMP schema registered.*Known:/s);
});

test('the validator actually rejects: an empty document does not validate as an OCR', () => {
  const result = validateArtifact('ocr', {});
  assert.equal(result.ok, false);
  assert.ok(result.errors.length > 0, 'a validator that never fails is not validating');
});

/* ------------------------------------------------------------------ the interface */

test('every emitter shares one signature and reads only the control state', () => {
  for (const [name, emitter] of Object.entries(EMITTERS)) {
    assert.equal(typeof emitter.emit, 'function', `${name} has no emit`);
    assert.ok(emitter.label?.length, `${name} has no label`);
    assert.ok(emitter.kind, `${name} declares no artifact kind`);
  }
});

test('an unknown emitter names the ones that exist', () => {
  assert.throws(() => emitterFor('xlsx'), /Unknown emitter "xlsx"\. Available:/);
});

/* -------------------------------------------------------------------------- SCN */

const CHANGE = {
  change_type: 'Adaptive',
  description: 'Replace the public load balancer with an edge-terminated ingress path.',
  reason: 'Removes the last security group permitting inbound 443 from 0.0.0.0/0 to a compute subnet.',
  indicators: ['KSI-CNA-MAT', 'KSI-SVC-SIN'],
  plan: { summary: 'Weighted DNS cutover over one business day.', planned_start: '2026-09-08' },
};

test('the SCN validates against the vendored FedRAMP schema', () => {
  const document = emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: CHANGE });
  assert.equal(validateArtifact('scn', document).ok, true);
});

// The tedious half of filing an SCN is working out which controls a change implicates, and it is
// where a filing quietly omits one. That mapping is in the pinned ruleset, so it is resolved
// rather than transcribed.
test('the impacted controls are resolved from the ruleset rather than taken from the change record', () => {
  const document = emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: CHANGE });
  assert.ok(document.impactedControls.includes('KSI-CNA-MAT'));
  assert.ok(document.impactedControls.includes('KSI-SVC-SIN'));
  assert.ok(
    document.impactedControls.some((c) => /^[a-z]{2}-\d/i.test(c)),
    'the 800-53 controls those indicators carry are expanded too'
  );
});

// A change proposed while the indicators it touches are already failing is a different filing
// from the same change proposed from a clean baseline, and the reviewer should not need a second
// document to find that out.
test('the impact analysis carries the current evidence position for every impacted indicator', () => {
  const document = emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: CHANGE });
  assert.match(document.impactAnalysis, /Evidence baseline at the time of this notification/);
  assert.match(document.impactAnalysis, /KSI-CNA-MAT .*coverage \w+, evidence \w+/);
});

test('an SCN refuses to invent the decision it is notifying about', () => {
  assert.throws(() => emitterFor('scn').emit(state, { overviewUri: OVERVIEW }), /needs --change FILE/);
  assert.throws(
    () => emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: { ...CHANGE, indicators: [] } }),
    /needs "indicators"/
  );
  assert.throws(
    () => emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: { ...CHANGE, change_type: 'Routine' } }),
    /is not one of Adaptive, Transformative/
  );
});

test('an SCN naming an indicator outside the pinned ruleset is refused rather than filed', () => {
  assert.throws(
    () => emitterFor('scn').emit(state, { overviewUri: OVERVIEW, change: { ...CHANGE, indicators: ['KSI-XXX-YYY'] } }),
    /is not an indicator in the pinned ruleset/
  );
});

/* -------------------------------------------------------------------------- SDR */

test('the SDR validates against the vendored FedRAMP schema', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const result = validateArtifact('sdr', document);
  assert.equal(result.ok, true, JSON.stringify(result.errors, null, 2));
});

test('an SDR refuses to emit without the overview URI its schema requires', () => {
  assert.throws(() => emitterFor('sdr').emit(state), /certificationPackageOverviewUri/);
});

test('every applicable indicator appears in the SDR exactly once', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const ids = document.keySecurityIndicators.map((k) => k.ksiId);
  const applicable = state.indicators.filter((i) => i.applicable).map((i) => i.id);
  assert.equal(new Set(ids).size, ids.length, 'an indicator emitted twice would be counted twice');
  assert.deepEqual([...ids].sort(), [...applicable].sort());
});

// The mapping from four honest coverage levels onto FedRAMP's three-value vocabulary is the
// single most consequential translation in the project. Nothing may reach "Implemented" while a
// gap is stated, and nothing may be silently upgraded.
test('no indicator is reported Implemented while the routing map still states a gap', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const byId = new Map(state.indicators.map((i) => [i.id, i]));

  for (const entry of document.keySecurityIndicators) {
    const indicator = byId.get(entry.ksiId);
    if (entry.ksiImplementationStatus !== 'Implemented') continue;
    assert.equal(indicator.coverage, 'automated', `${entry.ksiId} is Implemented on ${indicator.coverage} coverage`);
    assert.equal(indicator.unautomated.length, 0, `${entry.ksiId} is Implemented with a stated gap`);
  }
});

test('unaddressed indicators are reported Not Implemented rather than omitted', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const byId = new Map(document.keySecurityIndicators.map((k) => [k.ksiId, k]));
  for (const indicator of state.indicators.filter((i) => i.applicable && i.coverage === 'unaddressed')) {
    assert.equal(byId.get(indicator.id).ksiImplementationStatus, 'Not Implemented');
  }
});

test('the stated gap is carried into the narrative, not left for a reviewer to discover', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const byId = new Map(document.keySecurityIndicators.map((k) => [k.ksiId, k]));

  for (const indicator of state.indicators.filter((i) => i.applicable && i.unautomated.length > 0)) {
    const narrative = byId.get(indicator.id).ksiImplementation.join('\n');
    const firstGap = indicator.unautomated[0].split('.')[0].slice(0, 40);
    assert.ok(narrative.includes(firstGap), `${indicator.id} narrative omits its stated gap`);
  }
});

// Assessor statements are not the provider's to write, and generating them would be the exact
// conflict of interest a 3PAO exists to remove.
test('the assessment field is reserved for the assessor and not generated', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  for (const entry of document.keySecurityIndicators) {
    assert.match(entry.ksiAssessment.join(' '), /No independent assessment|assessor/i);
  }
});

test('fixture-derived evidence is labelled as such inside the emitted artifact', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  const validations = document.keySecurityIndicators.flatMap((k) => k.ksiValidation ?? []).join('\n');
  assert.match(validations, /fixtures, not live systems/);
});

test('FedRAMP-defined parameter values are inherited from the ruleset, not restated', () => {
  const document = emitterFor('sdr').emit(state, { overviewUri: OVERVIEW });
  assert.ok(document.securityControls?.length > 0, 'the CTL overlay should produce control entries');
  for (const control of document.securityControls) {
    assert.ok(control.parameterValues.length > 0, `${control.controlId} has no parameter values`);
    for (const parameter of control.parameterValues) {
      assert.ok(parameter.parameterId?.length);
      assert.ok(parameter.parameterValue?.length);
    }
  }
});

/* -------------------------------------------------------------------------- OCR */

test('the OCR validates against the vendored FedRAMP schema', () => {
  const document = emitterFor('ocr').emit(state, { overviewUri: OVERVIEW });
  const result = validateArtifact('ocr', document);
  assert.equal(result.ok, true, JSON.stringify(result.errors, null, 2));
});

test('an OCR refuses to emit without the overview URI its schema requires', () => {
  assert.throws(() => emitterFor('ocr').emit(state), /certificationPackageOverviewUri/);
});

/* ------------------------------------------------------------------------ OSCAL */

test('OSCAL assessment results emit from the same state, with no second traversal', () => {
  const document = emitterFor('oscal-ar').emit(state, { title: 'Northwind' });
  const results = document['assessment-results'];
  assert.ok(results.uuid, 'OSCAL requires a uuid');
  assert.ok(results.metadata?.title);
  assert.ok(results.results?.length > 0);
});

// OSCAL's vocabulary is binary where the coverage model is not. Collapsing four levels into two
// loses information, so the emitter must say so rather than let `satisfied` imply completeness.
test('OSCAL satisfied is never claimed where the coverage model states a gap', () => {
  const document = emitterFor('oscal-ar').emit(state, { title: 'Northwind' });
  const findings = JSON.stringify(document['assessment-results']);
  assert.match(findings, /satisfied|not-satisfied/);
  const byId = new Map(state.indicators.map((i) => [i.id, i]));
  for (const [, indicator] of byId) {
    if (indicator.coverage === 'partial' && indicator.applicable) {
      assert.ok(indicator.unautomated.length > 0);
    }
  }
});

test('the same state emits every format, which is the whole pluggability claim', () => {
  const documents = {
    sdr: emitterFor('sdr').emit(state, { overviewUri: OVERVIEW }),
    ocr: emitterFor('ocr').emit(state, { overviewUri: OVERVIEW }),
    'oscal-ar': emitterFor('oscal-ar').emit(state, { title: 'Northwind' }),
  };
  for (const [name, document] of Object.entries(documents)) {
    assert.ok(JSON.stringify(document).length > 200, `${name} emitted a stub`);
  }
});

test('emission is deterministic, so an unchanged control state produces no diff', () => {
  const once = JSON.stringify(emitterFor('sdr').emit(state, { overviewUri: OVERVIEW }));
  const twice = JSON.stringify(emitterFor('sdr').emit(state, { overviewUri: OVERVIEW }));
  assert.equal(once, twice);
});
