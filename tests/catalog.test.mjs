import assert from 'node:assert/strict';
import { test } from 'node:test';

import { catalog, controlIndex, controlOverlay, normaliseControlId, resolveIndicator, themes } from '../src/catalog/ksi.mjs';
import { definitions, loadPin, loadRules, requirements, rulesProvenance } from '../src/catalog/rules.mjs';

/**
 * These tests assert against the *pinned* ruleset, not against numbers I remember reading.
 *
 * That distinction matters for the drift story. When FedRAMP publishes a new consolidated
 * ruleset, `npm run vendor:sync` changes the pin and some of these assertions change with it.
 * That is the intended behaviour: the test suite is one of the places the harness notices that
 * the ground moved, and a suite written to be indifferent to the ruleset version would notice
 * nothing.
 */

test('the vendored ruleset is pinned by hash and the pin matches the file on disk', () => {
  const pin = loadPin();
  const provenance = rulesProvenance();
  assert.match(provenance.sha256, /^[0-9a-f]{64}$/);
  assert.equal(provenance.sha256, pin.sources.rules.sha256);
  assert.ok(provenance.version, 'the ruleset must carry a version');
});

test('the ruleset parses and carries the KSI section', () => {
  const rules = loadRules();
  assert.ok(rules.KSI, 'FedRAMP publishes indicators under a KSI key');
  assert.ok(Object.keys(rules.KSI).length >= 10, 'there should be at least ten themes');
});

/* --------------------------------------------------------------------- indicators */

test('Class C resolves the full mandatory indicator set', () => {
  const { indicators, counts } = catalog({ klass: 'c' });
  assert.equal(indicators.length, counts.total);
  assert.equal(counts.applicable, indicators.filter((i) => i.applicable).length);
  assert.ok(counts.applicable >= 40, `expected a substantial indicator set, got ${counts.applicable}`);
});

test('every indicator has an id, a name and the text of the claim', () => {
  for (const indicator of catalog({ klass: 'c' }).indicators) {
    assert.match(indicator.id, /^KSI-[A-Z]{3}-[A-Z]{3}$/);
    assert.ok(indicator.name?.length, `${indicator.id} has no name`);
    assert.ok(indicator.statement?.length, `${indicator.id} has no statement`);
  }
});

test('indicator ids are unique across themes', () => {
  const ids = catalog({ klass: 'c' }).indicators.map((i) => i.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('class narrows rather than widens: Class B applicability is a subset of Class C', () => {
  const b = new Set(catalog({ klass: 'b' }).indicators.filter((i) => i.applicable).map((i) => i.id));
  const c = new Set(catalog({ klass: 'c' }).indicators.filter((i) => i.applicable).map((i) => i.id));
  for (const id of b) assert.ok(c.has(id), `${id} applies at B but not at C`);
  assert.ok(b.size <= c.size);
});

test('an indicator optional at one class is marked applicable at the class that requires it', () => {
  // KSI-CNA-EIS is optional at Class B and required at Class C in the pinned ruleset.
  const atC = resolveIndicator('KSI-CNA-EIS', { klass: 'c' });
  assert.equal(atC.applicable, true);
  assert.equal(atC.optional, false);
});

test('resolving an unknown indicator throws rather than returning an empty shell', () => {
  assert.throws(() => resolveIndicator('KSI-ZZZ-ZZZ', { klass: 'c' }), /KSI-ZZZ-ZZZ/);
});

test('themes account for every indicator and none is orphaned', () => {
  const counted = themes().reduce((n, t) => n + t.indicator_count, 0);
  assert.equal(counted, catalog({ klass: 'c' }).indicators.length);
});

/* ---------------------------------------------------------- 800-53 control bridge */

// The ruleset uses two dialects for the same control: KSI mappings use the OSCAL-style dotted
// form (ac-6.1) and the CTL section uses a dashed, zero-padded form (AC-06-01). Nothing can be
// crosswalked until those converge, so this is the first thing to pin down.
test('the two control id dialects in the ruleset normalise to one comparable form', () => {
  assert.equal(normaliseControlId('AC-2'), 'ac-2');
  assert.equal(normaliseControlId('ac-2(1)'), 'ac-2.1');
  assert.equal(normaliseControlId('AC-02(01)'), 'ac-2.1');
  assert.equal(normaliseControlId('AC-2 (1)'), 'ac-2.1');
  assert.equal(normaliseControlId('AC-06-01'), 'ac-6.1');
});

test('normalisation is idempotent, so it is safe to apply on either side of a comparison', () => {
  for (const raw of ['AC-2', 'ac-2(1)', 'AC-06-01', 'ia-5.1']) {
    assert.equal(normaliseControlId(normaliseControlId(raw)), normaliseControlId(raw));
  }
});

test('the control index maps 800-53 controls back to the indicators that touch them', () => {
  const index = controlIndex();
  assert.ok(index.size > 100, `expected a broad control mapping, got ${index.size}`);
  for (const [control, ids] of index) {
    assert.match(control, /^[a-z]{2}-\d+(\.\d+)?$/, `"${control}" is not a control id this code can normalise`);
    assert.ok(ids.length > 0);
  }
});

test('an indicator with mapped controls reports them, and they appear in the reverse index', () => {
  const indicator = resolveIndicator('KSI-IAM-ELP', { klass: 'c' });
  assert.ok(indicator.controls.length > 0, 'KSI-IAM-ELP maps to many controls');
  const index = controlIndex();
  for (const control of indicator.controls.slice(0, 5)) {
    assert.ok(index.get(control)?.includes('KSI-IAM-ELP'), `${control} does not map back to KSI-IAM-ELP`);
  }
});

test('FedRAMP parameter overlays are read from the ruleset rather than restated', () => {
  const overlay = controlOverlay('AC-06-01');
  assert.ok(overlay, 'AC-06-01 carries FedRAMP-defined parameters in the CTL section');
  assert.ok(overlay.parameters.length > 0);
  for (const parameter of overlay.parameters) {
    assert.ok(parameter.parameterId?.length, 'a parameter needs an id to be emitted into an SDR');
    assert.ok(parameter.value?.length, 'a parameter with no value is not an overlay');
  }
});

// This is the crosswalk working: an indicator cites ac-6.1, the overlay lives under AC-06-01,
// and the ODP reaches the emitted SDR only because both forms resolve to the same control.
test('an overlay resolves from either id dialect to the same control', () => {
  assert.equal(controlOverlay('ac-6.1')?.control_id, 'AC-06-01');
  assert.equal(controlOverlay('AC-6(1)')?.control_id, 'AC-06-01');
  assert.deepEqual(controlOverlay('ac-6.1'), controlOverlay('AC-06-01'));
});

test('a control with no FedRAMP overlay returns nothing rather than an empty overlay', () => {
  assert.equal(controlOverlay('ZZ-99'), null);
});

/* ------------------------------------------------------------------- requirements */

test('FRR requirements are addressable by process and framework', () => {
  const certification = requirements('FRC', { framework: '20x' });
  assert.ok(certification.length > 0, 'the certification process publishes requirements');
  for (const requirement of certification) {
    assert.ok(requirement.id?.length);
    assert.equal(requirement.process, 'FRC');
  }
});

// Some certification requirements say different things at different classes. Asked without a
// class they resolve to no statement at all, which is the honest answer: there is no class-free
// version of the requirement. Anything generating package text has to supply the class or it
// will silently emit a requirement with no content.
test('class-varying requirements have no statement until a class is supplied', () => {
  const unresolved = requirements('FRC', { framework: '20x' }).filter((r) => r.varies_by_class);
  assert.ok(unresolved.length > 0, 'the certification process has class-varying requirements');
  for (const requirement of unresolved) {
    assert.equal(requirement.statement, undefined, `${requirement.id} invented a class-free statement`);
  }

  const atC = requirements('FRC', { framework: '20x', klass: 'c' });
  for (const requirement of atC) {
    assert.ok(requirement.statement?.length, `${requirement.id} has no statement even at Class C`);
  }
});

test('an unknown FRR process names the ones that exist instead of returning nothing', () => {
  assert.throws(() => requirements('fedramp-certification'), /No FRR process.*Known:/s);
});

// MUST, SHOULD and MAY decide whether a gap is a finding or a preference, so the field has to
// survive flattening.
test('requirement force is preserved so a finding can be told from a preference', () => {
  const forces = new Set(requirements('FRC', { framework: '20x' }).map((r) => r.force).filter(Boolean));
  assert.ok(forces.size > 0, 'requirements carry a force');
});

test('definitions resolve the vocabulary the rules are written in, keyed by term', () => {
  const defs = definitions();
  assert.ok(defs instanceof Map);
  assert.ok(defs.size > 0);
  // Indicator text leans on FedRAMP's narrower meaning of ordinary-looking words, so lookups
  // are case-insensitive by term rather than by FRD id.
  const persistently = defs.get('persistently');
  assert.ok(persistently?.definition?.length, 'FedRAMP defines "persistently" and indicators rely on it');
});
