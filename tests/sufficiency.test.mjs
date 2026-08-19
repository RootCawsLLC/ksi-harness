import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildState } from '../src/evidence/state.mjs';
import { loadRoutes, validateRoutes } from '../src/routes/routes.mjs';
import { declaredProviders, resolveSufficiency } from '../src/routes/sufficiency.mjs';

/**
 * `automated` costs a written argument that the checks leave nothing material out, and for a long
 * time nobody could write one for any of the 46. The reason turned out not to be that the evidence
 * was too weak. It was that the question was malformed: sufficiency is a property of a *boundary*,
 * and the routing map declared it as a property of an indicator.
 *
 * KSI-CNA-DFP is the case that exposed it. Its two clauses are settled for an estate whose
 * providers can enumerate their own service surface, and one of them is genuinely open for an
 * estate that includes AWS. Declared globally, the honest answer is `partial` — including for the
 * boundaries where that is demonstrably false.
 */

const AUTOMATED = {
  coverage: 'automated',
  cadence: 'daily',
  checks: ['gcp.service.surface'],
  sufficiency: { holds_when: { providers_within: ['gcp'] }, argument: 'It settles the claim.' },
  unautomated: ['On AWS the functionality clause is open.'],
};

/* ------------------------------------------------------------------- providers */

test('providers come from the declaration, not from what was collected', () => {
  assert.deepEqual([...declaredProviders({ gcp: { projects: [{ id: 'p' }] } })], ['gcp']);
  assert.deepEqual([...declaredProviders({ aws: { accounts: ['1'] }, gcp: { organization_id: 'o' } })].sort(), ['aws', 'gcp']);
  assert.equal(declaredProviders(null), null, 'no profile is distinct from an empty one');
  assert.equal(declaredProviders({}).size, 0);
});

/* ------------------------------------------------------------------ resolution */

test('the condition holds when the boundary declares nothing outside it', () => {
  const r = resolveSufficiency(AUTOMATED, { gcp: { projects: [{ id: 'p' }] } });
  assert.equal(r.status, 'holds');
  assert.equal(r.coverage, 'automated');
});

// The case the whole change exists for: one map, two boundaries, two different true answers.
test('the same route resolves to partial on a boundary the argument does not cover', () => {
  const r = resolveSufficiency(AUTOMATED, { gcp: { projects: [{ id: 'p' }] }, aws: { accounts: ['1'] } });
  assert.equal(r.status, 'fails');
  assert.equal(r.coverage, 'partial');
  assert.match(r.detail, /also declares aws/);
});

// Conservative when it cannot decide. Crediting automation you have not confirmed applies is the
// same move as calling an unchecked bucket an evidence vault.
test('an unresolvable condition reports partial rather than assuming the best case', () => {
  const r = resolveSufficiency(AUTOMATED, null);
  assert.equal(r.status, 'unresolved');
  assert.equal(r.coverage, 'partial');
  assert.match(r.detail, /could not be checked/);
});

// Vacuous truth is not evidence — the same rule the bundle contract applies to zero decidable items.
test('an empty boundary satisfies the condition only vacuously, and is refused', () => {
  const r = resolveSufficiency(AUTOMATED, {});
  assert.equal(r.status, 'fails');
  assert.equal(r.coverage, 'partial');
  assert.match(r.detail, /vacuously/);
});

test('a route that is not automated is left alone', () => {
  const r = resolveSufficiency({ coverage: 'partial' }, { gcp: { projects: [{ id: 'p' }] } });
  assert.equal(r.status, 'not-applicable');
  assert.equal(r.coverage, 'partial');
});

// Reaching this means the route bypassed validation. Report it rather than honour it.
test('sufficiency claimed with no condition is not honoured', () => {
  const r = resolveSufficiency({ coverage: 'automated', sufficiency: { argument: 'trust me' } }, { gcp: { projects: [{ id: 'p' }] } });
  assert.equal(r.coverage, 'partial');
  assert.match(r.detail, /without stating the boundary/);
});

/* ------------------------------------------------------------------ validation */

const validateOne = (id, route) => validateRoutes({ routes: { [id]: route }, klass: 'c' }).errors.filter((e) => e.startsWith(id));

test('prose alone is refused, because it does not say which boundary it argues about', () => {
  const errors = validateOne('KSI-CNA-DFP', { ...AUTOMATED, sufficiency: 'It settles the claim.' });
  assert.match(errors.join('\n'), /must be a mapping with "holds_when" and "argument"/);
});

test('a condition is required, and an unknown one is refused', () => {
  assert.match(
    validateOne('KSI-CNA-DFP', { ...AUTOMATED, sufficiency: { argument: 'x' } }).join('\n'),
    /must name the boundary the argument holds for/
  );
  assert.match(
    validateOne('KSI-CNA-DFP', { ...AUTOMATED, sufficiency: { holds_when: { phase_of_moon: ['full'] }, argument: 'x' } }).join('\n'),
    /unknown sufficiency condition "phase_of_moon"/
  );
});

// Where the condition does not hold the route *is* a partial route, and a partial with no stated
// gap reads as full coverage to anyone scanning a table.
test('an automated route without a gap for the uncovered case is refused', () => {
  const { unautomated, ...noGap } = AUTOMATED;
  assert.match(validateOne('KSI-CNA-DFP', noGap).join('\n'), /requires "unautomated" as well/);
});

test('the argument itself is still required; the condition only scopes it', () => {
  const errors = validateOne('KSI-CNA-DFP', { ...AUTOMATED, sufficiency: { holds_when: { providers_within: ['gcp'] } } });
  assert.match(errors.join('\n'), /requires an "argument"/);
});

/* ------------------------------------------------------- end to end, real routes */

test('the shipped map yields one automated indicator for a single-provider boundary and none otherwise', () => {
  const routes = loadRoutes();
  const count = (profile) =>
    buildState({ evidenceDir: '.evidence', klass: 'c', routes, profile }).indicators.filter(
      (i) => i.applicable && i.coverage === 'automated'
    ).length;

  assert.equal(count({ gcp: { projects: [{ id: 'p' }] } }), 1, 'KSI-CNA-DFP resolves automated here');
  assert.equal(count({ gcp: { projects: [{ id: 'p' }] }, aws: { accounts: ['1'] } }), 0, 'and partial once AWS is in scope');
  assert.equal(count(null), 0, 'and never without a profile to resolve against');
});

test('the resolved level is reported alongside what was declared, so neither is hidden', () => {
  const state = buildState({ evidenceDir: '.evidence', klass: 'c', profile: { aws: { accounts: ['1'] } } });
  const dfp = state.indicators.find((i) => i.id === 'KSI-CNA-DFP');
  assert.equal(dfp.declared_coverage, 'automated');
  assert.equal(dfp.coverage, 'partial');
  assert.equal(dfp.sufficiency_holds, 'fails');
  assert.ok(dfp.unautomated.length, 'and the gap it falls back to is present');
});
