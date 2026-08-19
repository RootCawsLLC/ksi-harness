import assert from 'node:assert/strict';
import { test } from 'node:test';

import { catalog } from '../src/catalog/ksi.mjs';
import { ALL_CHECKS, CHECK_IDS, duplicateCheckIds } from '../src/collectors/registry.mjs';
import { CADENCES, COVERAGE_LEVELS, checkToIndicators, loadRoutes, validateRoutes } from '../src/routes/routes.mjs';
import { resolveSufficiency } from '../src/routes/sufficiency.mjs';

/**
 * The routing map is where this project is most able to lie to itself, so it gets the strictest
 * tests. Two failure modes are worth more than all the others:
 *
 *  - claiming a check that no collector implements, which manufactures coverage out of intent
 *  - claiming a coverage level without the argument that level requires, which is how "partial"
 *    quietly reads as "done" to anyone scanning a table
 *
 * The validator refuses both. These tests confirm it refuses them, using synthetic routes rather
 * than the real map, because a test that only ever sees a valid map cannot tell whether the
 * validator works or is simply silent.
 */

const KNOWN_CHECK = [...CHECK_IDS][0];

/** A minimal valid route of each coverage level, to mutate in the negative cases below. */
const valid = {
  // Sufficiency is a mapping rather than prose alone: the argument has to say which boundary it
  // is an argument about, and the route stays honest on boundaries the condition does not cover.
  automated: {
    coverage: 'automated',
    cadence: 'daily',
    checks: [KNOWN_CHECK],
    sufficiency: { holds_when: { providers_within: ['gcp'] }, argument: 'It settles the claim.' },
    unautomated: ['On a boundary the condition does not cover, this is what is missing.'],
  },
  partial: { coverage: 'partial', cadence: 'daily', checks: [KNOWN_CHECK], unautomated: ['The rest is not automated.'] },
  manual: {
    coverage: 'manual',
    cadence: 'annual',
    checks: [],
    manual_evidence: { owner: 'Someone', artifact: 'A review', why_not_automated: 'It is a judgement.' },
  },
  unaddressed: { coverage: 'unaddressed', checks: [], reason: 'Not built yet.', next: 'Build it.' },
};

/** Validates a single indicator's route in isolation, ignoring the "every indicator needs one" rule. */
function validateOne(id, route) {
  const result = validateRoutes({ routes: { [id]: { id, checks: [], unautomated: [], ...route } }, klass: 'c' });
  return result.errors.filter((e) => e.startsWith(id));
}

/* ------------------------------------------------------------------ the real map */

test('the shipped routing map is valid for Class C', () => {
  const result = validateRoutes({ routes: loadRoutes(), klass: 'c' });
  assert.deepEqual(result.errors, [], 'the routing map must validate or the coverage report is not trustworthy');
  assert.equal(result.ok, true);
});

test('every applicable Class C indicator has a route, so no gap is merely forgotten', () => {
  const routes = loadRoutes();
  const missing = catalog({ klass: 'c' })
    .indicators.filter((i) => i.applicable)
    .map((i) => i.id)
    .filter((id) => !routes[id]);
  assert.deepEqual(missing, []);
});

test('no route claims a check that no collector implements', () => {
  const claimed = [...new Set(Object.values(loadRoutes()).flatMap((r) => r.checks))];
  assert.deepEqual(claimed.filter((c) => !CHECK_IDS.has(c)), []);
});

test('every implemented check is claimed by at least one route', () => {
  const index = checkToIndicators(loadRoutes());
  const orphans = [...CHECK_IDS].filter((c) => !index.has(c));
  assert.deepEqual(orphans, [], 'a check nobody claims is evidence collected for nothing');
});

test('the reverse index is many-to-many, because one check can support several indicators', () => {
  const index = checkToIndicators(loadRoutes());
  const shared = [...index.values()].filter((ids) => ids.length > 1);
  assert.ok(shared.length > 0, 'a KSI is broad enough that checks are reused across indicators');
});

test('no route declares the same check twice', () => {
  for (const [id, route] of Object.entries(loadRoutes())) {
    assert.equal(new Set(route.checks).size, route.checks.length, `${id} repeats a check`);
  }
});

test('every declared cadence is in the vocabulary', () => {
  for (const [id, route] of Object.entries(loadRoutes())) {
    if (route.cadence === undefined) continue;
    assert.ok(route.cadence in CADENCES, `${id} claims unknown cadence "${route.cadence}"`);
  }
});

/**
 * This used to assert that nothing was automated, which was true and became the wrong assertion.
 *
 * The zero was never the property worth protecting; it was a symptom of the real one — that
 * `automated` costs a written argument nobody could produce. When it turned out the argument was
 * unwritable because sufficiency is boundary-dependent and the map declared it globally, the fix
 * made one indicator promotable. Keeping the old assertion would have meant either reverting a
 * correct change or deleting the test that guards the honesty.
 *
 * So it now asserts the thing the zero stood for: **no route claims sufficiency unconditionally,
 * and every route that claims it stays honest where the condition does not hold.**
 */
test('every automated route names the boundary its argument holds for, and its gap elsewhere', () => {
  const routes = Object.entries(loadRoutes());
  for (const [, route] of routes) assert.ok(COVERAGE_LEVELS.includes(route.coverage));

  const automated = routes.filter(([, r]) => r.coverage === 'automated');
  for (const [id, route] of automated) {
    assert.ok(route.sufficiency?.argument, `${id}: automated without a written argument`);
    assert.ok(
      Object.keys(route.sufficiency?.holds_when ?? {}).length,
      `${id}: claims sufficiency for every boundary, which is the assumption that made the argument unwritable`
    );
    assert.ok(
      route.unautomated?.length,
      `${id}: no gap stated for boundaries the condition does not cover, where this resolves to partial`
    );
  }
});

// The headline stays honest by default. Resolution is conservative when it cannot be performed,
// so a report run without a profile credits nothing it could not confirm applies.
test('with no profile, nothing resolves to automated however it is declared', () => {
  const routes = loadRoutes();
  for (const [id, route] of Object.entries(routes)) {
    assert.notEqual(resolveSufficiency(route, null).coverage, 'automated', `${id} resolved automated with no profile`);
  }
});

/* --------------------------------------------------------- the validator's teeth */

test('a check no collector implements is rejected', () => {
  const errors = validateOne('KSI-IAM-ELP', { ...valid.partial, checks: ['aws.invented.check'] });
  assert.match(errors.join('\n'), /no collector implements/);
});

test('automated coverage without a sufficiency argument is rejected', () => {
  const { sufficiency, ...withoutArgument } = valid.automated;
  assert.match(validateOne('KSI-IAM-ELP', withoutArgument).join('\n'), /requires a "sufficiency" argument/);
});

test('automated coverage with no checks is rejected', () => {
  assert.match(validateOne('KSI-IAM-ELP', { ...valid.automated, checks: [] }).join('\n'), /with no checks/);
});

test('partial coverage without a stated gap is rejected', () => {
  const { unautomated, ...withoutGap } = valid.partial;
  assert.match(validateOne('KSI-IAM-ELP', withoutGap).join('\n'), /requires "unautomated"/);
});

test('partial coverage with no checks is rejected, because that is unaddressed', () => {
  assert.match(validateOne('KSI-IAM-ELP', { ...valid.partial, checks: [] }).join('\n'), /the level is "unaddressed"/);
});

test('manual coverage needs an owner, an artifact and a reason', () => {
  for (const field of ['owner', 'artifact', 'why_not_automated']) {
    const manual_evidence = { ...valid.manual.manual_evidence };
    delete manual_evidence[field];
    assert.match(
      validateOne('KSI-CED-RAT', { ...valid.manual, manual_evidence }).join('\n'),
      new RegExp(`manual_evidence\\.${field}`)
    );
  }
});

test('manual coverage that also declares checks is rejected, because that is partial', () => {
  assert.match(
    validateOne('KSI-CED-RAT', { ...valid.manual, checks: [KNOWN_CHECK] }).join('\n'),
    /Use "partial" when automation contributes/
  );
});

test('unaddressed coverage needs both a reason and a named next step', () => {
  const { next, ...withoutNext } = valid.unaddressed;
  assert.match(validateOne('KSI-CNA-IBP', withoutNext).join('\n'), /requires "next"/);
  const { reason, ...withoutReason } = valid.unaddressed;
  assert.match(validateOne('KSI-CNA-IBP', withoutReason).join('\n'), /requires a "reason"/);
});

test('an unknown coverage level is rejected', () => {
  assert.match(validateOne('KSI-IAM-ELP', { coverage: 'mostly-fine' }).join('\n'), /is not one of/);
});

test('an unknown cadence is rejected', () => {
  assert.match(validateOne('KSI-IAM-ELP', { ...valid.partial, cadence: 'occasionally' }).join('\n'), /cadence/);
});

test('a route for an indicator outside the ruleset is rejected', () => {
  const result = validateRoutes({ routes: { 'KSI-ZZZ-ZZZ': { id: 'KSI-ZZZ-ZZZ', coverage: 'partial', checks: [] } } });
  assert.match(result.errors.join('\n'), /is not an indicator in the pinned ruleset/);
});

test('every valid shape passes, so the validator is strict rather than merely noisy', () => {
  assert.deepEqual(validateOne('KSI-IAM-ELP', valid.automated), []);
  assert.deepEqual(validateOne('KSI-IAM-ELP', valid.partial), []);
  assert.deepEqual(validateOne('KSI-CED-RAT', valid.manual), []);
  assert.deepEqual(validateOne('KSI-CNA-IBP', valid.unaddressed), []);
});

/* ------------------------------------------------------------------- the registry */

test('check ids are unique across collectors, so evidence is never ambiguous', () => {
  assert.deepEqual(duplicateCheckIds(), []);
});

test('every registered check declares indicators, a fixture and an assertion', () => {
  for (const check of ALL_CHECKS) {
    assert.match(check.id, /^[a-z0-9]+(\.[a-z0-9-]+){2,}$/, `${check.id} is not provider.domain.slug`);
    assert.ok(check.ksis?.length, `${check.id} maps to no indicator`);
    assert.ok(check.assertion?.length, `${check.id} states no assertion`);
    assert.ok(check.fixture?.length, `${check.id} has no fixture, so it cannot be demonstrated offline`);
  }
});

test('every indicator a check claims exists in the catalog', () => {
  const known = new Set(catalog({ klass: 'c' }).indicators.map((i) => i.id));
  for (const check of ALL_CHECKS) {
    for (const ksi of check.ksis) assert.ok(known.has(ksi), `${check.id} claims unknown indicator ${ksi}`);
  }
});

// A check's own view of which indicators it supports and the routing map's view must agree.
// If they drift, the coverage report and the evidence bundles tell different stories about the
// same run, and the bundle is the thing an assessor reads.
test('a check and its routes agree on which indicators it supports', () => {
  const index = checkToIndicators(loadRoutes());
  for (const check of ALL_CHECKS) {
    const routed = new Set(index.get(check.id) ?? []);
    for (const ksi of check.ksis) {
      assert.ok(
        routed.has(ksi),
        `${check.id} declares ${ksi} but no route for ${ksi} claims it. Either add the check to that route or ` +
          `remove the indicator from the check.`
      );
    }
  }
});
