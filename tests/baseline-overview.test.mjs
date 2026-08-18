import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { catalog } from '../src/catalog/ksi.mjs';
import { rulesProvenance } from '../src/catalog/rules.mjs';
import { ALL_CHECKS } from '../src/collectors/registry.mjs';
import { emitterFor } from '../src/emit/index.mjs';
import { validateArtifact } from '../src/emit/validate.mjs';
import { buildBaseline } from '../src/routes/baseline.mjs';
import { loadRoutes, validateRoutes } from '../src/routes/routes.mjs';

/**
 * Two pieces that make the harness handable to someone who did not write it: a routing map a
 * new boundary can honestly start from, and the one document every other artifact points at.
 */

/* ------------------------------------------------------------------- baseline */

function parseBaseline(klass) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-baseline-'));
  const path = join(dir, 'routes.baseline.yaml');
  writeFileSync(path, buildBaseline({ klass, now: new Date('2026-08-18T00:00:00Z') }));
  const routes = loadRoutes({ path });
  rmSync(dir, { recursive: true, force: true });
  return routes;
}

test('the baseline declares every applicable indicator and validates as a routing map', () => {
  for (const klass of ['a', 'b', 'c']) {
    const routes = parseBaseline(klass);
    const applicable = catalog({ klass }).indicators.filter((i) => i.applicable);
    for (const indicator of applicable) {
      assert.ok(routes[indicator.id], `${indicator.id} applies at Class ${klass} and the baseline omits it`);
    }
    const result = validateRoutes({ routes, klass });
    assert.equal(result.ok, true, `Class ${klass}: ${result.errors.join('; ')}`);
  }
});

// The whole point: a new adopter starts from "nothing has been assessed", which is true on
// day one, rather than from this repository's claims about a different environment.
test('every generated route is unaddressed, with the reason and next step the validator demands', () => {
  const routes = parseBaseline('c');
  for (const route of Object.values(routes)) {
    assert.equal(route.coverage, 'unaddressed', `${route.id} is not unaddressed`);
    assert.deepEqual(route.checks, [], `${route.id} claims a check`);
    assert.ok(route.reason?.length, `${route.id} has no reason`);
    assert.ok(route.next?.length, `${route.id} has no next step`);
  }
});

// A generated baseline that silently predates a ruleset bump would be describing indicators
// that have since changed, so it records what it was generated from.
test('the baseline records the ruleset it came from, so a stale one is visible', () => {
  const text = buildBaseline({ klass: 'c', now: new Date('2026-08-18T00:00:00Z') });
  const provenance = rulesProvenance();
  assert.match(text, new RegExp(provenance.version.replace(/\./g, '\\.')));
  assert.match(text, /sha256:[a-f0-9]{32}/);
  assert.match(text, /Generated: 2026-08-18/);
});

// Unclaimed checks are the backlog, and the validator naming each one is the mechanism that
// makes the backlog shrink visibly rather than being forgotten.
test('the baseline claims no check, so every implemented collector shows up as backlog', () => {
  const result = validateRoutes({ routes: parseBaseline('c'), klass: 'c' });
  const unclaimed = result.warnings.filter((w) => /is implemented but no route claims it/.test(w));
  assert.equal(unclaimed.length, ALL_CHECKS.length);
});

test('the baseline carries each indicator name and statement as comments, so the author can read what they are declaring against', () => {
  const text = buildBaseline({ klass: 'c' });
  const applicable = catalog({ klass: 'c' }).indicators.filter((i) => i.applicable);

  for (const indicator of applicable) {
    assert.ok(text.includes(`# ${indicator.name}`), `${indicator.id}: its name is not emitted as a comment`);
    // The statement is wrapped across comment lines, so match on a distinctive run of words
    // from it rather than the whole string.
    const words = indicator.statement.replace(/\s+/g, ' ').trim().split(' ').slice(0, 5).join(' ');
    assert.ok(text.includes(words), `${indicator.id}: the opening of its statement is not emitted`);
  }
  assert.ok(applicable.length >= 40, 'sanity: the catalog resolved a full class');
});

/* ------------------------------------------------------------------- overview */

const PROFILE = {
  service_name: 'Northwind Voice API',
  provider: 'Northwind Systems, Inc.',
  certification: {
    package_id: 'FR0000000000',
    service_acronym: 'NVA',
    description: 'A speech synthesis and transcription service.',
    website: 'https://northwind.example',
    logo: 'https://northwind.example/logo.png',
    service_model: ['SaaS'],
    deployment_model: 'Government Community Cloud',
    contacts: [
      { type: 'Security', name: 'Security Operations', email: 'security@northwind.example' },
      { type: 'Sales', name: 'Federal Sales', email: 'gov-sales@northwind.example' },
    ],
  },
};

test('the overview validates against the vendored FedRAMP schema', () => {
  const document = emitterFor('overview').emit(null, { profile: PROFILE });
  assert.equal(validateArtifact('overview', document).ok, true);
});

// The schema expresses this as two abstract `contains` clauses, so ajv reports it
// unhelpfully. A package rejected at submission for a missing Sales contact has cost a cycle.
test('a missing Sales contact is named rather than reported as a schema abstraction', () => {
  const profile = {
    ...PROFILE,
    certification: { ...PROFILE.certification, contacts: [{ type: 'Security', email: 'a@b.example' }] },
  };
  assert.throws(() => emitterFor('overview').emit(null, { profile }), /requires a Sales contact/);
});

test('the closed vocabularies are checked with the field named, not left to the validator', () => {
  const bad = (over) => ({ ...PROFILE, certification: { ...PROFILE.certification, ...over } });
  assert.throws(() => emitterFor('overview').emit(null, { profile: bad({ deployment_model: 'Private Cloud' }) }), /deployment_model "Private Cloud" is not one of/);
  assert.throws(() => emitterFor('overview').emit(null, { profile: bad({ service_model: ['FaaS'] }) }), /service_model "FaaS" is not one of/);
});

test('a missing required field says which field and what it is for', () => {
  const without = { ...PROFILE, certification: { ...PROFILE.certification, logo: undefined } };
  assert.throws(() => emitterFor('overview').emit(null, { profile: without }), /needs certification\.logo/);
  assert.throws(() => emitterFor('overview').emit(null, {}), /requires --profile/);
});

// MAS-CSO-TPR. A non-certified dependency inside a package targeting certification is the
// thing that surfaces late and expensively.
test('third-party resources are split by certification status, because those are different risks', () => {
  const profile = {
    ...PROFILE,
    certification: {
      ...PROFILE.certification,
      third_party: {
        certified: [{ id: 'FR1805751477', use_case: 'Primary compute.' }],
        non_certified: [{ name: 'Atlas', provider: 'MongoDB', use_case: 'Tenant metadata.' }],
      },
    },
  };
  const document = emitterFor('overview').emit(null, { profile });
  assert.equal(document.thirdPartyInformationResources.certified[0].fedRampCertifiedThirdPartyInformationResource, 'FR1805751477');
  assert.equal(document.thirdPartyInformationResources.nonCertified[0].name, 'Atlas');
  assert.equal(validateArtifact('overview', document).ok, true);
});

// The overview is a declaration, not an observation. It must never claim to have been
// derived from collected evidence.
test('the overview reads only the profile and never the evidence state', () => {
  const document = emitterFor('overview').emit(
    { indicators: [], counts: {}, ruleset: {} },
    { profile: PROFILE }
  );
  assert.equal(document.serviceIdentification.serviceName, 'Northwind Voice API');
  assert.equal(document.certifiedServices, undefined, 'nothing is invented from an empty state');
});
