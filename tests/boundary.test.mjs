import assert from 'node:assert/strict';
import { test } from 'node:test';

import { attribute, loadBoundary, partition, withinBoundary } from '../src/boundary/boundary.mjs';
import { gradeAttribution } from '../src/collectors/boundary/attribution.mjs';
import { buildBundle } from '../src/evidence/bundle.mjs';

/**
 * A boundary drawn around a product mode rather than a network perimeter.
 *
 * The state these tests exist for is the third one. In and out are easy; a resource nobody
 * has attributed is the state that grows silently, because nobody adds a label to a resource
 * they forgot they created — and it is the state where "is this in the authorization" has no
 * answer.
 */

const PROFILE = {
  boundary: {
    description: 'TTS and STT, zero-retention mode only.',
    selector: { gcp_label: 'fedramp-boundary', aws_tag: 'FedRAMPBoundary', in_values: [true, 'in-scope'], out_values: [false] },
    in_scope: [{ id: 'tts', name: 'Text to Speech', condition: 'Zero retention mode only' }],
    out_of_scope: [
      { id: 'telephony', name: 'Telephony', excluded_by: 'Not deployed.', attested_by: 'Platform lead' },
    ],
  },
};

const boundary = loadBoundary(PROFILE);

const bundle = (graded) =>
  buildBundle({
    checkId: 'boundary.scope.attribution',
    ksis: ['KSI-PIY-GIV'],
    collectorPath: 'src/collectors/boundary/attribution.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-18T04:00:00.000Z',
    assertion: 'test',
    scope: {},
    items: graded.items,
    population: graded.population,
  });

/* ------------------------------------------------------------------- the model */

test('a resource is placed in exactly one of three states, across either provider', () => {
  assert.equal(attribute({ labels: { 'fedramp-boundary': 'true' } }, boundary).state, 'in');
  assert.equal(attribute({ labels: { 'fedramp-boundary': 'in-scope' } }, boundary).state, 'in');
  assert.equal(attribute({ tags: { FedRAMPBoundary: 'true' } }, boundary).state, 'in', 'the AWS tag works too');
  assert.equal(attribute({ labels: { 'fedramp-boundary': 'false' } }, boundary).state, 'out');
  assert.equal(attribute({ labels: { env: 'prod' } }, boundary).state, 'unattributed');
});

// Somebody labelled it and used a value the profile does not define. That is the same
// "nobody has decided this" problem wearing a typo, and it must not resolve to either side.
test('a selector value the profile does not define is unattributed, not a default', () => {
  const verdict = attribute({ labels: { 'fedramp-boundary': 'maybe' } }, boundary);
  assert.equal(verdict.state, 'unattributed');
  assert.match(verdict.reason, /is not one the profile defines/);
});

test('partitioning keeps the three sets disjoint and complete', () => {
  const resources = [
    { id: 'a', labels: { 'fedramp-boundary': 'true' } },
    { id: 'b', labels: { 'fedramp-boundary': 'false' } },
    { id: 'c', labels: {} },
  ];
  const parts = partition(resources, boundary);
  assert.deepEqual(parts.in.map((r) => r.id), ['a']);
  assert.deepEqual(parts.out.map((r) => r.id), ['b']);
  assert.deepEqual(parts.unattributed.map((r) => r.id), ['c']);
  assert.equal(parts.in.length + parts.out.length + parts.unattributed.length, resources.length);
});

// The filter must not be where unattributed resources disappear. The collector that
// enumerated them is often the only thing that will ever see them.
test('filtering to the boundary carries unattributed resources through rather than dropping them', () => {
  const resources = [
    { id: 'a', labels: { 'fedramp-boundary': 'true' } },
    { id: 'b', labels: { 'fedramp-boundary': 'false' } },
    { id: 'c', labels: {} },
  ];
  const { graded, excluded, unattributed } = withinBoundary(resources, boundary);
  assert.deepEqual(graded.map((r) => r.id), ['a', 'c']);
  assert.deepEqual(excluded.map((r) => r.id), ['b']);
  assert.deepEqual(unattributed.map((r) => r.id), ['c']);
});

test('with no boundary declared, every resource is graded and nothing is silently excluded', () => {
  const resources = [{ id: 'a' }, { id: 'b' }];
  const { graded, excluded } = withinBoundary(resources, null);
  assert.equal(graded.length, 2);
  assert.equal(excluded.length, 0);
});

/* ------------------------------------------------------------- the declaration */

test('an incomplete boundary declaration is refused rather than defaulted', () => {
  assert.equal(loadBoundary({}), null, 'no boundary at all is a legitimate state');
  assert.throws(() => loadBoundary({ boundary: { selector: { gcp_label: 'x' }, in_scope: [{ id: 'a', name: 'A' }] } }), /description is required/);
  assert.throws(
    () => loadBoundary({ boundary: { description: 'd', selector: {}, in_scope: [{ id: 'a', name: 'A' }] } }),
    /needs at least one of gcp_label or aws_tag/
  );
  assert.throws(() => loadBoundary({ boundary: { description: 'd', selector: { gcp_label: 'x' }, in_scope: [] } }), /at least one capability/);
});

// No cloud API confirms a product feature is off. An exclusion without a named attester is
// an assertion nobody owns, which is the same failure the manual coverage level guards.
test('an out-of-scope capability without a named attester is refused', () => {
  assert.throws(
    () =>
      loadBoundary({
        boundary: {
          description: 'd',
          selector: { gcp_label: 'x' },
          in_scope: [{ id: 'a', name: 'A' }],
          out_of_scope: [{ id: 'b', name: 'B', excluded_by: 'off by default' }],
        },
      }),
    /needs excluded_by and attested_by/
  );
});

/* ------------------------------------------------------------------ the check */

test('an unattributed resource fails, because its membership depends on who is asked', () => {
  const graded = gradeAttribution(
    [
      { id: 'gcs/audio', capability: 'tts', labels: { 'fedramp-boundary': 'true' } },
      { id: 'gcs/orphan', labels: { env: 'prod' } },
    ],
    boundary
  );
  const orphan = graded.items.find((i) => i.id === 'resource/gcs/orphan');
  assert.equal(orphan.status, 'fail');
  assert.match(orphan.detail, /depends on who is asked/);
  assert.equal(bundle(graded).result, 'fail');
});

// The gap no per-resource item would surface: the boundary names a capability and nothing
// in the estate is attributed to it.
test('a declared capability with no attributed resource fails on its own terms', () => {
  const graded = gradeAttribution([], boundary);
  const capability = graded.items.find((i) => i.id === 'capability/tts');
  assert.equal(capability.status, 'fail');
  assert.match(capability.detail, /no enumerated resource is attributed to it/);
});

test('out-of-scope capabilities are recorded with their attester and kept out of the pass rate', () => {
  const graded = gradeAttribution([{ id: 'a', capability: 'tts', labels: { 'fedramp-boundary': 'true' } }], boundary);
  const telephony = graded.items.find((i) => i.id === 'capability/telephony');
  assert.equal(telephony.status, 'not-applicable');
  assert.match(telephony.detail, /Attested by Platform lead/);
  assert.match(telephony.detail, /stated exclusion rather than a tested one/);
});

test('a resource outside the boundary leaves the assessment surface rather than passing', () => {
  const graded = gradeAttribution(
    [
      { id: 'a', capability: 'tts', labels: { 'fedramp-boundary': 'true' } },
      { id: 'b', labels: { 'fedramp-boundary': 'false' } },
    ],
    boundary
  );
  assert.equal(graded.items.find((i) => i.id === 'resource/b').status, 'not-applicable');
  assert.equal(bundle(graded).result, 'pass', 'an out-of-scope resource is not a finding');
});

test('the denominator is the declared capabilities plus the enumerated estate', () => {
  const graded = gradeAttribution([{ id: 'a', capability: 'tts', labels: { 'fedramp-boundary': 'true' } }], boundary, {
    unexamined: [{ id: 'project/x', reason: 'PERMISSION_DENIED enumerating resources' }],
  });
  const b = bundle(graded);
  assert.equal(b.population.expected, 4, '1 in-scope capability + 1 out-of-scope + 1 resource + 1 unexamined');
  assert.equal(b.population.complete, false);
  assert.match(b.population.reconciliation, /project\/x/);
});
