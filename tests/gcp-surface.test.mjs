import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildBundle } from '../src/evidence/bundle.mjs';
import { gradeServiceSurface, intendedFor } from '../src/collectors/gcp/services.mjs';

/**
 * The functionality half of KSI-CNA-DFP, and the check that made the first `automated` promotion
 * possible.
 *
 * Its whole claim rests on one property: a GCP project can only be acted upon through a service
 * API that is enabled on it. So the enabled set *is* the functional surface rather than a proxy
 * for it, and comparing it against a declared surface makes "strictly defined" falsifiable.
 */

const P = 'skylark-transcribe-prod';
const bundleOf = (graded) =>
  buildBundle({
    checkId: 'gcp.service.surface',
    ksis: ['KSI-CNA-DFP'],
    collectorPath: 'src/collectors/gcp/services.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-19T12:00:00.000Z',
    assertion: 'test',
    scope: {},
    ...graded,
  });

/* -------------------------------------------------------------------- grading */

test('a service enabled and declared passes', () => {
  const g = gradeServiceSurface(['run.googleapis.com'], { projectId: P, intended: ['run.googleapis.com'] });
  assert.equal(g.items.length, 1);
  assert.equal(g.items[0].status, 'pass');
});

// The finding the check exists for.
test('a service enabled and undeclared fails, because that is functionality nobody defined', () => {
  const g = gradeServiceSurface(['run.googleapis.com', 'aiplatform.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com'],
  });
  const bad = g.items.find((i) => i.id.includes('aiplatform'));
  assert.equal(bad.status, 'fail');
  assert.match(bad.detail, /appears in no declared service surface/);
});

// The reverse, which most implementations skip. A stale document is not an exposure, so it warns
// rather than failing — but a definition that has drifted is no longer a definition of anything.
test('a service declared and not enabled warns rather than failing', () => {
  const g = gradeServiceSurface(['run.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com', 'dataflow.googleapis.com'],
  });
  const stale = g.items.find((i) => i.id.includes('dataflow'));
  assert.equal(stale.status, 'warn');
  assert.match(stale.detail, /describes an estate that is not running/);
});

test('services every project carries are filtered, because enabling them was never a decision', () => {
  const g = gradeServiceSurface(['logging.googleapis.com', 'monitoring.googleapis.com', 'run.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com'],
  });
  assert.equal(g.items.length, 1, 'only the service somebody chose to enable is graded');
  assert.equal(g.items[0].status, 'pass');
});

/* ----------------------------------------------------------------- population */

/**
 * The ordering that makes the check falsifiable at all: the denominator comes from the API, not
 * from the declaration. Counting only declared services would omit the undeclared one — which is
 * the single failure this check exists to find.
 */
test('the denominator comes from the provider, so an undeclared service cannot hide in it', () => {
  const g = gradeServiceSurface(['run.googleapis.com', 'aiplatform.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com'],
  });
  assert.equal(g.population.expected, 2, 'both enabled services are in the population, declared or not');
  assert.match(g.population.enumerated_from, /never the profile declaration/);

  const bundle = bundleOf(g);
  assert.equal(bundle.population.examined, 2);
  assert.equal(bundle.population.complete, true);
  assert.equal(bundle.result, 'fail');
});

test('the population spans both directions, so neither side shrinks it by omission', () => {
  const g = gradeServiceSurface(['run.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com', 'dataflow.googleapis.com'],
  });
  assert.equal(g.population.expected, 2, '1 enabled + 1 declared-but-absent');
  assert.equal(bundleOf(g).result, 'warn', 'a stale declaration caps the check below pass');
});

test('a project whose surface is entirely declared passes over a real population', () => {
  const g = gradeServiceSurface(['run.googleapis.com', 'speech.googleapis.com'], {
    projectId: P,
    intended: ['run.googleapis.com', 'speech.googleapis.com'],
  });
  const bundle = bundleOf(g);
  assert.equal(bundle.result, 'pass');
  assert.equal(bundle.population.decidable, 2, 'and it decided something, so the pass is earned');
});

/* -------------------------------------------------------------- the declaration */

test('a per-project surface overrides the boundary-wide one', () => {
  const profile = {
    gcp: { intended_services: ['a.googleapis.com'], projects: [{ id: P, intended_services: ['b.googleapis.com'] }] },
  };
  assert.deepEqual(intendedFor(profile, P), ['b.googleapis.com']);
  assert.deepEqual(intendedFor(profile, 'other'), ['a.googleapis.com'], 'falling back to the boundary-wide list');
  assert.equal(intendedFor({ gcp: { projects: [] } }, P), null, 'and no declaration is null, not an empty surface');
});
