import assert from 'node:assert/strict';
import { test } from 'node:test';

import { compare } from '../scripts/lockfile-classes.mjs';

/**
 * The defect these pin was observed twice, at two versions, from the same source.
 *
 * Dependabot's lockfile regeneration writes `@aws-sdk/client-sts` into the root lockfile's
 * `dependencies` while `package.json` declares it only under `optionalDependencies` — where the
 * lockfile also still declares it. It arrived on #31 at 3.1116.0, was removed by #33, and came
 * back identically on #35 at 3.1124.0.
 *
 * The reason it needs a check rather than review discipline: the package *set* is unchanged, so
 * every supply-chain comparison that asks "what was added or removed" is structurally blind to
 * it. Three such checks passed on both PRs.
 */

const lock = (root) => ({ packages: { '': root } });

test('a lockfile that agrees with its manifest reports nothing', () => {
  const manifest = { dependencies: { ajv: '^8.17.1' }, optionalDependencies: { '@aws-sdk/client-sts': '^3.1124.0' } };
  const l = lock({ dependencies: { ajv: '^8.17.1' }, optionalDependencies: { '@aws-sdk/client-sts': '^3.1124.0' } });
  assert.deepEqual(compare(manifest, l, '.'), []);
});

// The exact shape of #31 and #35: present in both classes in the lockfile, one in the manifest.
test('the observed defect is reported, and as two distinct problems', () => {
  const manifest = { dependencies: { ajv: '^8.17.1' }, optionalDependencies: { '@aws-sdk/client-sts': '^3.1124.0' } };
  const l = lock({
    dependencies: { '@aws-sdk/client-sts': '3.1124.0', ajv: '^8.17.1' },
    optionalDependencies: { '@aws-sdk/client-sts': '^3.1124.0' },
  });

  const problems = compare(manifest, l, '.');
  assert.equal(problems.length, 2, 'being in two classes and disagreeing with the manifest are different faults');
  assert.ok(problems.some((p) => /under dependencies and optionalDependencies at once/.test(p)));
  assert.ok(problems.some((p) => /package\.json declares it only under optionalDependencies/.test(p)));
});

/**
 * Recorded as a list rather than overwritten. Collapsing a package's classes to the last one seen
 * would make the two-class case — which is the defect itself — indistinguishable from a correct
 * single-class declaration.
 */
test('a package in two lockfile classes is caught even when the manifest agrees with one of them', () => {
  const manifest = { dependencies: { x: '1.0.0' } };
  const l = lock({ dependencies: { x: '1.0.0' }, devDependencies: { x: '1.0.0' } });
  assert.ok(compare(manifest, l, '.').some((p) => /under dependencies and devDependencies at once/.test(p)));
});

test('a package the lockfile carries and the manifest does not is reported', () => {
  const problems = compare({ dependencies: {} }, lock({ dependencies: { 'left-pad': '1.3.0' } }), '.');
  assert.equal(problems.length, 1);
  assert.match(problems[0], /left-pad .* not in package\.json at all/);
});

test('a package the manifest declares and the lockfile omits is reported', () => {
  const problems = compare({ dependencies: { ajv: '^8.17.1' } }, lock({ dependencies: {} }), '.');
  assert.equal(problems.length, 1);
  assert.match(problems[0], /ajv is in package\.json .* missing from the lockfile/);
});

// devDependencies and optionalDependencies are separate classes, not decoration: a runtime
// dependency recorded as a dev one installs differently in production.
test('moving a package between classes is a disagreement, not a match', () => {
  const manifest = { devDependencies: { typescript: '7.0.2' } };
  const l = lock({ dependencies: { typescript: '7.0.2' } });
  const problems = compare(manifest, l, 'web');
  assert.ok(problems.some((p) => /under dependencies in the lockfile but package\.json declares it only under devDependencies/.test(p)));
});

test('an empty manifest and an empty lockfile agree', () => {
  assert.deepEqual(compare({}, lock({}), '.'), []);
});

// Version drift is a different question and deliberately not this check's job — a structural
// differ covering versions, resolved hosts and install scripts is still open on #34.
test('versions are not compared, only classes', () => {
  const manifest = { dependencies: { ajv: '^8.17.1' } };
  const l = lock({ dependencies: { ajv: '^9.0.0' } });
  assert.deepEqual(compare(manifest, l, '.'), []);
});

test('a lockfile with no root package entry is refused rather than passed', () => {
  assert.throws(() => compare({}, { packages: {} }, '.'), /no root package entry/);
});
