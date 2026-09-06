import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ALLOWED_HOSTS, diffLockfiles, hostOf } from '../scripts/lockfile-diff.mjs';

/**
 * The rest of #34: the lockfile changes a reviewer cannot see.
 *
 * A dependency bump arrives as hundreds of lines of generated JSON, and the properties worth
 * knowing about look exactly like the rest of it. `lockfile-classes.mjs` closed the one defect that
 * had recurred; these are the three that would be invisible if they ever happened.
 */

const lock = (packages) => ({ packages });
const pkg = (over = {}) => ({
  version: '1.0.0',
  resolved: 'https://registry.npmjs.org/thing/-/thing-1.0.0.tgz',
  integrity: 'sha512-AAAA',
  ...over,
});

const kinds = (findings) => findings.map((f) => f.kind).sort();

/* ------------------------------------------------------------------ the quiet one */

/**
 * The strongest signal this can produce, and the reason the differ is worth having at all.
 *
 * A version is a claim. An integrity hash is a measurement of the artifact. The same version
 * resolving to different bytes means the published artifact was replaced, which is the shape of a
 * supply-chain compromise rather than an upgrade — and it is completely invisible in a diff, since
 * one opaque hash looks like any other.
 */
test('the same version with different bytes is reported', () => {
  const before = lock({ 'node_modules/thing': pkg({ integrity: 'sha512-AAAA' }) });
  const after = lock({ 'node_modules/thing': pkg({ integrity: 'sha512-BBBB' }) });

  const findings = diffLockfiles(before, after);
  assert.deepEqual(kinds(findings), ['integrity-changed-without-version']);
  assert.match(findings[0].detail, /published artifact was replaced/);
});

// An ordinary upgrade changes both, and must not be reported as anything.
test('a genuine version bump changing its hash is not a finding', () => {
  const before = lock({ 'node_modules/thing': pkg({ version: '1.0.0', integrity: 'sha512-AAAA' }) });
  const after = lock({ 'node_modules/thing': pkg({ version: '1.1.0', integrity: 'sha512-BBBB' }) });
  assert.deepEqual(diffLockfiles(before, after), []);
});

/* -------------------------------------------------------------------- the registry */

test('a package moving to a different registry is reported', () => {
  const before = lock({ 'node_modules/thing': pkg() });
  const after = lock({
    'node_modules/thing': pkg({ resolved: 'https://evil.example.com/thing/-/thing-1.0.0.tgz' }),
  });

  const findings = diffLockfiles(before, after);
  // Not an allowed host at all, so it is caught by the stronger of the two rules.
  assert.deepEqual(kinds(findings), ['host-not-allowed']);
  assert.match(findings[0].detail, /evil\.example\.com/);
});

/**
 * The allowlist is checked against the list rather than against the previous value, so a
 * substituted registry is caught even with no baseline — a baseline-relative rule can say nothing
 * about the first lockfile it ever sees.
 */
test('a disallowed host is caught with no baseline at all', () => {
  const after = lock({
    'node_modules/thing': pkg({ resolved: 'https://packages.internal.example/thing.tgz' }),
  });
  assert.deepEqual(kinds(diffLockfiles(null, after)), ['host-not-allowed']);
});

test('the allowed registry is not reported, however many packages use it', () => {
  const after = lock({
    'node_modules/a': pkg(),
    'node_modules/b': pkg(),
    'node_modules/c': pkg(),
  });
  assert.deepEqual(diffLockfiles(null, after), []);
  assert.deepEqual(ALLOWED_HOSTS, ['registry.npmjs.org']);
});

// `file:` links and workspace entries are not fetched over the network and have no host.
test('a link or workspace entry has no host and is not reported', () => {
  assert.equal(hostOf({ resolved: 'file:..' }), null, 'a file URL parses with an empty host');
  assert.equal(hostOf({}), null);
  // npm writes the parent link in web/package-lock.json as a bare relative path, not a URL.
  assert.equal(hostOf({ resolved: '..', link: true }), null, 'recognised by the link flag');
  const after = lock({ 'node_modules/ksi-harness': { resolved: '..', link: true } });
  assert.deepEqual(diffLockfiles(null, after), []);
});

/* --------------------------------------------------------------- install-time code */

test('a package that gains an install script is reported', () => {
  const before = lock({ 'node_modules/thing': pkg() });
  const after = lock({ 'node_modules/thing': pkg({ hasInstallScript: true }) });

  const findings = diffLockfiles(before, after);
  assert.deepEqual(kinds(findings), ['install-script-added']);
  assert.match(findings[0].detail, /gained an install script/);
});

test('a new package that runs code at install time is reported', () => {
  const findings = diffLockfiles(lock({}), lock({ 'node_modules/newthing': pkg({ hasInstallScript: true }) }));
  assert.deepEqual(kinds(findings), ['install-script-added']);
  assert.match(findings[0].detail, /is new and runs a script at install time/);
});

// Reporting every package that already has one would be a list nobody reads. The change is the
// signal, so an unchanged install script says nothing.
test('a package that always had an install script is not reported again', () => {
  const before = lock({ 'node_modules/thing': pkg({ hasInstallScript: true }) });
  const after = lock({ 'node_modules/thing': pkg({ hasInstallScript: true, version: '1.0.0' }) });
  assert.deepEqual(diffLockfiles(before, after), []);
});

/* ------------------------------------------------------------------------ shape */

/**
 * With no baseline the diff-based checks must stay silent rather than treating everything as new.
 * Manufacturing findings on a first run is how a check gets ignored on every subsequent one.
 */
test('with no baseline only the state-based check speaks', () => {
  const after = lock({
    'node_modules/a': pkg({ hasInstallScript: true }),
    'node_modules/b': pkg({ resolved: 'https://elsewhere.example/b.tgz' }),
  });
  const findings = diffLockfiles(null, after);
  assert.deepEqual(kinds(findings), ['host-not-allowed', 'install-script-added']);
});

test('an unchanged lockfile produces nothing', () => {
  const same = lock({ 'node_modules/thing': pkg(), 'node_modules/other': pkg({ version: '2.0.0' }) });
  assert.deepEqual(diffLockfiles(same, same), []);
});

test('findings carry which lockfile they came from', () => {
  const after = lock({ 'node_modules/thing': pkg({ resolved: 'https://nope.example/x.tgz' }) });
  const [finding] = diffLockfiles(null, after, 'web/package-lock.json');
  assert.equal(finding.where, 'web/package-lock.json');
  assert.equal(finding.package, 'thing');
});

/**
 * The real aws-sdk bump this issue came from. It changed 12 resolved URLs and a great many
 * versions, and none of it should trip these checks — a differ that fires on ordinary bumps is one
 * that gets switched off before it ever sees a real finding.
 */
test('an ordinary multi-package version bump is silent', () => {
  const names = ['client-sts', 'client-s3', 'client-ec2', 'client-iam'];
  const build = (version, hash) =>
    lock(
      Object.fromEntries(
        names.map((n) => [
          `node_modules/@aws-sdk/${n}`,
          pkg({
            version,
            resolved: `https://registry.npmjs.org/@aws-sdk/${n}/-/${n}-${version}.tgz`,
            integrity: `sha512-${hash}`,
          }),
        ])
      )
    );
  assert.deepEqual(diffLockfiles(build('3.1116.0', 'OLD'), build('3.1124.0', 'NEW')), []);
});
