import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { parse, stringify } from 'yaml';

import { accountRegions, accountScope, perAccount } from '../src/collectors/lib/aws.mjs';
import { runAll } from '../src/collectors/run-all.mjs';
import { buildBundle, stampProfile, verifyChain, verifyIntegrity } from '../src/evidence/bundle.mjs';
import {
  acceptAnchor,
  anchoredProfile,
  anchorEntry,
  appendAnchor,
  readAnchorLog,
  reconcileAgainstAnchor,
  verifyAnchorChain,
} from '../src/evidence/anchor.mjs';
import { readLocker } from '../src/evidence/locker.mjs';
import { profileSha256 } from '../src/evidence/profile.mjs';

/**
 * Every list in a profile is a denominator, and a run under a narrower one produces evidence just
 * as consistent as the run before it. These pin the three things that make a changed profile
 * visible: every bundle names the profile it was graded against, every anchor entry names the
 * profile it was collected under, and a change cannot enter the anchor log except as an
 * acceptance carrying who and why.
 */

const AT = '2026-08-18T04:00:00.000Z';
const NORTHWIND = 'examples/northwind.profile.yaml';
const PROFILE = parse(readFileSync(NORTHWIND, 'utf8'));
const temporary = [];

after(() => {
  for (const dir of temporary) rmSync(dir, { recursive: true, force: true });
});

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-profile-'));
  temporary.push(dir);
  return dir;
}

const manifest = (over = {}) => ({
  generated_at: '2026-09-05T12:00:00.000Z',
  root_sha256: 'a'.repeat(64),
  bundle_count: 4,
  checks: [{ check_id: 'github.change.pr-review', runs: 2 }],
  ...over,
});
const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

/* ------------------------------------------------------------------- the hash */

test('the profile hash ignores comments, key order and layout, and nothing else', () => {
  const text = readFileSync(NORTHWIND, 'utf8');
  const reordered = Object.fromEntries(Object.entries(PROFILE).reverse());
  assert.equal(profileSha256(parse(`# a new comment\n${text}\n\n`)), profileSha256(PROFILE));
  assert.equal(profileSha256(parse(stringify(reordered))), profileSha256(PROFILE));

  // A contact or a threshold is as much a change as a region: deciding which changes matter is
  // the judgment the acceptance exists to put in front of a person.
  const changed = structuredClone(PROFILE);
  changed.contacts.security = 'someone-else@northwind.example';
  assert.notEqual(profileSha256(changed), profileSha256(PROFILE));
  const loosened = structuredClone(PROFILE);
  loosened.aws.public_ports = [...(loosened.aws.public_ports ?? []), 22];
  assert.notEqual(profileSha256(loosened), profileSha256(PROFILE));

  assert.equal(profileSha256(null), null);
  assert.match(profileSha256({}), /^[0-9a-f]{64}$/);
});

/* -------------------------------------------------------------------- bundles */

test('every bundle a run writes names the profile it was graded against, and still verifies', async () => {
  const { bundles } = await runAll({ profile: PROFILE, fixture: 'fixtures/collectors', collectedAt: AT });
  const recorded = profileSha256(PROFILE);
  assert.ok(bundles.length > 0);
  for (const bundle of bundles) {
    assert.equal(bundle.profile_sha256, recorded, bundle.check_id);
    assert.equal(verifyIntegrity(bundle).ok, true, `${bundle.check_id} no longer verifies after stamping`);
  }
});

test('the stamp is inside the hashed body, so editing it breaks the bundle', async () => {
  const { bundles } = await runAll({ profile: PROFILE, fixture: 'fixtures/collectors', collectedAt: AT, only: ['github'] });
  const forged = { ...bundles[0], profile_sha256: B };
  assert.equal(verifyIntegrity(forged).ok, false);
});

test('a chain of stamped bundles written across runs verifies', async () => {
  const dir = scratch();
  await runAll({ profile: PROFILE, fixture: 'fixtures/collectors', collectedAt: AT, outDir: dir, only: ['github'] });
  await runAll({ profile: PROFILE, fixture: 'fixtures/collectors', collectedAt: '2026-08-19T04:00:00.000Z', outDir: dir, only: ['github'] });
  const locker = readLocker(dir);
  assert.ok(locker.checks.size > 0);
  for (const [checkId, { history }] of locker.checks) {
    assert.equal(history.length, 2, checkId);
    assert.equal(verifyChain(history).ok, true, `${checkId} chain broke`);
  }
});

test('stamping without a profile leaves the bundle untouched', () => {
  const bundle = buildBundle({
    checkId: 'github.change.pr-review',
    ksis: ['KSI-CMT-LMC'],
    collectorPath: 'x',
    collectorVersion: '1.0.0',
    collectedAt: AT,
    assertion: 'a',
    scope: {},
    population: { expected: 1, enumerated_from: 'test', source_of_truth: 'test' },
    items: [{ id: 'i', status: 'pass' }],
  });
  assert.equal(stampProfile(bundle, null), bundle);
  assert.equal('profile_sha256' in stampProfile(bundle, null), false);
});

/* --------------------------------------------------------------------- anchor */

test('an anchor entry records the profile, and omits the key when there is none', () => {
  assert.equal(anchorEntry(manifest(), { profileSha256: A }).profile_sha256, A);
  assert.equal('profile_sha256' in anchorEntry(manifest()), false, 'a null key would change the hash of every old entry');
});

test('a log mixing entries with and without a profile verifies end to end', () => {
  const path = join(scratch(), 'anchor.jsonl');
  appendAnchor(path, manifest());
  appendAnchor(path, manifest({ root_sha256: 'c'.repeat(64) }), { profileSha256: A });
  acceptAnchor(path, manifest({ root_sha256: 'c'.repeat(64) }), { by: 'susan', reason: 'regions', profileSha256: B });
  assert.equal(verifyAnchorChain(readAnchorLog(path)).ok, true);
});

test('reconciliation reports where the profile stands, and fails only on a change', () => {
  const path = join(scratch(), 'anchor.jsonl');
  appendAnchor(path, manifest());
  const entries = () => readAnchorLog(path);

  assert.equal(reconcileAgainstAnchor(manifest(), entries()).profile.status, 'not_checked');
  const first = reconcileAgainstAnchor(manifest(), entries(), { profileSha256: A });
  assert.equal(first.profile.status, 'unrecorded', 'a log that never recorded a profile has nothing to have changed from');
  assert.equal(first.ok, true);

  appendAnchor(path, manifest(), { profileSha256: A });
  assert.equal(reconcileAgainstAnchor(manifest(), entries(), { profileSha256: A }).profile.status, 'unchanged');

  const changed = reconcileAgainstAnchor(manifest(), entries(), { profileSha256: B });
  assert.equal(changed.ok, false);
  const finding = changed.findings.find((f) => f.kind === 'profile_changed');
  assert.ok(finding);
  assert.match(finding.detail, /ksi anchor accept --profile/, 'the finding names the remedy');
  assert.match(finding.detail, /accept_profile_change/);
});

// An entry written without a profile, for instance an acceptance of a root made without
// --profile, must not reset the comparison to "unrecorded".
test('the comparison is against the last entry that recorded a profile', () => {
  const path = join(scratch(), 'anchor.jsonl');
  appendAnchor(path, manifest(), { profileSha256: A });
  acceptAnchor(path, manifest({ root_sha256: 'd'.repeat(64) }), { by: 'susan', reason: 'root only' });
  assert.equal(anchoredProfile(readAnchorLog(path)).sha256, A);
  const r = reconcileAgainstAnchor(manifest({ root_sha256: 'd'.repeat(64) }), readAnchorLog(path), { profileSha256: B });
  assert.equal(r.profile.status, 'changed');
});

test('a pipeline entry cannot introduce a changed profile; only an acceptance can', () => {
  const path = join(scratch(), 'anchor.jsonl');
  appendAnchor(path, manifest(), { profileSha256: A });
  assert.throws(() => appendAnchor(path, manifest(), { profileSha256: B }), /profile changed/);
  assert.equal(readAnchorLog(path).length, 1, 'and nothing is written');

  assert.throws(() => acceptAnchor(path, manifest(), { by: 'susan', profileSha256: B }), /must state why/);
  const accepted = acceptAnchor(path, manifest(), { by: 'susan', reason: 'Declared us-east-1', profileSha256: B });
  assert.equal(accepted.profile_sha256, B);
  assert.deepEqual(Object.keys(accepted.accepted).sort(), ['at', 'by', 'reason']);

  assert.doesNotThrow(() => appendAnchor(path, manifest(), { profileSha256: B }));
  assert.equal(reconcileAgainstAnchor(manifest(), readAnchorLog(path), { profileSha256: B }).ok, true);
});

/* ------------------------------------------------------------------------ CLI */

function ksi(args, env = {}) {
  const r = spawnSync(process.execPath, ['src/cli.mjs', ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

// The whole workflow through the real commands: anchor, change the profile, be refused at verify
// and at publish, accept with a reason, carry on.
test('end to end: a changed profile is refused until accepted, and the acceptance is on record', () => {
  const dir = scratch();
  const evidence = join(dir, 'evidence');
  const anchor = join(dir, 'anchor.jsonl');
  const original = join(dir, 'original.yaml');
  const changed = join(dir, 'changed.yaml');
  const base = { ...PROFILE, evidence: {} };
  writeFileSync(original, stringify(base));
  writeFileSync(changed, stringify({ ...base, aws: { ...base.aws, public_ports: [443, 22] } }));

  assert.equal(ksi(['collect', '--profile', original, '--fixture', '--out', evidence, '--only', 'github']).code, 0);
  const published = ksi(['publish', '--profile', original, '--evidence', evidence, '--anchor', anchor]);
  assert.equal(published.code, 0, published.out);
  assert.equal(readAnchorLog(anchor)[0].profile_sha256, profileSha256(base));

  const same = ksi(['verify', '--evidence', evidence, '--anchor', anchor, '--profile', original]);
  assert.equal(same.code, 0, same.out);
  assert.match(same.out, /profile {5}matches the anchor/);

  const refused = ksi(['verify', '--evidence', evidence, '--anchor', anchor, '--profile', changed]);
  assert.equal(refused.code, 1);
  assert.match(refused.out, /\[profile_changed\]/);

  const blocked = ksi(['publish', '--profile', changed, '--evidence', evidence, '--anchor', anchor]);
  assert.equal(blocked.code, 1);
  assert.match(blocked.out, /Refusing to publish: the profile changed/);
  assert.equal(readAnchorLog(anchor).length, 1, 'a refused publish writes nothing to the anchor');

  const noReason = ksi(['anchor', 'accept', '--evidence', evidence, '--anchor', anchor, '--profile', changed, '--by', 'susan']);
  assert.equal(noReason.code, 2);

  const accepted = ksi([
    'anchor', 'accept', '--evidence', evidence, '--anchor', anchor, '--profile', changed,
    '--by', 'susan', '--reason', 'Port 22 opened for the bastion, change #12',
  ]);
  assert.equal(accepted.code, 0, accepted.out);
  assert.match(accepted.out, /profile: [0-9a-f]{12} -> [0-9a-f]{12} \(CHANGED\)/);
  const entry = readAnchorLog(anchor).at(-1);
  assert.equal(entry.profile_sha256, profileSha256(parse(readFileSync(changed, 'utf8'))));
  assert.equal(entry.accepted.reason, 'Port 22 opened for the bastion, change #12');

  assert.equal(ksi(['verify', '--evidence', evidence, '--anchor', anchor, '--profile', changed]).code, 0);
  assert.equal(ksi(['verify', '--evidence', evidence, '--anchor', anchor, '--profile', original]).code, 1, 'and the old one is now the change');
  assert.equal(ksi(['publish', '--profile', changed, '--evidence', evidence, '--anchor', anchor]).code, 0);
});

test('verify without --profile says the profile was not checked, rather than staying silent', () => {
  const dir = scratch();
  const evidence = join(dir, 'evidence');
  const anchor = join(dir, 'anchor.jsonl');
  const profile = join(dir, 'p.yaml');
  writeFileSync(profile, stringify({ ...PROFILE, evidence: {} }));
  ksi(['collect', '--profile', profile, '--fixture', '--out', evidence, '--only', 'github']);
  ksi(['publish', '--profile', profile, '--evidence', evidence, '--anchor', anchor]);
  assert.match(ksi(['verify', '--evidence', evidence, '--anchor', anchor]).out, /profile {5}not checked/);
});

/* ------------------------------------------------------------------- workflow */

// The acceptance is only an established workflow if the pipeline offers it, runs it before the
// verify that would refuse the change, and checks the profile at all.
test('ccm.yml offers the acceptance, runs it before verify, and verifies against the profile', () => {
  const workflow = parse(readFileSync('.github/workflows/ccm.yml', 'utf8'));
  const input = workflow.on.workflow_dispatch.inputs.accept_profile_change;
  assert.equal(input?.type, 'string');

  const steps = workflow.jobs.collect.steps;
  const accept = steps.findIndex((s) => s.name === 'Accept the profile change');
  const verify = steps.findIndex((s) => s.name === 'Verify the restored locker');
  const restore = steps.findIndex((s) => s.name === 'Restore the anchor log');
  assert.ok(restore < accept && accept < verify, 'restore the anchor, then accept, then verify');

  const step = steps[accept];
  assert.match(step.run, /anchor accept .*--profile "\$PROFILE" .*--reason "\$REASON"/);
  // Free text from whoever dispatched the run must never be interpolated into the script.
  assert.doesNotMatch(step.run, /\$\{\{/);
  assert.equal(step.env.REASON, '${{ inputs.accept_profile_change }}');
  assert.match(steps[verify].run, /verify .*--anchor "\$ANCHOR_LOG" --profile "\$PROFILE"/);
});

/* ------------------------------------------------------------------ AWS scope */

test('the AWS scope records the regions each account was examined in, including the fallback', () => {
  const profile = { aws: { accounts: [], collector_role: 'Reader' } };
  const accounts = [{ id: '111111111111', regions: ['us-west-2', 'us-east-1'] }, { id: '222222222222' }];
  assert.deepEqual(accountScope(profile, accounts), {
    accounts: ['111111111111', '222222222222'],
    regions: { '111111111111': ['us-west-2', 'us-east-1'], '222222222222': ['us-east-1'] },
    collector_role: 'Reader',
  });
  assert.deepEqual(accountRegions({ aws: { regions: ['eu-west-1'] } }, { id: '3' }), ['eu-west-1']);
});

// The scope is only true if it names the regions the collection actually used.
test('perAccount examines exactly the regions the scope records', async () => {
  // One account per call: more than one needs a collector role, and assuming it needs AWS.
  for (const account of [{ id: '111111111111', regions: ['us-west-2', 'eu-central-1'] }, { id: '222222222222' }]) {
    const profile = { aws: { accounts: [account] } };
    let seen;
    const { accounts } = await perAccount(profile, async ({ regions }) => {
      seen = regions;
      return { items: [] };
    });
    assert.deepEqual(seen, accountScope(profile, accounts).regions[account.id], account.id);
  }
});

test('every regional AWS bundle carries the regions in its scope', async () => {
  // Fixture bundles use the fixture's own scope, so this reads the live scope builders instead.
  const sources = ['config', 'data', 'logging', 'network', 'transit'].map((f) =>
    readFileSync(`src/collectors/aws/${f}.mjs`, 'utf8')
  );
  for (const source of sources) {
    assert.match(source, /accountScope\(profile, accounts\)/);
    assert.doesNotMatch(source, /accounts: accounts\.map\(\(a\) => a\.id\)/, 'a hand-built scope would drop the regions');
  }
});
