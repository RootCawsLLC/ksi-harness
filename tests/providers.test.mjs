import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

import {
  ALWAYS_REQUIRED,
  OPTIONAL_SOURCES,
  SCOPED_PROVIDERS,
  collected,
  declaredProviders,
  outOfScope,
  providerScope,
  undeclaredSource,
} from '../src/boundary/providers.mjs';
import { COLLECTORS, providerOf } from '../src/collectors/registry.mjs';
import { runAll } from '../src/collectors/run-all.mjs';
import { emitterFor } from '../src/emit/index.mjs';
import { writeBundle } from '../src/evidence/bundle.mjs';
import { buildState } from '../src/evidence/state.mjs';
import { coverageJson, coverageMarkdown, coverageText } from '../src/report/coverage.mjs';
import { loadRoutes } from '../src/routes/routes.mjs';
import { resolveSufficiency } from '../src/routes/sufficiency.mjs';
import { FIXTURE_PROFILE } from './fixture-profile.mjs';

/**
 * A family the profile has no section for is not collected.
 *
 * The bug this guards: an AWS-and-GitHub service ran every GCP collector into a refusal, and every
 * indicator routed to an AWS check and a GCP check read `no-evidence`, because absent outranks
 * failing. Eleven failing indicators were reported as unexamined. Scoping fixes that, and opens
 * the opposite risk: a profile that loses a section gets a cleaner report. So most of these tests
 * are about the exclusion being stated, never silent.
 *
 * An identity provider or a policy gate is different: a service can lack one, but the indicators
 * it serves still apply. Its collectors do not run, and its checks stay in the indicator as absent
 * with the reason named, so leaving out `idp` can never make KSI-IAM-AAM look out of scope.
 */

const OPTIONAL = Object.keys(OPTIONAL_SOURCES);

const AT = '2026-08-18T04:00:00.000Z';
const NOW = Date.parse(AT) + 6 * 60 * 60 * 1000;
const FIXTURES = 'fixtures/collectors';

// Northwind with its GCP and GitHub sections removed: an AWS-only service that keeps its
// identity provider, policy gate and boundary declaration.
const { gcp: _gcp, github: _github, ...AWS_ONLY } = FIXTURE_PROFILE;
// And one with no identity provider, policy gate or boundary declaration either.
const { idp: _idp, pipeline: _pipeline, boundary: _boundary, ...AWS_BARE } = AWS_ONLY;

const temporary = [];
after(() => {
  for (const dir of temporary) rmSync(dir, { recursive: true, force: true });
});

async function lockerFor(profile) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-providers-'));
  temporary.push(dir);
  const { bundles } = await runAll({ profile, fixture: FIXTURES, collectedAt: AT });
  for (const bundle of bundles) writeBundle(bundle, dir);
  return dir;
}

/* ------------------------------------------------------------------ declaration */

test('a section is the declaration, and an empty one still declares the provider', () => {
  assert.deepEqual([...declaredProviders({ aws: { accounts: ['1'] } })], ['aws']);
  // Someone who wrote `gcp:` meant GCP is in the boundary. Reading it as "not used" would let a
  // half-written profile shrink the boundary, so it is in scope and its collectors refuse it.
  assert.deepEqual([...declaredProviders({ gcp: null })], ['gcp']);
  assert.deepEqual([...declaredProviders({ gcp: { projects: [] } })], ['gcp']);
  assert.equal(declaredProviders({}).size, 0);
});

test('without a profile nothing is excluded, so every check stays expected', () => {
  assert.equal(declaredProviders(null), null);
  assert.equal(providerScope(null), null);
  for (const family of [...SCOPED_PROVIDERS, ...OPTIONAL, ...ALWAYS_REQUIRED]) {
    assert.equal(outOfScope(family, null), false);
    assert.equal(undeclaredSource(family, null), null);
    assert.equal(collected(family, null), true);
  }
});

test('an optional source without a section is not collected, but is never outside the boundary', () => {
  for (const family of OPTIONAL) {
    assert.equal(outOfScope(family, {}), false, `${family} was scoped out`);
    assert.equal(collected(family, {}), false, `${family} would run with no section`);
    assert.match(undeclaredSource(family, {}), /declared in the profile/);
    assert.equal(undeclaredSource(family, { [family]: null }), null, 'an empty section is still a declaration');
  }
});

test('a required declaration is always collected, so its collector refuses a missing section', () => {
  for (const family of ALWAYS_REQUIRED) assert.equal(collected(family, {}), true, family);
});

// A new collector family must be classified on purpose. GitLab added to neither list would be
// always expected, and an AWS-and-GitLab service would be back to every GitLab-less indicator
// reading `no-evidence`, or worse, the reverse for an unclassified infrastructure provider.
test('every registered collector family is classified exactly once', () => {
  const families = new Set(COLLECTORS.flatMap((c) => c.CHECKS.map((check) => providerOf(check.id))));
  for (const family of families) {
    const groups = [SCOPED_PROVIDERS.includes(family), OPTIONAL.includes(family), ALWAYS_REQUIRED.includes(family)];
    assert.equal(
      groups.filter(Boolean).length,
      1,
      `${family} must be in exactly one of SCOPED_PROVIDERS, OPTIONAL_SOURCES and ALWAYS_REQUIRED`
    );
  }
  for (const listed of [...SCOPED_PROVIDERS, ...OPTIONAL, ...ALWAYS_REQUIRED]) {
    assert.ok(families.has(listed), `${listed} is classified but no collector registers it`);
  }
});

// runAll decides to skip a collector from its first check, so a collector spanning two providers
// would be skipped or run whole on the strength of one of them.
test('no collector spans providers', () => {
  for (const collector of COLLECTORS) {
    const providers = new Set(collector.CHECKS.map((c) => providerOf(c.id)));
    assert.equal(providers.size, 1, `${collector.PATH} declares checks for ${[...providers].join(', ')}`);
  }
});

/* ------------------------------------------------------------------- collection */

test('collectors for an undeclared provider are skipped and named, not run into a refusal', async () => {
  const result = await runAll({ profile: AWS_ONLY, fixture: FIXTURES, collectedAt: AT });

  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.providers, { in_scope: ['aws'], out_of_scope: ['gcp', 'github'], undeclared_sources: [] });
  const produced = new Set(result.bundles.map((b) => providerOf(b.check_id)));
  assert.equal(produced.has('gcp') || produced.has('github'), false);
  assert.ok(produced.has('aws'));
  for (const family of [...OPTIONAL, ...ALWAYS_REQUIRED]) assert.ok(produced.has(family), `${family} should still run`);

  // Every skipped collector is accounted for by path, so the log shows what the boundary left out.
  assert.deepEqual(result.skipped, [
    { family: 'gcp', reason: 'not declared in the profile, so outside the boundary', collectors: pathsOf('gcp') },
    { family: 'github', reason: 'not declared in the profile, so outside the boundary', collectors: pathsOf('github') },
  ]);
});

function pathsOf(family) {
  return COLLECTORS.filter((c) => providerOf(c.CHECKS[0].id) === family).map((c) => c.PATH);
}

// The live path, so the collectors would refuse if they ran. A service with no IdP used to fail
// every collection on that refusal; the gap belongs in the coverage report, not the exit code.
test('collectors for an undeclared source are skipped with the reason, not run into a failure', async () => {
  // Nothing declared at all: every provider is outside the boundary, every optional source is
  // undeclared, and only the required register runs, and refuses.
  const result = await runAll({ profile: {}, collectedAt: AT });
  assert.deepEqual(
    result.failures.map((f) => f.collector),
    pathsOf('thirdparty'),
    'only the required declaration may fail for a missing section'
  );
  assert.deepEqual(result.providers.undeclared_sources, [...OPTIONAL].sort());
  for (const family of OPTIONAL) {
    const entry = result.skipped.find((s) => s.family === family);
    assert.deepEqual(entry, { family, reason: OPTIONAL_SOURCES[family], collectors: pathsOf(family) });
  }
});

test('a skipped provider is logged, so the collection output says what it left out', async () => {
  const lines = [];
  await runAll({ profile: AWS_ONLY, fixture: FIXTURES, collectedAt: AT, log: (l) => lines.push(l) });
  assert.ok(lines.some((l) => /skip\s+gcp: not declared in the profile/.test(l)));
  assert.ok(lines.some((l) => /skip\s+github: not declared in the profile/.test(l)));
});

test('an empty section is in scope: its collectors run and refuse the missing projects', async () => {
  // No fixture, so this is the live path; the refusal happens before any client is built.
  const result = await runAll({ profile: { gcp: null }, collectedAt: AT, only: ['gcp'] });
  assert.equal(result.skipped.length, 0);
  assert.ok(result.failures.length > 0);
  for (const failure of result.failures) assert.match(failure.error, /No GCP projects in the profile/);
});

test('--only naming an undeclared provider or one of its checks is refused, not answered with nothing', async () => {
  await assert.rejects(runAll({ profile: AWS_ONLY, fixture: FIXTURES, collectedAt: AT, only: ['gcp'] }), /no section for/);
  await assert.rejects(
    runAll({ profile: AWS_ONLY, fixture: FIXTURES, collectedAt: AT, only: ['aws', 'github.change.pr-review'] }),
    /github\.change\.pr-review names something the profile has no section for/
  );
  await assert.rejects(runAll({ profile: AWS_BARE, fixture: FIXTURES, collectedAt: AT, only: ['idp'] }), /no section for/);
});

/* ------------------------------------------------------------------------ state */

let awsLocker;
let awsState;
before(async () => {
  awsLocker = await lockerFor(AWS_ONLY);
  awsState = buildState({ evidenceDir: awsLocker, klass: 'c', now: NOW, profile: AWS_ONLY });
});

test('out-of-scope checks leave the indicator and are named beside it', () => {
  const routes = loadRoutes();
  for (const indicator of awsState.indicators.filter((i) => routes[i.id]?.checks)) {
    const declared = routes[indicator.id].checks;
    const outside = declared.filter((id) => ['gcp', 'github'].includes(providerOf(id)));
    assert.deepEqual(indicator.out_of_scope_checks, outside, indicator.id);
    assert.deepEqual(
      indicator.checks.map((c) => c.check_id),
      declared.filter((id) => !outside.includes(id)),
      indicator.id
    );
  }
});

// The bug itself. With no profile the same locker is graded strictly, as before.
test('a failing AWS check is reported as failing, not hidden behind an absent GCP check', () => {
  const strict = buildState({ evidenceDir: awsLocker, klass: 'c', now: NOW });
  const unmasked = awsState.indicators.filter((i) => {
    const before = strict.indicators.find((s) => s.id === i.id);
    return before.evidence_state === 'no-evidence' && i.evidence_state === 'failing';
  });
  assert.ok(unmasked.length > 0, 'the fixtures should contain an AWS failure an absent GCP check used to mask');
  for (const indicator of unmasked) {
    assert.ok(indicator.out_of_scope_checks.length > 0, `${indicator.id} changed state without anything set aside`);
  }
  assert.equal(strict.providers, null);
  for (const indicator of strict.indicators) assert.deepEqual(indicator.out_of_scope_checks ?? [], [], indicator.id);
});

// Removing a provider must never be a way to reach a pass: an indicator only GCP evidences has
// nothing evidencing it in an AWS boundary, and says so.
test('an indicator whose every check is out of scope is no-evidence, never satisfied', () => {
  const emptied = awsState.indicators.filter((i) => i.out_of_scope_checks?.length && i.checks.length === 0);
  assert.ok(emptied.length > 0, 'expected at least one GCP-only route, such as KSI-IAM-SNU');
  for (const indicator of emptied) {
    if (['manual', 'unaddressed'].includes(indicator.declared_coverage)) continue;
    assert.equal(indicator.evidence_state, 'no-evidence', indicator.id);
  }
});

test('evidence in the locker for a provider the profile no longer declares is named and counted nowhere', async () => {
  const full = await lockerFor(FIXTURE_PROFILE);
  const state = buildState({ evidenceDir: full, klass: 'c', now: NOW, profile: AWS_ONLY });
  assert.ok(state.evidence.out_of_scope_checks.length > 0);
  for (const id of state.evidence.out_of_scope_checks) assert.match(id, /^(gcp|github)\./);
  for (const indicator of state.indicators) {
    for (const check of indicator.checks) assert.doesNotMatch(check.check_id, /^(gcp|github)\./, indicator.id);
  }
  // And the per-indicator outcome is the same as if that evidence were not there at all.
  const states = (s) => Object.fromEntries(s.indicators.map((i) => [i.id, i.evidence_state]));
  assert.deepEqual(states(state), states(awsState));
});

// No IdP must not read as "identity is out of scope". The checks stay, absent, with the reason.
test('checks for an undeclared source stay in the indicator as absent, with the reason', async () => {
  const bare = await lockerFor(AWS_BARE);
  const state = buildState({ evidenceDir: bare, klass: 'c', now: NOW, profile: AWS_BARE });
  const routes = loadRoutes();

  let seen = 0;
  for (const indicator of state.indicators.filter((i) => routes[i.id]?.checks)) {
    for (const id of routes[indicator.id].checks.filter((c) => OPTIONAL.includes(providerOf(c)))) {
      seen += 1;
      assert.ok(!indicator.out_of_scope_checks.includes(id), `${id} was scoped out of ${indicator.id}`);
      const check = indicator.checks.find((c) => c.check_id === id);
      assert.equal(check?.present, false, `${id} should be in ${indicator.id} and absent`);
      assert.equal(check.absent_reason, OPTIONAL_SOURCES[providerOf(id)]);
    }
  }
  assert.ok(seen > 0);

  const aam = state.indicators.find((i) => i.id === 'KSI-IAM-AAM');
  assert.equal(aam.evidence_state, 'no-evidence', 'an indicator only an IdP evidences has no evidence without one');
  assert.deepEqual(state.providers.undeclared_sources, [...OPTIONAL].sort());
});

test('a check that should have run and did not carries no reason, so the two gaps stay distinct', () => {
  const strict = buildState({ evidenceDir: awsLocker, klass: 'c', now: NOW });
  const absent = strict.indicators.flatMap((i) => i.checks).filter((c) => !c.present);
  assert.ok(absent.length > 0);
  for (const check of absent) assert.equal(check.absent_reason, null, check.check_id);
});

test('the report and the SDR give the reason an undeclared source has no evidence', async () => {
  const bare = await lockerFor(AWS_BARE);
  const state = buildState({ evidenceDir: bare, klass: 'c', now: NOW, profile: AWS_BARE });

  const md = coverageMarkdown(state);
  assert.match(md, /\*\*not declared:\*\* boundary, idp, pipeline/);
  assert.match(md, /`idp\.account\.provisioning` absent \(no identity provider declared in the profile\)/);
  assert.match(coverageText(state), /\(not declared: boundary, idp, pipeline\)/);
  const finding = coverageJson(state).findings.find((f) => f.indicator === 'KSI-IAM-AAM');
  assert.equal(finding.checks[0].absent_reason, 'no identity provider declared in the profile');

  const sdr = emitterFor('sdr').emit(state, { overviewUri: 'https://northwind.example/overview.json' });
  const aam = sdr.keySecurityIndicators.find((k) => k.ksiId === 'KSI-IAM-AAM').ksiValidation.join('\n');
  assert.match(aam, /idp\.account\.provisioning: not collected, no identity provider declared in the profile\./);
  assert.doesNotMatch(aam, /declared but no evidence bundle/);
});

/* --------------------------------------------------------------------- reports */

test('the coverage report states which providers it covers and which it left out', () => {
  const md = coverageMarkdown(awsState);
  assert.match(md, /\*\*Providers in scope:\*\* aws · \*\*outside the boundary:\*\* gcp, github/);
  assert.match(coverageText(awsState), /providers: aws {2}\(outside the boundary: gcp, github\)/);

  const json = coverageJson(awsState);
  assert.deepEqual(json.providers, { in_scope: ['aws'], out_of_scope: ['gcp', 'github'], undeclared_sources: [] });
  const rnt = json.indicators.find((i) => i.id === 'KSI-CNA-RNT');
  assert.deepEqual(rnt.out_of_scope_checks, ['gcp.network.ingress-exposure']);
});

test('a report without a profile says every provider was expected', () => {
  const strict = buildState({ evidenceDir: awsLocker, klass: 'c', now: NOW });
  assert.match(coverageMarkdown(strict), /no profile was supplied, so every provider.s checks are expected/);
  assert.match(coverageText(strict), /providers: no profile, every provider expected/);
});

test('the report warns about evidence for providers outside the boundary', async () => {
  const full = await lockerFor(FIXTURE_PROFILE);
  const state = buildState({ evidenceDir: full, klass: 'c', now: NOW, profile: AWS_ONLY });
  assert.match(coverageMarkdown(state), /The locker holds evidence for providers outside this boundary/);
  assert.match(coverageText(state), /evidence outside the boundary, not counted: /);
});

test('the SDR names the checks the boundary excluded and claims nothing for an emptied indicator', () => {
  const sdr = emitterFor('sdr').emit(awsState, { overviewUri: 'https://northwind.example/overview.json' });
  const byId = Object.fromEntries(sdr.keySecurityIndicators.map((k) => [k.ksiId, k]));

  const snu = awsState.indicators.find((i) => i.id === 'KSI-IAM-SNU');
  assert.deepEqual(snu.checks, [], 'KSI-IAM-SNU is routed only to a GCP check');
  const snuText = byId['KSI-IAM-SNU'].ksiImplementation.join('\n');
  assert.doesNotMatch(snuText, /Evidenced by 0/);
  assert.match(snuText, /nothing here evidences it/);
  assert.match(snuText, /outside the declared boundary: gcp\.iam\.service-account-keys/);

  const rnt = byId['KSI-CNA-RNT'].ksiImplementation.join('\n');
  assert.match(rnt, /Evidenced by 1 automated check\(s\) \(aws\.network\.ingress-exposure\)/);
  assert.match(rnt, /outside the declared boundary: gcp\.network\.ingress-exposure/);
});

/* ------------------------------------------------------------------ sufficiency */

// Sufficiency and collection read the same rule, so a section that is in scope for one is in
// scope for the other. An empty AWS section still puts AWS in the boundary.
test('an empty section counts against a sufficiency argument the same way it counts for collection', () => {
  const route = {
    coverage: 'automated',
    checks: ['gcp.service.surface'],
    sufficiency: { holds_when: { providers_within: ['gcp'] }, argument: 'It settles the claim.' },
    unautomated: ['On AWS the functionality clause is open.'],
  };
  assert.equal(resolveSufficiency(route, { gcp: { projects: [{ id: 'p' }] } }).coverage, 'automated');
  assert.equal(resolveSufficiency(route, { gcp: { projects: [{ id: 'p' }] }, aws: null }).coverage, 'partial');
});
