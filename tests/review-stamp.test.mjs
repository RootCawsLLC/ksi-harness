import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { REVIEW_FIELDS, reviewFingerprints } from '../src/catalog/fingerprint.mjs';
import { normaliseControlId } from '../src/catalog/ksi.mjs';
import { loadRules } from '../src/catalog/rules.mjs';
import { diffRulesets, driftMarkdown, rulesAtRef } from '../src/report/drift.mjs';
import { loadRoutes, stampReviewed, validateRoutes } from '../src/routes/routes.mjs';

/**
 * The route stamp is what turns a ruleset bump from something a reviewer may read into something
 * the build refuses until they have. These tests reword indicators in a copy of the real pinned
 * ruleset and confirm the gate notices, names the right field, and agrees with the drift report
 * about what moved. A gate that stays quiet on a reword is the exact failure it exists to stop,
 * so the negative cases matter more than the clean one.
 */

const ROUTES_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'routes', 'routes.yaml');
const PINNED = reviewFingerprints();
const indicatorIn = (rules, id) => rules.KSI[id.split('-')[1]].indicators[id];

/** The FRD entry defining a term, found by name as indicators cite it. */
function termIn(rules, name) {
  for (const bucket of Object.values(rules.FRD.data)) {
    for (const entry of Object.values(bucket)) if (entry?.term?.toLowerCase() === name.toLowerCase()) return entry;
  }
  throw new Error(`no FRD entry for ${name}`);
}

/** Every CTL entry with the normalised id an indicator's mapping would use. */
function ctlEntries(rules) {
  return Object.values(rules.CTL).flatMap((family) =>
    Object.entries(family).map(([id, entry]) => ({ id: normaliseControlId(id), entry }))
  );
}

/** A copy of the pinned ruleset with one edit applied. */
function edited(edit) {
  const rules = structuredClone(loadRules());
  edit(rules);
  return rules;
}

/** Validation of a single route against a given ruleset's fingerprints. */
function errorsFor(id, route, rules = loadRules()) {
  const { errors } = validateRoutes({
    routes: { [id]: { id, checks: [], unautomated: [], ...route } },
    fingerprints: reviewFingerprints(rules),
  });
  return errors.filter((e) => e.startsWith(`${id}:`));
}

const PARTIAL = (id) => ({
  coverage: 'partial',
  cadence: 'daily',
  checks: [loadRoutes()['KSI-IAM-ELP'].checks[0]],
  unautomated: ['The rest.'],
  reviewed: { ...PINNED.get(id) },
});

const MANUAL = (id) => ({
  coverage: 'manual',
  cadence: 'annual',
  manual_evidence: { owner: 'o', artifact: 'a', why_not_automated: 'w' },
  reviewed: { ...PINNED.get(id) },
});

/* ---------------------------------------------------------------- the shipped map */

test('every shipped route carries a stamp that matches the pinned ruleset, unaddressed ones included', () => {
  for (const [id, route] of Object.entries(loadRoutes())) {
    assert.deepEqual(route.reviewed, PINNED.get(id), `${id} is not stamped against the pinned ruleset`);
  }
});

/* ----------------------------------------------------------------- the gate's teeth */

test('a route that claims coverage without a stamp is rejected, at every claiming level', () => {
  const { reviewed, ...unstamped } = PARTIAL('KSI-IAM-ELP');
  assert.match(errorsFor('KSI-IAM-ELP', unstamped).join('\n'), /requires "reviewed"/);
  assert.match(
    errorsFor('KSI-CED-RAT', {
      coverage: 'manual',
      cadence: 'annual',
      manual_evidence: { owner: 'o', artifact: 'a', why_not_automated: 'w' },
    }).join('\n'),
    /requires "reviewed"/
  );
  const automated = { ...loadRoutes()['KSI-CNA-DFP'] };
  delete automated.reviewed;
  assert.match(errorsFor('KSI-CNA-DFP', automated).join('\n'), /requires "reviewed"/);
});

test('an unaddressed route needs no stamp, but a stale one is still rejected', () => {
  const route = { coverage: 'unaddressed', reason: 'r', next: 'n' };
  assert.deepEqual(errorsFor('KSI-CNA-IBP', route), []);

  const reworded = edited((r) => { indicatorIn(r, 'KSI-CNA-IBP').statement = 'Something else entirely.'; });
  assert.match(
    errorsFor('KSI-CNA-IBP', { ...route, reviewed: { ...PINNED.get('KSI-CNA-IBP') } }, reworded).join('\n'),
    /statement, its cited terms, or what one of those terms means changed/
  );
});

test('a reworded statement fails the text stamp and leaves the controls stamp alone', () => {
  const rules = edited((r) => { indicatorIn(r, 'KSI-IAM-ELP').statement += ' Now with more.'; });
  const errors = errorsFor('KSI-IAM-ELP', PARTIAL('KSI-IAM-ELP'), rules);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /statement, its cited terms, or what one of those terms means changed/);
  assert.match(errors[0], /--fields text$/);
});

test('a change to cited terms or class variants is a text change, because they carry obligations', () => {
  const termAdded = edited((r) => { indicatorIn(r, 'KSI-IAM-ELP').terms = [...(indicatorIn(r, 'KSI-IAM-ELP').terms ?? []), 'Persistently']; });
  assert.match(errorsFor('KSI-IAM-ELP', PARTIAL('KSI-IAM-ELP'), termAdded).join('\n'), /statement, its cited terms, or what one of those terms means changed/);

  const variant = edited((r) => { indicatorIn(r, 'KSI-IAM-ELP').varies_by_class = { b: { statement: 'x' } }; });
  assert.match(errorsFor('KSI-IAM-ELP', PARTIAL('KSI-IAM-ELP'), variant).join('\n'), /statement, its cited terms, or what one of those terms means changed/);
});

test('a term list that only changes order is not a change', () => {
  const reordered = edited((r) => { indicatorIn(r, 'KSI-CED-RAT').terms = [...indicatorIn(r, 'KSI-CED-RAT').terms].reverse(); });
  assert.ok(indicatorIn(loadRules(), 'KSI-CED-RAT').terms.length > 1, 'needs an indicator citing several terms');
  assert.deepEqual(reviewFingerprints(reordered).get('KSI-CED-RAT'), PINNED.get('KSI-CED-RAT'));
});

test('redefining a cited term fails the text stamp, though no indicator changed', () => {
  const term = indicatorIn(loadRules(), 'KSI-CED-RAT').terms[0];
  const redefined = edited((r) => { termIn(r, term).definition += ' Except on weekends.'; });
  const errors = errorsFor('KSI-CED-RAT', { ...MANUAL('KSI-CED-RAT') }, redefined);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /what one of those terms means changed/);

  const renoted = edited((r) => { termIn(r, term).note = 'A note that changes how the term reads.'; });
  assert.equal(errorsFor('KSI-CED-RAT', { ...MANUAL('KSI-CED-RAT') }, renoted).length, 1);
});

test('bookkeeping on a cited term is not a change: changelog, alternates, tag, rendering hints', () => {
  const term = indicatorIn(loadRules(), 'KSI-CED-RAT').terms[0];
  const churned = edited((r) => {
    const entry = termIn(r, term);
    entry.updated = [...(entry.updated ?? []), { date: '2099-01-01', comment: 'Touched.' }];
    entry.alts = [...(entry.alts ?? []), 'another spelling'];
    entry.tag = 'Retagged';
    entry.ignore_in_terms = true;
  });
  assert.deepEqual(reviewFingerprints(churned).get('KSI-CED-RAT'), PINNED.get('KSI-CED-RAT'));
});

test('a changed CTL value for a mapped control fails the controls stamp alone', () => {
  const mapped = ctlEntries(loadRules()).find(({ id }) => indicatorIn(loadRules(), 'KSI-SVC-SIN').controls.includes(id));
  assert.ok(mapped, 'KSI-SVC-SIN needs a mapped control with a CTL entry');
  const rules = edited((r) => {
    ctlEntries(r).find(({ id }) => id === mapped.id).entry.guidance = ['Something weaker.'];
  });
  const errors = errorsFor('KSI-SVC-SIN', PARTIAL('KSI-SVC-SIN'), rules);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /CTL values for them/);
});

test('a CTL change the indicator does not map, or one only to its changelog, is not a change', () => {
  const elp = indicatorIn(loadRules(), 'KSI-IAM-ELP').controls;
  const unmapped = ctlEntries(loadRules()).find(({ id }) => !elp.includes(id));
  const mapped = ctlEntries(loadRules()).find(({ id }) => elp.includes(id));
  assert.ok(unmapped && mapped, 'needs one CTL entry IAM-ELP maps and one it does not');
  const rules = edited((r) => {
    ctlEntries(r).find(({ id }) => id === unmapped.id).entry.guidance = ['Changed.'];
    ctlEntries(r).find(({ id }) => id === mapped.id).entry.updated = [{ date: '2099-01-01', comment: 'Touched.' }];
  });
  assert.deepEqual(reviewFingerprints(rules).get('KSI-IAM-ELP'), PINNED.get('KSI-IAM-ELP'));
});

test('a stamp is checked at every class, including one where the indicator does not apply', () => {
  const rules = edited((r) => { indicatorIn(r, 'KSI-SVC-RUD').statement = 'Reworded.'; });
  const { errors, warnings } = validateRoutes({
    routes: { 'KSI-SVC-RUD': { id: 'KSI-SVC-RUD', checks: [], unautomated: [], ...MANUAL('KSI-SVC-RUD') } },
    klass: 'a',
    fingerprints: reviewFingerprints(rules),
  });
  assert.match(warnings.join('\n'), /does not apply at Class A/, 'precondition: SVC-RUD does not apply at Class A');
  assert.match(errors.join('\n'), /KSI-SVC-RUD: the indicator's statement/);
});

test('a changed control mapping fails the controls stamp alone, and says what it does to emitted output', () => {
  const rules = edited((r) => { indicatorIn(r, 'KSI-IAM-ELP').controls.push('zz-99'); });
  const errors = errorsFor('KSI-IAM-ELP', PARTIAL('KSI-IAM-ELP'), rules);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /800-53 mappings, or FedRAMP's CTL values for them, changed/);
  assert.match(errors[0], /SDR and OSCAL/);
  assert.match(errors[0], /--fields controls$/);
});

test('a rename alone does not invalidate the review, because a name moves no claim', () => {
  const rules = edited((r) => { indicatorIn(r, 'KSI-IAM-ELP').name = 'Renamed'; });
  assert.deepEqual(errorsFor('KSI-IAM-ELP', PARTIAL('KSI-IAM-ELP'), rules), []);
});

test('a malformed, partial or over-specified stamp is rejected rather than half-trusted', () => {
  assert.match(errorsFor('KSI-IAM-ELP', { ...PARTIAL('KSI-IAM-ELP'), reviewed: 'yes' }).join('\n'), /must be a mapping/);
  assert.match(errorsFor('KSI-IAM-ELP', { ...PARTIAL('KSI-IAM-ELP'), reviewed: null }).join('\n'), /must be a mapping/);
  const { controls, ...textOnly } = PINNED.get('KSI-IAM-ELP');
  assert.match(errorsFor('KSI-IAM-ELP', { ...PARTIAL('KSI-IAM-ELP'), reviewed: textOnly }).join('\n'), /reviewed\.controls" is missing/);
  const extra = { ...PINNED.get('KSI-IAM-ELP'), statement: 'abc' };
  assert.match(errorsFor('KSI-IAM-ELP', { ...PARTIAL('KSI-IAM-ELP'), reviewed: extra }).join('\n'), /not a review field/);
});

/* ------------------------------------------------- the gate and the report agree */

// The validator and drift both decide "changed" from reviewFingerprint. This pins them together
// across every indicator and every kind of edit, so a future change to one that forgets the
// other fails here instead of shipping a report that disagrees with the gate.
test('drift marks a stamp field stale exactly where the gate rejects it, across every indicator', () => {
  const pinned = loadRules();
  const routes = Object.fromEntries(
    Object.entries(loadRoutes()).map(([id, route]) => [id, { ...route, reviewed: { ...PINNED.get(id) } }])
  );
  const bumped = edited((r) => {
    indicatorIn(r, 'KSI-SCR-MIT').statement = 'Reworded.';
    indicatorIn(r, 'KSI-PIY-RES').terms = [];
    indicatorIn(r, 'KSI-IAM-ELP').controls.pop();
    indicatorIn(r, 'KSI-CNA-DFP').controls.push('cm-99');
    indicatorIn(r, 'KSI-SVC-RUD').statement = 'Reworded.';
    indicatorIn(r, 'KSI-SVC-RUD').controls.push('si-99');
    indicatorIn(r, 'KSI-CED-RAT').name = 'Renamed only';
    termIn(r, indicatorIn(r, 'KSI-MLA-LET').terms[0]).definition += ' Redefined.';
    // A control SIN maps and RAT does not, so the rename-only probe below stays a rename only
    // whatever FedRAMP maps next. Picking SIN's first entry broke this the day RAT gained ir-9.4.
    const sin = indicatorIn(r, 'KSI-SVC-SIN').controls;
    const rat = indicatorIn(r, 'KSI-CED-RAT').controls;
    ctlEntries(r).find(({ id }) => sin.includes(id) && !rat.includes(id)).entry.guidance = ['Weaker.'];
  });

  const diff = diffRulesets({ from: pinned, to: bumped, routes });
  const { errors } = validateRoutes({ routes, fingerprints: reviewFingerprints(bumped) });

  for (const field of REVIEW_FIELDS) {
    const fromDrift = diff.changed.filter((c) => c.stale.includes(field)).map((c) => c.id).sort();
    const fromGate = errors
      .filter((e) => e.includes(`(reviewed.${field} `))
      .map((e) => e.split(':')[0])
      .sort();
    assert.deepEqual(fromGate, fromDrift, `drift and the gate disagree about ${field}`);
  }
  assert.deepEqual(diff.changed.find((c) => c.id === 'KSI-CED-RAT').stale, []);
  assert.deepEqual(diff.changed.find((c) => c.id === 'KSI-SVC-RUD').stale, ['text', 'controls']);
  // A redefinition and a CTL move change nothing on the indicator, so drift must name them rather
  // than skip the indicator; skipping is the report calling clean what the gate refuses.
  const anyCitingLetTerm = diff.changed.find((c) => c.id === 'KSI-MLA-LET');
  assert.ok(anyCitingLetTerm.fields.includes('term definitions'));
  assert.ok(diff.changed.find((c) => c.id === 'KSI-SVC-SIN').fields.includes('parameter values'));
});

test('drift names the terms and controls that moved, not just that something did', () => {
  const bumped = edited((r) => {
    const i = indicatorIn(r, 'KSI-CED-RAT');
    i.terms = [...i.terms.slice(1), 'Brand New Term'];
    i.controls = [...i.controls.slice(1), 'zz-1'];
  });
  const row = diffRulesets({ from: loadRules(), to: bumped }).changed.find((c) => c.id === 'KSI-CED-RAT');
  const before = indicatorIn(loadRules(), 'KSI-CED-RAT');
  assert.ok(before.terms.length > 1, 'needs an indicator citing several terms');
  assert.deepEqual(row.terms_added, ['Brand New Term']);
  assert.deepEqual(row.terms_removed, [before.terms[0]]);
  assert.deepEqual(row.controls_added, ['zz-1']);
  assert.deepEqual(row.controls_removed, [before.controls[0]]);
});

test('identical rulesets report no drift', () => {
  const diff = diffRulesets({ from: loadRules(), to: structuredClone(loadRules()) });
  assert.equal(diff.ok, true);
  assert.equal(diff.changed.length, 0);
});

test('comparing a ref against the pin labels the sides as such and asks for review, not a sync', () => {
  const bumped = edited((r) => { indicatorIn(r, 'KSI-SCR-MIT').statement = 'Reworded.'; });
  const md = driftMarkdown(diffRulesets({ from: loadRules(), to: bumped, labels: { from: 'main', to: 'pinned' } }));
  assert.match(md, /^main `.*` → pinned `/m);
  assert.match(md, /Route stamp to renew after review: text/);
  assert.match(md, /ksi routes reviewed/);
  assert.doesNotMatch(md, /vendor:sync/);
});

test('the ruleset at a ref is read from git, and a ref that does not resolve throws', () => {
  assert.ok(rulesAtRef('HEAD').KSI, 'HEAD should carry a committed ruleset');
  assert.throws(() => rulesAtRef('no-such-ref-anywhere'));
  assert.throws(() => rulesAtRef(''), /needs a git ref/);
  assert.throws(() => rulesAtRef('--output=/tmp/x'), /needs a git ref/);
});

/* ------------------------------------------------------------------ the writer */

function scratchRoutes() {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-stamp-'));
  const path = join(dir, 'routes.yaml');
  copyFileSync(ROUTES_PATH, path);
  return path;
}

/** Fingerprints with one indicator's field replaced, standing in for a bumped pin. */
function bumpedPrints(id, field) {
  const prints = new Map([...PINNED].map(([k, v]) => [k, { ...v }]));
  prints.get(id)[field] = '0000000000000000';
  return prints;
}

test('renewing a stamp rewrites that one line and nothing else in the file', () => {
  const path = scratchRoutes();
  const before = readFileSync(path, 'utf8').split('\n');
  stampReviewed({ ids: ['KSI-SCR-MIT'], fields: ['text'], path, fingerprints: bumpedPrints('KSI-SCR-MIT', 'text') });
  const after = readFileSync(path, 'utf8').split('\n');

  assert.equal(after.length, before.length);
  const changed = after.map((l, i) => (l === before[i] ? null : i)).filter((i) => i !== null);
  assert.equal(changed.length, 1);
  assert.deepEqual(loadRoutes({ path })['KSI-SCR-MIT'].reviewed, {
    text: '0000000000000000',
    controls: PINNED.get('KSI-SCR-MIT').controls,
  });
});

test('renewing one field keeps the other, so acknowledging controls does not launder a reword', () => {
  const path = scratchRoutes();
  const prints = bumpedPrints('KSI-IAM-ELP', 'text');
  prints.get('KSI-IAM-ELP').controls = '1111111111111111';
  stampReviewed({ ids: ['KSI-IAM-ELP'], fields: ['controls'], path, fingerprints: prints });
  const stamp = loadRoutes({ path })['KSI-IAM-ELP'].reviewed;
  assert.equal(stamp.controls, '1111111111111111');
  assert.equal(stamp.text, PINNED.get('KSI-IAM-ELP').text, 'the stale text stamp must survive');
});

test('a route with no stamp gets one inserted under its key', () => {
  const path = scratchRoutes();
  writeFileSync(path, readFileSync(path, 'utf8').replace(/^KSI-PIY-RES:\n {2}reviewed: \{[^}]*\}\n/m, 'KSI-PIY-RES:\n'));
  assert.equal(loadRoutes({ path })['KSI-PIY-RES'].reviewed, undefined);
  stampReviewed({ ids: ['KSI-PIY-RES'], fields: ['text', 'controls'], path });
  assert.deepEqual(loadRoutes({ path })['KSI-PIY-RES'].reviewed, PINNED.get('KSI-PIY-RES'));
  assert.equal(validateRoutes({ routes: loadRoutes({ path }) }).ok, true);
});

test('the writer refuses to renew everything, an unknown field, or a route that does not exist', () => {
  const path = scratchRoutes();
  const untouched = readFileSync(path, 'utf8');
  assert.throws(() => stampReviewed({ ids: [], fields: ['text'], path }), /no "all"/);
  assert.throws(() => stampReviewed({ ids: ['KSI-IAM-ELP'], fields: [], path }), /--fields/);
  assert.throws(() => stampReviewed({ ids: ['KSI-IAM-ELP'], fields: ['everything'], path }), /--fields/);
  assert.throws(() => stampReviewed({ ids: ['KSI-ZZZ-ZZZ'], fields: ['text'], path }), /not an indicator/);
  assert.equal(readFileSync(path, 'utf8'), untouched);
});

test('the writer re-reads what it wrote, and refuses a value YAML would read differently', () => {
  const path = scratchRoutes();
  const untouched = readFileSync(path, 'utf8');
  const prints = new Map([...PINNED].map(([k, v]) => [k, { ...v }]));
  // A backslash escape inside the quotes parses as a tab, so the written stamp is not the one
  // meant. Real digests are hex and never do this; the guard is what would catch the day one did.
  prints.get('KSI-IAM-ELP').text = 'ab\\tcd';
  assert.throws(
    () => stampReviewed({ ids: ['KSI-IAM-ELP'], fields: ['text'], path, fingerprints: prints }),
    /did not land where intended/
  );
  assert.equal(readFileSync(path, 'utf8'), untouched);
});

test('a stamp written in a layout the writer does not own is refused rather than guessed at', () => {
  const path = scratchRoutes();
  const { text, controls } = PINNED.get('KSI-IAM-ELP');
  writeFileSync(
    path,
    readFileSync(path, 'utf8').replace(
      /^KSI-IAM-ELP:\n {2}reviewed: \{[^}]*\}\n/m,
      `KSI-IAM-ELP:\n  reviewed:\n    text: ${text}\n    controls: ${controls}\n`
    )
  );
  const untouched = readFileSync(path, 'utf8');
  assert.throws(() => stampReviewed({ ids: ['KSI-IAM-ELP'], fields: ['text'], path }), /one-line flow mapping/);
  assert.equal(readFileSync(path, 'utf8'), untouched);
});
