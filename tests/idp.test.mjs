import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildBundle } from '../src/evidence/bundle.mjs';
import { gradePrivilegePath, gradeProvisioning } from '../src/collectors/idp/lifecycle.mjs';
import { AUTOMATED_SOURCES, normaliseOktaGroups, normaliseOktaUsers, resolveIdp } from '../src/collectors/lib/idp.mjs';

/**
 * KSI-IAM-AAM is the only indicator in the catalog that asks about a *mechanism* rather than an
 * outcome: lifecycle and privileges "securely managed using automation".
 *
 * The consequence these tests exist to protect: a boundary with a flawless permission set, every
 * entry of it typed in by an administrator, fails this indicator while passing every cloud-side
 * check the harness has. Once an account exists, hand-built and provisioned are indistinguishable
 * downstream — so if the evidence does not come from the identity provider, it does not exist.
 */

const AUTOMATED = new Set(['ACTIVE_DIRECTORY', 'SCIM']);
const account = (login, over = {}) => ({ login, status: 'ACTIVE', live: true, source: 'SCIM', ...over });

const bundleOf = (checkId, graded) =>
  buildBundle({
    checkId,
    ksis: ['KSI-IAM-AAM'],
    collectorPath: 'src/collectors/idp/lifecycle.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-19T12:00:00.000Z',
    assertion: 'test',
    scope: {},
    ...graded,
  });

/* ------------------------------------------------------------------- lifecycle */

test('an account from a directory or SCIM passes, because automation created it', () => {
  const g = gradeProvisioning([account('a@x'), account('b@x', { source: 'ACTIVE_DIRECTORY' })], {
    automatedSources: AUTOMATED,
  });
  assert.deepEqual(g.items.map((i) => i.status), ['pass', 'pass']);
});

// The finding the whole collector exists for, and the one no downstream check can see.
test('an account created at a console fails however correct its permissions are', () => {
  const g = gradeProvisioning([account('break-glass@x', { source: 'OKTA' })], { automatedSources: AUTOMATED });
  assert.equal(g.items[0].status, 'fail');
  assert.match(g.items[0].detail, /not an automated source/);
  assert.match(g.items[0].detail, /somebody created it/);
});

/**
 * Deprovisioned accounts are excluded rather than passed, and the difference is not cosmetic.
 * Counting them as evidence of automation would let an estate improve its score by accumulating
 * dead accounts, which is the opposite of what the indicator wants.
 */
test('a deprovisioned account is not-applicable, not a free pass', () => {
  const g = gradeProvisioning(
    [account('gone@x', { status: 'DEPROVISIONED', live: false, source: 'OKTA' }), account('live@x')],
    { automatedSources: AUTOMATED }
  );
  assert.equal(g.items[0].status, 'not-applicable');

  const bundle = bundleOf('idp.account.provisioning', g);
  assert.equal(bundle.population.expected, 2, 'it stays in the denominator');
  assert.equal(bundle.population.decidable, 1, 'but decides nothing');
  assert.equal(bundle.result, 'pass');
});

test('an estate of only dead accounts cannot pass, because it decided nothing', () => {
  const g = gradeProvisioning([account('gone@x', { status: 'DEPROVISIONED', live: false })], {
    automatedSources: AUTOMATED,
  });
  assert.equal(bundleOf('idp.account.provisioning', g).result, 'warn');
});

// Enumerated before filtering, so the report can show how much of the estate was set aside.
test('the population counts every account the provider returned, live or not', () => {
  const g = gradeProvisioning(
    [account('a@x'), account('b@x', { live: false, status: 'SUSPENDED' }), account('c@x', { source: 'OKTA' })],
    { automatedSources: AUTOMATED }
  );
  assert.equal(g.population.expected, 3);
  assert.match(g.population.enumerated_from, /before filtering by status/);
});

/* -------------------------------------------------------------------- privilege */

test('a privileged group driven by a rule passes; a hand-curated one fails', () => {
  const g = gradePrivilegePath(
    [
      { name: 'Platform Admins', membership: 'manual', privileged: true },
      { name: 'Engineers', membership: 'rule', privileged: true },
    ],
    [],
    {}
  );
  assert.equal(g.items.find((i) => i.id.includes('Platform Admins')).status, 'fail');
  assert.equal(g.items.find((i) => i.id.includes('Engineers')).status, 'pass');
});

// The leaver problem, stated as a configuration property rather than a process one.
test('privilege granted directly to a person fails, because nothing will take it away', () => {
  const g = gradePrivilegePath([], [{ subject: 'amara@x', target: 'roles/owner', via: 'direct' }], {});
  assert.equal(g.items[0].status, 'fail');
  assert.match(g.items[0].detail, /no membership to fall out of/);
});

test('unprivileged groups are not graded, so the check stays about privileged access', () => {
  const g = gradePrivilegePath([{ name: 'Everyone', membership: 'manual', privileged: false }], [], {});
  assert.equal(g.items.length, 0);
  assert.equal(bundleOf('idp.privilege.assignment', g).result, 'warn', 'and a check that graded nothing cannot pass');
});

/* ----------------------------------------------------------------- the provider */

test('an identity provider is declared, never discovered', () => {
  assert.equal(resolveIdp({}), null, 'no idp block is absence, not a default');
  assert.throws(() => resolveIdp({ idp: {} }), /idp.provider is required/);
  assert.throws(() => resolveIdp({ idp: { provider: 'okta' } }), /idp.domain is required/);
});

// Declining is better than a normaliser written against documentation rather than responses.
test('an unimplemented provider is refused rather than guessed at', () => {
  assert.throws(() => resolveIdp({ idp: { provider: 'entra', domain: 'x' } }), /Only okta is implemented/);
});

test('the defaults are the automated sources, and the profile can narrow them', () => {
  const wide = resolveIdp({ idp: { provider: 'okta', domain: 'x' } });
  assert.equal(wide.automatedSources.has('ACTIVE_DIRECTORY'), true);
  assert.equal(wide.automatedSources.size, AUTOMATED_SOURCES.length);

  const narrow = resolveIdp({ idp: { provider: 'okta', domain: 'x', automated_sources: ['SCIM'] } });
  assert.deepEqual([...narrow.automatedSources], ['SCIM']);
});

/* --------------------------------------------------------------- normalisation */

test('Okta records where an identity came from, and that is what is read', () => {
  const [user] = normaliseOktaUsers(
    [{ id: '00u1', status: 'ACTIVE', profile: { login: 'a@x' }, credentials: { provider: { type: 'ACTIVE_DIRECTORY' } } }],
    {}
  );
  assert.equal(user.source, 'ACTIVE_DIRECTORY');
  assert.equal(user.live, true);
});

test('an account with no recorded provider is UNKNOWN, which is not automated', () => {
  const [user] = normaliseOktaUsers([{ id: '00u1', status: 'ACTIVE', profile: { login: 'a@x' } }], {});
  assert.equal(user.source, 'UNKNOWN');
  assert.equal(gradeProvisioning([user], { automatedSources: AUTOMATED }).items[0].status, 'fail');
});

test('a locked-out account is still live, because it can be recovered into use', () => {
  const [user] = normaliseOktaUsers([{ id: '1', status: 'LOCKED_OUT', profile: { login: 'a@x' } }], {});
  assert.equal(user.live, true, 'lockout is temporary; deprovisioning is not');
});

test('group membership is classified by how it is driven, and declared privilege is carried through', () => {
  const idp = { privilegedGroups: new Set(['Platform Admins']) };
  const groups = normaliseOktaGroups(
    [
      { id: '00g1', type: 'OKTA_GROUP', profile: { name: 'Platform Admins' } },
      { id: '00g2', type: 'BUILT_IN', profile: { name: 'Everyone' } },
    ],
    idp
  );
  assert.equal(groups[0].membership, 'manual');
  assert.equal(groups[0].privileged, true);
  assert.equal(groups[1].membership, 'directory');
  assert.equal(groups[1].privileged, false);
});
