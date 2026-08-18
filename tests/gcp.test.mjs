import assert from 'node:assert/strict';
import { test } from 'node:test';

import { classifyFailure, resolveProjects, RunBroken } from '../src/collectors/lib/gcp.mjs';
import {
  ADMIN_EQUIVALENT,
  gradePrivilegedAccess,
  gradeServiceAccountKeys,
  isHumanMember,
  PRIMITIVE_ROLES,
} from '../src/collectors/gcp/iam.mjs';
import { buildBundle } from '../src/evidence/bundle.mjs';

/**
 * The GCP collectors exist because ElevenLabs' primary leveraged system is GCP High, and
 * because the failure modes on GCP are not the AWS ones with different nouns. The three
 * these tests pin are the characteristic ones: a downloaded service account key, a primitive
 * role bound to a person, and an Organization Policy constraint that decides whether either
 * can happen again tomorrow.
 */

const AT = '2026-08-18T04:00:00.000Z';
const bundle = (graded, over = {}) =>
  buildBundle({
    checkId: 'gcp.iam.service-account-keys',
    ksis: ['KSI-IAM-SNU'],
    collectorPath: 'src/collectors/gcp/iam.mjs',
    collectorVersion: '1.0.0',
    collectedAt: AT,
    assertion: 'test',
    scope: {},
    items: graded.items,
    population: graded.population,
    ...over,
  });

/* ------------------------------------------------------------- service account keys */

test('a user-managed key fails, because a downloaded private key has no safe configuration', () => {
  const graded = gradeServiceAccountKeys(
    [{ email: 'deploy@p.iam.gserviceaccount.com', keys: [{ keyType: 'USER_MANAGED', validAfterTime: '2024-01-01T00:00:00Z' }] }],
    { projectId: 'p', keyCreationDisabled: true }
  );
  const item = graded.items.find((i) => i.id.includes('deploy@'));
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /outside Google's control/);
});

// Google-rotated keys are a different object from a downloaded one and must not be graded
// as though someone had exported them.
test('a Google-managed key is not a downloaded key', () => {
  const graded = gradeServiceAccountKeys(
    [{ email: 'runtime@p.iam.gserviceaccount.com', keys: [{ keyType: 'SYSTEM_MANAGED' }] }],
    { projectId: 'p', keyCreationDisabled: true }
  );
  assert.equal(graded.items.find((i) => i.id.includes('runtime@')).status, 'pass');
});

// The preventive half. Two projects with identically clean key lists are not in the same
// state if one of them rejects key creation at the API and the other does not.
test('the organization policy constraint is graded as its own population member', () => {
  const clean = [{ email: 'a@p.iam.gserviceaccount.com', keys: [] }];

  const enforced = gradeServiceAccountKeys(clean, { projectId: 'p', keyCreationDisabled: true });
  assert.equal(enforced.items[0].id, 'project/p');
  assert.equal(enforced.items[0].status, 'pass');
  assert.equal(bundle(enforced).result, 'pass');

  const notEnforced = gradeServiceAccountKeys(clean, { projectId: 'p', keyCreationDisabled: false });
  assert.equal(notEnforced.items[0].status, 'fail');
  assert.match(notEnforced.items[0].detail, /without changing anything in the list above/);
  assert.equal(bundle(notEnforced).result, 'fail', 'a clean key list under an unenforced constraint is not a pass');

  const unknown = gradeServiceAccountKeys(clean, { projectId: 'p', keyCreationDisabled: null });
  assert.equal(unknown.items[0].status, 'warn', 'an unreadable constraint is not an enforced one');
});

test('a service account whose keys could not be listed is a gap, not an account without keys', () => {
  const graded = gradeServiceAccountKeys([{ email: 'a@p.iam.gserviceaccount.com', keys: [] }], {
    projectId: 'p',
    keyCreationDisabled: true,
    unexamined: [{ id: 'serviceAccount/b@p.iam.gserviceaccount.com', reason: 'PERMISSION_DENIED on keys.list' }],
  });
  const b = bundle(graded);
  assert.equal(b.population.expected, 3, 'project claim plus both enumerated accounts');
  assert.equal(b.population.examined, 2);
  assert.equal(b.population.complete, false);
  assert.equal(b.result, 'warn');
});

/* ------------------------------------------------------------------ privileged access */

test('a primitive role on a person is standing privilege and fails', () => {
  const graded = gradePrivilegedAccess([{ role: 'roles/owner', members: ['user:founder@x.io'] }], { projectId: 'p' });
  const item = graded.items.find((i) => i.id.includes('founder'));
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /Standing primitive role/);
});

// The control on a workload binding is the identity federation, which this check has not
// read — so it surfaces rather than judges.
test('a primitive role on a workload warns rather than failing', () => {
  const graded = gradePrivilegedAccess(
    [{ role: 'roles/editor', members: ['serviceAccount:tf@p.iam.gserviceaccount.com'] }],
    { projectId: 'p' }
  );
  assert.equal(graded.items.find((i) => i.id.includes('tf@')).status, 'warn');
});

// A binding that outlives the account it was granted to is nobody's, and it is common.
test('a binding to a deleted principal fails', () => {
  const graded = gradePrivilegedAccess(
    [{ role: 'roles/editor', members: ['deleted:user:gone@x.io?uid=123'] }],
    { projectId: 'p' }
  );
  const item = graded.items.find((i) => i.id.includes('deleted'));
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /nobody owns/);
});

test('non-privileged bindings leave the population rather than counting as passes', () => {
  const graded = gradePrivilegedAccess(
    [
      { role: 'roles/owner', members: ['user:a@x.io'] },
      { role: 'roles/logging.viewer', members: ['group:sec@x.io', 'user:b@x.io'] },
      { role: 'roles/storage.objectViewer', members: ['serviceAccount:s@p.iam.gserviceaccount.com'] },
    ],
    { projectId: 'p' }
  );
  const b = bundle(graded, { checkId: 'gcp.iam.privileged-access', ksis: ['KSI-IAM-ELP'] });
  assert.equal(b.population.expected, 2, 'the project claim plus the single privileged member-binding');
  assert.equal(b.population.examined, 2);
  assert.equal(b.population.complete, true, 'the denominator counts privileged bindings, not every binding');
});

// The denominator is computed from the policy before grading. If it were derived from the
// items the loop produced, it could never disagree with them.
test('the privileged-access denominator comes from the policy, not from the graded items', () => {
  const bindings = [
    { role: 'roles/owner', members: ['user:a@x.io', 'user:b@x.io'] },
    { role: 'roles/iam.securityAdmin', members: ['serviceAccount:s@p.iam.gserviceaccount.com'] },
  ];
  const graded = gradePrivilegedAccess(bindings, { projectId: 'p' });
  assert.equal(graded.population.expected, 4, 'project claim plus three privileged member-bindings');
});

test('a project IAM policy with no bindings warns rather than passing over nothing', () => {
  const graded = gradePrivilegedAccess([], { projectId: 'p' });
  const b = bundle(graded, { checkId: 'gcp.iam.privileged-access', ksis: ['KSI-IAM-ELP'] });
  assert.equal(b.result, 'warn');
  assert.match(b.items[0].detail, /describes the collection rather than the project/);
});

test('member kinds are classified so a person and a workload are never graded alike', () => {
  assert.equal(isHumanMember('user:a@x.io'), true);
  assert.equal(isHumanMember('group:sec@x.io'), true);
  assert.equal(isHumanMember('domain:x.io'), true);
  assert.equal(isHumanMember('serviceAccount:s@p.iam.gserviceaccount.com'), false);
  assert.ok(PRIMITIVE_ROLES.has('roles/owner') && PRIMITIVE_ROLES.has('roles/editor'));
  assert.ok(ADMIN_EQUIVALENT.has('roles/iam.serviceAccountKeyAdmin'), 'minting keys is administrative in effect');
});

/* ------------------------------------------------------------------- the API surface */

// Three unrelated facts arrive as the same status code, and conflating them produces
// evidence that is wrong in different directions.
test('a 403 is disambiguated into a disabled API, a permission gap, or a broken run', () => {
  const disabled = classifyFailure(403, { error: { message: 'Cloud Asset API has not been used in project 1 before' } });
  assert.equal(disabled.kind, 'api-disabled');
  assert.equal(disabled.status, 'fail');

  const denied = classifyFailure(403, { error: { message: 'Permission iam.serviceAccounts.list denied' } });
  assert.equal(denied.kind, 'permission');
  assert.equal(denied.status, 'warn', 'an unverifiable control is not a failing one');

  assert.throws(
    () => classifyFailure(429, { error: { message: 'Quota exceeded for quota metric' } }),
    RunBroken,
    'a security conclusion drawn from an exhausted quota is not a finding'
  );
});

test('projects are declared in the profile, never discovered from the organization', () => {
  assert.deepEqual(resolveProjects({ gcp: { projects: ['a', { id: 'b' }] } }), [{ id: 'a' }, { id: 'b' }]);
  assert.throws(() => resolveProjects({ gcp: { projects: [] } }), /declared, never discovered/);
  assert.throws(() => resolveProjects({}), /No GCP projects in the profile/);
});
