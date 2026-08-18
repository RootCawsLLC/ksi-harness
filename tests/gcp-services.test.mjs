import assert from 'node:assert/strict';
import { test } from 'node:test';

import { gradeEncryptionAtRest } from '../src/collectors/gcp/data.mjs';
import { destinationIsExternal, gradeAuditConfig, gradeSinkIntegrity } from '../src/collectors/gcp/logging.mjs';
import { gradeIngressExposure, portsOpenedBy } from '../src/collectors/gcp/network.mjs';
import { DEFAULT_CONSTRAINTS, gradeOrgConstraints } from '../src/collectors/gcp/policy.mjs';
import { buildBundle } from '../src/evidence/bundle.mjs';

/**
 * The GCP services beyond identity. Each of these pins a failure mode that has no clean AWS
 * analogue, which is the reason the family is written rather than aliased.
 */

const AT = '2026-08-18T04:00:00.000Z';
const bundle = (graded, checkId = 'gcp.logging.audit-config', ksis = ['KSI-MLA-LET']) =>
  buildBundle({
    checkId,
    ksis,
    collectorPath: 'src/collectors/gcp/x.mjs',
    collectorVersion: '1.0.0',
    collectedAt: AT,
    assertion: 'test',
    scope: {},
    items: graded.items,
    population: graded.population,
  });

/* --------------------------------------------------------------- audit config */

// Data Access logs default to off. A project can look thoroughly logged and hold no record
// of who read anything.
test('a service missing Data Access logging fails, and says why the default is the problem', () => {
  const graded = gradeAuditConfig([{ service: 'allServices', auditLogConfigs: [{ logType: 'ADMIN_READ' }] }], {
    projectId: 'p',
    declaredServices: ['storage.googleapis.com'],
  });
  const item = graded.items.find((i) => i.id.includes('storage'));
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /default to off/);
});

// The case that reads as compliant and is not: logging enabled, one principal quietly removed.
test('an exempted member fails even though logging is enabled', () => {
  const graded = gradeAuditConfig(
    [
      {
        service: 'storage.googleapis.com',
        auditLogConfigs: [
          { logType: 'DATA_READ', exemptedMembers: ['serviceAccount:batch@p.iam.gserviceaccount.com'] },
          { logType: 'DATA_WRITE' },
        ],
      },
    ],
    { projectId: 'p', declaredServices: ['storage.googleapis.com'] }
  );
  const item = graded.items.find((i) => i.id.includes('storage'));
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /removes them from the trail silently/);
});

test('the denominator is the declared service list, which is what makes this evidence for MLA-LET', () => {
  const graded = gradeAuditConfig([{ service: 'allServices', auditLogConfigs: [{ logType: 'DATA_READ' }, { logType: 'DATA_WRITE' }] }], {
    projectId: 'p',
    declaredServices: ['a.googleapis.com', 'b.googleapis.com', 'c.googleapis.com'],
  });
  const b = bundle(graded);
  assert.equal(b.population.expected, 4, 'project claim plus three declared services');
  assert.equal(b.result, 'pass', 'an allServices config covers each declared service');
});

test('an allServices configuration is graded separately, because a new service inherits it', () => {
  const without = gradeAuditConfig(
    [{ service: 'storage.googleapis.com', auditLogConfigs: [{ logType: 'DATA_READ' }, { logType: 'DATA_WRITE' }] }],
    { projectId: 'p', declaredServices: ['storage.googleapis.com'] }
  );
  assert.equal(without.items[0].id, 'project/p');
  assert.equal(without.items[0].status, 'fail');
  assert.match(without.items[0].detail, /produces no Data Access record until someone remembers/);
});

/* ----------------------------------------------------------------- log sinks */

// A record the audited party can alter is not a record.
test('a sink writing back into the project it audits is not tamper-resistant', () => {
  assert.equal(destinationIsExternal('storage.googleapis.com/projects/p/buckets/logs', 'p'), false);
  assert.equal(destinationIsExternal('storage.googleapis.com/projects/central-logs/buckets/logs', 'p'), true);

  const graded = gradeSinkIntegrity(
    [{ name: 's', destination: 'storage.googleapis.com/projects/p/buckets/logs', retention: { days: 400, locked: true }, readers: [] }],
    { projectId: 'p' }
  );
  const item = graded.items.find((i) => i.id === 'sink/s');
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /alterable by whoever can alter the project/);
});

test('unlocked retention is a finding, because it can be shortened after the fact', () => {
  const graded = gradeSinkIntegrity(
    [{ name: 's', destination: 'storage.googleapis.com/projects/other/buckets/l', retention: { days: 400, locked: false }, readers: [] }],
    { projectId: 'p' }
  );
  assert.match(graded.items.find((i) => i.id === 'sink/s').detail, /not locked, so it can be shortened/);
});

test('a reader the profile does not declare is a least-privilege finding on log data', () => {
  const graded = gradeSinkIntegrity(
    [
      {
        name: 's',
        destination: 'storage.googleapis.com/projects/other/buckets/l',
        retention: { days: 400, locked: true },
        readers: ['group:security@x.io', 'allUsers'],
      },
    ],
    { projectId: 'p', declaredReaders: ['group:security@x.io'] }
  );
  assert.match(graded.items.find((i) => i.id === 'sink/s').detail, /readable by allUsers/);
});

test('a project with no sink fails rather than passing over an empty list', () => {
  const b = bundle(gradeSinkIntegrity([], { projectId: 'p' }), 'gcp.logging.sink-integrity', ['KSI-MLA-OSM']);
  assert.equal(b.result, 'fail');
  assert.match(b.items[0].detail, /age out on their own schedule/);
});

/* -------------------------------------------------------------- org policy */

// The preventive half: what today's state permits tomorrow.
test('an unenforced constraint fails even when nothing has exploited it yet', () => {
  const graded = gradeOrgConstraints(
    [{ constraint: 'iam.disableServiceAccountKeyCreation', enforced: false, exceptions: [] }],
    { projectId: 'p', required: [DEFAULT_CONSTRAINTS[0]] }
  );
  assert.equal(graded.items.find((i) => i.id.includes('disableServiceAccountKey')).status, 'fail');
});

// Enforced-with-exceptions is the state that reads as green on a dashboard.
test('an enforced constraint carrying exceptions warns rather than passing', () => {
  const graded = gradeOrgConstraints(
    [{ constraint: 'storage.publicAccessPrevention', enforced: true, exceptions: ['projects/public-assets'] }],
    { projectId: 'p', required: [{ id: 'storage.publicAccessPrevention', why: 'x' }] }
  );
  const item = graded.items.find((i) => i.id.includes('publicAccessPrevention'));
  assert.equal(item.status, 'warn');
  assert.match(item.detail, /1 exception/);
});

test('a constraint absent from the hierarchy fails and says so distinctly from an unenforced one', () => {
  const graded = gradeOrgConstraints([], { projectId: 'p', required: [{ id: 'sql.restrictPublicIp', why: 'x' }] });
  assert.match(graded.items.find((i) => i.id.includes('restrictPublicIp')).detail, /Not enforced anywhere in the hierarchy/);
});

test('the required constraint set is the denominator, declared before anything was read', () => {
  const graded = gradeOrgConstraints([], { projectId: 'p', required: DEFAULT_CONSTRAINTS });
  const b = bundle(graded, 'gcp.policy.org-constraints', ['KSI-CNA-EIS']);
  assert.equal(b.population.expected, 1 + DEFAULT_CONSTRAINTS.length);
  assert.equal(b.result, 'fail');
});

/* ------------------------------------------------------------------ network */

test('ports are expanded from ranges, and "all" is distinguished from a wide range', () => {
  assert.deepEqual(portsOpenedBy([{ IPProtocol: 'tcp', ports: ['22'] }]), [22]);
  assert.deepEqual(portsOpenedBy([{ IPProtocol: 'tcp', ports: ['80', '443'] }]), [80, 443]);
  assert.deepEqual(portsOpenedBy([{ IPProtocol: 'tcp', ports: ['8080-8082'] }]), [8080, 8081, 8082]);
  assert.equal(portsOpenedBy([{ IPProtocol: 'all' }]), null);
  assert.equal(portsOpenedBy([{ IPProtocol: 'tcp' }]), null, 'no ports means every port');
});

// A rule with no target applies to every instance in the network, which is how a rule
// written for one host becomes a network-wide opening.
test('an untargeted open rule is graded harder than the same ports scoped to a tag', () => {
  const scoped = gradeIngressExposure(
    [{ name: 'a', direction: 'INGRESS', sourceRanges: ['0.0.0.0/0'], targetTags: ['web'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] }],
    { scopeId: 'p' }
  );
  assert.equal(scoped.items.find((i) => i.id === 'firewall/a').status, 'pass');

  const wide = gradeIngressExposure(
    [{ name: 'a', direction: 'INGRESS', sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] }],
    { scopeId: 'p' }
  );
  const item = wide.items.find((i) => i.id === 'firewall/a');
  assert.equal(item.status, 'warn');
  assert.match(item.detail, /every instance in the network/);
});

test('a disabled rule is latent rather than passing, so it cannot improve the ratio', () => {
  const graded = gradeIngressExposure(
    [{ name: 'a', direction: 'INGRESS', disabled: true, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] }],
    { scopeId: 'p' }
  );
  assert.equal(graded.items.find((i) => i.id === 'firewall/a').status, 'not-applicable');
});

test('SSH open to the internet fails', () => {
  const graded = gradeIngressExposure(
    [{ name: 'ssh', direction: 'INGRESS', priority: 100, sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] }],
    { scopeId: 'p' }
  );
  assert.equal(graded.items.find((i) => i.id === 'firewall/ssh').status, 'fail');
});

/* --------------------------------------------------------------------- data */

// Everything on GCS and PD is encrypted unconditionally, so "is it encrypted" is vacuous.
// The claim with an answer is key custody against a declaration.
test('a bucket declared as requiring CMEK and lacking one is the failure this check can find', () => {
  const graded = gradeEncryptionAtRest(
    { buckets: [{ name: 'voice-models', default_kms_key: null }], disks: [] },
    { scopeId: 'p', cmekRequired: ['voice-models'] }
  );
  const item = graded.items.find((i) => i.id === 'bucket/voice-models');
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /Declared as requiring a customer-managed key/);
});

test('a Google-managed key passes and records custody rather than being punished', () => {
  const graded = gradeEncryptionAtRest({ buckets: [{ name: 'web', default_kms_key: null }], disks: [] }, { scopeId: 'p' });
  const item = graded.items.find((i) => i.id === 'bucket/web');
  assert.equal(item.status, 'pass');
  assert.equal(item.observed.customer_managed_key, false);
});

test('a project with no storage warns rather than passing over nothing', () => {
  const b = bundle(gradeEncryptionAtRest({ buckets: [], disks: [] }, { scopeId: 'p' }), 'gcp.data.encryption-at-rest', ['KSI-SVC-SIN']);
  assert.equal(b.result, 'warn');
});
