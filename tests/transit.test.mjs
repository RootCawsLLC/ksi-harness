import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildBundle } from '../src/evidence/bundle.mjs';
import {
  deniesInsecureTransport,
  gradeMutualAuthentication as gradeAwsMutualAuth,
  gradeTlsEnforcement as gradeAwsTls,
} from '../src/collectors/aws/transit.mjs';
import {
  gradeMutualAuthentication as gradeGcpMutualAuth,
  gradeTlsEnforcement as gradeGcpTls,
} from '../src/collectors/gcp/transit.mjs';
import {
  compareTlsVersion,
  elbPolicyFloor,
  resolveMinTlsVersion,
  resolveMutualAuthRequired,
} from '../src/collectors/lib/transit.mjs';

/**
 * Encryption in transit, and the authenticity of the peer at the other end of it.
 *
 * The at-rest checks settle half of KSI-SVC-SIN. Encrypted disks say nothing about the same
 * information crossing a network, and the pairing these tests care most about is a bucket under a
 * customer-managed key that will still answer a plaintext HTTP request — the configuration that
 * makes an at-rest-only report actively misleading rather than merely incomplete.
 */

const MIN = '1.2';
const bundleOf = (checkId, ksi, graded) =>
  buildBundle({
    checkId,
    ksis: [ksi],
    collectorPath: 'src/collectors/aws/transit.mjs',
    collectorVersion: '1.0.0',
    collectedAt: '2026-08-19T12:00:00.000Z',
    assertion: 'test',
    scope: {},
    ...graded,
  });

const listener = (over = {}) => ({
  load_balancer: 'edge',
  port: 443,
  protocol: 'HTTPS',
  ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06',
  redirects_to_https: false,
  mutual_authentication: 'off',
  ...over,
});

/* ------------------------------------------------------- the version floor */

/**
 * The floor is declared because it cannot be resolved.
 *
 * Every other parameterised judgement in this harness comes from the pinned ruleset. The CTL
 * entry for sc-13 points at the Cryptographic Module Use rules and carries no version number, so
 * writing 1.2 into the source would be restating a rule the ruleset does not state.
 */
test('the TLS floor comes from the profile, and the bundle records whether it was declared', () => {
  assert.deepEqual(resolveMinTlsVersion({}), { version: '1.2', declared: false });
  assert.deepEqual(resolveMinTlsVersion({ transit: { min_tls_version: '1.3' } }), { version: '1.3', declared: true });
  assert.throws(() => resolveMinTlsVersion({ transit: { min_tls_version: 'strong' } }), /not a TLS version/);
});

test('AWS encodes the floor in the policy name, including the legacy names that predate it', () => {
  assert.equal(elbPolicyFloor('ELBSecurityPolicy-TLS13-1-2-2021-06'), '1.2');
  assert.equal(elbPolicyFloor('ELBSecurityPolicy-TLS-1-1-2017-01'), '1.1');
  assert.equal(elbPolicyFloor('ELBSecurityPolicy-FS-1-2-Res-2020-10'), '1.2');
  assert.equal(elbPolicyFloor('ELBSecurityPolicy-2016-08'), '1.0', 'reads as a security policy and permits TLS 1.0');
});

// AWS adds policies. Resolving an unknown name to "probably fine" would go quietly wrong for
// exactly the newest configurations, which is the wrong direction to be wrong in.
test('an unrecognised policy name resolves to nothing rather than to something acceptable', () => {
  assert.equal(elbPolicyFloor('ELBSecurityPolicy-Quantum-2099-01'), null);
  const graded = gradeAwsTls({ listeners: [listener({ ssl_policy: 'ELBSecurityPolicy-Quantum-2099-01' })] }, { minTlsVersion: MIN });
  assert.equal(graded.items[0].status, 'warn');
  assert.match(graded.items[0].detail, /does not recognise/);
});

test('version comparison is null rather than zero when either side is unparseable', () => {
  assert.equal(compareTlsVersion('1.2', '1.2'), 0);
  assert.ok(compareTlsVersion('1.0', '1.2') < 0);
  assert.ok(compareTlsVersion('TLS_1_3', '1.2') > 0);
  assert.equal(compareTlsVersion('modern', '1.2'), null);
});

/* --------------------------------------------------------- AWS enforcement */

test('a listener whose policy permits an older version than declared fails', () => {
  const graded = gradeAwsTls({ listeners: [listener({ ssl_policy: 'ELBSecurityPolicy-2016-08' })] }, { minTlsVersion: MIN });
  assert.equal(graded.items[0].status, 'fail');
  assert.deepEqual(graded.items[0].observed.permits, '1.0');
});

/**
 * A redirect listener is the standard bare-hostname handler. Failing it would put a permanent
 * finding on a correct configuration, and a report with a permanent finding on a correct
 * configuration is one people learn to skip — but it is not a silent pass either.
 */
test('a plaintext listener warns when it only redirects, and fails when it serves', () => {
  const redirect = gradeAwsTls({ listeners: [listener({ protocol: 'HTTP', port: 80, redirects_to_https: true })] }, { minTlsVersion: MIN });
  assert.equal(redirect.items[0].status, 'warn');
  assert.match(redirect.items[0].detail, /still cross unencrypted/);

  const serving = gradeAwsTls({ listeners: [listener({ protocol: 'HTTP', port: 80, redirects_to_https: false })] }, { minTlsVersion: MIN });
  assert.equal(serving.items[0].status, 'fail');
});

// TLS may terminate on the target behind a TCP listener and no describe call can tell. That is
// the "could not be evaluated" case, not a finding and not a pass.
test('a raw TCP listener is reported as not evaluated', () => {
  const graded = gradeAwsTls({ listeners: [listener({ protocol: 'TCP', port: 9000, ssl_policy: null })] }, { minTlsVersion: MIN });
  assert.equal(graded.items[0].status, 'warn');
  assert.match(graded.items[0].detail, /Not evaluated rather than assumed/);
});

/**
 * The pairing the at-rest check cannot see, and the reason this check is routed to the same
 * indicator rather than to a new one.
 */
test('a bucket with no secure-transport denial fails however well it is encrypted at rest', () => {
  const graded = gradeAwsTls(
    {
      buckets: [
        { name: 'artifacts', policy_present: true, denies_insecure_transport: true },
        { name: 'public-assets', policy_present: true, denies_insecure_transport: false },
        { name: 'logs', policy_present: false, denies_insecure_transport: false },
      ],
    },
    { minTlsVersion: MIN }
  );
  assert.deepEqual(graded.items.map((i) => i.status), ['pass', 'fail', 'fail']);
  assert.match(graded.items[2].detail, /No bucket policy at all/);
});

test('a secure-transport denial is recognised whatever case the condition key carries', () => {
  const policy = (key) => ({ Statement: [{ Effect: 'Deny', Condition: { Bool: { [key]: 'false' } } }] });
  assert.equal(deniesInsecureTransport(policy('aws:SecureTransport')), true);
  assert.equal(deniesInsecureTransport(policy('AWS:SecureTransport')), true);
  assert.equal(deniesInsecureTransport({ Statement: [{ Effect: 'Allow', Condition: { Bool: { 'aws:SecureTransport': 'false' } } }] }), false);
  assert.equal(deniesInsecureTransport(null), false);
});

/* --------------------------------------------------------- GCP enforcement */

/**
 * The finding the GCP check exists for, and the one most tools miss.
 *
 * An HTTPS proxy with no SSL policy is not a proxy without a policy — it is one running Google's
 * default, which negotiates down to TLS 1.0. Nothing on the resource says so, so an estate can be
 * entirely HTTPS and still accept TLS 1.0 on every path.
 */
test('an HTTPS proxy with no SSL policy fails, because the platform default permits TLS 1.0', () => {
  const graded = gradeGcpTls({ https_proxies: [{ name: 'api-https', ssl_policy: null }] }, { minTlsVersion: MIN });
  assert.equal(graded.items[0].status, 'fail');
  assert.equal(graded.items[0].observed.permits, '1.0');
  assert.match(graded.items[0].detail, /Google default/);
});

test('an attached policy is resolved to its floor, and one that is unresolvable warns', () => {
  const data = {
    https_proxies: [
      { name: 'web', ssl_policy: 'tls12' },
      { name: 'internal', ssl_policy: 'legacy' },
      { name: 'ghost', ssl_policy: 'elsewhere' },
    ],
    ssl_policies: [
      { name: 'tls12', min_tls_version: 'TLS_1_2', profile: 'MODERN' },
      { name: 'legacy', min_tls_version: 'TLS_1_0', profile: 'COMPATIBLE' },
    ],
  };
  assert.deepEqual(gradeGcpTls(data, { minTlsVersion: MIN }).items.map((i) => i.status), ['pass', 'fail', 'warn']);
});

test('a target HTTP proxy warns when its URL map only redirects, and fails when it serves', () => {
  const graded = gradeGcpTls(
    {
      http_proxies: [
        { name: 'web-redirect', url_map: 'redirect-map', redirects_to_https: true },
        { name: 'legacy-http', url_map: 'legacy-map', redirects_to_https: false },
      ],
    },
    { minTlsVersion: MIN }
  );
  assert.deepEqual(graded.items.map((i) => i.status), ['warn', 'fail']);
});

/* ------------------------------------------------ mutual authentication */

/**
 * The design decision behind KSI-SVC-VCM: the population is the declaration.
 *
 * The indicator is scoped to communications between machine-based resources. An internet-facing
 * load balancer serving browsers is not one, and grading it for client certificates would be a
 * finding against a correct configuration — so an undeclared listener is not in the population at
 * all, however it is configured.
 */
test('only declared machine-to-machine paths are graded, however the rest are configured', () => {
  const data = { listeners: [listener({ load_balancer: 'public-web', mutual_authentication: 'off' })] };
  assert.deepEqual(gradeAwsMutualAuth(data, { required: [] }).items, []);
  assert.equal(gradeAwsMutualAuth(data, { required: ['public-web'] }).items[0].status, 'fail');
});

/**
 * And the price of that design, stated where it cannot be missed: a boundary that declares
 * nothing evidences nothing, and the bundle contract refuses to call that a pass.
 */
test('an empty declaration is a warning, not a clean result', () => {
  const bundle = bundleOf('aws.transit.mutual-authentication', 'KSI-SVC-VCM', gradeAwsMutualAuth({ listeners: [] }, { required: [] }));
  assert.equal(bundle.population.decidable, 0);
  assert.equal(bundle.result, 'warn');
});

test('passthrough fails: the certificate is forwarded and nothing on this path validates it', () => {
  const data = { listeners: [listener({ load_balancer: 'mesh', mutual_authentication: 'passthrough' })] };
  const item = gradeAwsMutualAuth(data, { required: ['mesh'] }).items[0];
  assert.equal(item.status, 'fail');
  assert.match(item.detail, /still admits a client presenting no certificate/);
});

test('verify passes and names the trust store the decision rests on', () => {
  const data = { listeners: [listener({ load_balancer: 'mesh', mutual_authentication: 'verify', trust_store: 'arn:internal-ca' })] };
  const item = gradeAwsMutualAuth(data, { required: ['mesh'] }).items[0];
  assert.equal(item.status, 'pass');
  assert.equal(item.observed.trust_store, 'arn:internal-ca');
});

// The declaration and the estate disagreeing is itself the finding: nothing here can tell a
// removed path from a renamed one, and either way the profile no longer describes the boundary.
test('a declared path that does not exist fails rather than being quietly dropped', () => {
  const graded = gradeAwsMutualAuth({ listeners: [] }, { required: ['decommissioned-api'] });
  assert.equal(graded.items[0].status, 'fail');
  assert.equal(graded.items[0].id, 'declared/decommissioned-api');
  assert.equal(graded.population.expected, 1, 'and it still occupies the denominator');
});

test('a GCP backend with security settings but no client TLS policy is the near-miss, and fails', () => {
  const data = {
    backend_services: [
      { name: 'mesh-payments', has_security_settings: true, client_tls_policy: 'mtls-strict' },
      { name: 'mesh-ledger', has_security_settings: true, client_tls_policy: null },
    ],
  };
  const graded = gradeGcpMutualAuth(data, { required: ['mesh-payments', 'mesh-ledger'] });
  assert.equal(graded.items[0].status, 'pass');
  assert.equal(graded.items[1].status, 'fail');
  assert.match(graded.items[1].detail, /configured for a mesh and is not validating/);
});

test('the declaration is read per provider and refuses a shape it cannot iterate', () => {
  const profile = { transit: { mutual_auth_required: { aws: ['edge'], gcp: ['mesh'] } } };
  assert.deepEqual(resolveMutualAuthRequired(profile, 'aws'), ['edge']);
  assert.deepEqual(resolveMutualAuthRequired({}, 'gcp'), []);
  assert.throws(() => resolveMutualAuthRequired({ transit: { mutual_auth_required: { aws: 'edge' } } }, 'aws'), /must be a list/);
});
