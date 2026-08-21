import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture, mergeGraded, optional, pages, passRate, perAccount, service } from '../lib/aws.mjs';
import { compareTlsVersion, elbPolicyFloor, resolveMinTlsVersion, resolveMutualAuthRequired } from '../lib/transit.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/aws/transit.mjs';

export const CHECKS = [
  {
    id: 'aws.transit.tls-enforcement',
    ksis: ['KSI-SVC-SIN'],
    fixture: 'aws-transit',
    assertion:
      'No path into the account accepts application traffic in the clear: every load balancer listener either ' +
      'terminates TLS at or above the declared minimum version or exists only to redirect to one, and every ' +
      'bucket policy denies requests made without transport security.',
  },
  {
    id: 'aws.transit.mutual-authentication',
    ksis: ['KSI-SVC-VCM'],
    fixture: 'aws-transit',
    assertion:
      'Every listener the profile declares as a machine-to-machine path verifies its clients with mutual TLS ' +
      'rather than accepting any client that completes a one-way handshake.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Whether anything in the account still speaks plaintext.
 *
 * The at-rest checks answer half of `KSI-SVC-SIN` — "information is encrypted or otherwise secured
 * from unwanted access" is not settled by encrypted disks when the same information crosses a
 * network unprotected. This is the other half, and the route named it as the top gap.
 *
 * Two surfaces, because they are the two an AWS boundary actually leaks through:
 *
 * **Load balancer listeners.** A listener is where a protocol decision becomes observable. HTTP
 * and raw TCP terminate in the clear; HTTPS and TLS terminate encrypted, and the security policy
 * attached to them sets the version floor.
 *
 * **Bucket policies.** S3 endpoints answer over HTTP as readily as HTTPS, and nothing in the
 * bucket's own configuration prevents it — the control is a policy statement denying requests
 * where `aws:SecureTransport` is false. A bucket encrypted with a customer-managed key and no such
 * statement is one that will hand its contents to a plaintext request, which is the pairing that
 * makes reporting at-rest encryption alone actively misleading.
 *
 * ## Why a redirect listener warns instead of failing
 *
 * An HTTP listener whose only action is a redirect to HTTPS serves no application data in the
 * clear, and it is how essentially every public service handles a user typing the bare hostname.
 * Failing it would put a permanent finding on a correct configuration, and a report with a
 * permanent finding on a correct configuration is one people learn to skip. It is not silently
 * passed either: the request line and Host header still cross unencrypted, so it warns and says
 * so.
 *
 * A raw TCP listener warns for a different reason — TLS may terminate on the target behind it,
 * and no describe call can tell. That is the "could not be evaluated" case rather than a finding.
 */
export function gradeTlsEnforcement(data, { minTlsVersion, scopeId = 'account', unexamined = [] } = {}) {
  const items = [];

  for (const listener of data.listeners ?? []) {
    const id = `listener/${listener.load_balancer}/${listener.port}`;
    const protocol = String(listener.protocol ?? '').toUpperCase();

    if (protocol === 'HTTP') {
      items.push(
        listener.redirects_to_https
          ? {
              id,
              status: 'warn',
              detail:
                'Plaintext listener whose only action is a redirect to HTTPS. No application data is served in ' +
                'the clear, but the request line and Host header still cross unencrypted before the redirect.',
              observed: { protocol, redirect: true },
            }
          : {
              id,
              status: 'fail',
              detail:
                'Plaintext HTTP listener forwarding to a target group, so application traffic is served ' +
                'unencrypted.',
              observed: { protocol, redirect: false },
            }
      );
      continue;
    }

    if (protocol === 'TCP' || protocol === 'UDP' || protocol === 'TCP_UDP') {
      items.push({
        id,
        status: 'warn',
        detail:
          `${protocol} listener: TLS may terminate on the target behind it, and no describe call can tell. Not ` +
          'evaluated rather than assumed either way.',
        observed: { protocol },
      });
      continue;
    }

    const floor = elbPolicyFloor(listener.ssl_policy);
    if (!floor) {
      items.push({
        id,
        status: 'warn',
        detail:
          `Encrypted listener with security policy "${listener.ssl_policy ?? 'none'}", whose version floor this ` +
          'harness does not recognise. Reported rather than assumed acceptable, because a policy AWS added ' +
          'after this collector was written is exactly where a silent pass would hide.',
        observed: { protocol, ssl_policy: listener.ssl_policy ?? null },
      });
      continue;
    }

    const delta = compareTlsVersion(floor, minTlsVersion);
    items.push(
      delta < 0
        ? {
            id,
            status: 'fail',
            detail:
              `Security policy ${listener.ssl_policy} permits TLS ${floor}, below the declared minimum of ` +
              `${minTlsVersion}. A client offering the older version is accepted.`,
            observed: { protocol, ssl_policy: listener.ssl_policy, permits: floor, minimum: minTlsVersion },
          }
        : {
            id,
            status: 'pass',
            detail: `Terminates TLS with ${listener.ssl_policy}, which floors at TLS ${floor}.`,
            observed: { protocol, ssl_policy: listener.ssl_policy, permits: floor, minimum: minTlsVersion },
          }
    );
  }

  for (const bucket of data.buckets ?? []) {
    items.push(
      bucket.denies_insecure_transport
        ? {
            id: `bucket/${bucket.name}`,
            status: 'pass',
            detail: 'Bucket policy denies requests where aws:SecureTransport is false.',
          }
        : {
            id: `bucket/${bucket.name}`,
            status: 'fail',
            detail:
              bucket.policy_present
                ? 'Bucket policy does not deny requests made without transport security, so the bucket answers ' +
                  'plaintext HTTP requests as readily as HTTPS.'
                : 'No bucket policy at all, so nothing refuses a plaintext HTTP request to this bucket.',
            observed: { policy_present: Boolean(bucket.policy_present) },
          }
    );
  }

  const enumerated = (data.listeners?.length ?? 0) + (data.buckets?.length ?? 0);
  return {
    items,
    population: {
      expected: enumerated + unexamined.length,
      unexamined,
      source_of_truth:
        'elasticloadbalancing:DescribeListeners over every load balancer in the account, plus s3:GetBucketPolicy ' +
        'per bucket',
      enumerated_from:
        'elasticloadbalancing:DescribeLoadBalancers and s3:ListBuckets, counted before any protocol or policy ' +
        'was read',
    },
    metric: { metric_id: 'aws.transit.paths_refusing_plaintext', value: passRate(items), unit: 'ratio' },
  };
}

/**
 * Whether the paths declared as machine-to-machine actually authenticate their peers.
 *
 * `KSI-SVC-VCM` is about communications between *machine-based* information resources, and that
 * qualifier is the whole design of this check. An internet-facing load balancer serving browsers
 * is not a machine-to-machine path, and requiring client certificates of it would be a finding
 * against a correct configuration — so the population is what the profile *declares* as such,
 * exactly as `gcp.data.encryption-at-rest` grades against declared CMEK buckets. A declaration is
 * what turns "some traffic should be mutually authenticated" into something falsifiable.
 *
 * The consequence is that an empty declaration evidences nothing, and the bundle says so: with no
 * declared paths there is nothing decidable, and the population contract caps the result at `warn`
 * rather than reporting a clean pass over an empty set. That is the correct reading — a boundary
 * that has not identified its machine-to-machine paths has not shown they are validated.
 *
 * A declared listener that no longer exists is a `fail` rather than an omission. It means the
 * declaration and the estate disagree, and the harness cannot tell whether the path was removed or
 * merely renamed — the same reasoning as an undeclared outbound integration in the third-party
 * register.
 */
export function gradeMutualAuthentication(data, { required = [], unexamined = [] } = {}) {
  const items = [];
  const listeners = data.listeners ?? [];

  for (const name of required) {
    const matched = listeners.filter((l) => l.load_balancer === name || l.arn === name);

    if (matched.length === 0) {
      items.push({
        id: `declared/${name}`,
        status: 'fail',
        detail:
          'Declared in transit.mutual_auth_required but no listener by that name was found in the account. The ' +
          'declaration and the estate disagree, and nothing here can tell a removed path from a renamed one.',
      });
      continue;
    }

    for (const listener of matched) {
      const id = `listener/${listener.load_balancer}/${listener.port}`;
      const mode = String(listener.mutual_authentication ?? 'off').toLowerCase();

      if (mode === 'verify') {
        items.push({
          id,
          status: 'pass',
          detail:
            `Mutual TLS in verify mode against ${listener.trust_store ?? 'a trust store'}, so a client is ` +
            'admitted on a certificate this boundary chose to trust.',
          observed: { mutual_authentication: mode, trust_store: listener.trust_store ?? null },
        });
        continue;
      }

      if (mode === 'passthrough') {
        items.push({
          id,
          status: 'fail',
          detail:
            'Mutual TLS is in passthrough mode: the client certificate is forwarded to the target and not ' +
            'validated here. Something downstream may check it, but nothing on this path does, so the listener ' +
            'still admits a client presenting no certificate at all.',
          observed: { mutual_authentication: mode },
        });
        continue;
      }

      items.push({
        id,
        status: 'fail',
        detail:
          'Declared as a machine-to-machine path with mutual authentication off. The listener accepts any client ' +
          'that completes a one-way handshake, so the peer is encrypted to and never identified.',
        observed: { mutual_authentication: mode },
      });
    }
  }

  return {
    items,
    population: {
      expected: items.length + unexamined.length,
      unexamined,
      source_of_truth:
        'the machine-to-machine paths declared at transit.mutual_auth_required.aws, resolved against ' +
        'elasticloadbalancing:DescribeListeners',
      enumerated_from:
        'the declared paths, counted before any listener was read — an undeclared path cannot be graded here, ' +
        'and a declared one that no longer exists still occupies the denominator',
    },
    metric: { metric_id: 'aws.transit.declared_paths_mutually_authenticated', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

/** True when a bucket policy denies on aws:SecureTransport being false. */
export function deniesInsecureTransport(policy) {
  for (const statement of policy?.Statement ?? []) {
    if (statement.Effect !== 'Deny') continue;
    const condition = statement.Condition?.Bool ?? {};
    for (const [key, value] of Object.entries(condition)) {
      if (key.toLowerCase() !== 'aws:securetransport') continue;
      const values = Array.isArray(value) ? value : [value];
      if (values.some((v) => String(v).toLowerCase() === 'false')) return true;
    }
  }
  return false;
}

async function fetchTransit(region, credentials) {
  const unexamined = [];

  const { client: elb, sdk: elbsdk } = await service('elbv2', region, credentials);
  const balancers = await pages(
    elb,
    elbsdk.DescribeLoadBalancersCommand,
    {},
    (r) => r.LoadBalancers,
    'Marker',
    'NextMarker'
  );

  const listeners = [];
  for (const balancer of balancers) {
    let described;
    try {
      described = await pages(
        elb,
        elbsdk.DescribeListenersCommand,
        { LoadBalancerArn: balancer.LoadBalancerArn },
        (r) => r.Listeners,
        'Marker',
        'NextMarker'
      );
    } catch (err) {
      unexamined.push({ id: `load-balancer/${balancer.LoadBalancerName}`, reason: err.message });
      continue;
    }

    for (const listener of described) {
      // A redirect is recorded as a default action, so the distinction between "serves plaintext"
      // and "exists to get clients onto TLS" is readable here and nowhere else.
      const actions = listener.DefaultActions ?? [];
      const redirects =
        actions.length > 0 &&
        actions.every((a) => a.Type === 'redirect' && String(a.RedirectConfig?.Protocol ?? '').toUpperCase() === 'HTTPS');

      listeners.push({
        arn: listener.ListenerArn,
        load_balancer: balancer.LoadBalancerName,
        port: listener.Port,
        protocol: listener.Protocol,
        ssl_policy: listener.SslPolicy ?? null,
        redirects_to_https: redirects,
        mutual_authentication: listener.MutualAuthentication?.Mode ?? 'off',
        trust_store: listener.MutualAuthentication?.TrustStoreArn ?? null,
      });
    }
  }

  const { client: s3, sdk: s3sdk } = await service('s3', region, credentials);
  const listed = await s3.send(new s3sdk.ListBucketsCommand({}));
  const buckets = [];
  for (const bucket of listed.Buckets ?? []) {
    try {
      const got = await optional(s3.send(new s3sdk.GetBucketPolicyCommand({ Bucket: bucket.Name })), [
        'NoSuchBucketPolicy',
      ]);
      const policy = got?.Policy ? JSON.parse(got.Policy) : null;
      buckets.push({
        name: bucket.Name,
        policy_present: Boolean(policy),
        denies_insecure_transport: deniesInsecureTransport(policy),
      });
    } catch (err) {
      // Same line as the at-rest collector draws: a bucket this credential cannot read is a gap,
      // not a bucket without a policy. Grading it as a failure would manufacture a finding out of
      // a permission.
      unexamined.push({ id: `bucket/${bucket.Name}`, reason: err.message });
    }
  }

  return { listeners, buckets, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = (check) => ({
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
    previousHash: previousHashes.get(check.id)?.hash ?? null,
    chainIndex: previousHashes.get(check.id)?.index ?? 0,
  });

  const { version: minTlsVersion, declared } = resolveMinTlsVersion(profile);
  const required = resolveMutualAuthRequired(profile, 'aws');

  if (fixture) {
    const data = loadFixture(fixture, 'aws-transit');
    const floor = data.min_tls_version ?? minTlsVersion;
    return [
      buildBundle({
        ...common(CHECKS[0]),
        scope: fixtureScope(fixture, 'aws-transit', { min_tls_version: floor }),
        ...gradeTlsEnforcement(data, {
          minTlsVersion: floor,
          scopeId: data.account ?? 'fixture',
          unexamined: data.unexamined ?? [],
        }),
      }),
      buildBundle({
        ...common(CHECKS[1]),
        scope: fixtureScope(fixture, 'aws-transit', { mutual_auth_required: data.mutual_auth_required ?? [] }),
        ...gradeMutualAuthentication(data, { required: data.mutual_auth_required ?? [] }),
      }),
    ];
  }

  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, region, credentials }) => {
    const data = await fetchTransit(region, credentials);
    return { data, graded: gradeTlsEnforcement(data, { minTlsVersion, scopeId: account.id, unexamined: data.unexamined }) };
  });

  // One fetch, two checks. Re-listing every load balancer to grade mutual authentication would
  // double the API cost and, worse, grade the two checks against two different observations of an
  // estate that can change between them.
  const tlsParts = parts.map((p) => ({ scope: p.scope, graded: p.graded.graded }));
  const authParts = parts.map((p) => ({
    scope: p.scope,
    graded: gradeMutualAuthentication(p.graded.data, { required }),
  }));

  const scope = {
    accounts: accounts.map((a) => a.id),
    collector_role: profile?.aws?.collector_role ?? null,
    min_tls_version: minTlsVersion,
    min_tls_version_declared: declared,
  };

  return [
    buildBundle({
      ...common(CHECKS[0]),
      scope,
      ...mergeGraded(tlsParts, {
        sourceOfTruth: 'load balancer listeners and bucket policies in each declared account',
        enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'aws.transit.paths_refusing_plaintext', unit: 'ratio' },
        unexamined,
      }),
    }),
    buildBundle({
      ...common(CHECKS[1]),
      scope: { ...scope, mutual_auth_required: required },
      ...mergeGraded(authParts, {
        sourceOfTruth: 'the machine-to-machine paths declared at transit.mutual_auth_required.aws',
        enumeratedFrom: 'the declared paths, resolved against the listeners found in each declared account',
        metric: { metric_id: 'aws.transit.declared_paths_mutually_authenticated', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
