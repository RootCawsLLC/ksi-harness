import { buildBundle } from '../../evidence/bundle.mjs';
import { api, endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';
import { compareTlsVersion, resolveMinTlsVersion, resolveMutualAuthRequired } from '../lib/transit.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/transit.mjs';

export const CHECKS = [
  {
    id: 'gcp.transit.tls-enforcement',
    ksis: ['KSI-SVC-SIN'],
    fixture: 'gcp-transit',
    assertion:
      'No load balancer in scope serves application traffic in the clear, and every HTTPS proxy is bound to an ' +
      'SSL policy whose minimum TLS version meets the declared floor rather than inheriting the platform default.',
  },
  {
    id: 'gcp.transit.mutual-authentication',
    ksis: ['KSI-SVC-VCM'],
    fixture: 'gcp-transit',
    assertion:
      'Every backend service the profile declares as a machine-to-machine path is bound to a client TLS policy, ' +
      'so its peers are authenticated rather than merely encrypted to.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Whether a GCP boundary still terminates anything in the clear, and at what floor.
 *
 * The AWS collector's finding is usually a listener somebody left on port 80. GCP's is quieter and
 * is the reason this check earns its place separately rather than being the same logic with
 * different nouns:
 *
 * **A target HTTPS proxy with no SSL policy attached is not a proxy without a policy — it is one
 * running Google's default,** and that default negotiates down to TLS 1.0. There is no field
 * saying so and nothing in the console flags it. An estate can be entirely HTTPS, hold no plaintext
 * proxy at all, and still accept TLS 1.0 on every path, which is precisely the configuration a
 * reviewer expects a compliance tool to catch and most do not. So an absent `sslPolicy` is graded
 * against the declared floor exactly as an attached one is, with the detail saying where the floor
 * came from.
 *
 * Plaintext ingress is a `targetHttpProxy`. As on AWS, one whose URL map does nothing but redirect
 * to HTTPS warns rather than fails: no application data crosses in the clear, and failing the
 * standard bare-hostname redirect would put a permanent finding on a correct configuration.
 */
export function gradeTlsEnforcement(data, { minTlsVersion, scopeId = 'project', unexamined = [] } = {}) {
  const items = [];
  const policies = new Map((data.ssl_policies ?? []).map((p) => [p.name, p]));

  for (const proxy of data.http_proxies ?? []) {
    items.push(
      proxy.redirects_to_https
        ? {
            id: `http-proxy/${proxy.name}`,
            status: 'warn',
            detail:
              'Plaintext proxy whose URL map only redirects to HTTPS. No application data is served in the ' +
              'clear, though the request still crosses unencrypted before the redirect.',
            observed: { redirect: true },
          }
        : {
            id: `http-proxy/${proxy.name}`,
            status: 'fail',
            detail:
              `Target HTTP proxy serving URL map ${proxy.url_map ?? 'unknown'}, so application traffic is ` +
              'served unencrypted.',
            observed: { redirect: false, url_map: proxy.url_map ?? null },
          }
    );
  }

  for (const proxy of data.https_proxies ?? []) {
    const id = `https-proxy/${proxy.name}`;

    if (!proxy.ssl_policy) {
      // The finding this check exists for. Google's default profile is COMPATIBLE, which
      // negotiates down to TLS 1.0, and nothing in the resource says so.
      items.push({
        id,
        status: 'fail',
        detail:
          'No SSL policy is attached, so the proxy runs the Google default, which negotiates down to TLS 1.0 — ' +
          `below the declared minimum of ${minTlsVersion}. The resource carries no field saying this, which is ` +
          'why an all-HTTPS estate can still accept TLS 1.0 on every path.',
        observed: { ssl_policy: null, permits: '1.0', minimum: minTlsVersion },
      });
      continue;
    }

    const policy = policies.get(proxy.ssl_policy);
    if (!policy) {
      items.push({
        id,
        status: 'warn',
        detail:
          `Bound to SSL policy "${proxy.ssl_policy}", which was not among the policies listed for this project. ` +
          'The floor could not be resolved, so it is reported rather than assumed.',
        observed: { ssl_policy: proxy.ssl_policy },
      });
      continue;
    }

    const delta = compareTlsVersion(policy.min_tls_version, minTlsVersion);
    if (delta == null) {
      items.push({
        id,
        status: 'warn',
        detail: `SSL policy ${policy.name} reports minTlsVersion "${policy.min_tls_version}", which this harness could not parse.`,
        observed: { ssl_policy: policy.name, permits: policy.min_tls_version ?? null },
      });
      continue;
    }

    items.push(
      delta < 0
        ? {
            id,
            status: 'fail',
            detail:
              `SSL policy ${policy.name} permits TLS ${policy.min_tls_version}, below the declared minimum of ` +
              `${minTlsVersion}.`,
            observed: {
              ssl_policy: policy.name,
              permits: policy.min_tls_version,
              minimum: minTlsVersion,
              profile: policy.profile ?? null,
            },
          }
        : {
            id,
            status: 'pass',
            detail: `Bound to SSL policy ${policy.name}, which floors at TLS ${policy.min_tls_version}.`,
            observed: {
              ssl_policy: policy.name,
              permits: policy.min_tls_version,
              minimum: minTlsVersion,
              profile: policy.profile ?? null,
            },
          }
    );
  }

  const enumerated = (data.http_proxies?.length ?? 0) + (data.https_proxies?.length ?? 0);
  return {
    items,
    population: {
      expected: enumerated + unexamined.length,
      unexamined,
      source_of_truth:
        'compute:targetHttpProxies.list and compute:targetHttpsProxies.list, with compute:sslPolicies.list ' +
        'resolving each attached policy',
      enumerated_from:
        'targetHttpProxies.list and targetHttpsProxies.list per declared project, counted before any SSL policy ' +
        'was resolved',
    },
    metric: { metric_id: 'gcp.transit.proxies_meeting_tls_floor', value: passRate(items), unit: 'ratio' },
  };
}

/**
 * Whether the declared machine-to-machine backends authenticate their peers.
 *
 * Same design as the AWS half and for the same reason: `KSI-SVC-VCM` is scoped to communications
 * between machine-based resources, so the population is what the profile declares rather than every
 * backend service in the project. Requiring client certificates of a public web backend would be a
 * finding against a correct configuration.
 *
 * GCP expresses this as `securitySettings.clientTlsPolicy` on a backend service — the Traffic
 * Director mechanism that makes a mesh mutually authenticated. A backend with security settings but
 * no client TLS policy is the interesting near-miss: it is configured for a mesh and is not
 * validating peers in it.
 */
export function gradeMutualAuthentication(data, { required = [], unexamined = [] } = {}) {
  const items = [];
  const backends = new Map((data.backend_services ?? []).map((b) => [b.name, b]));

  for (const name of required) {
    const backend = backends.get(name);

    if (!backend) {
      items.push({
        id: `declared/${name}`,
        status: 'fail',
        detail:
          'Declared in transit.mutual_auth_required but no backend service by that name exists in the project. ' +
          'The declaration and the estate disagree, and nothing here distinguishes a removed path from a ' +
          'renamed one.',
      });
      continue;
    }

    const id = `backend-service/${name}`;
    if (backend.client_tls_policy) {
      items.push({
        id,
        status: 'pass',
        detail:
          `Bound to client TLS policy ${backend.client_tls_policy}, so peers on this path present certificates ` +
          'this boundary validates.',
        observed: {
          client_tls_policy: backend.client_tls_policy,
          subject_alt_names: backend.subject_alt_names ?? [],
        },
      });
      continue;
    }

    items.push({
      id,
      status: 'fail',
      detail:
        backend.has_security_settings
          ? 'Carries security settings but no clientTlsPolicy, so the backend is configured for a mesh and is ' +
            'not validating the peers in it.'
          : 'Declared as a machine-to-machine path with no clientTlsPolicy, so traffic to this backend is ' +
            'encrypted to a peer nothing identifies.',
      observed: { client_tls_policy: null, has_security_settings: Boolean(backend.has_security_settings) },
    });
  }

  return {
    items,
    population: {
      expected: items.length + unexamined.length,
      unexamined,
      source_of_truth:
        'the machine-to-machine paths declared at transit.mutual_auth_required.gcp, resolved against ' +
        'compute:backendServices.list',
      enumerated_from:
        'the declared paths, counted before any backend service was read — a declared path that no longer ' +
        'exists still occupies the denominator',
    },
    metric: { metric_id: 'gcp.transit.declared_paths_mutually_authenticated', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchTransit(projectId, token) {
  const unexamined = [];

  const listOrGap = async (path, label) => {
    const res = await paginate(endpoint('compute', path), 'items', { token });
    if (!res.ok) {
      unexamined.push({
        id: `project/${projectId}/${label}`,
        reason: res.classification?.detail ?? `${label} failed with HTTP ${res.status}`,
      });
      return null;
    }
    return res.items;
  };

  const httpProxies = (await listOrGap(`/projects/${projectId}/global/targetHttpProxies`, 'targetHttpProxies')) ?? [];
  const httpsProxies = (await listOrGap(`/projects/${projectId}/global/targetHttpsProxies`, 'targetHttpsProxies')) ?? [];
  const sslPolicies = (await listOrGap(`/projects/${projectId}/global/sslPolicies`, 'sslPolicies')) ?? [];
  const backends = (await listOrGap(`/projects/${projectId}/global/backendServices`, 'backendServices')) ?? [];

  // A target HTTP proxy is only plaintext ingress if its URL map actually serves something. A map
  // whose default action is an HTTPS redirect is the standard bare-hostname handler, and the
  // distinction is only visible in the map rather than on the proxy.
  const urlMaps = new Map();
  for (const proxy of httpProxies) {
    const name = proxy.urlMap?.split('/').pop();
    if (!name || urlMaps.has(name)) continue;
    const res = await api(endpoint('compute', `/projects/${projectId}/global/urlMaps/${name}`), { token });
    urlMaps.set(name, res.ok ? res.body : null);
    if (!res.ok) {
      unexamined.push({
        id: `url-map/${name}`,
        reason: res.classification?.detail ?? `urlMaps.get failed with HTTP ${res.status}`,
      });
    }
  }

  return {
    http_proxies: httpProxies.map((p) => {
      const mapName = p.urlMap?.split('/').pop();
      const map = mapName ? urlMaps.get(mapName) : null;
      return {
        name: p.name,
        url_map: mapName ?? null,
        redirects_to_https: Boolean(map?.defaultUrlRedirect?.httpsRedirect),
      };
    }),
    https_proxies: httpsProxies.map((p) => ({
      name: p.name,
      ssl_policy: p.sslPolicy?.split('/').pop() ?? null,
    })),
    ssl_policies: sslPolicies.map((p) => ({
      name: p.name,
      min_tls_version: p.minTlsVersion ?? null,
      profile: p.profile ?? null,
    })),
    backend_services: backends.map((b) => ({
      name: b.name,
      has_security_settings: Boolean(b.securitySettings),
      client_tls_policy: b.securitySettings?.clientTlsPolicy?.split('/').pop() ?? null,
      subject_alt_names: b.securitySettings?.subjectAltNames ?? [],
    })),
    unexamined,
  };
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
  const required = resolveMutualAuthRequired(profile, 'gcp');

  if (fixture) {
    const data = loadFixture(fixture, 'gcp-transit');
    const floor = data.min_tls_version ?? minTlsVersion;
    return [
      buildBundle({
        ...common(CHECKS[0]),
        scope: fixtureScope(fixture, 'gcp-transit', { project: data.project, min_tls_version: floor }),
        ...gradeTlsEnforcement(data, {
          minTlsVersion: floor,
          scopeId: data.project,
          unexamined: data.unexamined ?? [],
        }),
      }),
      buildBundle({
        ...common(CHECKS[1]),
        scope: fixtureScope(fixture, 'gcp-transit', {
          project: data.project,
          mutual_auth_required: data.mutual_auth_required ?? [],
        }),
        ...gradeMutualAuthentication(data, { required: data.mutual_auth_required ?? [] }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const data = await fetchTransit(project.id, token);
    return { data, graded: gradeTlsEnforcement(data, { minTlsVersion, scopeId: project.id, unexamined: data.unexamined }) };
  });

  // One fetch feeding both checks, so the two are graded against the same observation of an estate
  // that can change between calls.
  const tlsParts = parts.map((p) => ({ scope: p.scope, graded: p.graded.graded }));
  const authParts = parts.map((p) => ({
    scope: p.scope,
    graded: gradeMutualAuthentication(p.graded.data, { required }),
  }));

  const scope = {
    projects: projects.map((p) => p.id),
    min_tls_version: minTlsVersion,
    min_tls_version_declared: declared,
  };

  return [
    buildBundle({
      ...common(CHECKS[0]),
      scope,
      ...mergeGraded(tlsParts, {
        sourceOfTruth: 'target proxies and SSL policies in each declared project',
        enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'gcp.transit.proxies_meeting_tls_floor', unit: 'ratio' },
        unexamined,
      }),
    }),
    buildBundle({
      ...common(CHECKS[1]),
      scope: { ...scope, mutual_auth_required: required },
      ...mergeGraded(authParts, {
        sourceOfTruth: 'the machine-to-machine paths declared at transit.mutual_auth_required.gcp',
        enumeratedFrom: 'the declared paths, resolved against the backend services found in each declared project',
        metric: { metric_id: 'gcp.transit.declared_paths_mutually_authenticated', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
