export { fixtureScope, loadFixture } from './fixtures.mjs';
export { accountItem, mergeGraded, passRate } from './grade.mjs';

/**
 * Shared plumbing for the GCP checks. Plain `fetch` against the REST APIs, with
 * google-auth-library used only to mint an access token.
 *
 * Deliberately not the per-service client libraries. Half a dozen `@google-cloud/*`
 * packages would each need pinning, and the REST surfaces here — resource manager, IAM,
 * logging, org policy, compute, storage — are stable and well documented. One optional
 * dependency instead of six, and the same shape as lib/github.mjs, which already reads a
 * paginated JSON API by hand.
 *
 * The failure classification is the part that earns its keep, for the same reason it does
 * on the GitHub side: a 403 from a Google API is at least three unrelated facts.
 *
 *   quota / rate limit   The run is broken. Throw. A security conclusion drawn from an
 *                        exhausted quota is not a finding.
 *   API not enabled      A real finding, and a specific one: the service this check reads
 *                        has never been turned on in this project.
 *   permission denied    A finding, but an unverifiable one. Warn, and name the permission.
 *
 * Collapsing those into "the check failed" is how a collector comes to report a clean pass
 * over a project it was never allowed to read.
 */

const BASE = {
  crm: 'https://cloudresourcemanager.googleapis.com/v1',
  crm3: 'https://cloudresourcemanager.googleapis.com/v3',
  iam: 'https://iam.googleapis.com/v1',
  orgpolicy: 'https://orgpolicy.googleapis.com/v2',
  logging: 'https://logging.googleapis.com/v2',
  compute: 'https://compute.googleapis.com/compute/v1',
  storage: 'https://storage.googleapis.com/storage/v1',
  serviceusage: 'https://serviceusage.googleapis.com/v1',
};

export class RunBroken extends Error {}

/**
 * An access token from Application Default Credentials.
 *
 * Workload Identity Federation is the intended path and the reason no key file is read
 * here: a downloaded service account key is the single most characteristic GCP finding
 * there is, and two of this harness's own checks would fail a collector that used one.
 */
export async function accessToken() {
  let GoogleAuth;
  try {
    ({ GoogleAuth } = await import('google-auth-library'));
  } catch {
    throw new Error(
      'google-auth-library is not installed. It is an optional dependency because the repository must ' +
        'install and test without it. Run: npm install google-auth-library'
    );
  }
  const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform.read-only'] });
  const client = await auth.getClient();
  const { token } = await client.getAccessToken();
  if (!token) throw new Error('Application Default Credentials produced no access token.');
  return token;
}

/** Reads a non-2xx response and says which of the three things it is. */
export function classifyFailure(status, body) {
  const message = String(body?.error?.message ?? '');
  const reason = body?.error?.details?.[0]?.reason ?? body?.error?.status ?? '';

  if (status === 429 || /quota|rate limit/i.test(message) || reason === 'RATE_LIMIT_EXCEEDED') {
    throw new RunBroken(
      `GCP API quota exhausted: ${message}. This is a broken run rather than a finding — treating it as a ` +
        `security conclusion would be a conclusion drawn from an exhausted quota.`
    );
  }
  if (status === 403 && /has not been used|is disabled|SERVICE_DISABLED/i.test(message + reason)) {
    return { kind: 'api-disabled', status: 'fail', detail: `Required API is not enabled: ${message}` };
  }
  if (status === 403 || status === 401) {
    return { kind: 'permission', status: 'warn', detail: `Credential lacks permission to verify this: ${message}` };
  }
  if (status === 404) return { kind: 'absent', status: 'warn', detail: `Not found: ${message || 'no resource'}` };
  return null;
}

/**
 * One API call. Returns `{ ok, status, body, classification }`.
 *
 * Non-2xx is returned rather than thrown, apart from a broken run, because "this project
 * never enabled Cloud Asset Inventory" is a finding about the project and has to reach the
 * bundle rather than abort the collection.
 */
export async function api(url, { token, method = 'GET' } = {}) {
  const res = await fetch(url, {
    method,
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
  });
  let body = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { error: { message: text.slice(0, 200) } };
    }
  }
  if (res.ok) return { ok: true, status: res.status, body };
  return { ok: false, status: res.status, body, classification: classifyFailure(res.status, body) };
}

/** Follows `nextPageToken` and concatenates one named collection across pages. */
export async function paginate(url, collection, { token, max = 100 } = {}) {
  const out = [];
  let pageToken;
  for (let page = 0; page < max; page += 1) {
    const sep = url.includes('?') ? '&' : '?';
    const res = await api(pageToken ? `${url}${sep}pageToken=${encodeURIComponent(pageToken)}` : url, { token });
    if (!res.ok) return { ok: false, items: out, ...res };
    out.push(...(res.body?.[collection] ?? []));
    pageToken = res.body?.nextPageToken;
    if (!pageToken) break;
  }
  return { ok: true, items: out };
}

export const endpoint = (service, path) => `${BASE[service]}${path}`;

/**
 * Projects in scope, from the profile.
 *
 * Same principle as the AWS accounts and the GitHub repositories: declared, never
 * discovered. Enumerating the organization would let a shadow project — the failure mode
 * named in the GRC Engineering Club cloud chapter, and the one Org Policy exists to
 * prevent — enter the authorization boundary without anyone deciding it should.
 */
export function resolveProjects(profile) {
  const projects = profile?.gcp?.projects ?? [];
  if (!Array.isArray(projects) || projects.length === 0) {
    throw new Error(
      'No GCP projects in the profile (gcp.projects). Scope is declared, never discovered: enumerating the ' +
        'organization would let a project outside governance join the boundary without a decision.'
    );
  }
  return projects.map((p) => (typeof p === 'string' ? { id: p } : p));
}

/**
 * Runs one grading function against every project the profile declares.
 *
 * Returns `{ parts, unexamined, projects }` shaped for `mergeGraded`. A project that cannot
 * be read becomes an itemised gap rather than an absence, which is the difference between a
 * boundary of six projects reported as incomplete and a boundary of four reported as clean.
 */
export async function perProject(profile, fn) {
  const projects = resolveProjects(profile);
  const token = await accessToken();
  const parts = [];
  const unexamined = [];

  for (const project of projects) {
    try {
      const graded = await fn({ project, token, organizationId: profile?.gcp?.organization_id ?? null });
      parts.push({ scope: project.id, graded });
    } catch (err) {
      if (err instanceof RunBroken) throw err;
      unexamined.push({ id: `project/${project.id}`, reason: err.message });
    }
  }

  return { parts, unexamined, projects };
}
