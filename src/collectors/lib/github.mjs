export { fixtureScope, loadFixture } from './fixtures.mjs';
export { passRate } from './grade.mjs';

/**
 * Shared plumbing for the GitHub checks. Plain `fetch`, no SDK.
 *
 * The whole value of this module is `classifyFailure`. A 403 from the GitHub API is at
 * least three unrelated facts, and conflating them produces evidence that is wrong in
 * different directions:
 *
 *   rate limit      The run is broken. Throw — reporting a finding here would record a
 *                   security conclusion drawn from an exhausted quota.
 *   missing scope   A finding, but an unverifiable one: warn, and say which permission.
 *   plan gate       A finding, and a hard one: the control cannot pass on this plan, so it
 *                   fails rather than warns. "Upgrade to GitHub Pro" is a real 403 body.
 *
 * This distinction came out of live runs in RootCawsLLC/grc-wizard and each case is pinned
 * by a regression test carrying the exact wire shape observed.
 */

const API = 'https://api.github.com';

export class RunBroken extends Error {}

export function token() {
  const t = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!t) {
    throw new Error(
      'No GITHUB_TOKEN or GH_TOKEN in the environment. Locally: export GITHUB_TOKEN=$(gh auth token). ' +
        'In Actions the default token cannot read other repositories, so a scoped secret is required.'
    );
  }
  return t;
}

function headers(auth) {
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${auth}`,
    'x-github-api-version': '2022-11-28',
    'user-agent': 'ksi-harness',
  };
}

/**
 * Reads a 403 and says which of the three things it is.
 *
 * Returned as data rather than thrown (except for the broken-run case) so the caller decides
 * how it lands in the bundle.
 */
export function classifyFailure(status, body, rateLimitRemaining) {
  const message = String(body?.message ?? '');

  if (status === 403 || status === 429) {
    if (/rate limit|secondary rate|abuse detection/i.test(message) || rateLimitRemaining === '0') {
      throw new RunBroken(
        `GitHub rate limit reached: ${message}. This is a broken run, not a finding — treating it as a ` +
          `security conclusion would be a conclusion drawn from an exhausted quota.`
      );
    }
    if (/upgrade to github|not available for your plan|only available|advanced security/i.test(message)) {
      return { kind: 'plan-gate', status: 'fail', detail: `Unavailable on this GitHub plan: ${message}` };
    }
    return { kind: 'permission', status: 'warn', detail: `Token lacks permission to verify this: ${message}` };
  }
  if (status === 404) return { kind: 'absent', status: 'warn', detail: `Not found: ${message || 'no resource'}` };
  return null;
}

/**
 * One API call. Returns `{ ok, status, body, classification }`.
 *
 * Non-2xx responses are not thrown, apart from a broken run, because "the token cannot see
 * branch protection" is a finding about the repository and needs to reach the bundle.
 */
export async function api(path, { auth = token(), method = 'GET' } = {}) {
  const res = await fetch(path.startsWith('http') ? path : `${API}${path}`, { method, headers: headers(auth) });
  let body = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { message: text.slice(0, 200) };
    }
  }
  if (res.ok) return { ok: true, status: res.status, body, link: res.headers.get('link') };
  const classification = classifyFailure(res.status, body, res.headers.get('x-ratelimit-remaining'));
  return { ok: false, status: res.status, body, classification };
}

/**
 * Follows `Link: rel="next"` verbatim rather than incrementing a page counter.
 *
 * Constructing the next URL by hand drops query parameters the server added and silently
 * truncates the population, which is the failure this exists to avoid.
 */
export async function paginate(path, { auth = token(), max = 100 } = {}) {
  const out = [];
  let url = path.startsWith('http') ? path : `${API}${path}`;
  for (let page = 0; page < max && url; page += 1) {
    const res = await api(url, { auth });
    if (!res.ok) return { ok: false, items: out, ...res };
    out.push(...(Array.isArray(res.body) ? res.body : [res.body]));
    const next = /<([^>]+)>;\s*rel="next"/.exec(res.link ?? '');
    url = next?.[1] ?? null;
  }
  return { ok: true, items: out };
}

/**
 * Repositories in scope, from the profile.
 *
 * Same principle as the AWS accounts: declared, never discovered. An org-wide listing would
 * let a new repository enter the certification boundary without anyone deciding it should.
 */
export function resolveRepos(profile) {
  const repos = profile?.github?.repositories ?? [];
  if (!Array.isArray(repos) || repos.length === 0) {
    throw new Error(
      'No repositories in the profile (github.repositories). Scope is declared, never discovered: ' +
        'an org-wide listing would let a new repository join the boundary without a decision.'
    );
  }
  return repos.map((r) => (typeof r === 'string' ? { name: r } : r));
}
