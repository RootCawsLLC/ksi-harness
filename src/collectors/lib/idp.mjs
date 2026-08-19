export { fixtureScope, loadFixture } from './fixtures.mjs';
export { mergeGraded, passRate } from './grade.mjs';

/**
 * Talking to an identity provider, and normalising what it says.
 *
 * The cloud collectors read an account's *resulting* state: who holds which role today. That is
 * the wrong instrument for `KSI-IAM-AAM`, which asks whether the lifecycle and privileges of
 * accounts, roles and groups are "securely managed **using automation**". The indicator is about
 * the mechanism, not the outcome — a perfectly correct set of permissions assigned by hand fails
 * it, and only the identity provider knows which it was.
 *
 * Two providers dominate this space and describe the same facts with different nouns, so the
 * collector grades a normalised shape rather than a vendor payload:
 *
 *   account   { id, login, status, source, privileged }
 *   group     { id, name, membership, privileged }
 *   grant     { id, subject, target, via }        via: 'group' | 'direct'
 *
 * `source` is the one that matters. An account created by directory sync, SCIM, or an HR feed was
 * provisioned by automation; one created through the admin console was provisioned by a person.
 * Both look identical once they exist, which is exactly why the indicator has to be evidenced at
 * the provider rather than downstream.
 *
 * Okta is implemented. Entra ID is not, and the profile refuses an unknown provider rather than
 * guessing at a shape it has never seen — a normaliser written against documentation instead of
 * responses is how a collector reports confidently about a payload it has never received.
 */

export const PROVIDERS = Object.freeze(['okta']);

/** Provisioning sources that constitute automation. Anything else is a person at a console. */
export const AUTOMATED_SOURCES = Object.freeze([
  'ACTIVE_DIRECTORY',
  'LDAP',
  'SCIM',
  'HR_IMPORT',
  'IMPORTED',
  'APP_IMPORT',
]);

/** Okta lifecycle states that mean the account can still be used. */
const LIVE = new Set(['ACTIVE', 'RECOVERY', 'PASSWORD_EXPIRED', 'LOCKED_OUT']);

export class IdpUnavailable extends Error {}

/**
 * Reads the IdP block, refusing rather than defaulting.
 *
 * An identity provider nobody declared is not discovered, for the same reason no account or
 * project is (ADR 0004). Guessing here would be worse than elsewhere: the estate of identities is
 * precisely the thing an authorization boundary is drawn around.
 */
export function resolveIdp(profile) {
  const idp = profile?.idp;
  if (!idp) return null;

  if (!idp.provider) {
    throw new Error('idp.provider is required. Known: ' + PROVIDERS.join(', ') + '.');
  }
  if (!PROVIDERS.includes(idp.provider)) {
    throw new Error(
      `Unknown idp.provider "${idp.provider}". Only ${PROVIDERS.join(', ')} is implemented. A normaliser ` +
        'written against documentation rather than real responses would report confidently about a payload ' +
        'it has never seen, which is worse than declining.'
    );
  }
  if (!idp.domain) throw new Error(`idp.domain is required for ${idp.provider}.`);

  return {
    provider: idp.provider,
    domain: idp.domain,
    tokenEnv: idp.token_env ?? 'KSI_IDP_TOKEN',
    automatedSources: new Set(idp.automated_sources ?? AUTOMATED_SOURCES),
    privilegedGroups: new Set(idp.privileged_groups ?? []),
    // An HR feed is the only thing that can answer "does this account correspond to a person who
    // still works here". Optional, and its absence is a stated gap rather than a silent one.
    hrSource: idp.hr_source ?? null,
  };
}

function token(idp) {
  const value = process.env[idp.tokenEnv];
  if (!value) {
    throw new IdpUnavailable(
      `${idp.tokenEnv} is not set, so ${idp.domain} could not be read. This is a credentials failure and not ` +
        'a finding about the identity provider.'
    );
  }
  return value;
}

async function oktaPaginate(idp, path, { fetchImpl = fetch, max = 50 } = {}) {
  const out = [];
  let url = `https://${idp.domain}/api/v1${path}`;
  for (let page = 0; url && page < max; page += 1) {
    const res = await fetchImpl(url, {
      headers: { authorization: `SSWS ${token(idp)}`, accept: 'application/json' },
    });
    if (res.status === 401 || res.status === 403) {
      throw new IdpUnavailable(`${idp.domain} returned HTTP ${res.status}. The token cannot read this resource.`);
    }
    if (!res.ok) throw new IdpUnavailable(`${idp.domain} returned HTTP ${res.status} for ${path}.`);
    out.push(...(await res.json()));

    // Okta paginates by Link header, and a collector that ignored it would report on the first
    // 200 identities and call the population complete.
    const link = res.headers.get?.('link') ?? '';
    const next = /<([^>]+)>;\s*rel="next"/.exec(link);
    url = next ? next[1] : null;
  }
  return out;
}

/** Okta users → the normalised account shape. */
export function normaliseOktaUsers(users, idp) {
  return users.map((u) => ({
    id: u.id,
    login: u.profile?.login ?? u.id,
    status: u.status,
    live: LIVE.has(u.status),
    // `credentials.provider.type` is how Okta records where the identity actually comes from.
    source: u.credentials?.provider?.type ?? 'UNKNOWN',
    lastLogin: u.lastLogin ?? null,
  }));
}

/** Okta groups → the normalised group shape. `APP_GROUP` and `BUILT_IN` are directory-driven. */
export function normaliseOktaGroups(groups, idp) {
  return groups.map((g) => ({
    id: g.id,
    name: g.profile?.name ?? g.id,
    // OKTA_GROUP is hand-curated unless a group rule drives it; the rule list is fetched separately.
    membership: g.type === 'OKTA_GROUP' ? 'manual' : 'directory',
    privileged: idp.privilegedGroups.has(g.profile?.name ?? ''),
  }));
}

export async function fetchOkta(idp, { fetchImpl = fetch } = {}) {
  const [users, groups, rules] = await Promise.all([
    oktaPaginate(idp, '/users?limit=200', { fetchImpl }),
    oktaPaginate(idp, '/groups?limit=200', { fetchImpl }),
    oktaPaginate(idp, '/groups/rules?limit=200', { fetchImpl }),
  ]);

  // A group with a rule behind it is membership by policy rather than by hand, whatever its type.
  const ruled = new Set(rules.flatMap((r) => r.actions?.assignUserToGroups?.groupIds ?? []));
  const normalisedGroups = normaliseOktaGroups(groups, idp).map((g) =>
    ruled.has(g.id) ? { ...g, membership: 'rule' } : g
  );

  return { accounts: normaliseOktaUsers(users, idp), groups: normalisedGroups };
}
