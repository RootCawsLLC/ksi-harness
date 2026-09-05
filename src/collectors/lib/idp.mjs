import { readFileSync } from 'node:fs';

export { fixtureScope, loadFixture } from './fixtures.mjs';
export { mergeGraded, passRate } from './grade.mjs';

/**
 * Talking to an identity provider, and normalizing what it says.
 *
 * The cloud collectors read an account's *resulting* state: who holds which role today. That is
 * the wrong instrument for `KSI-IAM-AAM`, which asks whether the lifecycle and privileges of
 * accounts, roles and groups are "securely managed **using automation**". The indicator is about
 * the mechanism, not the outcome — a perfectly correct set of permissions assigned by hand fails
 * it, and only the identity provider knows which it was.
 *
 * Two providers dominate this space and describe the same facts with different nouns, so the
 * collector grades a normalized shape rather than a vendor payload:
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
    // still works here". Optional, and its absence is reported per account as an unexamined
    // population rather than as a silent pass — see resolveHrSource.
    hrSource: resolveHrSource(idp.hr_source),
    // Identities the roster is not expected to contain, declared one login at a time. The
    // roster collector explains why this is a list rather than a naming convention.
    nonHumanAccounts: new Set((idp.non_human_accounts ?? []).map((l) => String(l).trim().toLowerCase())),
  };
}

/**
 * Reading the roster the profile declares.
 *
 * `KSI-IAM-AAM` has two halves and the collector above evidences one of them. "Lifecycle and
 * privileges ... securely managed using automation" is not settled by showing that provisioning
 * was automated: an account created flawlessly by SCIM, holding exactly the right permissions,
 * and belonging to somebody who left in March passes every check the identity provider can
 * answer on its own. The provisioning source records how an account was created and never
 * whether it should still exist.
 *
 * Only an authoritative roster of people can answer that, and it lives outside the identity
 * provider by definition — which is the whole reason the reconciliation is the finding rather
 * than either list alone. The same shape as `thirdparty.register.review`: a declaration, an
 * independent observation, and the gap between them treated as the result.
 *
 * A file rather than an API, for now. Every HRIS worth reconciling against exports one, the
 * export is what an assessor will be shown anyway, and a normaliser written against Workday's
 * API without ever having received a Workday response would be the mistake this library already
 * refuses to make for Entra ID.
 *
 * `max_age_days` is not decoration. A roster is a snapshot, and a stale snapshot still lists a
 * leaver as employed — so the check would read clean for exactly as long as nobody refreshed the
 * export. Freshness is graded as an explicit member of the population rather than assumed,
 * because a check whose premise has quietly expired is indistinguishable from one that passed.
 */
export const HR_SOURCE_KINDS = Object.freeze(['file']);

/** Worker states that mean the person still works here. */
const EMPLOYED = new Set(['active', 'leave']);

export function resolveHrSource(hrSource) {
  if (!hrSource) return null;

  const kind = hrSource.kind ?? 'file';
  if (!HR_SOURCE_KINDS.includes(kind)) {
    throw new Error(
      `Unknown idp.hr_source.kind "${kind}". Known: ${HR_SOURCE_KINDS.join(', ')}. An HRIS integration written ` +
        'against documentation rather than real exports would report confidently about a payload it has never ' +
        'received.'
    );
  }
  if (!hrSource.path) {
    throw new Error('idp.hr_source.path is required: the roster is a file this harness reads, not one it discovers.');
  }

  return {
    kind,
    path: hrSource.path,
    // Seven days is a working default for a nightly export that occasionally misses a night. It is
    // deliberately shorter than any plausible notice period: the window this check exists to close
    // is the one between a termination and the account being disabled.
    maxAgeDays: hrSource.max_age_days ?? 7,
  };
}

/**
 * Reads and normalizes the roster.
 *
 * Kept separate from grading so the grader takes plain data, like every other collector here.
 * A roster that cannot be read is thrown rather than treated as an empty roster — an empty
 * roster would mark every account in the estate unattributable, which is a spectacular finding
 * to report because a path was wrong.
 */
export function loadRoster(source, { readFileImpl = readFileSync } = {}) {
  let raw;
  try {
    raw = readFileImpl(source.path, 'utf8');
  } catch (err) {
    throw new IdpUnavailable(
      `The HR roster declared at idp.hr_source.path (${source.path}) could not be read: ${err.message}. ` +
        'This is a configuration failure and not a finding about the estate.'
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new IdpUnavailable(`The HR roster at ${source.path} is not valid JSON: ${err.message}`);
  }
  return normaliseRoster(parsed);
}

/**
 * The exported roster → the normalized worker shape.
 *
 * `status` is narrowed to employed / not employed / unrecognised rather than passed through.
 * Every HRIS spells its states differently and a grader branching on vendor vocabulary would
 * quietly treat an unmapped state as whichever branch it fell into; unrecognised is carried as
 * its own case so it can be warned about instead.
 */
export function normaliseRoster(raw) {
  const workers = (raw.workers ?? []).map((w) => {
    const status = String(w.status ?? '').trim().toLowerCase();
    return {
      email: String(w.email ?? w.login ?? '').trim().toLowerCase(),
      status,
      // On leave is still employed. Suspending a parental-leave account may well be correct
      // policy, but it is not this indicator's question, and grading it here would produce
      // findings that are wrong in the one direction this repository cannot afford.
      employed: EMPLOYED.has(status) ? true : status === 'terminated' ? false : null,
      terminationDate: w.termination_date ?? null,
    };
  });

  return {
    asOf: raw.as_of ?? null,
    system: raw.system ?? 'unnamed HR system',
    workers,
    byEmail: new Map(workers.filter((w) => w.email).map((w) => [w.email, w])),
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

/** Okta users → the normalized account shape. */
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

/** Okta groups → the normalized group shape. `APP_GROUP` and `BUILT_IN` are directory-driven. */
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
