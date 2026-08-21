import { buildBundle } from '../../evidence/bundle.mjs';
import {
  fetchOkta,
  fixtureScope,
  IdpUnavailable,
  loadFixture,
  loadRoster,
  normaliseRoster,
  passRate,
  resolveIdp,
} from '../lib/idp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/idp/roster.mjs';

export const CHECKS = [
  {
    id: 'idp.account.roster',
    ksis: ['KSI-IAM-AAM'],
    fixture: 'idp-roster',
    assertion:
      'Every live account in the identity provider corresponds to a worker the authoritative HR roster records ' +
      'as still employed, or is a declared non-human identity, and the roster it was reconciled against is ' +
      'current enough for that to mean anything.',
  },
];

/**
 * Whether the accounts that exist belong to people who still work here.
 *
 * This is the second half of `KSI-IAM-AAM` and the half `idp.account.provisioning` cannot reach.
 * That check reads the provisioning source, which records how an account was created; this one
 * asks whether it should still exist. The two are independent, and the gap between them is the
 * one the route named for as long as nothing read `idp.hr_source`: an account provisioned
 * flawlessly by SCIM, holding exactly the right permissions, belonging to somebody who left in
 * March, passes every other check in this harness.
 *
 * It is deliberately the same shape as `thirdparty.register.review` — a declaration, an
 * independent observation, and the gap between them treated as the finding. A check that reads
 * only the identity provider is close to tautological: it confirms that a directory says what it
 * says. The reconciliation is the whole instrument, which is why the roster has to come from
 * outside and why a missing one is reported rather than defaulted around.
 *
 * ## Three ways an account can fail to be attributable
 *
 * **A worker record that ended.** The account is live and the roster says the person left. This
 * is the finding the check exists for and the only one that is unambiguous: two authoritative
 * systems disagree, and the disagreement is a live credential.
 *
 * **No worker record at all.** Unattributable rather than proven orphaned — it might be a
 * service account nobody declared. It is still a `fail`, because the assertion is that every
 * live account is attributable to a current worker *or* to a declared non-human identity, and an
 * account matching neither is exactly the thing an assessor asks about first. The remedy differs
 * from the case above, so the detail says which one it is.
 *
 * **An unrecognised worker state.** Warned, not failed. Every HRIS spells its states
 * differently, and a grader that resolved an unmapped state into either branch would be
 * confidently wrong in one direction; `warn` says the roster was read and this row could not be
 * interpreted, which is what actually happened.
 *
 * ## What a declared non-human identity is, and why it is a list
 *
 * A service account is not in an HR roster and never should be, so it genuinely leaves the
 * denominator — this is the `not-applicable` case the contributing guide describes, not a polite
 * pass. What makes it honest is that the exclusion is *declared*: `idp.non_human_accounts` names
 * each login.
 *
 * A prefix convention would have been less typing and is the reason this is not one. `svc-` is a
 * naming convention, and a naming convention is something an orphaned account can be renamed
 * into — the exclusion would then be granted by the very estate being assessed rather than by
 * the profile. An explicit list is auditable, is diffable when it grows, and cannot be widened
 * by anything happening inside the boundary.
 *
 * ## What this deliberately does not establish
 *
 * The reverse direction: a worker on the roster with no account. That is a provisioning gap
 * rather than an access one, nobody's access is excessive because of it, and folding it in here
 * would mix a finding about credentials with a finding about onboarding. It is stated on the
 * route rather than silently omitted.
 */

/** Roster freshness, graded as an explicit member of the population rather than assumed. */
function gradeFreshness(roster, { maxAgeDays, now }) {
  const id = 'roster/as-of';

  if (!roster.asOf) {
    return {
      id,
      status: 'fail',
      detail:
        `The roster from ${roster.system} carries no as_of, so nothing establishes that it is current. An ` +
        'undated roster lists a leaver as employed for exactly as long as nobody refreshes the export, and ' +
        'this check would read clean throughout.',
    };
  }

  const asOf = Date.parse(roster.asOf);
  if (Number.isNaN(asOf)) {
    return { id, status: 'fail', detail: `The roster as_of ("${roster.asOf}") is not a parseable timestamp.` };
  }

  const ageDays = (now - asOf) / 86400000;
  if (ageDays > maxAgeDays) {
    return {
      id,
      status: 'fail',
      detail:
        `The roster is ${ageDays.toFixed(1)} days old against a ${maxAgeDays}-day limit. A termination more ` +
        'recent than the export is invisible here, so the accounts below were reconciled against a roster ' +
        'that cannot yet know about them.',
      observed: { as_of: roster.asOf, age_days: Number(ageDays.toFixed(1)), max_age_days: maxAgeDays },
    };
  }

  return {
    id,
    status: 'pass',
    detail: `Roster from ${roster.system} is ${ageDays.toFixed(1)} days old, within the ${maxAgeDays}-day limit.`,
    observed: { as_of: roster.asOf, age_days: Number(ageDays.toFixed(1)), max_age_days: maxAgeDays },
  };
}

/**
 * Grades the account list against the roster.
 *
 * `roster` may be null, and that branch is the reason this function exists rather than the
 * collector simply throwing when no roster is declared. Throwing would produce no bundle, and a
 * route with a missing bundle reports `no-evidence` for the whole indicator — which would hide
 * the findings the other two checks did make. Instead the accounts are enumerated and reported
 * as *unexamined*, which is the case the population contract was built for: the bundle says
 * there are N accounts, that it examined none of them, and why. The ceiling is `warn`, the
 * indicator reads `degraded` rather than clean, and the gap sits in the evidence where a reader
 * will hit it instead of in a prose note on the route.
 */
export function gradeRoster(accounts, roster, { nonHumanAccounts = new Set(), maxAgeDays = 7, now, unexamined = [] }) {
  const population = {
    source_of_truth:
      'the HR roster declared at idp.hr_source, reconciled against the identity provider account list',
    enumerated_from:
      'every account the provider returned, before filtering by status, plus the roster snapshot itself — the ' +
      'provider list alone cannot say whether an account should still exist, and the roster alone cannot say ' +
      'which accounts exist',
  };

  if (!roster) {
    return {
      items: [],
      population: {
        ...population,
        expected: accounts.length + unexamined.length,
        unexamined: [
          ...accounts.map((account) => ({
            id: `account/${account.login}`,
            reason:
              'no HR roster is declared at idp.hr_source, so nothing authoritative says whether this account ' +
              'belongs to a current worker',
          })),
          ...unexamined,
        ],
      },
      // No metric at all rather than a zero. The metric is a trend line, and a 0.0 here would
      // plot as an estate where no account is attributable to anybody — a far worse claim than
      // the true one, which is that nothing was measured. The population already says that.
      metric: undefined,
    };
  }

  const items = [gradeFreshness(roster, { maxAgeDays, now })];

  for (const account of accounts) {
    const id = `account/${account.login}`;
    const login = String(account.login ?? '').trim().toLowerCase();

    if (!account.live) {
      // Same reasoning as the provisioning check: a deprovisioned account cannot authenticate, so
      // who it belonged to is no longer a live question. Excluded rather than passed, because
      // counting dead accounts as evidence of attribution would let an estate improve its score
      // by accumulating them.
      items.push({ id, status: 'not-applicable', detail: `Status ${account.status}; the account cannot authenticate.` });
      continue;
    }

    if (nonHumanAccounts.has(login)) {
      items.push({
        id,
        status: 'not-applicable',
        detail:
          'Declared in idp.non_human_accounts, so no worker record is expected. The exclusion comes from the ' +
          'profile rather than from anything inside the boundary.',
      });
      continue;
    }

    const worker = roster.byEmail.get(login);

    if (!worker) {
      items.push({
        id,
        status: 'fail',
        detail:
          `No record in the ${roster.system} roster and not declared in idp.non_human_accounts. The account ` +
          'can authenticate and nothing attributes it to a person or to a service, which is the state an ' +
          'assessor asks about first.',
        observed: { attribution: 'none' },
      });
      continue;
    }

    if (worker.employed === false) {
      const since = worker.terminationDate ? Date.parse(worker.terminationDate) : null;
      const elapsed = since && !Number.isNaN(since) ? Math.floor((now - since) / 86400000) : null;
      items.push({
        id,
        status: 'fail',
        detail:
          `${roster.system} records this worker as terminated` +
          (worker.terminationDate ? ` on ${worker.terminationDate}` : '') +
          (elapsed != null ? `, ${elapsed} days ago` : '') +
          ', and the account can still authenticate. Provisioning was automated; deprovisioning was not.',
        observed: { worker_status: worker.status, termination_date: worker.terminationDate, days_since: elapsed },
      });
      continue;
    }

    if (worker.employed === null) {
      items.push({
        id,
        status: 'warn',
        detail:
          `${roster.system} records this worker with status "${worker.status}", which is not a state this ` +
          'harness maps to employed or terminated. The row was read and could not be interpreted; resolving ' +
          'it either way would be confidently wrong in one direction.',
        observed: { worker_status: worker.status },
      });
      continue;
    }

    items.push({
      id,
      status: 'pass',
      detail: `${roster.system} records this worker as employed (status: ${worker.status}).`,
      observed: { worker_status: worker.status },
    });
  }

  return {
    items,
    population: {
      ...population,
      // The roster's own freshness is a member of the population, not a precondition of it. A
      // check whose premise expired has to be visible in the same numbers as its findings.
      expected: accounts.length + 1 + unexamined.length,
      unexamined,
    },
    metric: { metric_id: 'idp.accounts_attributable_to_current_workers', value: passRate(items), unit: 'ratio' },
  };
}

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const check = CHECKS[0];
  const common = {
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
    previousHash: previousHashes.get(check.id)?.hash ?? null,
    chainIndex: previousHashes.get(check.id)?.index ?? 0,
  };

  // `collectedAt` rather than the runner's clock, for the same reason the bundle refuses to
  // default it: roster age is an evidence statement, and an evidence statement dated by whichever
  // machine happened to run is not one.
  const now = Date.parse(collectedAt);

  if (fixture) {
    const identity = loadFixture(fixture, 'idp-accounts');
    const data = loadFixture(fixture, 'idp-roster');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'idp-roster', { provider: identity.provider, domain: identity.domain }),
        ...gradeRoster(identity.accounts, data.roster ? normaliseRoster(data.roster) : null, {
          nonHumanAccounts: new Set((data.non_human_accounts ?? []).map((l) => l.toLowerCase())),
          maxAgeDays: data.max_age_days ?? 7,
          now,
        }),
      }),
    ];
  }

  const idp = resolveIdp(profile);
  if (!idp) {
    throw new Error(
      'No idp block declared in the profile, so accounts cannot be reconciled against a roster. KSI-IAM-AAM ' +
        'asks whether account lifecycle is securely managed, and half of that is whether the accounts belong ' +
        'to anybody.'
    );
  }

  try {
    const { accounts } = await fetchOkta(idp);
    // An undeclared roster is not a collection failure — it is a boundary that has not connected
    // its HR system, and the bundle says so per account. A declared one that cannot be read is a
    // failure, and loadRoster throws rather than grading against an empty roster: an empty roster
    // would mark every account in the estate unattributable because a path was wrong.
    const roster = idp.hrSource ? loadRoster(idp.hrSource) : null;

    return [
      buildBundle({
        ...common,
        scope: { provider: idp.provider, domain: idp.domain, hr_source: idp.hrSource?.path ?? null },
        ...gradeRoster(accounts, roster, {
          nonHumanAccounts: idp.nonHumanAccounts,
          maxAgeDays: idp.hrSource?.maxAgeDays ?? 7,
          now,
        }),
      }),
    ];
  } catch (err) {
    if (err instanceof IdpUnavailable) {
      throw new Error(`${err.message} No evidence was produced for KSI-IAM-AAM; this is not a passing state.`);
    }
    throw err;
  }
}
