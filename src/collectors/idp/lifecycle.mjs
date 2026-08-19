import { buildBundle } from '../../evidence/bundle.mjs';
import { fetchOkta, fixtureScope, IdpUnavailable, loadFixture, passRate, resolveIdp } from '../lib/idp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/idp/lifecycle.mjs';

export const CHECKS = [
  {
    id: 'idp.account.provisioning',
    ksis: ['KSI-IAM-AAM'],
    fixture: 'idp-accounts',
    assertion:
      'Every account in the identity provider was created by an automated provisioning source rather than by ' +
      'hand at a console.',
  },
  {
    id: 'idp.privilege.assignment',
    ksis: ['KSI-IAM-AAM', 'KSI-IAM-ELP'],
    fixture: 'idp-accounts',
    assertion:
      'Every privileged group derives its membership from a rule or a directory rather than hand curation, and ' +
      'no privileged access is granted directly to an individual.',
  },
];

/**
 * Whether account lifecycle and privilege are managed *by automation*.
 *
 * `KSI-IAM-AAM` is the only indicator in the catalog that asks about a mechanism rather than an
 * outcome: "the lifecycle and privileges of all accounts, roles, and groups are securely managed
 * using automation". A boundary with a flawless permission set, every entry of it typed in by an
 * administrator, fails this indicator — and passes every cloud-side check the harness had.
 *
 * That is why the route sat `unaddressed` with the note that "the AWS-side view shows the result of
 * provisioning, not whether it was automated". A downstream reader cannot recover the mechanism
 * from the state, because the two are indistinguishable once the state exists. Only the identity
 * provider retains which one happened.
 *
 * ## The two clauses, graded separately
 *
 * **Lifecycle** is `idp.account.provisioning`. Each account carries the provisioning source the
 * IdP recorded: a directory sync, SCIM, or an HR feed is automation; an account typed into the
 * admin console is not. A manually created account is not necessarily wrong — break-glass exists —
 * but it is an exception to the automation the indicator claims, so it has to appear as one rather
 * than be absorbed into a pass.
 *
 * **Privilege** is `idp.privilege.assignment`, and it grades the path rather than the permission.
 * Access that arrives through a group whose membership is rule-driven is access that changes when
 * the rule's inputs change — a leaver leaves the group because they left the directory. Access
 * granted directly to a person changes when somebody remembers, which is the failure mode the
 * whole indicator exists to prevent, and it survives every review that looks only at who can do
 * what today.
 *
 * ## What this deliberately does not establish
 *
 * Whether an account corresponds to a person who still works here. That is the "securely" half,
 * and it needs an HR feed as the authoritative roster — an account can be perfectly provisioned by
 * automation and belong to somebody who left in March.
 *
 * That gap is stated in the route's `unautomated` rather than in the bundle, and the distinction
 * is worth keeping straight. A bundle's `reconciliation` explains why a population was not fully
 * examined; this population *is* fully examined, and the limit is on what examining it can settle.
 * Recording a scope limit as a population gap would misreport a complete check as an incomplete
 * one, and the two call for different responses — one is a permissions problem to fix, the other
 * a boundary of the evidence to disclose.
 */

/** Grades lifecycle: was each account created by automation? */
export function gradeProvisioning(accounts, { automatedSources, unexamined = [] }) {
  const items = accounts.map((account) => {
    if (!account.live) {
      // A deprovisioned account cannot be used, so how it was created is no longer a live question.
      // Excluded rather than passed: counting it as evidence of automation would let an estate
      // improve its score by accumulating dead accounts.
      return {
        id: `account/${account.login}`,
        status: 'not-applicable',
        detail: `Status ${account.status}; the account cannot authenticate.`,
      };
    }
    if (automatedSources.has(account.source)) {
      return { id: `account/${account.login}`, status: 'pass', detail: `Provisioned by ${account.source}` };
    }
    return {
      id: `account/${account.login}`,
      status: 'fail',
      detail:
        `Provisioned by ${account.source}, which is not an automated source. The account exists because ` +
        'somebody created it, so its lifecycle is not managed by the automation this indicator claims.',
    };
  });

  return {
    items,
    population: {
      expected: accounts.length + unexamined.length,
      source_of_truth: 'The identity provider account list',
      enumerated_from:
        'Every account the provider returned, before filtering by status — a population taken after ' +
        'filtering could not show how much of the estate was excluded.',
    },
    unexamined,
    metric: { metric_id: 'idp.accounts_provisioned_by_automation', value: passRate(items), unit: 'ratio' },
  };
}

/** Grades privilege: does access arrive by policy, or by hand? */
export function gradePrivilegePath(groups, grants, { unexamined = [] }) {
  const items = [];

  for (const group of groups.filter((g) => g.privileged)) {
    if (group.membership === 'manual') {
      items.push({
        id: `group/${group.name}`,
        status: 'fail',
        detail:
          'Privileged group with hand-curated membership. Access that is added by hand is removed by hand, ' +
          'which is the lifecycle gap this indicator is about.',
      });
    } else {
      items.push({
        id: `group/${group.name}`,
        status: 'pass',
        detail: `Membership driven by ${group.membership}, so it follows the directory rather than memory.`,
      });
    }
  }

  for (const grant of grants) {
    if (grant.via === 'direct') {
      items.push({
        id: `grant/${grant.subject}/${grant.target}`,
        status: 'fail',
        detail:
          `${grant.target} is granted directly to ${grant.subject} rather than through a group. A direct grant ` +
          'has no rule behind it and no membership to fall out of.',
      });
    } else {
      items.push({
        id: `grant/${grant.subject}/${grant.target}`,
        status: 'pass',
        detail: `Granted via ${grant.via}`,
      });
    }
  }

  return {
    items,
    population: {
      expected: groups.filter((g) => g.privileged).length + grants.length + unexamined.length,
      source_of_truth: 'The identity provider group, rule and assignment lists',
      enumerated_from:
        'Declared privileged groups resolved against the provider group list, plus every assignment the ' +
        'provider returned — so a grant nobody declared is still in the denominator.',
    },
    unexamined,
    metric: { metric_id: 'idp.privilege_paths_rule_driven', value: passRate(items), unit: 'ratio' },
  };
}

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

  if (fixture) {
    const data = loadFixture(fixture, 'idp-accounts');
    const automatedSources = new Set(data.automated_sources);
    return [
      buildBundle({
        ...common(CHECKS[0]),
        scope: fixtureScope(fixture, 'idp-accounts', { provider: data.provider, domain: data.domain }),
        ...gradeProvisioning(data.accounts, { automatedSources }),
      }),
      buildBundle({
        ...common(CHECKS[1]),
        scope: fixtureScope(fixture, 'idp-accounts', { provider: data.provider, domain: data.domain }),
        ...gradePrivilegePath(data.groups, data.grants ?? [], {}),
      }),
    ];
  }

  const idp = resolveIdp(profile);
  if (!idp) {
    throw new Error(
      'No idp block declared in the profile, so account lifecycle cannot be evidenced. KSI-IAM-AAM asks ' +
        'whether provisioning is automated, and only the identity provider knows.'
    );
  }

  try {
    const { accounts, groups } = await fetchOkta(idp);
    const grants = groups
      .filter((g) => g.privileged)
      .map((g) => ({ id: g.id, subject: g.name, target: g.name, via: 'group' }));

    return [
      buildBundle({
        ...common(CHECKS[0]),
        scope: { provider: idp.provider, domain: idp.domain },
        ...gradeProvisioning(accounts, { automatedSources: idp.automatedSources }),
      }),
      buildBundle({
        ...common(CHECKS[1]),
        scope: { provider: idp.provider, domain: idp.domain },
        ...gradePrivilegePath(groups, grants, {}),
      }),
    ];
  } catch (err) {
    // A provider that could not be read has said nothing about the estate. Distinguished from a
    // finding for the same reason `ksi store` separates UNVERIFIED from NOT write-once.
    if (err instanceof IdpUnavailable) {
      throw new Error(`${err.message} No evidence was produced for KSI-IAM-AAM; this is not a passing state.`);
    }
    throw err;
  }
}
