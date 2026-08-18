import { buildBundle } from '../../evidence/bundle.mjs';
import { api, fixtureScope, loadFixture, paginate, passRate, resolveRepos } from '../lib/github.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/github/change.mjs';

export const CHECKS = [
  {
    id: 'github.change.pr-review',
    ksis: ['KSI-CMT-LMC', 'KSI-CMT-VTD'],
    fixture: 'github-commits',
    assertion:
      'Every commit reaching a production default branch in the period arrived through a pull request approved by ' +
      'someone other than its author.',
  },
  {
    id: 'github.change.branch-protection',
    ksis: ['KSI-CMT-RMV', 'KSI-CMT-RVP'],
    fixture: 'github-branch-protection',
    assertion:
      'Every production default branch requires review before merge and enumerates every actor permitted to ' +
      'bypass that requirement.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades commits against their approving pull request.
 *
 * Reviewing settings tells you what is *supposed* to happen; reviewing commits tells you what
 * did. They diverge, which is why this check exists alongside branch protection rather than
 * instead of it: a bypass actor, an admin override or a brief window with protection off all
 * leave the settings looking correct while unreviewed code is on the branch.
 *
 * Self-approval is a failure. An approval from the commit's own author satisfies a naive
 * "has an approval" test and satisfies nothing else.
 */
export function gradePrReview(commits) {
  const items = commits.map((commit) => {
    const short = commit.sha.slice(0, 8);
    const id = `${commit.repo}@${short}`;

    if (commit.merge_commit) {
      return { id, status: 'not-applicable', detail: 'Merge commit; the reviewed change is its parent pull request' };
    }
    if (!commit.pulls?.length) {
      return {
        id,
        status: 'fail',
        detail: `Pushed directly to ${commit.branch} with no pull request`,
        observed: { author: commit.author },
      };
    }

    const approvals = commit.pulls.flatMap((pull) =>
      (pull.reviews ?? []).filter((r) => r.state === 'APPROVED').map((r) => ({ pull: pull.number, by: r.user }))
    );
    if (approvals.length === 0) {
      return {
        id,
        status: 'fail',
        detail: `Merged via #${commit.pulls[0].number} with no approving review`,
        observed: { author: commit.author, pulls: commit.pulls.map((p) => p.number) },
      };
    }

    const independent = approvals.filter((a) => a.by !== commit.author);
    if (independent.length === 0) {
      return {
        id,
        status: 'fail',
        detail: `Only approval on #${approvals[0].pull} is from the commit author (${commit.author})`,
        observed: { author: commit.author, approvers: approvals.map((a) => a.by) },
      };
    }
    return {
      id,
      status: 'pass',
      detail: `Approved on #${independent[0].pull} by ${independent[0].by}`,
      observed: { author: commit.author, approvers: independent.map((a) => a.by) },
    };
  });

  return {
    items,
    population: {
      expected: commits.length,
      examined: items.length,
      source_of_truth: 'Every commit on each declared production default branch in the period, via repos/commits',
    },
    metric: { metric_id: 'github.change.reviewed_commits', value: passRate(items), unit: 'ratio' },
  };
}

/**
 * Grades classic branch protection and rulesets as a union.
 *
 * Reading only one of the two is the common mistake and it fails in both directions: a
 * repository protected solely by a ruleset looks unprotected to a classic-protection check,
 * and a repository whose ruleset is weaker than its classic protection looks stronger than it
 * is. The union is what actually applies.
 *
 * Bypass actors get their own item because the settings page does not show them next to the
 * review requirement, so a repository can require two approvals while letting an app merge
 * without any — and that combination reads as compliant in every screenshot.
 */
export function gradeBranchProtection(repos) {
  const items = repos.map((repo) => {
    const id = `${repo.repo}:${repo.branch}`;

    if (repo.unverifiable) {
      return { id, status: 'warn', detail: repo.unverifiable, observed: { reason: 'permission' } };
    }
    if (repo.plan_gated) {
      return { id, status: 'fail', detail: repo.plan_gated, observed: { reason: 'plan-gate' } };
    }

    const reviewsRequired = Math.max(repo.classic?.required_approvals ?? 0, repo.ruleset?.required_approvals ?? 0);
    const problems = [];
    if (reviewsRequired < 1) problems.push('no review required before merge');
    if (!(repo.classic?.dismiss_stale ?? repo.ruleset?.dismiss_stale)) {
      problems.push('stale approvals are not dismissed on new commits');
    }
    if (repo.classic && repo.classic.enforce_admins === false && !repo.ruleset) {
      problems.push('administrators are exempt from the requirement');
    }

    const bypass = [...(repo.ruleset?.bypass_actors ?? []), ...(repo.classic?.bypass_actors ?? [])];
    if (bypass.length) problems.push(`${bypass.length} bypass actor(s): ${bypass.join(', ')}`);

    return problems.length
      ? {
          id,
          status: 'fail',
          detail: problems.join('; '),
          observed: { required_approvals: reviewsRequired, bypass_actors: bypass },
        }
      : {
          id,
          status: 'pass',
          detail: `${reviewsRequired} approval(s) required, stale approvals dismissed, no bypass actor`,
          observed: { required_approvals: reviewsRequired },
        };
  });

  return {
    items,
    population: {
      expected: repos.length,
      examined: items.length,
      source_of_truth: 'Declared production default branches, with classic protection and rulesets read as a union',
    },
    metric: { metric_id: 'github.change.protected_branches', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchCommits(repos, since) {
  const commits = [];
  const unexamined = [];

  for (const repo of repos) {
    const branch = repo.branch ?? 'main';
    const listed = await paginate(`/repos/${repo.name}/commits?sha=${branch}&since=${since}&per_page=100`);
    if (!listed.ok) {
      unexamined.push(`${repo.name}: ${listed.classification?.detail ?? `HTTP ${listed.status}`}`);
      continue;
    }

    for (const commit of listed.items) {
      // One reviews call per pull request, not per commit: a squashed branch shares its pull
      // request across commits and re-requesting it per commit multiplies the call count
      // without changing the answer.
      const pullsRes = await api(`/repos/${repo.name}/commits/${commit.sha}/pulls`);
      const pulls = [];
      if (pullsRes.ok) {
        for (const pull of pullsRes.body ?? []) {
          const reviews = await paginate(`/repos/${repo.name}/pulls/${pull.number}/reviews?per_page=100`);
          pulls.push({
            number: pull.number,
            reviews: reviews.ok ? reviews.items.map((r) => ({ state: r.state, user: r.user?.login })) : [],
          });
        }
      }

      commits.push({
        repo: repo.name,
        branch,
        sha: commit.sha,
        author: commit.author?.login ?? commit.commit?.author?.email ?? 'unknown',
        merge_commit: (commit.parents ?? []).length > 1,
        pulls,
      });
    }
  }

  return { commits, unexamined };
}

async function fetchProtection(repos) {
  const out = [];
  for (const repo of repos) {
    const branch = repo.branch ?? 'main';
    const record = { repo: repo.name, branch };

    const classic = await api(`/repos/${repo.name}/branches/${branch}/protection`);
    if (classic.ok) {
      const reviews = classic.body.required_pull_request_reviews;
      record.classic = {
        required_approvals: reviews?.required_approving_review_count ?? 0,
        dismiss_stale: Boolean(reviews?.dismiss_stale_reviews),
        enforce_admins: Boolean(classic.body.enforce_admins?.enabled),
        bypass_actors: [
          ...(reviews?.bypass_pull_request_allowances?.users ?? []).map((u) => `user:${u.login}`),
          ...(reviews?.bypass_pull_request_allowances?.teams ?? []).map((t) => `team:${t.slug}`),
          ...(reviews?.bypass_pull_request_allowances?.apps ?? []).map((a) => `app:${a.slug}`),
        ],
      };
    } else if (classic.classification?.kind === 'plan-gate') {
      record.plan_gated = classic.classification.detail;
    } else if (classic.classification?.kind === 'permission') {
      record.unverifiable = classic.classification.detail;
    }
    // A 404 here means no classic protection, which is a legitimate state when a ruleset
    // provides the protection instead. It is not recorded as an error.

    const rulesets = await api(`/repos/${repo.name}/rulesets?includes_parents=true`);
    if (rulesets.ok) {
      for (const summary of rulesets.body ?? []) {
        const full = await api(`/repos/${repo.name}/rulesets/${summary.id}`);
        if (!full.ok) continue;
        const pullRule = (full.body.rules ?? []).find((r) => r.type === 'pull_request');
        if (!pullRule) continue;
        record.ruleset = {
          name: full.body.name,
          required_approvals: pullRule.parameters?.required_approving_review_count ?? 0,
          dismiss_stale: Boolean(pullRule.parameters?.dismiss_stale_reviews_on_push),
          bypass_actors: (full.body.bypass_actors ?? []).map(
            (a) => `${a.actor_type}:${a.actor_id}(${a.bypass_mode})`
          ),
        };
      }
    } else if (rulesets.classification?.kind === 'permission' && !record.classic) {
      record.unverifiable = rulesets.classification.detail;
    }

    if (!record.classic && !record.ruleset && !record.unverifiable && !record.plan_gated) {
      record.classic = { required_approvals: 0, dismiss_stale: false, enforce_admins: false, bypass_actors: [] };
    }
    out.push(record);
  }
  return out;
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const bundles = [];

  if (fixture) {
    const commitData = loadFixture(fixture, 'github-commits');
    bundles.push(
      buildBundle({
        ...common,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'github-commits'),
        ...gradePrReview(commitData.commits),
      })
    );

    const protectionData = loadFixture(fixture, 'github-branch-protection');
    bundles.push(
      buildBundle({
        ...common,
        checkId: CHECKS[1].id,
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'github-branch-protection'),
        ...gradeBranchProtection(protectionData.branches),
      })
    );
    return bundles;
  }

  const repos = resolveRepos(profile);
  const windowDays = profile?.github?.window_days ?? 30;
  const since = new Date(Date.parse(collectedAt) - windowDays * 86400000).toISOString();
  const scope = { repositories: repos.map((r) => r.name), branch_window_days: windowDays, since };

  const { commits, unexamined } = await fetchCommits(repos, since);
  const review = gradePrReview(commits);
  if (unexamined.length) {
    review.population.expected += unexamined.length;
    review.population.reconciliation = `${unexamined.length} repository listing(s) could not be read: ${unexamined.join('; ')}`;
  }
  bundles.push(
    buildBundle({ ...common, checkId: CHECKS[0].id, ksis: CHECKS[0].ksis, assertion: CHECKS[0].assertion, scope, ...review })
  );

  bundles.push(
    buildBundle({
      ...common,
      checkId: CHECKS[1].id,
      ksis: CHECKS[1].ksis,
      assertion: CHECKS[1].assertion,
      scope,
      ...gradeBranchProtection(await fetchProtection(repos)),
    })
  );

  return bundles;
}
