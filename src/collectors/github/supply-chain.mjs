import { buildBundle } from '../../evidence/bundle.mjs';
import { api, fixtureScope, loadFixture, passRate, resolveRepos } from '../lib/github.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/github/supply-chain.mjs';

export const CHECKS = [
  {
    id: 'github.supply-chain.workflow-pinning',
    ksis: ['KSI-SCR-MIT', 'KSI-SVC-VRI'],
    fixture: 'github-workflows',
    assertion:
      'Every third-party action referenced by a CI workflow is pinned to an immutable commit revision rather than ' +
      'a mutable tag or branch.',
  },
];

/* ------------------------------------------------------------------- grading */

const SHA = /^[0-9a-f]{40}$/;

/**
 * Extracts `uses:` references from workflow YAML by line scan rather than by parsing.
 *
 * Deliberate: a workflow that fails to parse still runs its `uses:` lines as far as this
 * check is concerned, and a parser that throws on one malformed file would drop the whole
 * repository's population. The scan is tolerant of anything the parser would reject, and the
 * shape being matched — `uses: owner/repo@ref` — is stable enough that tolerance costs
 * nothing here.
 */
export function extractUses(yamlText) {
  const out = [];
  const lines = yamlText.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const match = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)['"]?/.exec(line);
    if (!match) continue;
    const comment = /#\s*(.*)$/.exec(line)?.[1]?.trim() ?? null;
    out.push({ ref: match[1], line: index + 1, comment });
  }
  return out;
}

/**
 * Classifies one action reference.
 *
 * `local` and `docker` are not-applicable rather than passes: a path reference resolves
 * inside the repository and is covered by the change-management checks, and a registry
 * reference is a different provenance question than a git revision. Marking them
 * not-applicable keeps them out of the pass-rate denominator instead of inflating it.
 */
export function classifyUse(use) {
  const { ref } = use;
  if (ref.startsWith('./') || ref.startsWith('.\\')) return { kind: 'local', status: 'not-applicable' };
  if (ref.startsWith('docker://')) return { kind: 'docker', status: 'not-applicable' };

  const at = ref.lastIndexOf('@');
  if (at === -1) {
    return { kind: 'unpinned', status: 'fail', detail: `"${ref}" has no revision at all, so it resolves to the default branch` };
  }
  const name = ref.slice(0, at);
  const revision = ref.slice(at + 1);
  const firstParty = name.startsWith('actions/') || name.startsWith('github/');

  if (SHA.test(revision)) {
    return { kind: 'pinned', status: 'pass', detail: `${name} pinned to ${revision.slice(0, 12)}` };
  }
  // A tag is mutable: an upstream maintainer, or anyone who compromises them, can move v4 to
  // point at new code without any change in this repository. That is the supply-chain risk
  // the indicator names, so a first-party tag is a warning rather than an exemption.
  return firstParty
    ? { kind: 'tag-first-party', status: 'warn', detail: `${name} pinned to mutable tag "${revision}" (GitHub-owned action)` }
    : { kind: 'tag-third-party', status: 'fail', detail: `${name} pinned to mutable tag "${revision}"` };
}

export function gradeWorkflowPinning(repos, { declared = null, unexamined = [] } = {}) {
  const items = [];
  let expected = 0;

  for (const repo of repos) {
    if (repo.unverifiable) {
      expected += 1;
      items.push({ id: `${repo.repo}`, status: 'warn', detail: repo.unverifiable });
      continue;
    }
    if ((repo.workflows ?? []).length === 0) {
      expected += 1;
      items.push({ id: `${repo.repo}`, status: 'not-applicable', detail: 'No CI workflows in this repository' });
      continue;
    }

    for (const workflow of repo.workflows) {
      for (const use of extractUses(workflow.content)) {
        expected += 1;
        const verdict = classifyUse(use);
        items.push({
          id: `${repo.repo}/${workflow.path}:${use.line}`,
          status: verdict.status,
          detail: verdict.detail ?? `${verdict.kind}: ${use.ref}`,
          observed: { uses: use.ref, kind: verdict.kind },
        });
      }
    }
  }

  // A repository the profile declares but that never answered adds one to the denominator and
  // nothing to the numerator, so a boundary that quietly lost a repository reports incomplete
  // rather than clean over whatever remained.
  const missing = declared ? declared.filter((r) => !repos.some((x) => x.repo === r.name)) : [];
  const gaps = [
    ...unexamined,
    ...missing.map((r) => ({ id: r.name, reason: 'declared in the profile but no workflow listing was returned' })),
  ];

  return {
    items,
    population: {
      expected: expected + gaps.length,
      unexamined: gaps,
      source_of_truth: 'Every `uses:` reference in every file under .github/workflows in each declared repository',
      enumerated_from:
        'the repositories declared in the profile; each one that answered contributes its own workflow references, ' +
        'and each one that did not is itemized rather than dropped',
    },
    metric: { metric_id: 'github.supply_chain.pinned_actions', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchWorkflows(repos) {
  const out = [];
  for (const repo of repos) {
    const record = { repo: repo.name, workflows: [] };
    const listing = await api(`/repos/${repo.name}/contents/.github/workflows`);

    if (!listing.ok) {
      if (listing.classification?.kind === 'absent') {
        out.push(record);
        continue;
      }
      record.unverifiable = listing.classification?.detail ?? `HTTP ${listing.status}`;
      out.push(record);
      continue;
    }

    for (const entry of listing.body ?? []) {
      if (entry.type !== 'file' || !/\.ya?ml$/.test(entry.name)) continue;
      const file = await api(`/repos/${repo.name}/contents/${entry.path}`);
      if (!file.ok) continue;
      const content =
        file.body.encoding === 'base64' ? Buffer.from(file.body.content, 'base64').toString('utf8') : file.body.content;
      record.workflows.push({ path: entry.path, content });
    }
    out.push(record);
  }
  return out;
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chain = {
    previousHash: previousHashes.get(CHECKS[0].id)?.hash ?? null,
    chainIndex: previousHashes.get(CHECKS[0].id)?.index ?? 0,
  };

  if (fixture) {
    const data = loadFixture(fixture, 'github-workflows');
    return [
      buildBundle({
        ...common,
        ...chain,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'github-workflows'),
        ...gradeWorkflowPinning(data.repositories, { unexamined: data.unexamined ?? [] }),
      }),
    ];
  }

  const repos = resolveRepos(profile);
  return [
    buildBundle({
      ...common,
      ...chain,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: { repositories: repos.map((r) => r.name) },
      ...gradeWorkflowPinning(await fetchWorkflows(repos), { declared: repos }),
    }),
  ];
}
