import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture } from '../lib/fixtures.mjs';
import { passRate } from '../lib/grade.mjs';

/**
 * Turns the pre-merge policy gate into evidence.
 *
 * Every other collector here reads deployed state, which answers "is the boundary configured
 * correctly right now". That leaves a real hole: KSI-MLA-EVC singles out infrastructure as code
 * "especially", and IaC is evaluated before it is ever deployed. A CI job that fails a build is
 * a control, but a red X in a pipeline that nobody retains is not evidence of one — the run log
 * ages out, and next quarter there is nothing to show an assessor.
 *
 * So the gate result is folded into the locker on the same contract as everything else, with one
 * property that matters more than the pass rate: the population is derived from the filesystem,
 * not from the report. Reading the count of evaluated files out of conftest's own output would
 * make the reconciliation circular — a file silently skipped by a bad --policy path or an ignore
 * rule would simply not appear, and the gate would report a clean pass over a shrinking
 * denominator. Globbing the declared roots independently is what makes "every file was
 * evaluated" a falsifiable claim rather than a restatement of the tool's output.
 */

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/pipeline/policy-gate.mjs';

export const CHECKS = [
  {
    id: 'pipeline.iac.policy-gate',
    ksis: ['KSI-CMT-VTD', 'KSI-CNA-EIS', 'KSI-MLA-EVC'],
    fixture: 'conftest-report',
    assertion:
      'Every infrastructure-as-code file in the declared roots was evaluated by the policy gate before merge, ' +
      'and none carries a denied finding.',
  },
];

/* ------------------------------------------------------------------- grading */

const IAC_FILE = /\.(tf|tf\.json)$/;

/** Conftest reports OS-native separators; compare on a single normalised form. */
const normalise = (p) => p.split(/[\\/]/).join('/');

export function findIacFiles(root, { base = root } = {}) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      // .terraform holds provider binaries and vendored modules that the team does not author
      // and cannot fix, so gating them would produce findings nobody can action.
      if (entry.name === '.terraform' || entry.name === '.git') continue;
      out.push(...findIacFiles(full, { base }));
      continue;
    }
    if (IAC_FILE.test(entry.name)) out.push(normalise(relative(base, full)));
  }
  return out;
}

/** Findings carry the indicator id in the message; recovering it links a gate rule to a KSI. */
export function ksisInMessage(msg) {
  return [...new Set(msg.match(/KSI-[A-Z]{3}-[A-Z]{3}/g) ?? [])].sort();
}

/**
 * Grades one file per item rather than one finding per item.
 *
 * A file is the unit that either did or did not pass the gate, and it is the unit whose absence
 * from the report is detectable. Findings are carried in `observed` so nothing is lost.
 */
export function gradeGate({ report, expectedFiles, reportRoot }) {
  const byFile = new Map();
  for (const entry of report) {
    const key = normalise(reportRoot ? relative(reportRoot, entry.filename) : entry.filename);
    const record = byFile.get(key) ?? { failures: [], warnings: [], successes: 0 };
    record.failures.push(...(entry.failures ?? []));
    record.warnings.push(...(entry.warnings ?? []));
    record.successes += entry.successes ?? 0;
    byFile.set(key, record);
  }

  const items = [];
  const flagged = new Set();

  for (const file of expectedFiles) {
    const record = byFile.get(file);

    if (!record) {
      // Not a pass and not a fail: the gate has nothing to say about this file. Treating an
      // unevaluated file as passing is the failure mode this population exists to catch.
      items.push({
        id: file,
        status: 'warn',
        detail: 'Present in a gated root but absent from the policy report, so it was never evaluated.',
      });
      continue;
    }

    for (const finding of [...record.failures, ...record.warnings]) {
      for (const ksi of ksisInMessage(finding.msg)) flagged.add(ksi);
    }

    if (record.failures.length) {
      items.push({
        id: file,
        status: 'fail',
        detail: `${record.failures.length} denied finding(s): ${record.failures.map((f) => f.msg).join(' | ')}`,
        observed: { failures: record.failures.map((f) => f.msg), warnings: record.warnings.map((w) => w.msg) },
      });
      continue;
    }
    if (record.warnings.length) {
      items.push({
        id: file,
        status: 'warn',
        detail: `${record.warnings.length} advisory finding(s): ${record.warnings.map((w) => w.msg).join(' | ')}`,
        observed: { warnings: record.warnings.map((w) => w.msg) },
      });
      continue;
    }
    items.push({
      id: file,
      status: 'pass',
      detail: `Evaluated against ${record.successes} rule(s) with no findings.`,
    });
  }

  // Files the gate reported on that are not in the declared roots. Usually a misconfigured
  // root rather than an attack, but it means the two views of scope disagree and that is worth
  // surfacing rather than discarding.
  const unexpected = [...byFile.keys()].filter((f) => !expectedFiles.includes(f));

  const examined = items.filter((i) => i.status !== 'warn' || !i.detail.startsWith('Present in a gated root')).length;
  const population = {
    expected: expectedFiles.length,
    examined,
    source_of_truth:
      'Every .tf and .tf.json file under the declared infrastructure roots, enumerated from the working tree ' +
      'rather than from the policy report',
  };
  if (examined !== expectedFiles.length) {
    population.reconciliation =
      `${expectedFiles.length - examined} file(s) exist in a gated root but were not evaluated by the policy ` +
      `gate. They are reported as warnings above and are not counted as passing.`;
  }

  return {
    items,
    population,
    metric: { metric_id: 'pipeline.iac.gate_pass_rate', value: passRate(items), unit: 'ratio' },
    indicatorsFlagged: [...flagged].sort(),
    unexpected,
  };
}

/* ------------------------------------------------------------------ fetching */

export function readReport(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed)) throw new Error(`${path}: expected a conftest JSON report (an array of file results).`);
  return parsed;
}

function resolveRoots(profile) {
  const roots = profile?.pipeline?.iac_roots ?? [];
  return roots.map((root) => ({ root, files: findIacFiles(resolve(root)).map((f) => normalise(join(root, f))) }));
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit }) {
  const check = CHECKS[0];
  const common = {
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
  };

  if (fixture) {
    const data = loadFixture(fixture, 'conftest-report');
    const graded = gradeGate({ report: data.report, expectedFiles: data.expected_files });
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'conftest-report', {
          iac_roots: data.iac_roots,
          policy_source: data.policy_source,
          indicators_flagged: graded.indicatorsFlagged,
        }),
        items: graded.items,
        population: graded.population,
        metric: graded.metric,
      }),
    ];
  }

  const reportPath = profile?.pipeline?.policy_report;
  if (!reportPath) {
    throw new Error(
      'pipeline.iac.policy-gate needs profile.pipeline.policy_report — the path to `conftest test --output json` ' +
        'output — and profile.pipeline.iac_roots. Run `npm run policy:report` first.'
    );
  }

  const roots = resolveRoots(profile);
  const expectedFiles = roots.flatMap((r) => r.files);
  const graded = gradeGate({ report: readReport(reportPath), expectedFiles, reportRoot: process.cwd() });

  return [
    buildBundle({
      ...common,
      scope: {
        iac_roots: roots.map((r) => r.root),
        policy_source: profile?.pipeline?.policy_source ?? 'policy/rego',
        indicators_flagged: graded.indicatorsFlagged,
        files_reported_outside_declared_roots: graded.unexpected.length ? graded.unexpected : undefined,
      },
      items: graded.items,
      population: graded.population,
      metric: graded.metric,
    }),
  ];
}
