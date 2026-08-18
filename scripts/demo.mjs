#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';

/**
 * The whole path, end to end, against fixtures. No credentials, no cloud account, no network.
 *
 * Ordered so the argument builds rather than just the artifacts: verify the ruleset pin, show what
 * the ruleset actually says, show how each indicator is routed and what the routing refuses to
 * claim, collect, report, then emit. The report comes before the artifacts on purpose — the
 * interesting output of this project is the coverage report, not the SDR.
 */

const EVIDENCE = '.evidence';
const PROFILE = 'examples/northwind.profile.yaml';
const OVERVIEW = 'https://northwind.example/fedramp/overview.json';

const steps = [
  {
    title: 'The ruleset is pinned by hash, not fetched at run time',
    why: 'A report is only meaningful against a known ruleset. This fails if a vendored file drifts from its pin.',
    argv: ['scripts/vendor-sync.mjs', 'verify'],
  },
  {
    title: 'The Key Security Indicator catalog, resolved for Class C',
    why:
      'Read from the pinned file, never restated in this repository. Class C is the ceiling: Class D does not ' +
      'exist yet, so High stays on Rev5.',
    argv: ['src/cli.mjs', 'catalog', '--class', 'c'],
  },
  {
    title: 'One indicator in full',
    why:
      'Statement, the FedRAMP-defined terms it leans on, its 800-53 mappings, and how it is routed — including ' +
      'what the automation does not establish.',
    argv: ['src/cli.mjs', 'explain', 'KSI-SVC-SIN'],
  },
  {
    title: 'The routing map validates against the catalog and the check registry',
    why:
      'A route claiming a check no collector implements is an error. Coverage cannot be manufactured out of intent.',
    argv: ['src/cli.mjs', 'routes', 'validate'],
  },
  {
    title: 'Collect evidence',
    why:
      'Eleven checks across AWS, GitHub and the CI pipeline. Every bundle carries a population reconciliation and ' +
      'a content hash, and every one here is marked as fixture-derived.',
    argv: ['src/cli.mjs', 'collect', '--profile', PROFILE, '--fixture', 'fixtures/collectors', '--out', EVIDENCE],
  },
  {
    title: 'The coverage report',
    why:
      'The point of the project. Zero indicators are reported as fully automated, against twenty with real ' +
      'passing evidence — because `automated` requires a written argument that nothing material is missing.',
    argv: ['src/cli.mjs', 'coverage', '--evidence', EVIDENCE],
  },
  {
    title: 'FedRAMP 20x Security Decision Record',
    why: 'Validated against the vendored FedRAMP schema before it is written. Rule FRC-CSO-JSN requires that.',
    argv: [
      'src/cli.mjs', 'emit', 'sdr',
      '--evidence', EVIDENCE,
      '--profile', PROFILE,
      '--overview-uri', OVERVIEW,
      '--out', 'out/sdr.json',
    ],
  },
  {
    title: 'FedRAMP 20x Ongoing Certification Report',
    why: 'The quarterly artifact, generated from the same state rather than written by hand.',
    argv: [
      'src/cli.mjs', 'emit', 'ocr',
      '--evidence', EVIDENCE,
      '--profile', PROFILE,
      '--overview-uri', OVERVIEW,
      '--out', 'out/ocr.json',
    ],
  },
  {
    title: 'OSCAL assessment results, from the same control state',
    why:
      'Format pluggability made concrete. 20x does not use OSCAL, but Rev5 runs to 2027 and customers ask for it, ' +
      'so it is a projection of the same state rather than a second system.',
    argv: ['src/cli.mjs', 'emit', 'oscal-ar', '--evidence', EVIDENCE, '--out', 'out/oscal-assessment-results.json'],
  },
  {
    title: 'The full coverage report as Markdown',
    why: 'Every indicator, every stated gap, every unaddressed item with its named next step.',
    argv: ['src/cli.mjs', 'coverage', '--evidence', EVIDENCE, '--md', 'out/coverage.md', '--json', 'out/coverage.json'],
  },
];

const rule = (char = '─') => console.log(char.repeat(78));

// Start clean so the demo cannot appear to succeed on evidence left over from an earlier run.
if (existsSync(EVIDENCE)) rmSync(EVIDENCE, { recursive: true, force: true });

let failed = 0;

for (const [index, step] of steps.entries()) {
  console.log('');
  rule();
  console.log(`${String(index + 1).padStart(2)}. ${step.title}`);
  console.log(`    ${step.why}`);
  console.log(`    $ node ${step.argv.join(' ')}`);
  rule();

  try {
    const out = execFileSync(process.execPath, step.argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    process.stdout.write(out.trimEnd() ? `${out.trimEnd()}\n` : '');
  } catch (err) {
    process.stdout.write(err.stdout ?? '');
    process.stderr.write(err.stderr ?? '');
    console.error(`\n    step failed with exit code ${err.status}`);
    failed += 1;
  }
}

console.log('');
rule('═');
if (failed) {
  console.error(`${failed} step(s) failed.`);
  process.exit(1);
}
console.log('Wrote out/sdr.json, out/ocr.json, out/oscal-assessment-results.json, out/coverage.md, out/coverage.json');
console.log('');
console.log('The evidence here is fixture-derived and marked as such in every bundle and in the emitted SDR.');
console.log('For the preventive half — the policy gate and its negative control — run: npm run policy');
rule('═');
