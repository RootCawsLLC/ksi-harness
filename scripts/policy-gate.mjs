#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Runs the preventive policy gate and writes a machine-readable report.
 *
 * Two things happen here that a plain `conftest test` in a workflow file does not do.
 *
 * First, the negative control. The suite is run against a directory of deliberately
 * non-conforming Terraform and the run *fails* if that directory comes back clean. A policy set
 * that has only ever been pointed at passing input tells you nothing about whether it works —
 * and this repository has already had that exact bug twice: rules that matched no resources
 * because the input shape was wrong, and an IAM rule that skipped the string form of `Action`.
 * Both showed green. Asserting that the gate can still fail is the cheapest available defence
 * against a control that has quietly stopped being one.
 *
 * Second, the report is retained as an artifact so the pipeline collector can fold it into the
 * evidence locker. A red X in a CI run is a control; a red X nobody kept is not evidence of one.
 */

const CONFTEST = process.env.CONFTEST_BIN ?? (existsSync('.tools/conftest.exe') ? '.tools/conftest.exe' : 'conftest');
const OPA = process.env.OPA_BIN ?? (existsSync('.tools/opa.exe') ? '.tools/opa.exe' : 'opa');

const POLICY = 'policy/rego';
const GATED = 'policy/terraform/compliant';
const NEGATIVE_CONTROL = 'policy/terraform/violations';
const OUT_DIR = '.policy';

function run(bin, args) {
  try {
    return { ok: true, stdout: execFileSync(bin, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }) };
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(
        `${bin} is not installed. Install OPA and conftest, or set OPA_BIN / CONFTEST_BIN. ` +
          `See .github/workflows/policy.yml for the versions CI uses.`
      );
    }
    return { ok: false, stdout: err.stdout ?? '', stderr: err.stderr ?? '', status: err.status };
  }
}

function conftestJson(dir) {
  const result = run(CONFTEST, ['test', '--policy', POLICY, '--output', 'json', '--no-color', dir]);
  const text = (result.stdout || '').trim();
  if (!text) throw new Error(`conftest produced no output for ${dir}: ${result.stderr ?? ''}`);
  return JSON.parse(text);
}

const tally = (report) => ({
  files: report.length,
  failures: report.reduce((n, f) => n + (f.failures?.length ?? 0), 0),
  warnings: report.reduce((n, f) => n + (f.warnings?.length ?? 0), 0),
  successes: report.reduce((n, f) => n + (f.successes ?? 0), 0),
});

const problems = [];

// ---------------------------------------------------------------- policy unit tests

const unit = run(OPA, ['test', POLICY]);
process.stdout.write(unit.stdout || '');
if (!unit.ok) {
  process.stderr.write(unit.stderr || '');
  problems.push('The policy unit tests failed.');
}

// -------------------------------------------------------------- the gate under test

const gated = conftestJson(GATED);
const gatedTally = tally(gated);
console.log(
  `gate      ${GATED}: ${gatedTally.files} file(s), ${gatedTally.successes} rule pass(es), ` +
    `${gatedTally.warnings} warning(s), ${gatedTally.failures} failure(s)`
);
for (const file of gated) {
  for (const f of file.failures ?? []) console.log(`  FAIL ${file.filename}: ${f.msg}`);
  for (const w of file.warnings ?? []) console.log(`  WARN ${file.filename}: ${w.msg}`);
}
if (gatedTally.failures > 0) problems.push(`${gatedTally.failures} denied finding(s) in ${GATED}.`);

// ----------------------------------------------------------------- negative control

const negative = conftestJson(NEGATIVE_CONTROL);
const negativeTally = tally(negative);
console.log(
  `negative  ${NEGATIVE_CONTROL}: ${negativeTally.failures} failure(s), ${negativeTally.warnings} warning(s) ` +
    `— expected to be non-zero`
);
if (negativeTally.failures === 0) {
  problems.push(
    `${NEGATIVE_CONTROL} produced no failures. That directory is deliberately non-conforming, so a clean ` +
      `result means the policies are not matching anything — most likely the input shape changed. The gate is ` +
      `not enforcing what it claims to enforce.`
  );
}

// ------------------------------------------------------------------------- artifact

mkdirSync(OUT_DIR, { recursive: true });
const reportPath = join(OUT_DIR, 'conftest-report.json');
writeFileSync(reportPath, `${JSON.stringify(gated, null, 2)}\n`, 'utf8');
writeFileSync(
  join(OUT_DIR, 'negative-control.json'),
  `${JSON.stringify(negative, null, 2)}\n`,
  'utf8'
);
console.log(`\nwrote ${reportPath}`);
console.log('Fold it into the evidence locker with: ksi collect --only pipeline --profile <profile>');

if (problems.length) {
  console.error('\nGate failed:');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('\nGate passed, and the negative control still fails as designed.');
