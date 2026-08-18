// Confirms that a checkov run actually evaluated the tree, then summarises it.
//
// This exists because of a real failure. The repo previously used the published checkov action,
// which pinned a 2022-era image, rejected the output flags it was given, exited on an argparse
// error, and still let the job report success. Checkov scanned nothing and the tick stayed green.
//
// An advisory scanner is allowed to find nothing. It is not allowed to be silently absent, because
// "no findings" and "never ran" render identically in a passing pipeline. So the scan carries the
// same negative control the conftest gate does: the deliberately non-conforming fixtures must
// produce failures. If they stop doing so, the scanner is broken, not the infrastructure.

import { readFileSync } from 'node:fs';
import { argv } from 'node:process';
import { pathToFileURL } from 'node:url';

// Checkov emits an object for a single framework and an array when several report together.
export const readReport = (path) => {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  return Array.isArray(parsed) ? parsed : [parsed];
};

// The directory whose contents are written to fail. Kept as an argument rather than a constant so
// the negative control is stated by the caller and visible in the workflow.
export const NEGATIVE_CONTROL = 'violations';

export const assessScan = (reports, negativeControl = NEGATIVE_CONTROL) => {
  const collect = (key) => reports.flatMap((report) => report.results?.[key] ?? []);
  const passed = collect('passed_checks');
  const failed = collect('failed_checks');
  const files = new Set([...passed, ...failed].map((check) => check.file_path));

  const problems = [];
  if (!passed.length && !failed.length) problems.push('checkov reported no evaluated checks at all');
  else if (!files.size) problems.push('checkov evaluated no files');

  // These fixtures are written to be non-conforming; a scanner that clears them is not telling the
  // truth about the configurations that matter.
  if (!failed.some((check) => check.file_path?.includes(negativeControl))) {
    problems.push(
      `the deliberately non-conforming fixtures under ${negativeControl} produced no checkov ` +
        'failures, which means the scan did not really evaluate them',
    );
  }

  return { passed, failed, files, problems };
};

const main = (path) => {
  const { passed, failed, files, problems } = assessScan(readReport(path));

  console.log(`checkov  ${files.size} file(s), ${passed.length} pass(es), ${failed.length} failure(s)`);
  for (const check of failed) {
    console.log(`  ${check.check_id} ${check.file_path}: ${check.check_name}`);
  }

  if (problems.length) {
    console.error('\nThe checkov scan cannot be trusted:');
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exit(1);
  }

  console.log('\nScan verified: checkov ran, and the non-conforming fixtures still fail it.');
};

// Only act when run as a command. Imported by the tests, this file is just the two functions above.
if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) {
  main(argv[2] ?? '.checkov/results_json.json');
}
