// The scan verifier is itself a control, so it gets the same treatment as the rest: prove it fails
// when it should. The cases below are the three ways an advisory scanner goes quietly wrong —
// nothing evaluated, findings present but the negative control clean, and a report shape change.

import test from 'node:test';
import assert from 'node:assert/strict';

import { assessScan } from '../scripts/checkov-assert.mjs';

const check = (id, file, name = 'a check') => ({ check_id: id, file_path: file, check_name: name });

const report = (passed = [], failed = []) => ({
  check_type: 'terraform',
  results: { passed_checks: passed, failed_checks: failed },
});

test('a scan that evaluated files and failed the negative control is trusted', () => {
  const { problems, files, passed, failed } = assessScan([
    report(
      [check('CKV_AWS_18', '/policy/terraform/compliant/main.tf')],
      [check('CKV_AWS_23', '/policy/terraform/violations/main.tf')],
    ),
  ]);

  assert.deepEqual(problems, []);
  assert.equal(files.size, 2);
  assert.equal(passed.length, 1);
  assert.equal(failed.length, 1);
});

test('an empty report is a broken scan rather than a clean one', () => {
  const { problems } = assessScan([report()]);

  assert.equal(problems.length, 2, 'both the empty run and the silent negative control are named');
  assert.match(problems[0], /no evaluated checks/);
});

// The failure this file exists to catch. Checkov runs, reports passes, and the fixtures that are
// written to be non-conforming come back clean — which means it is not really looking at them.
test('findings everywhere except the negative control is still a broken scan', () => {
  const { problems } = assessScan([
    report([check('CKV_AWS_18', '/policy/terraform/violations/main.tf')], []),
  ]);

  assert.equal(problems.length, 1);
  assert.match(problems[0], /produced no checkov failures/);
});

test('reports from several frameworks are read together', () => {
  const { problems, files } = assessScan([
    report([check('CKV_AWS_18', '/policy/terraform/compliant/main.tf')], []),
    report([], [check('CKV_AWS_23', '/policy/terraform/violations/main.tf')]),
  ]);

  assert.deepEqual(problems, []);
  assert.equal(files.size, 2);
});

// A checkov upgrade that renames the result keys would otherwise read as a clean scan.
test('an unrecognised report shape fails rather than reading as clean', () => {
  const { problems } = assessScan([{ check_type: 'terraform', results: { renamed_checks: [] } }]);

  assert.ok(problems.length > 0);
  assert.match(problems[0], /no evaluated checks/);
});

test('the negative control directory is caller-declared', () => {
  const reports = [report([], [check('CKV_AWS_23', '/fixtures/nonconforming/main.tf')])];

  assert.deepEqual(assessScan(reports, 'nonconforming').problems, []);
  assert.equal(assessScan(reports, 'violations').problems.length, 1);
});
