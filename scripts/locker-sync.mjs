#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Restores and publishes the evidence locker on a dedicated branch.
 *
 * This script exists because the harness's central claim did not survive its own pipeline.
 * Twenty-six of the forty-six indicators use FedRAMP's defined sense of "persistently", and
 * the argument that a scheduled collection satisfies them rests entirely on retained bundle
 * history: `observedIntervalDays` needs at least two runs to report an interval at all, and
 * `assessCadence` cannot fail a claim it has no history to test. The scheduled workflow was
 * checking out the repository fresh, collecting into a gitignored directory and uploading it
 * as an artifact that nothing ever read back. Every run therefore started from an empty
 * locker, every cadence assessment reported "only one run so far", and `cadence_unmet` was
 * structurally zero. The mechanism was real and the pipeline never gave it anything to work
 * on.
 *
 * A branch rather than the default branch, for two reasons. Evidence changes on a schedule
 * and the code changes on review, so mixing them makes `git log` on the source useless. And
 * a branch is trivially replaced by a private append-only store — S3 with Object Lock, or a
 * WORM bucket — which is what a real deployment should use, because a bundle names accounts,
 * roles, buckets and failing resources. This default is appropriate for a public repository
 * monitoring itself, where every fact in the locker is already public. It is not appropriate
 * for a boundary with anything in it. See the guard on KSI_EVIDENCE_BRANCH in ccm.yml.
 */

const run = (args, opts = {}) => execFileSync('git', args, { encoding: 'utf8', stdio: 'pipe', ...opts }).trim();
const quiet = (args, opts = {}) => {
  try {
    run(args, opts);
    return true;
  } catch {
    return false;
  }
};

function remoteUrl() {
  const repo = process.env.GITHUB_REPOSITORY;
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  const server = process.env.GITHUB_SERVER_URL ?? 'https://github.com';
  if (!repo) throw new Error('GITHUB_REPOSITORY is not set; this script is meant to run inside Actions.');
  if (!token) throw new Error('GITHUB_TOKEN is not set; the locker branch cannot be fetched or pushed without it.');
  return `${server.replace('https://', `https://x-access-token:${token}@`)}/${repo}.git`;
}

/**
 * Clones the locker branch into `dir`, creating it as an orphan when it does not exist yet.
 *
 * The depth is deliberately not 1. The locker's own history is the evidence of recurrence, so
 * a shallow clone that discards it would reintroduce the bug this script fixes — with the
 * added indignity of appearing to work.
 */
function restore(dir, branch) {
  const url = remoteUrl();
  if (existsSync(dir)) throw new Error(`${dir} already exists; refusing to overwrite a locker in place.`);

  if (quiet(['ls-remote', '--exit-code', '--heads', url, branch])) {
    run(['clone', '--branch', branch, '--single-branch', url, dir]);
    console.log(`Restored the evidence locker from branch ${branch}.`);
  } else {
    run(['clone', '--depth', '1', url, dir]);
    run(['checkout', '--orphan', branch], { cwd: dir });
    quiet(['rm', '-rf', '.'], { cwd: dir });
    mkdirSync(join(dir, 'evidence'), { recursive: true });
    console.log(`Branch ${branch} does not exist yet; started an empty locker on a new orphan branch.`);
  }
  mkdirSync(join(dir, 'evidence'), { recursive: true });
}

/**
 * Commits and pushes whatever the collection wrote.
 *
 * A run that produced no change to the locker still committed under the previous design,
 * which would have made every scheduled run a commit and the history unreadable. An empty
 * diff is a successful no-op here — though in practice the collection timestamp changes every
 * bundle's hash, so this mostly matters when a run collected nothing at all.
 */
function publish(dir, branch, { message, runUri }) {
  run(['config', 'user.name', 'ksi-harness'], { cwd: dir });
  run(['config', 'user.email', 'ksi-harness@users.noreply.github.com'], { cwd: dir });
  run(['add', '-A'], { cwd: dir });

  const staged = run(['status', '--porcelain'], { cwd: dir });
  if (!staged) {
    console.log('The locker is unchanged; nothing to publish.');
    return 0;
  }

  const body = runUri ? `${message}\n\nCollected by ${runUri}` : message;
  run(['commit', '-m', body], { cwd: dir });
  run(['push', remoteUrl(), `HEAD:${branch}`], { cwd: dir });
  console.log(`Published the locker to ${branch}.`);
  return 0;
}

const [command, ...rest] = process.argv.slice(2);
const dir = rest[0] ?? '.locker';
const branch = process.env.KSI_EVIDENCE_BRANCH || 'evidence';

try {
  if (command === 'restore') {
    restore(dir, branch);
  } else if (command === 'publish') {
    publish(dir, branch, {
      message: process.env.KSI_COMMIT_MESSAGE ?? `Evidence collected ${new Date().toISOString()}`,
      runUri: process.env.KSI_RUN_URL ?? null,
    });
  } else {
    console.error('Usage: locker-sync.mjs restore|publish [dir]');
    process.exit(2);
  }
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
