#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * Fetches the anchor log from a repository the evidence writer does not own, and appends to it.
 *
 * The anchor exists to notice a locker that came back smaller than it went in, and its whole
 * value is determined by where it lives. `ccm.yml` used to write it to `.locker/anchor.jsonl`,
 * beside `.locker/evidence` — which reads like separation and is not, because `locker-sync
 * publish` commits all of `.locker` and pushes it. Anchor and evidence reached the same branch
 * in the same commit and came back together on restore, so anyone able to rewrite that branch
 * rewrote both, and the mechanism reduced to storing a hash beside its own data.
 *
 * Simply repointing the path was worse. Anything outside `.locker` was written after collection
 * and never restored: every run would start from a fresh checkout, find no anchor, take the
 * "not checked" branch and report a clean reconciliation forever. Structurally unfalsifiable,
 * and identical in shape to the cadence bug the locker sync was written to fix.
 *
 * So the anchor has to be *plumbed*, which is what this is: fetched before verification,
 * appended after publication, against a remote and a credential of its own.
 *
 * ## What this buys, stated precisely
 *
 * A principal who can write the evidence branch cannot rewrite the anchor, because the anchor
 * lives in a different repository behind a different token. A restored, mirrored or exported
 * copy of the locker is reconciled against a record that did not travel with it. Deleting the
 * evidence does not delete the account of how much of it there was.
 *
 * ## What it does not buy, which matters more
 *
 * **This is separation of storage and credential, not separation of control.** Both credentials
 * are referenced by one workflow in one repository, so whoever can modify that workflow — or
 * add a secret to it — can write both sides. An attacker with push access to the default branch
 * is not stopped by this; they are stopped by the branch protection on that branch, which is a
 * different control with different failure modes.
 *
 * Genuine independence would require the anchor to be appended by something the evidence writer
 * cannot influence at all: an append-only endpoint that rejects rewrites regardless of caller,
 * a third party's log, or an assessor's own copy. The RFC 3161 token is the closest thing here
 * to that property already, because the authority independently observed the same root.
 *
 * Saying which of these it is, is the point. A mechanism that is present, named, and weaker
 * than its documentation is the failure this repository exists to catch.
 */

/**
 * Line-ending translation is disabled on every call, which is not a Windows nicety.
 *
 * The anchor is an append-only log of chained entries. If git rewrites `\n` to `\r\n` on
 * checkout and back on commit, the file that comes back is not the file that went out — and a
 * record whose bytes depend on which platform last touched it is a poor thing to be reasoning
 * about deletion with. Cheaper to forbid the translation than to reason about where it applies.
 */
const run = (args, opts = {}) =>
  execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', ...args], {
    encoding: 'utf8',
    stdio: 'pipe',
    ...opts,
  }).trim();

/**
 * How the anchor is configured, and whether it is configured at all.
 *
 * Three states rather than two. A half-configured anchor is refused rather than quietly
 * treated as absent, because "somebody set KSI_ANCHOR_REPO and the token is missing" and
 * "nobody configured an anchor" call for opposite responses: the first is a broken deployment
 * that should stop, the second is a documented default that should continue.
 */
export function anchorRemote(env = process.env) {
  const repo = env.KSI_ANCHOR_REPO?.trim();
  const token = env.KSI_ANCHOR_TOKEN?.trim();

  if (!repo && !token) return { configured: false };

  if (repo && !token) {
    throw new Error(
      `KSI_ANCHOR_REPO is set to ${repo} but KSI_ANCHOR_TOKEN is not. The separation this provides is a ` +
        'separate credential; without one the anchor cannot be written at all, and falling back to the ' +
        'co-located default would silently restore the weakness the second repository was added to remove.'
    );
  }
  if (token && !repo) {
    throw new Error('KSI_ANCHOR_TOKEN is set but KSI_ANCHOR_REPO is not, so there is nowhere to write the anchor.');
  }
  if (!/^[^/\s]+\/[^/\s]+$/.test(repo)) {
    throw new Error(`KSI_ANCHOR_REPO must be "owner/name"; got "${repo}".`);
  }

  const server = env.GITHUB_SERVER_URL ?? 'https://github.com';
  return {
    configured: true,
    repo,
    branch: env.KSI_ANCHOR_BRANCH?.trim() || 'main',
    // One file per monitored boundary, so a single anchor repository can serve several without
    // their histories interleaving into one unreadable log.
    file: env.KSI_ANCHOR_FILE?.trim() || `anchors/${(env.GITHUB_REPOSITORY ?? 'unknown').replace('/', '__')}.jsonl`,
    url: `${server.replace('https://', `https://x-access-token:${token}@`)}/${repo}.git`,
  };
}

/**
 * Clone failures that mean the anchor repository is genuinely empty, and only those.
 *
 * The first run of a new programme legitimately has no anchor history, so an absent branch has to
 * be recoverable. Everything else — a bad credential, a malformed url, DNS, a 404 for a repository
 * this token cannot see — is a failure to *look*, and the difference is the whole value of the
 * mechanism. This `catch` used to be unconditional, and the consequence was observed rather than
 * theorised: a malformed token made `clone` fail, the fallback treated it as an empty repository,
 * restore reported "this is the first run against it", and `verify` went on to reconcile against a
 * stale copy of the anchor that had come back with the evidence branch. The run would have been
 * green if a later step had not failed for its own reasons.
 *
 * It is the same line `optional()` draws for the AWS collectors, and it is drawn conservatively:
 * anything not recognisably "there is nothing here" is raised.
 */
const NO_ANCHOR_YET =
  /Remote branch .+ not found in upstream|Could not find remote branch|You appear to have cloned an empty repository/i;

/**
 * Removes the token from anything about to be printed.
 *
 * It is embedded in the remote url, git quotes the url back in its error text, and
 * `execFileSync` puts the whole argument list in the message it throws. Redacting at the point of
 * output is the only place that covers all three. GitHub masks registered secrets in Actions logs,
 * but a developer running this locally has no such thing.
 */
export const redact = (text) => String(text ?? '').replace(/(x-access-token:)[^@\s]*/g, '$1***');

/** Clones the anchor repository into a scratch directory. Shallow is fine: only the tip is read. */
function checkout(remote) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-anchor-'));
  try {
    run(['clone', '--depth', '1', '--branch', remote.branch, '--single-branch', remote.url, dir]);
  } catch (err) {
    const reported = redact(err.stderr || err.message);
    if (!NO_ANCHOR_YET.test(reported)) {
      rmSync(dir, { recursive: true, force: true });
      throw new Error(
        `Could not read the anchor at ${remote.repo} (branch ${remote.branch}): ` +
          `${reported.split('\n').filter(Boolean).pop() ?? 'no detail from git'}\n` +
          'This is a failure to look, not evidence that there is nothing to see. Reporting it as an absent ' +
          'anchor would let a broken credential read as a clean reconciliation for as long as nobody read ' +
          'the logs.'
      );
    }
    run(['init', '--initial-branch', remote.branch, dir]);
    run(['remote', 'add', 'origin', remote.url], { cwd: dir });
  }
  return dir;
}

/**
 * Copies the anchor out of its repository to where `ksi verify` expects it.
 *
 * A missing file is not an error. The first collection of a new boundary has nothing to
 * reconcile against, and `verify` already distinguishes "no anchor log yet" from "the anchor
 * disagrees" — which are different findings and must not be merged into one.
 */
export function restore(localPath, remote) {
  const dir = checkout(remote);
  try {
    const source = join(dir, remote.file);
    if (!existsSync(source)) {
      // Authoritative has to include saying that there is nothing. `ANCHOR_LOG` points inside the
      // locker, so a file can be sitting at localPath already, restored from the evidence branch
      // along with the evidence — which is the copy this separation exists to distrust. Leaving it
      // would have `verify` reconcile the locker against a record its own writer controls, while
      // this line said the anchor was not found.
      if (existsSync(localPath)) {
        rmSync(localPath);
        console.log(
          `Discarded the co-located anchor at ${localPath}: it arrived with the evidence branch, and with a ` +
            'separate anchor repository configured it is not a record this run may rely on.'
        );
      }
      console.log(`No anchor at ${remote.repo}:${remote.file} yet; this is the first run against it.`);
      return { restored: false, entries: 0 };
    }
    // Reported rather than done quietly. `ANCHOR_LOG` points inside the locker, so this path can
    // already hold a copy that came back with the evidence branch, and the remote overwrites it on
    // every run. Saying so keeps the duplicate visible: it is not consulted, but while
    // `locker-sync publish` keeps committing it, a reader of that branch will find a file that
    // looks like the anchor and is not the one anything reconciles against.
    if (existsSync(localPath)) {
      console.log(
        `Overwriting the co-located copy at ${localPath} with ${remote.repo}:${remote.file}. The remote is the ` +
          'record; the copy on the evidence branch is not consulted.'
      );
    }
    mkdirSync(dirname(localPath), { recursive: true });
    copyFileSync(source, localPath);
    const entries = run(['show', `HEAD:${remote.file}`], { cwd: dir }).split('\n').filter(Boolean).length;
    console.log(`Restored the anchor from ${remote.repo}:${remote.file} (${entries} entry(s)).`);
    return { restored: true, entries };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Appends the local anchor back to its repository.
 *
 * Re-cloned immediately before writing rather than reusing the restore checkout, because the
 * two are separated by an entire collection. Copying the local file over the remote one would
 * overwrite anything appended in between — and since the log is chained, a lost entry is not a
 * missing line but a break that makes every later entry unverifiable.
 */
export function publish(localPath, remote) {
  if (!existsSync(localPath)) {
    console.log('No local anchor to publish.');
    return 0;
  }

  const dir = checkout(remote);
  try {
    const target = join(dir, remote.file);
    const before = existsSync(target) ? run(['show', `HEAD:${remote.file}`], { cwd: dir }).split('\n').filter(Boolean).length : 0;

    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(localPath, target);

    run(['config', 'user.name', 'ksi-harness'], { cwd: dir });
    run(['config', 'user.email', 'ksi-harness@users.noreply.github.com'], { cwd: dir });
    run(['add', '-A'], { cwd: dir });

    if (!run(['status', '--porcelain'], { cwd: dir })) {
      console.log('The anchor is unchanged; nothing to publish.');
      return 0;
    }

    // The count is in the commit subject so the repository's own log is readable as a record of
    // how the evidence grew, without anyone having to open the file.
    const after = run(['show', ':' + remote.file], { cwd: dir }).split('\n').filter(Boolean).length;
    if (after < before) {
      throw new Error(
        `Refusing to publish: the local anchor has ${after} entry(s) and ${remote.repo}:${remote.file} has ` +
          `${before}. An anchor that shrank is the exact condition it exists to detect, and overwriting the ` +
          'remote with it would destroy the record rather than report the problem.'
      );
    }

    const message = process.env.KSI_RUN_URL
      ? `Anchor ${process.env.GITHUB_REPOSITORY ?? ''} at ${after} entry(s)\n\nRecorded by ${process.env.KSI_RUN_URL}`
      : `Anchor ${process.env.GITHUB_REPOSITORY ?? ''} at ${after} entry(s)`;
    run(['commit', '-m', message], { cwd: dir });
    run(['push', remote.url, `HEAD:${remote.branch}`], { cwd: dir });
    console.log(`Published the anchor to ${remote.repo}:${remote.file} (${after} entry(s)).`);
    return 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------------- cli */

// Guarded so the functions above can be imported by tests without the CLI running.
if (process.argv[1]?.endsWith('anchor-sync.mjs')) {
  const [command, pathArg] = process.argv.slice(2);
  const localPath = pathArg ?? process.env.ANCHOR_LOG ?? '.locker/anchor.jsonl';

  try {
    const remote = anchorRemote();

    if (!remote.configured) {
      // Reported on every run rather than once in a comment. This is the degraded mode, and a
      // degraded mode nobody is told about is how a control becomes decoration.
      console.log(
        'No separate anchor repository configured (KSI_ANCHOR_REPO / KSI_ANCHOR_TOKEN).\n' +
          `The anchor stays at ${localPath}, which is published alongside the evidence it protects — so it\n` +
          'detects evidence lost by accident and NOT deliberate truncation by anyone who can write the\n' +
          'evidence branch. Acceptable for a repository monitoring itself. Not acceptable for a real boundary.'
      );
      process.exit(0);
    }

    if (command === 'restore') restore(localPath, remote);
    else if (command === 'publish') publish(localPath, remote);
    else {
      console.error('Usage: anchor-sync.mjs restore|publish [path]');
      process.exit(2);
    }
  } catch (err) {
    console.error(redact(err.message));
    process.exit(1);
  }
}
