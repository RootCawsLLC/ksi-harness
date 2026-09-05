import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { anchorRemote, assertWritable, publish, redact, restore } from '../scripts/anchor-sync.mjs';

/**
 * The anchor is only worth anything if it lives where the evidence writer cannot reach it, and
 * the previous arrangement failed that on a technicality: `anchor.jsonl` sat beside `evidence/`
 * rather than inside it, and `locker-sync publish` pushed the whole directory anyway.
 *
 * These run against real local git repositories rather than a mocked remote. The mechanism is
 * almost entirely git behaviour — clone a repo that may not exist yet, read a file that may not
 * exist yet, append, push — so mocking git would test the mock.
 */

// Same autocrlf guard as the script under test: the fixture must not reintroduce the
// translation the script exists to avoid.
const git = (args, cwd) =>
  execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', ...args], { encoding: 'utf8', stdio: 'pipe', cwd }).trim();

/** A bare repository standing in for the separate anchor repo, plus a remote pointing at it. */
function anchorRepo({ seeded = null, branch = 'main' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'ksi-anchorepo-'));
  const bare = join(root, 'anchors.git');
  git(['init', '--bare', '--initial-branch', branch, bare]);

  if (seeded) {
    const work = join(root, 'seed');
    git(['clone', bare, work]);
    mkdirSync(join(work, 'anchors'), { recursive: true });
    writeFileSync(join(work, 'anchors', 'boundary.jsonl'), seeded, 'utf8');
    git(['config', 'user.email', 't@example.com'], work);
    git(['config', 'user.name', 'test'], work);
    git(['add', '-A'], work);
    git(['commit', '-m', 'seed'], work);
    git(['push', 'origin', `HEAD:${branch}`], work);
  }

  return {
    root,
    remote: { configured: true, repo: 'test/anchors', branch, file: 'anchors/boundary.jsonl', url: bare },
    read() {
      const work = mkdtempSync(join(tmpdir(), 'ksi-read-'));
      try {
        git(['clone', '--depth', '1', bare, work]);
        const path = join(work, 'anchors', 'boundary.jsonl');
        return existsSync(path) ? readFileSync(path, 'utf8') : null;
      } catch {
        return null;
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

const ENTRY = (n) => `${JSON.stringify({ schema: 'ksi-harness/evidence-anchor/1', bundle_count: n })}\n`;

function localAnchor(contents) {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-local-'));
  const path = join(dir, 'anchor.jsonl');
  if (contents !== null) writeFileSync(path, contents, 'utf8');
  return { dir, path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/* ------------------------------------------------------------------ configuration */

// Three states, not two. "Half configured" and "not configured" call for opposite responses:
// one is a broken deployment that must stop, the other a documented default that continues.
test('an unconfigured anchor is a mode, not an error', () => {
  assert.equal(anchorRemote({}).configured, false);
});

test('a repository without a token is refused rather than downgraded', () => {
  assert.throws(
    () => anchorRemote({ KSI_ANCHOR_REPO: 'org/anchors' }),
    /KSI_ANCHOR_TOKEN is not./,
    'falling back here would silently restore the weakness the second repository was added to remove'
  );
  assert.throws(() => anchorRemote({ KSI_ANCHOR_TOKEN: 'x' }), /nowhere to write the anchor/);
});

test('a malformed repository name is refused before any network call', () => {
  assert.throws(() => anchorRemote({ KSI_ANCHOR_REPO: 'not-a-repo', KSI_ANCHOR_TOKEN: 'x' }), /must be "owner\/name"/);
});

test('the token never appears in the repository identity, only in the url', () => {
  const r = anchorRemote({ KSI_ANCHOR_REPO: 'org/anchors', KSI_ANCHOR_TOKEN: 'ghp_secret', GITHUB_REPOSITORY: 'o/r' });
  assert.equal(r.repo, 'org/anchors');
  assert.match(r.url, /x-access-token:ghp_secret@/);
  assert.equal(r.file, 'anchors/o__r.jsonl', 'one file per boundary, so one repo can serve several');
});

/* ----------------------------------------------------------------------- restore */

test('a first run against an empty anchor repository is reported, not failed', () => {
  const repo = anchorRepo();
  const local = localAnchor(null);
  try {
    const result = restore(local.path, repo.remote);
    assert.equal(result.restored, false);
    assert.equal(existsSync(local.path), false, 'verify must see "no anchor yet", not an empty one');
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

test('an existing anchor is fetched to where verify expects it', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) + ENTRY(2) });
  const local = localAnchor(null);
  try {
    const result = restore(local.path, repo.remote);
    assert.equal(result.restored, true);
    assert.equal(result.entries, 2);
    assert.equal(readFileSync(local.path, 'utf8'), ENTRY(1) + ENTRY(2));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

/* ----------------------------------------------------------------------- publish */

test('the anchor is appended to a repository that had none', () => {
  const repo = anchorRepo();
  const local = localAnchor(ENTRY(1));
  try {
    publish(local.path, repo.remote);
    assert.equal(repo.read(), ENTRY(1));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

test('a grown anchor replaces the shorter one, which is the ordinary case', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) });
  const local = localAnchor(ENTRY(1) + ENTRY(2));
  try {
    publish(local.path, repo.remote);
    assert.equal(repo.read(), ENTRY(1) + ENTRY(2));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

/**
 * The refusal that matters most, and the one a naive implementation gets backwards.
 *
 * `publish` copies the local file over the remote one, so a truncated local anchor would
 * overwrite the longer remote record — destroying the evidence of truncation with the same
 * command that was supposed to preserve it. The log is chained, so a lost entry is not a
 * missing line but a break that makes every later entry unverifiable.
 */
test('an anchor that shrank is refused rather than published over the longer record', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) + ENTRY(2) + ENTRY(3) });
  const local = localAnchor(ENTRY(1));
  try {
    assert.throws(() => publish(local.path, repo.remote), /anchor that shrank is the exact condition it exists to detect/);
    assert.equal(repo.read(), ENTRY(1) + ENTRY(2) + ENTRY(3), 'the remote record survives the refusal');
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

test('an unchanged anchor is not committed, so the log does not fill with empty runs', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) });
  const local = localAnchor(ENTRY(1));
  try {
    assert.equal(publish(local.path, repo.remote), 0);
    assert.equal(repo.read(), ENTRY(1));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

test('publishing with no local anchor does nothing rather than clearing the remote', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) });
  const local = localAnchor(null);
  try {
    assert.equal(publish(local.path, repo.remote), 0);
    assert.equal(repo.read(), ENTRY(1));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

/* -------------------------------------------------------------------- round trip */

// What the workflow actually does across two scheduled runs.
test('restore then publish carries history forward across runs', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) });
  const local = localAnchor(null);
  try {
    restore(local.path, repo.remote);
    assert.equal(readFileSync(local.path, 'utf8'), ENTRY(1), 'run 2 opens with run 1 history');

    // The collection appends, exactly as `ksi publish --anchor` would.
    writeFileSync(local.path, readFileSync(local.path, 'utf8') + ENTRY(2), 'utf8');
    publish(local.path, repo.remote);

    assert.equal(repo.read(), ENTRY(1) + ENTRY(2));
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

/* --------------------------------------------- failing to look is not finding nothing */

/**
 * These three pin behaviour that a live run got wrong on 2026-08-21.
 *
 * A malformed token made `clone` fail; the fallback in `checkout` was an unconditional `catch`, so
 * it treated the failure as an empty repository and restore reported "this is the first run
 * against it". `ANCHOR_LOG` points inside the locker, so a copy of the anchor was already sitting
 * at that path — restored from the evidence branch with the evidence — and `verify` reconciled the
 * locker against a record the evidence writer controls, reporting a clean result. The run only went
 * red because a later step failed for its own reasons.
 *
 * Both halves are needed. Raising on a broken credential closes the case observed; discarding the
 * co-located copy closes the same hole for a remote that is legitimately empty, where raising would
 * be wrong.
 */
test('a remote that cannot be read raises, rather than reporting an absent anchor', () => {
  const local = localAnchor(null);
  const remote = {
    configured: true,
    repo: 'test/anchors',
    branch: 'main',
    file: 'anchors/boundary.jsonl',
    url: join(local.dir, 'no-such-repository.git'),
  };
  try {
    assert.throws(() => restore(local.path, remote), /Could not read the anchor at test\/anchors/);
    assert.throws(() => restore(local.path, remote), /failure to look, not evidence that there is nothing/);
  } finally {
    local.cleanup();
  }
});

// git quotes the remote url back in its error text, and execFileSync puts the argument list in the
// message it throws. Neither is masked outside Actions.
test('a credential failure does not print the token it failed with', () => {
  const local = localAnchor(null);
  const remote = {
    configured: true,
    repo: 'test/anchors',
    branch: 'main',
    file: 'anchors/boundary.jsonl',
    url: `https://x-access-token:github_pat_NOT_A_REAL_SECRET@127.0.0.1:1/test/anchors.git`,
  };
  try {
    restore(local.path, remote);
    assert.fail('an unreachable remote must raise');
  } catch (err) {
    assert.doesNotMatch(err.message, /github_pat_NOT_A_REAL_SECRET/, 'the token reached the error text');
  } finally {
    local.cleanup();
  }
});

/**
 * The remote is authoritative in this mode, and that has to include saying there is nothing.
 * Anything left at the local path came back with the evidence branch, which is exactly the copy a
 * separate anchor repository exists to distrust.
 */
test('an empty remote discards a co-located anchor rather than reconciling against it', () => {
  const repo = anchorRepo();
  const local = localAnchor(ENTRY(1) + ENTRY(2));
  try {
    assert.equal(existsSync(local.path), true, 'precondition: the locker carried one back');
    const result = restore(local.path, repo.remote);
    assert.equal(result.restored, false);
    assert.equal(existsSync(local.path), false, 'verify must not be handed the evidence writer’s own copy');
  } finally {
    repo.cleanup();
    local.cleanup();
  }
});

// The text git produced on 2026-08-21, which quoted the url back with its userinfo intact. Other
// git errors strip it, which is exactly why this cannot be left to git.
test('the redaction removes a token from the url git quotes back', () => {
  const real = 'fatal: credential url cannot be parsed: https://x-access-token:github_pat_NOT_A_REAL_SECRET@github.com/x/y.git';
  const cleaned = redact(real);
  assert.doesNotMatch(cleaned, /github_pat_NOT_A_REAL_SECRET/);
  assert.match(cleaned, /x-access-token:\*\*\*@github\.com/);
  assert.equal(redact(undefined), '');
});

/* ------------------------------------------- proving the credential can write */

/**
 * A successful restore proves nothing about the anchor credential, and that is not academic.
 *
 * On 2026-08-21 the token was replaced with one owned by an account that had no access to the
 * anchor repository. `Restore the anchor log` succeeded, because `xnasusx/ksi-anchors` is public
 * and cloning it needs no credential at all. The failure surfaced only at the publish step, after
 * a full collection had already run and pushed evidence to the evidence branch -- which is also
 * how the gap in #65 opens.
 *
 * `git push --dry-run` negotiates authentication and permissions and then transfers nothing, so
 * the question can be answered in under a second instead of at the end of an hour.
 */
test('a writable remote passes the preflight and is not mutated by it', () => {
  const repo = anchorRepo({ seeded: ENTRY(1) });
  try {
    const before = repo.read();
    assert.equal(assertWritable(repo.remote).writable, true);
    assert.equal(repo.read(), before, 'a dry run must not change the remote');
  } finally {
    repo.cleanup();
  }
});

// The case that went undetected for a whole run.
test('a credential that cannot write is refused, before anything is collected', () => {
  const denied = () => {
    const err = new Error('command failed');
    err.stderr = 'remote: Permission to test/anchors.git denied to WrongAccount.\nfatal: unable to access: 403';
    throw err;
  };
  assert.throws(
    () => assertWritable({ repo: 'test/anchors', branch: 'main', url: 'https://x' }, { run: denied }),
    /cannot write test\/anchors/
  );
  assert.throws(
    () => assertWritable({ repo: 'test/anchors', branch: 'main', url: 'https://x' }, { run: denied }),
    /a successful restore proves nothing/
  );
});

// Being unreachable is not a permissions finding. Failing the run here would turn a network blip
// into an anchor-configuration error, and the publish step reports the real thing if it persists.
test('an unreachable remote is reported, not raised', () => {
  const unreachable = () => {
    const err = new Error('command failed');
    err.stderr = 'fatal: unable to access: Could not resolve host: github.com';
    throw err;
  };
  const result = assertWritable({ repo: 'test/anchors', branch: 'main', url: 'https://x' }, { run: unreachable });
  assert.equal(result.writable, null);
  assert.match(result.detail, /Could not resolve host/);
});

// git puts the remote url in its error text, and the url carries the token.
test('the preflight does not print the token it failed with', () => {
  const denied = () => {
    const err = new Error('command failed');
    err.stderr = "remote: Permission denied.\nfatal: unable to access 'https://x-access-token:github_pat_NOT_REAL@github.com/a/b.git/': 403";
    throw err;
  };
  try {
    assertWritable({ repo: 'a/b', branch: 'main', url: 'https://x' }, { run: denied });
    assert.fail('should have raised');
  } catch (err) {
    assert.doesNotMatch(err.message, /github_pat_NOT_REAL/);
    // The invariant is that the token never appears, not that a redaction marker does: which
    // line git's error is summarised from varies, and only some of them carry the url at all.
    assert.doesNotMatch(err.message, /x-access-token:[^*]/);
  }
});
