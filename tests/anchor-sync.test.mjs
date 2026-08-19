import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { anchorRemote, publish, restore } from '../scripts/anchor-sync.mjs';

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
