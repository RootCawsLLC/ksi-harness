import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, copyFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The commit guards, proved to refuse rather than merely to exist.
 *
 * `scripts/setup-git.mjs` has always PINNED the identity in local config. Nothing ENFORCED it:
 * `git -c user.name=...` walks past local config, and a fresh clone or a new worktree has no local
 * config at all until somebody runs setup. Until this hook, `.githooks/` in this repository was an
 * empty, untracked directory and `core.hooksPath` was unset, so every commit here was checked by
 * nothing.
 *
 * That is the expensive one to get wrong: this repository is public and owned by RootCawsLLC, the
 * account rejects pushes exposing its private address, and such a commit cannot be fixed forward.
 *
 * These drive real commits in a real repository with a real linked worktree. A guard nobody has
 * watched refuse is a guard nobody knows is running.
 */

const GOOD = ['-c', 'user.name=RootCawsLLC', '-c', 'user.email=317738477+RootCawsLLC@users.noreply.github.com'];

const git = (cwd, args, env = {}) =>
  execFileSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, ...env }, stdio: 'pipe' });

/** Returns combined output of a commit expected to be refused, or null if it was allowed. */
function refusal(cwd, args, env = {}) {
  try {
    git(cwd, args, env);
    return null;
  } catch (e) {
    return String(e.stderr ?? '') + String(e.stdout ?? '');
  }
}

function scaffold() {
  const dir = mkdtempSync(join(tmpdir(), 'ksi-guard-'));
  const primary = join(dir, 'primary');
  mkdirSync(primary);
  git(primary, ['init', '--quiet', '--initial-branch=main']);

  writeFileSync(join(primary, 'seed.txt'), 'seed\n');
  git(primary, ['add', 'seed.txt']);
  git(primary, [...GOOD, 'commit', '--quiet', '-m', 'seed']);

  // The hooks directory is COMMITTED, not merely created. core.hooksPath is the relative path
  // `.githooks`, which git resolves against each working tree - so an untracked directory exists
  // only in the primary checkout and a linked worktree runs no hooks at all.
  const hooks = join(primary, '.githooks');
  mkdirSync(hooks);
  const hook = join(hooks, 'pre-commit');
  copyFileSync(join(ROOT, '.githooks', 'pre-commit'), hook);
  chmodSync(hook, 0o755);
  git(primary, ['add', '.githooks/pre-commit']);
  git(primary, [...GOOD, 'commit', '--quiet', '-m', 'arm hooks']);
  git(primary, ['config', 'core.hooksPath', '.githooks']);

  const wt = join(dir, 'wt');
  git(primary, ['worktree', 'add', '--quiet', wt, '-b', 'session']);

  return { dir, primary, wt };
}

const stage = (cwd, name) => {
  writeFileSync(join(cwd, name), `${name}\n`);
  git(cwd, ['add', name]);
};

test('a wrong author name is refused', () => {
  const { dir, wt } = scaffold();
  try {
    stage(wt, 'a.txt');
    const out = refusal(wt, ['-c', 'user.name=Susan', '-c', 'user.email=s@example.com', 'commit', '-m', 'x']);
    assert.ok(out, 'a commit under the wrong name was allowed');
    assert.match(out, /wrong identity/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a real address is refused even under the right name', () => {
  const { dir, wt } = scaffold();
  try {
    stage(wt, 'b.txt');
    // The failure this exists for: the owning account rejects pushes exposing the private address,
    // so this commit could not be fixed forward.
    const out = refusal(wt, ['-c', 'user.name=RootCawsLLC', '-c', 'user.email=someone@pm.me', 'commit', '-m', 'x']);
    assert.ok(out, 'a commit with a real address was allowed');
    assert.match(out, /non-noreply address/);
    assert.match(out, /rewritten rather than fixed forward/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the correct identity commits in a worktree', () => {
  const { dir, wt } = scaffold();
  try {
    stage(wt, 'c.txt');
    git(wt, [...GOOD, 'commit', '--quiet', '-m', 'good commit']);
    assert.match(git(wt, ['log', '-1', '--format=%s']), /good commit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the primary checkout is refused, and staged work survives', () => {
  const { dir, primary } = scaffold();
  try {
    stage(primary, 'd.txt');
    const out = refusal(primary, [...GOOD, 'commit', '-m', 'x']);
    assert.ok(out, 'a commit in the primary checkout was allowed');
    assert.match(out, /refusing to commit in the primary checkout/);
    assert.match(out, /worktree\.mjs add ksi-harness/);
    // Refusing must not cost the work: the difference between a guard and a hazard.
    assert.match(git(primary, ['diff', '--cached', '--name-only']), /d\.txt/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ALLOW_PRIMARY_COMMIT is an exception, not a loophole', () => {
  const { dir, primary } = scaffold();
  try {
    stage(primary, 'e.txt');
    git(primary, [...GOOD, 'commit', '--quiet', '-m', 'deliberate'], { ALLOW_PRIMARY_COMMIT: '1' });
    assert.match(git(primary, ['log', '-1', '--format=%s']), /deliberate/);

    stage(primary, 'f.txt');
    for (const value of ['0', 'false', 'yes', '']) {
      assert.ok(
        refusal(primary, [...GOOD, 'commit', '-m', 'x'], { ALLOW_PRIMARY_COMMIT: value }),
        `ALLOW_PRIMARY_COMMIT=${JSON.stringify(value)} was treated as permission`
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('KSI_GIT_LOGIN retargets the guard, matching setup-git.mjs', () => {
  const { dir, wt } = scaffold();
  try {
    stage(wt, 'g.txt');
    // setup-git.mjs already honours this variable; the hook must agree with it, or the two
    // disagree about who owns the repository.
    const out = refusal(wt, [...GOOD, 'commit', '-m', 'x'], { KSI_GIT_LOGIN: 'SomeoneElse' });
    assert.ok(out, 'the hook ignored KSI_GIT_LOGIN');
    assert.match(out, /expected author name: SomeoneElse/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
