#!/usr/bin/env node
import { execFileSync } from 'node:child_process';

/**
 * Pins this repository's commit identity, and refuses to guess.
 *
 * The problem this solves is mundane and expensive: more than one GitHub account is authenticated
 * on this machine, and there is no global git identity. Without a local one, the first commit
 * either fails or lands under whatever git infers — and a public compliance repository attributed
 * to the wrong account is a mistake that has to be fixed by rewriting history.
 *
 * Two deliberate choices:
 *
 *  - Only ever writes local config. Touching --global on someone's machine to make one project
 *    work is not this script's business.
 *  - Runs from `prepare`, so it must not fail an install. A mismatch is a loud warning and a
 *    zero exit; `npm run setup` is the mode that writes.
 */

const EXPECTED_LOGIN = process.env.KSI_GIT_LOGIN ?? 'RootCawsLLC';
const writing = process.argv.includes('--write') || process.env.npm_lifecycle_event === 'setup';

const git = (args, { allowFailure = false } = {}) => {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (err) {
    if (allowFailure) return null;
    throw err;
  }
};

const inRepo = git(['rev-parse', '--is-inside-work-tree'], { allowFailure: true }) === 'true';
if (!inRepo) {
  // Installed as a dependency rather than cloned. Nothing to configure.
  process.exit(0);
}

/** The noreply address GitHub issues for an account, which keeps a personal address out of history. */
function noreply(login) {
  const id = ghJson(['api', `users/${login}`, '--jq', '.id']);
  return id ? `${id}+${login}@users.noreply.github.com` : null;
}

function ghJson(args) {
  try {
    return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

const localName = git(['config', '--local', 'user.name'], { allowFailure: true });
const localEmail = git(['config', '--local', 'user.email'], { allowFailure: true });
const activeLogin = ghJson(['api', 'user', '--jq', '.login']);

const problems = [];

if (activeLogin && activeLogin !== EXPECTED_LOGIN) {
  problems.push(
    `The active GitHub CLI account is "${activeLogin}" but this repository expects "${EXPECTED_LOGIN}". ` +
      `Switch with: gh auth switch --user ${EXPECTED_LOGIN}`
  );
}

if (localName && localName !== EXPECTED_LOGIN) {
  problems.push(`Local user.name is "${localName}", not "${EXPECTED_LOGIN}". Commits would be attributed to it.`);
}

if (!localName || !localEmail) {
  const email = noreply(EXPECTED_LOGIN);
  if (!writing) {
    problems.push(
      `No local commit identity is set, and there is no global one to fall back on, so a commit here would ` +
        `either fail or be attributed to whatever git infers. Run: npm run setup`
    );
  } else if (!email) {
    problems.push(
      `Cannot resolve the noreply address for "${EXPECTED_LOGIN}" — the GitHub CLI is not authenticated. ` +
        `Run \`gh auth login\`, or set it by hand:\n` +
        `  git config --local user.name "${EXPECTED_LOGIN}"\n` +
        `  git config --local user.email "<id>+${EXPECTED_LOGIN}@users.noreply.github.com"`
    );
  } else {
    git(['config', '--local', 'user.name', EXPECTED_LOGIN]);
    git(['config', '--local', 'user.email', email]);
    console.log(`Pinned this repository's commit identity to ${EXPECTED_LOGIN} <${email}>.`);
  }
}

if (problems.length) {
  console.warn('\nGit identity needs attention:');
  for (const problem of problems) console.warn(`  - ${problem}`);
  console.warn('');
  // Deliberately not a failure: `prepare` runs on install and breaking that would be worse than
  // the warning. `npm run setup` is where this gets fixed.
  process.exit(0);
}

const name = git(['config', 'user.name'], { allowFailure: true });
const email = git(['config', 'user.email'], { allowFailure: true });
if (name && email) console.log(`Commit identity: ${name} <${email}>`);
