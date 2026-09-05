#!/usr/bin/env node
/**
 * Whether each lockfile agrees with its manifest about what kind of dependency each package is.
 *
 * The defect this exists for, twice observed: dependabot's regeneration writes
 * `"@aws-sdk/client-sts"` into the root lockfile's `dependencies` while `package.json` lists it
 * only under `optionalDependencies` — where the lockfile *also* still lists it. Same package, two
 * classes, and a manifest that agrees with neither. It arrived on #31, was removed by #33, and
 * came back identically on #35 at the next version, so it is what happens to this project on
 * every aws-sdk bump rather than a slip that got through once.
 *
 * ## Why this rather than regenerating the lockfile and diffing it
 *
 * That was the cheaper idea, it is what #34 proposed, and testing it is what ruled it out.
 * `npm install --package-lock-only` does catch the defect — but its output depends on the npm
 * version running it. npm 11.9.0 *strips* the `libc` fields that the committed `web` lockfile
 * carries on `@next/swc-linux-*`, so a regenerate-and-diff check reports drift whenever the npm
 * doing the checking differs from the npm that generated the lockfile — which is exactly what
 * happens when dependabot, CI and a contributor's laptop are three different npm versions.
 *
 * As an advisory check that would be noise. As a required check it would be worse than noise: a
 * gate that goes red for reasons unconnected to the change is a gate people learn to bypass, and
 * this repository already has one control whose ordinary failure mode was disabling it (#30).
 *
 * So this compares the thing that is actually wrong — the class each package is declared under —
 * and nothing else. It invokes no package manager, reads no network, and gives the same answer on
 * every npm.
 *
 * ## What it deliberately does not check
 *
 * Versions, integrity hashes, resolved hosts, install scripts, or the set of transitive packages.
 * Those are worth checking and are a different job; a structural lockfile differ covering them is
 * still the better long-term answer and is still open on #34. This closes the one case that has
 * actually recurred.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The three classes a direct dependency can be declared under, in both files. */
const CLASSES = ['dependencies', 'devDependencies', 'optionalDependencies'];

/** `packages[""]` is the lockfile's record of the root project — its view of the manifest. */
function rootEntry(lock, where) {
  const root = lock.packages?.[''];
  if (!root) throw new Error(`${where}: lockfile has no root package entry; expected lockfileVersion 2 or 3.`);
  return root;
}

export function compare(manifest, lock, where) {
  const problems = [];
  const root = rootEntry(lock, where);

  // Which class does each side put a package in? A package may legitimately appear in only one.
  const classOf = (src) => {
    const seen = new Map();
    for (const cls of CLASSES) {
      for (const name of Object.keys(src[cls] ?? {})) {
        // Recorded as a list rather than overwritten: a package in two classes at once is the
        // defect itself, and collapsing it to the last one seen would hide it.
        seen.set(name, [...(seen.get(name) ?? []), cls]);
      }
    }
    return seen;
  };

  const inManifest = classOf(manifest);
  const inLock = classOf(root);

  for (const [name, classes] of inLock) {
    if (classes.length > 1) {
      problems.push(`${name} is in the lockfile under ${classes.join(' and ')} at once`);
    }
  }

  for (const [name, lockClasses] of inLock) {
    const manifestClasses = inManifest.get(name);
    if (!manifestClasses) {
      problems.push(`${name} is in the lockfile under ${lockClasses.join(', ')} but not in package.json at all`);
      continue;
    }
    const extra = lockClasses.filter((c) => !manifestClasses.includes(c));
    if (extra.length) {
      problems.push(
        `${name} is under ${extra.join(', ')} in the lockfile but package.json declares it only under ` +
          manifestClasses.join(', ')
      );
    }
  }

  for (const [name, manifestClasses] of inManifest) {
    if (!inLock.has(name)) {
      problems.push(`${name} is in package.json under ${manifestClasses.join(', ')} but missing from the lockfile`);
    }
  }

  return problems;
}

export function checkDir(dir) {
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8'));
  return compare(manifest, lock, dir);
}

if (process.argv[1]?.endsWith('lockfile-classes.mjs')) {
  const dirs = process.argv.slice(2);
  if (dirs.length === 0) dirs.push('.');

  let failed = false;
  for (const dir of dirs) {
    let problems;
    try {
      problems = checkDir(dir);
    } catch (err) {
      console.error(`  ERROR ${dir}: ${err.message}`);
      failed = true;
      continue;
    }
    if (problems.length === 0) {
      console.log(`  ok    ${dir}: lockfile and package.json agree on every dependency class`);
      continue;
    }
    failed = true;
    console.error(`  FAIL  ${dir}:`);
    for (const p of problems) console.error(`          ${p}`);
  }

  if (failed) {
    console.error(
      '\n  A lockfile that classifies a package differently from the manifest is one npm rewrites on\n' +
        '  every install, which leaves the tree permanently dirty and stops a real change being\n' +
        "  distinguishable from noise. Run 'npm install' in the directory named and commit the result.\n"
    );
    process.exit(1);
  }
  process.exit(0);
}
