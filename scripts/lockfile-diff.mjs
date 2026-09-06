#!/usr/bin/env node
/**
 * What changed between two lockfiles, restricted to the things a reviewer cannot see.
 *
 * `lockfile-classes.mjs` closed the one defect that had actually recurred. This is the rest of
 * #34: a dependency bump arrives as hundreds of lines of generated JSON, and the properties worth
 * knowing about are invisible in that diff because they look exactly like the rest of it.
 *
 * Three questions, chosen because each has a bad answer that a version bump can hide:
 *
 *   1. Did a package start being fetched from somewhere else?
 *   2. Did a package gain code that runs at install time?
 *   3. Did a package's contents change without its version changing?
 *
 * The third is the strongest signal here. A version is a claim; an integrity hash is a measurement
 * of the artifact. The same version resolving to different bytes means the published artifact was
 * replaced, which is the shape of a supply-chain compromise rather than an upgrade.
 *
 * ## What this is not
 *
 * It is not a supply-chain control. It cannot tell you whether a tarball matches the source that
 * claims to produce it — that is what pinning, provenance attestation and the timestamped locker
 * are for. All this does is ensure the reviewer is told what actually changed, rather than being
 * handed 553 lines and asked to spot it.
 *
 * ## The constraint that killed the previous idea
 *
 * #34 first proposed regenerating the lockfile and diffing it. That was ruled out by testing it:
 * `npm install --package-lock-only` output depends on the npm running it — npm 11.9.0 strips the
 * `libc` fields the committed `web` lockfile carries — so the check reports drift whenever the
 * checking npm differs from the generating one. Anything comparing *generated* output has that
 * problem.
 *
 * So this compares two committed artifacts to each other and never regenerates. Every field it
 * reads was written by whichever npm produced that file, and is compared only against the other
 * file's version of the same field.
 */
import { readFileSync } from 'node:fs';

/**
 * Registry hosts a package may legitimately come from.
 *
 * Deliberately a list rather than "whatever the previous lockfile used". A host change is worth
 * reporting, but a host that was never acceptable is worth reporting on the first run too — and a
 * baseline-relative rule cannot say anything about the very first lockfile it sees.
 */
export const ALLOWED_HOSTS = ['registry.npmjs.org'];

const packagesOf = (lock) => lock?.packages ?? {};

/** The registry host a package was fetched from, or null for a link/workspace entry. */
export function hostOf(entry) {
  if (!entry?.resolved) return null;

  // A workspace or file link is not fetched from anywhere, and npm does not write it as a URL:
  // `web/package-lock.json` records the parent as `{ resolved: "..", link: true }`, a bare relative
  // path. Recognised by the flag rather than by `new URL` throwing, so the reason it is skipped is
  // the reason it should be skipped.
  if (entry.link) return null;

  try {
    // `file:..` *is* a valid URL and parses with an empty host rather than throwing, so both
    // outcomes normalise to null. "Not fetched over the network" wants one representation, not
    // two — an empty string is falsy and would work by accident, which is a poor thing for a
    // security check to rest on.
    return new URL(entry.resolved).host || null;
  } catch {
    // A non-link entry whose `resolved` is not a URL is not something npm produces. It is left
    // unreported rather than guessed at: recognition here is conservative, as it is in
    // `NO_ANCHOR_YET` and `TRANSIENT_PUSH`, and a finding invented from an unfamiliar shape would
    // be the kind of false positive that gets a check switched off.
    return null;
  }
}

/**
 * Compares two lockfiles.
 *
 * `before` may be null — a lockfile that did not exist yet. The host allowlist still applies,
 * because it is a property of the file rather than of the change; the two diff-based checks
 * report nothing, because there is nothing to compare against and inventing a baseline would
 * manufacture findings.
 */
export function diffLockfiles(before, after, where = 'package-lock.json') {
  const findings = [];
  const olds = packagesOf(before);
  const news = packagesOf(after);

  for (const [path, entry] of Object.entries(news)) {
    if (!path) continue; // the root project, which resolves to nothing
    const name = path.replace(/^node_modules\//, '');
    const host = hostOf(entry);
    const prior = olds[path];

    // 1. A host that is not allowed at all. Checked against the list rather than against the
    // previous value, so a substituted registry is caught even in a lockfile with no baseline.
    if (host && !ALLOWED_HOSTS.includes(host)) {
      findings.push({
        kind: 'host-not-allowed',
        package: name,
        detail: `${name} resolves to ${host}, which is not an allowed registry`,
      });
    } else if (prior) {
      const priorHost = hostOf(prior);
      if (host && priorHost && host !== priorHost) {
        findings.push({
          kind: 'host-changed',
          package: name,
          detail: `${name} moved from ${priorHost} to ${host}`,
        });
      }
    }

    // 2. Code that runs at install time, newly. Reporting every package that has an install script
    // would be a list nobody reads; the change is the signal.
    if (entry.hasInstallScript && !prior?.hasInstallScript) {
      findings.push({
        kind: 'install-script-added',
        package: name,
        detail: prior
          ? `${name} gained an install script it did not have before`
          : `${name} is new and runs a script at install time`,
      });
    }

    // 3. Same version, different bytes. A version is a claim; integrity is a measurement of the
    // artifact, so this is the one finding here that cannot be explained by an upgrade.
    if (prior && entry.version && prior.version === entry.version && entry.integrity && prior.integrity && entry.integrity !== prior.integrity) {
      findings.push({
        kind: 'integrity-changed-without-version',
        package: name,
        detail:
          `${name}@${entry.version} has a different integrity hash than before, with no version change. ` +
          'The published artifact was replaced.',
      });
    }
  }

  return findings.map((f) => ({ ...f, where }));
}

const read = (path) => {
  if (!path || path === '-') return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`${path}: ${err.message}`);
  }
};

if (process.argv[1]?.endsWith('lockfile-diff.mjs')) {
  const [beforePath, afterPath, label] = process.argv.slice(2);
  if (!afterPath) {
    console.error('Usage: lockfile-diff.mjs <before.json|-> <after.json> [label]');
    process.exit(2);
  }

  const findings = diffLockfiles(read(beforePath), read(afterPath), label ?? afterPath);

  if (findings.length === 0) {
    console.log(`  ok    ${label ?? afterPath}: no registry, install-script or integrity changes`);
    process.exit(0);
  }

  console.error(`  FAIL  ${label ?? afterPath}:`);
  for (const f of findings) console.error(`          [${f.kind}] ${f.detail}`);
  console.error(
    '\n  These are the lockfile changes a reviewer cannot see in the diff. None of them is proof of\n' +
      '  compromise, and each has innocent explanations — a registry migration, a package adding a\n' +
      '  postinstall, a republished artifact. The point is that somebody decides, rather than the\n' +
      '  change arriving inside several hundred lines of generated JSON.\n'
  );
  process.exit(1);
}
