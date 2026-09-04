/**
 * Standalone ksi-harness driver.
 *
 * Runs in its own plain Node ESM process — the same way the CLI runs the tool — so ksi-harness
 * is never touched by the web bundler and its filesystem behaviour is exactly as shipped. The
 * API route spawns this, writes a RunRequest as JSON on stdin, and reads a RunResult as JSON on
 * stdout.
 *
 * This does NOT reimplement anything. It imports the real shipped library modules
 * (collectors/run-all, evidence/state, report/coverage, report/diff, emit/index, catalog, routes)
 * and drives the exact same path the offline `npm run demo` drives — collect against bundled
 * fixtures, fold the locker into control state, project the coverage report, and emit the 20x /
 * OSCAL artifacts. The ruleset, the routing map and the check registry are resolved by those
 * modules from their own module-relative paths inside the tool, never restated here.
 *
 * Target policy: this only ever runs the offline fixture path. It never reads real credentials,
 * never contacts a cloud account, and never collects real evidence. Every bundle it produces is
 * stamped fixture-derived by the tool itself.
 */
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse } from 'yaml';

// The real shipped tool, imported natively (never bundled by Next).
import { runAll } from 'ksi-harness/src/collectors/run-all.mjs';
import { buildState } from 'ksi-harness/src/evidence/state.mjs';
import { coverageJson } from 'ksi-harness/src/report/coverage.mjs';
import { diffLocker } from 'ksi-harness/src/report/diff.mjs';
import { emitterFor } from 'ksi-harness/src/emit/index.mjs';
import { validateRoutes } from 'ksi-harness/src/routes/routes.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function fixturesDir() {
  return process.env.KSI_FIXTURES_DIR ?? join(HERE, '..', 'ksi-fixtures');
}
function profilePath() {
  return process.env.KSI_PROFILE ?? join(HERE, '..', 'ksi-examples', 'northwind.profile.yaml');
}
function changePath() {
  return process.env.KSI_CHANGE ?? join(HERE, '..', 'ksi-examples', 'change.scn.yaml');
}

// The overview URI is a declared property of the certification package, not something observable
// in an account. The offline demo uses this placeholder; the emitted SDR/OCR/SCN point their
// certificationPackageOverviewUri at it.
const OVERVIEW_URI = 'https://northwind.example/fedramp/overview.json';

// The four artifacts the offline demo emits. `overview` is also available (profile-only) but the
// demo does not emit it, so it is off by default.
const ALL_ARTIFACTS = ['sdr', 'ocr', 'scn', 'oscal-ar'];

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const raw = await readStdin();
  const req = raw.trim() ? JSON.parse(raw) : {};
  const klass = 'c'; // Class C is the practical ceiling today; the demo profile declares it.
  const started = Date.now();
  const log = [];

  const requested = Array.isArray(req.artifacts) && req.artifacts.length
    ? ALL_ARTIFACTS.filter((k) => req.artifacts.includes(k))
    : ALL_ARTIFACTS;

  const profile = parse(readFileSync(profilePath(), 'utf8'));
  const change = parse(readFileSync(changePath(), 'utf8'));
  const fixture = fixturesDir();

  const evidenceDir = mkdtempSync(join(tmpdir(), 'ksi-web-evidence-'));

  try {
    // Two collections, exactly as the demo does: one collection is a collection, two are a
    // cadence. The second run chains onto the first rather than overwriting it, which is what
    // lets the report test a schedule claim and what the diff compares.
    const first = await runAll({ profile, fixture, outDir: evidenceDir, log: (l) => log.push(l) });
    const second = await runAll({ profile, fixture, outDir: evidenceDir, log: (l) => log.push(l) });

    const collectFailures = [...first.failures, ...second.failures];

    // Fold the catalog, routing map and evidence locker into control state — the single input
    // every emitter reads.
    const routeValidation = validateRoutes({ klass });
    const state = buildState({ evidenceDir, klass, profile });
    const coverage = coverageJson(state);

    // What changed between the two collections, item-level.
    const diff = diffLocker(evidenceDir, { latest: true });

    // Emit each requested artifact from the same state. Emitters validate against the vendored
    // FedRAMP schema on the write path where one exists; a validation failure throws and is
    // surfaced here rather than swallowed.
    const artifacts = [];
    for (const kind of requested) {
      const emitter = emitterFor(kind);
      try {
        const document = emitter.emit(state, {
          overviewUri: OVERVIEW_URI,
          baseUri: null,
          change: kind === 'scn' ? change : null,
          profile,
        });
        artifacts.push({
          kind,
          label: emitter.label,
          validated: Boolean(emitter.validated),
          bytes: Buffer.byteLength(JSON.stringify(document)),
          document,
        });
      } catch (err) {
        artifacts.push({
          kind,
          label: emitter.label,
          validated: Boolean(emitter.validated),
          error: err?.message ?? String(err),
          document: null,
        });
      }
    }

    process.stdout.write(
      JSON.stringify({
        ruleset: state.ruleset,
        klass,
        routesValid: routeValidation.ok,
        routeErrors: routeValidation.errors,
        counts: coverage.counts,
        evidence: coverage.evidence,
        themes: state.themes,
        indicators: coverage.indicators,
        findings: coverage.findings,
        diff,
        artifacts,
        collectFailures,
        collectLog: log,
        durationMs: Date.now() - started,
      }),
    );
  } finally {
    try {
      rmSync(evidenceDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

main().catch((err) => {
  process.stdout.write(JSON.stringify({ error: err?.stack ?? err?.message ?? String(err) }));
  process.exit(1);
});
