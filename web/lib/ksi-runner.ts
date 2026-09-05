/**
 * Server-only bridge to the real ksi-harness tool.
 *
 * It does NOT reimplement or import the tool into the Next bundle. It spawns a plain Node ESM
 * process (scripts/run-ksi.mjs) that imports ksi-harness natively and runs the exact shipped
 * path — collect against bundled fixtures, build control state, project the coverage report, and
 * emit the 20x / OSCAL artifacts — then relays that process's JSON result. Running out-of-process
 * keeps the tool's filesystem behaviour identical to the CLI and avoids the ESM/CJS interop that
 * importing an ESM tool into a `next start` bundle would force.
 */
import 'server-only';
import { spawn } from 'node:child_process';
import { join } from 'node:path';

export type ArtifactKind = 'sdr' | 'ocr' | 'scn' | 'oscal-ar';

export interface RunRequest {
  artifacts: ArtifactKind[];
}

export interface RunResult {
  ruleset: {
    version: string;
    last_updated: string;
    title: string;
    sha256: string;
    source_url: string;
    vendored_at: string;
  };
  klass: string;
  routesValid: boolean;
  routeErrors: string[];
  counts: unknown;
  evidence: unknown;
  themes: Array<{ short: string; name: string }>;
  indicators: unknown[];
  findings: unknown[];
  diff: unknown;
  artifacts: unknown[];
  collectFailures: unknown[];
  collectLog: string[];
  durationMs: number;
}

function scriptPath(): string {
  return process.env.KSI_SCRIPT ?? join(process.cwd(), 'scripts', 'run-ksi.mjs');
}

const HARD_TIMEOUT_MS = 290_000;

/**
 * How many runs may be in flight at once, and why there is a limit at all.
 *
 * Each run forks a Node process that performs two fixture collections, builds control state,
 * projects the coverage report and emits the 20x and OSCAL artifacts, holding a slot for up to
 * `HARD_TIMEOUT_MS`. Nothing bounded how many of those an anonymous caller could start at once, so
 * the cost of a request was high, the cost of making one was nothing, and the endpoint is meant to
 * be publicly reachable.
 *
 * The cap lives here rather than in the route because the resource being protected is the child
 * process, not the HTTP handler. A limit in the route protects the route; a second caller of
 * `runKsi` would walk straight past it.
 *
 * Two is a working default rather than a tuned one: enough that a second visitor is not made to
 * wait behind the first, few enough that the box is not the thing under test.
 */
const MAX_CONCURRENT_RUNS = Number(process.env.KSI_MAX_CONCURRENT_RUNS ?? 2);

/**
 * Refused for capacity, which is a different answer from a run that failed.
 *
 * The caller should retry; nothing is wrong with the request or the estate. Kept as its own type
 * so the route can map it to 429 rather than inferring from message text.
 */
export class RunCapacityExceeded extends Error {}

/**
 * The run exceeded its budget, which is safe to tell the caller.
 *
 * Typed rather than matched on message text so the route can answer it precisely. It is one of
 * exactly two outcomes whose message is composed here, from no external input, and is therefore
 * returnable as-is — every other failure carries whatever the child process happened to print.
 */
export class RunTimedOut extends Error {}

let active = 0;

/** Current in-flight run count. Exported for tests and for anything that wants to report load. */
export function activeRuns(): number {
  return active;
}

export async function runKsi(req: RunRequest): Promise<RunResult> {
  // Check and increment with no `await` between them. Node runs this on one thread, so the pair is
  // atomic in the only sense that matters here — a second request cannot observe the count between
  // the test and the increment. Written as one block deliberately: inserting an await above the
  // increment would reintroduce the race this exists to prevent.
  if (active >= MAX_CONCURRENT_RUNS) {
    throw new RunCapacityExceeded(
      `${MAX_CONCURRENT_RUNS} runs are already in progress. Each takes up to ${Math.round(
        HARD_TIMEOUT_MS / 1000
      )}s; try again shortly.`
    );
  }
  active += 1;

  try {
    return await spawnRun(req);
  } finally {
    // In `finally` so the slot is returned on every path — resolution, rejection, and the timeout
    // that kills the child. A decrement on the success path alone would leak a slot per failure
    // until the endpoint refused everything, which is a worse outage than the one being prevented.
    active -= 1;
  }
}

function spawnRun(req: RunRequest): Promise<RunResult> {
  return new Promise<RunResult>((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath()], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let out = '';
    let err = '';
    const killer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new RunTimedOut('Run timed out.'));
    }, HARD_TIMEOUT_MS);

    child.stdout.on('data', (c) => (out += c.toString()));
    child.stderr.on('data', (c) => (err += c.toString()));
    child.on('error', (e) => {
      clearTimeout(killer);
      reject(e);
    });
    child.on('close', () => {
      clearTimeout(killer);
      let parsed: (RunResult & { error?: string }) | null = null;
      try {
        parsed = JSON.parse(out);
      } catch {
        reject(new Error(`Run process produced no valid result.${err ? ` (${err.slice(0, 400)})` : ''}`));
        return;
      }
      if (parsed && parsed.error) {
        reject(new Error(parsed.error.split('\n')[0]));
        return;
      }
      resolve(parsed as RunResult);
    });

    child.stdin.write(JSON.stringify(req));
    child.stdin.end();
  });
}
