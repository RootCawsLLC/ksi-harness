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

export async function runKsi(req: RunRequest): Promise<RunResult> {
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
      reject(new Error('Run timed out.'));
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
