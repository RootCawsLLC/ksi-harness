import { NextResponse } from 'next/server';
import { runKsi, type RunRequest, type ArtifactKind } from '@/lib/ksi-runner';

// The run drives the real tool out-of-process: two fixture collections, state build, coverage
// projection and artifact emission. It needs the Node runtime and a generous budget.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

const KNOWN: ArtifactKind[] = ['sdr', 'ocr', 'scn', 'oscal-ar'];

export async function POST(request: Request) {
  let body: Partial<RunRequest>;
  try {
    body = (await request.json()) as Partial<RunRequest>;
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const artifacts = Array.isArray(body.artifacts)
    ? body.artifacts.filter((a): a is ArtifactKind => KNOWN.includes(a as ArtifactKind))
    : KNOWN;

  try {
    const result = await runKsi({ artifacts });
    return NextResponse.json(result);
  } catch (err) {
    console.error('[run] failed:', err);
    const message = err instanceof Error ? err.message : 'Run failed.';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
