import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { runKsi, RunCapacityExceeded, RunTimedOut, type RunRequest, type ArtifactKind } from '@/lib/ksi-runner';

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
    // Capacity is not failure. The request was well formed and the estate is fine; there was
    // simply no slot. 429 with Retry-After says that, where a 500 would report a broken service
    // and invite exactly the retry storm the limit exists to avoid.
    if (err instanceof RunCapacityExceeded) {
      return NextResponse.json(
        { error: err.message },
        { status: 429, headers: { 'Retry-After': '60' } }
      );
    }

    // The budget was exceeded. Composed here from no external input, so it is safe to return and
    // is genuinely useful: a caller who waited five minutes should be told why rather than handed
    // an opaque failure.
    if (err instanceof RunTimedOut) {
      return NextResponse.json({ error: err.message }, { status: 504 });
    }

    // Everything else carries whatever the child printed. The runner puts up to 400 characters of
    // its stderr into the rejection message, and a spawn failure carries the interpreter path — so
    // returning `err.message` handed absolute filesystem paths, module resolution detail and stack
    // structure to any caller who could make a run fail.
    //
    // Nothing here leaked a credential: the child runs the offline fixture path and never prints
    // the environment. What it leaked was internal shape, from a public demo of a tool whose
    // argument is that evidence should say exactly what it establishes and no more.
    //
    // The detail is kept, not discarded. It goes to the log with an id the response also carries,
    // so an operator can find the one run a caller is asking about without the response having
    // described the machine it ran on.
    const id = randomUUID().slice(0, 8);
    console.error(`[run] failed id=${id}:`, err);
    return NextResponse.json({ error: 'Run failed.', id }, { status: 500 });
  }
}
