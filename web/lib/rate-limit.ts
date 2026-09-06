/**
 * Per-caller rate limiting for `/api/run`, and the header parse it depends on.
 *
 * The concurrency cap in `ksi-runner.ts` bounds how much work is in flight. It does nothing to stop
 * one caller occupying every slot continuously, reconnecting the instant one frees — the service
 * stops falling over and stays trivially deniable to everyone else. That is what this closes.
 *
 * ## Why the header can be trusted here, and how it is read
 *
 * Identifying a caller means trusting `X-Forwarded-For`, and trusting it wrongly is a worse
 * vulnerability than the one being fixed: if a caller can choose the value, they can mint unlimited
 * identities and the limit becomes decoration.
 *
 * It is safe here because of a specific deployment fact rather than a general one. `infra-web`
 * deploys this as an **AWS App Runner** service, which is reachable only through AWS's own managed
 * load balancer. That is exactly one proxy in front of the app, and it *appends* the address it saw
 * to any `X-Forwarded-For` the client sent.
 *
 * So the entry that matters is the **rightmost**, not the leftmost:
 *
 *     client sends:      X-Forwarded-For: 1.2.3.4          (attacker-chosen)
 *     App Runner makes:  X-Forwarded-For: 1.2.3.4, 203.0.113.7
 *                                                   ^^^^^^^^^^ the address it actually saw
 *
 * Reading the leftmost entry — which is the more common mistake, because it is the convention when
 * you trust the whole chain — would take the attacker-chosen value and hand out a fresh bucket per
 * request. Reading the rightmost takes the one value in the header that a client cannot influence.
 *
 * **This is correct for exactly one trusted proxy.** Put a CDN in front of App Runner and the
 * rightmost entry becomes the CDN, every visitor collapses into one bucket, and the limit starts
 * refusing real users. That is a deployment change requiring a change here, which is why the
 * assumption is written down rather than implied.
 */

/** How the caller was identified, so the route can say when it could not be. */
export type CallerId = { id: string; source: 'forwarded' | 'unidentified' };

/**
 * The address App Runner saw, or an admission that it is unknown.
 *
 * Absent header means the app is not behind the proxy it was designed for — running locally, or
 * deployed somewhere this reasoning does not hold. Inventing an identifier then would create one
 * shared bucket that any caller could exhaust for everyone, so it says so instead and lets the
 * caller decide.
 */
export function callerFrom(headers: Headers): CallerId {
  const forwarded = headers.get('x-forwarded-for');
  if (!forwarded) return { id: 'unidentified', source: 'unidentified' };

  const hops = forwarded
    .split(',')
    .map((hop) => hop.trim())
    .filter(Boolean);

  const nearest = hops[hops.length - 1];
  return nearest ? { id: nearest, source: 'forwarded' } : { id: 'unidentified', source: 'unidentified' };
}

export interface RateLimitVerdict {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/**
 * A fixed-window counter, deliberately in memory and deliberately small.
 *
 * In memory because App Runner runs a small number of instances and the alternative — a shared
 * store — is a dependency, a failure mode and a cost for a demo that runs fixtures. The limit is
 * therefore per instance, which is stated on the route rather than implied.
 *
 * `maxTracked` is not decoration. A limiter that allocates an entry per distinct address is itself
 * a memory-exhaustion surface: an attacker with a large address pool would grow the map without
 * bound, and the mitigation would become the outage. Expired entries are pruned on each call and
 * the oldest are evicted once the cap is reached.
 */
export class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly windowMs: number;
  private readonly maxPerWindow: number;
  private readonly maxTracked: number;

  // Fields are declared and assigned rather than written as constructor parameter properties.
  // Those are TypeScript-only syntax that erasure cannot remove, so a module using them cannot be
  // executed by plain `node` — which is exactly how the behaviour below is tested, without a
  // bundler or a transpile step in the way.
  constructor(windowMs: number, maxPerWindow: number, maxTracked: number = 10_000) {
    this.windowMs = windowMs;
    this.maxPerWindow = maxPerWindow;
    this.maxTracked = maxTracked;
  }

  check(id: string, now: number = Date.now()): RateLimitVerdict {
    this.prune(now);

    const entry = this.hits.get(id);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(id, { count: 1, resetAt: now + this.windowMs });
      this.evictIfCrowded();
      return { allowed: true, remaining: this.maxPerWindow - 1, retryAfterSeconds: 0 };
    }

    if (entry.count >= this.maxPerWindow) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)),
      };
    }

    entry.count += 1;
    return { allowed: true, remaining: this.maxPerWindow - entry.count, retryAfterSeconds: 0 };
  }

  /** Visible for tests and for anything that wants to report load. */
  size(): number {
    return this.hits.size;
  }

  private prune(now: number): void {
    for (const [id, entry] of this.hits) {
      if (entry.resetAt <= now) this.hits.delete(id);
    }
  }

  /**
   * Evicts the entries closest to expiry once the map is full.
   *
   * Dropping an entry lets that caller start a fresh window early, which is the right way to fail:
   * the alternative is unbounded growth, and a limiter that takes the box down has not helped.
   */
  private evictIfCrowded(): void {
    if (this.hits.size <= this.maxTracked) return;
    const byExpiry = [...this.hits.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt);
    const excess = this.hits.size - this.maxTracked;
    for (let i = 0; i < excess; i += 1) this.hits.delete(byExpiry[i][0]);
  }
}

/**
 * The shared limiter for `/api/run`.
 *
 * Three runs per five minutes. Each run occupies a slot for up to 290 seconds and there are two
 * slots, so this is roughly "one caller may keep one slot busy" — enough to use the demo properly,
 * not enough to hold the service.
 */
export const runLimiter = new RateLimiter(
  Number(process.env.KSI_RATE_WINDOW_MS ?? 300_000),
  Number(process.env.KSI_RATE_MAX ?? 3)
);
