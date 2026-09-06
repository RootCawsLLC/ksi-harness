import assert from 'node:assert/strict';
import { test } from 'node:test';

import { callerFrom, RateLimiter } from '../web/lib/rate-limit.ts';

/**
 * Per-caller limiting for `/api/run`, and the header parse the whole thing rests on.
 *
 * The concurrency cap bounds how much work is in flight; it does nothing to stop one caller
 * occupying every slot continuously. This closes that — but only if the caller is identified from
 * a value the caller cannot choose, which is the property these tests exist to pin.
 *
 * Imported straight from the TypeScript source. Node erases the types, so the code under test is
 * the code that ships rather than a compiled copy or a reimplementation.
 */

const headers = (value) => new Headers(value == null ? {} : { 'x-forwarded-for': value });

/* ----------------------------------------------------------- identifying the caller */

/**
 * The test that decides whether this is a security control or a decoration.
 *
 * `infra-web` deploys this as an AWS App Runner service, reachable only through AWS's managed load
 * balancer — exactly one proxy, which *appends* the address it saw to whatever the client sent. So
 * the rightmost entry is the one a client cannot influence.
 *
 * Taking the leftmost is the more natural mistake, because it is the convention when the whole
 * chain is trusted. It would take the attacker-chosen value and hand out a fresh bucket per
 * request, leaving a limiter that cannot limit anything.
 */
test('a caller cannot choose their own identity by sending X-Forwarded-For', () => {
  const spoofed = callerFrom(headers('1.2.3.4, 203.0.113.7'));
  assert.equal(spoofed.id, '203.0.113.7', 'the rightmost hop is the address the proxy saw');
  assert.notEqual(spoofed.id, '1.2.3.4', 'never the value the client supplied');

  const deeper = callerFrom(headers('evil, also-evil, 198.51.100.9'));
  assert.equal(deeper.id, '198.51.100.9');
});

test('a single hop is read as the caller', () => {
  assert.deepEqual(callerFrom(headers('203.0.113.7')), { id: '203.0.113.7', source: 'forwarded' });
});

/**
 * No header means the app is not behind the proxy it was designed for. Inventing an identifier
 * would create one shared bucket that any caller could exhaust for everybody, so it admits it
 * instead and the route decides what to do.
 */
test('an absent or empty header is an admission, not an invented identity', () => {
  assert.equal(callerFrom(headers(null)).source, 'unidentified');
  assert.equal(callerFrom(headers(' , ')).source, 'unidentified');
  assert.equal(callerFrom(headers('')).source, 'unidentified');
});

/* --------------------------------------------------------------------- the limit */

test('a caller gets its allowance and is then refused', () => {
  const limiter = new RateLimiter(1000, 3);
  const now = 1000;
  assert.deepEqual([1, 2, 3].map(() => limiter.check('a', now).allowed), [true, true, true]);

  const refused = limiter.check('a', now);
  assert.equal(refused.allowed, false);
  assert.equal(refused.remaining, 0);
  assert.ok(refused.retryAfterSeconds >= 1, 'and says how long to wait');
});

test('callers are limited independently', () => {
  const limiter = new RateLimiter(1000, 1);
  const now = 1000;
  assert.equal(limiter.check('a', now).allowed, true);
  assert.equal(limiter.check('a', now).allowed, false);
  assert.equal(limiter.check('b', now).allowed, true, 'one caller cannot exhaust another');
});

test('the window reopens', () => {
  const limiter = new RateLimiter(1000, 1);
  assert.equal(limiter.check('a', 1000).allowed, true);
  assert.equal(limiter.check('a', 1500).allowed, false);
  assert.equal(limiter.check('a', 2001).allowed, true);
});

/**
 * A limiter that allocates an entry per distinct address is itself a memory-exhaustion surface: an
 * attacker with a large address pool grows the map without bound and the mitigation becomes the
 * outage. Evicting is the right way to fail — a caller gets a fresh window early, which is a far
 * smaller problem than the process dying.
 */
test('the limiter is not itself a memory exhaustion surface', () => {
  const limiter = new RateLimiter(60_000, 5, 100);
  for (let i = 0; i < 5000; i += 1) limiter.check(`ip-${i}`, 1000);
  assert.ok(limiter.size() <= 100, `tracked ${limiter.size()} entries against a cap of 100`);
});

test('expired entries are pruned rather than accumulating', () => {
  const limiter = new RateLimiter(1000, 5, 10_000);
  for (let i = 0; i < 50; i += 1) limiter.check(`ip-${i}`, 1000);
  assert.equal(limiter.size(), 50);
  limiter.check('someone-else', 3000);
  assert.equal(limiter.size(), 1, 'the window passed, so the old entries are gone');
});
