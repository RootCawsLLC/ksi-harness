import { randomBytes } from 'node:crypto';

import {
  boolean,
  find,
  integer,
  nullValue,
  octetString,
  oid,
  parse,
  readGeneralizedTime,
  readInteger,
  sequence,
  TAG,
  walk,
} from './der.mjs';

/**
 * RFC 3161 trusted timestamping for the evidence locker.
 *
 * The gap this closes is the fourth property of defensible evidence, and it was the weakest
 * one here by some distance. `buildBundle` requires `collectedAt` and its own comment says
 * the value must come from a trusted source rather than the executing runner's clock — and
 * then nothing verified that, because nothing could. In practice CI passed `new Date()`. A
 * bundle therefore asserted its own age, which is exactly the shape of claim this repository
 * refuses everywhere else.
 *
 * The chain already establishes *order*: bundle N+1 carries the hash of bundle N, so no
 * bundle can be inserted into the middle of a check's history after the fact. What it cannot
 * establish is *when*, because every timestamp in it comes from the same untrusted clock. A
 * Time Stamping Authority signs a hash together with its own time, which turns "this
 * evidence claims to be from Tuesday" into "a third party attests this data existed by
 * Tuesday".
 *
 * The manifest root is what gets stamped, not each bundle. One network call per collection
 * rather than one per check, and it loses nothing: the manifest names every bundle hash and
 * every chain head, so a token over the root attests that the entire locker in that state
 * existed by that time. Consecutive runs then *bracket* each bundle — collected after the
 * previous run's attested time and before this one's — which is a tighter and more honest
 * claim than a self-asserted instant.
 *
 * What this module does not do is verify the TSA's signature. That requires the authority's
 * certificate chain and full CMS verification, which is a job for `openssl ts -verify` or an
 * equivalent, and pretending otherwise would be the same overstatement the content hash made
 * before the chain existed. What it does do is check that the token the authority returned is
 * a token *for the data that was sent*, and report the attested time — so a TSA returning a
 * token over something else, or a failure status, is caught rather than filed.
 */

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

/** PKIStatus values that carry a usable token. Everything else is a refusal. */
const GRANTED = new Set([0n, 1n]);

const STATUS_TEXT = {
  0: 'granted',
  1: 'granted with modifications',
  2: 'rejected',
  3: 'waiting',
  4: 'revocation warning',
  5: 'revocation notification',
};

/**
 * Builds a DER TimeStampReq over a SHA-256 digest.
 *
 * `certReq` asks the authority to include its certificate in the token. It costs a few
 * hundred bytes and is what makes the stored token independently verifiable later, which is
 * the entire point of keeping it.
 */
export function buildRequest(digestHex, { nonce = randomBytes(8), certReq = true } = {}) {
  const digest = Buffer.from(digestHex, 'hex');
  if (digest.length !== 32) throw new Error(`A SHA-256 digest is 32 bytes; got ${digest.length}.`);

  return sequence(
    integer(1),
    sequence(sequence(oid(OID_SHA256), nullValue()), octetString(digest)),
    integer(nonce),
    boolean(certReq)
  );
}

/**
 * DER INTEGER content as hex, with the leading zero a positive integer may carry removed.
 *
 * `integer()` prepends 0x00 when the high bit is set, so the same nonce can come back one
 * byte longer than it went out and compare unequal while being identical. Normalising both
 * sides is what makes the comparison about the value rather than about its encoding.
 */
function normaliseNonce(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i += 1;
  return buf.subarray(i).toString('hex');
}

/**
 * Locates the TSTInfo and the three fields read from it.
 *
 * By shape rather than by position, for the same reason the caller searches every nested
 * OCTET STRING: authorities differ in how much optional material they include. TSTInfo is the
 * constructed node carrying a GeneralizedTime as a *direct* child and a 32-byte OCTET STRING
 * somewhere beneath it — the message imprint sits one level down inside MessageImprint.
 *
 * The nonce is found by its position relative to genTime rather than by index, which is what
 * makes it robust: TSTInfo holds three INTEGERs (version, serialNumber, nonce), and the first
 * two both precede genTime. `accuracy` is a SEQUENCE, so its inner integers are not siblings,
 * and `ordering` is a BOOLEAN. So the first INTEGER *after* the GeneralizedTime is the nonce,
 * whether or not the optional fields between them are present.
 */
function findTstInfo(root) {
  for (const node of walk(root)) {
    if (!node.children.length) continue;

    const timeIndex = node.children.findIndex((c) => c.tag === TAG.GENERALIZED_TIME);
    if (timeIndex === -1) continue;

    const imprint = find(node, (n) => n.tag === TAG.OCTET_STRING && n.value.length === 32);
    if (!imprint) continue;

    const nonce = node.children.slice(timeIndex + 1).find((c) => c.tag === TAG.INTEGER) ?? null;
    return { node, time: node.children[timeIndex], imprint, nonce };
  }
  return null;
}

/**
 * Reads a TimeStampResp far enough to know whether it is usable and what it attests.
 *
 * Navigation is by shape rather than by strict position. The token is a CMS SignedData whose
 * encapsulated content is a DER TSTInfo, and authorities differ in how much optional material
 * they include around it, so locating TSTInfo by looking for the structure that contains both
 * a GeneralizedTime and a 32-byte OCTET STRING is more robust than counting fields — and it
 * fails loudly rather than reading the wrong element.
 */
export function parseResponse(der, { expectDigestHex = null, expectNonce = null } = {}) {
  const root = parse(der);
  const statusInfo = root.children[0];
  if (!statusInfo) throw new Error('RFC 3161: response has no PKIStatusInfo.');

  const status = readInteger(statusInfo.children[0]);
  const granted = GRANTED.has(status);
  const statusText = STATUS_TEXT[Number(status)] ?? `unknown status ${status}`;

  if (!granted) {
    const freeText = find(statusInfo, (n) => n.tag === 0x0c || n.tag === 0x13);
    return {
      granted: false,
      status: Number(status),
      statusText,
      detail: freeText ? freeText.value.toString('utf8') : null,
      genTime: null,
      digestHex: null,
    };
  }

  const token = root.children[1];
  if (!token) throw new Error('RFC 3161: status is granted but the response carries no token.');

  // The TSTInfo lives inside the CMS eContent OCTET STRING. Re-parse every OCTET STRING that
  // is itself well-formed DER, then take the one that looks like a TSTInfo.
  const candidates = [];
  for (const node of walk(token)) {
    if (node.tag !== TAG.OCTET_STRING) continue;
    try {
      candidates.push(parse(node.value));
    } catch {
      // Not nested DER — an ordinary octet string, which is the common case.
    }
  }
  candidates.push(token);

  let tstInfo = null;
  for (const candidate of candidates) {
    tstInfo = findTstInfo(candidate);
    if (tstInfo) break;
  }
  if (!tstInfo) throw new Error('RFC 3161: no TSTInfo carrying a generalized time and a SHA-256 imprint was found.');

  const genTime = readGeneralizedTime(tstInfo.time);
  const digestHex = tstInfo.imprint.value.toString('hex');
  const nonceHex = tstInfo.nonce ? normaliseNonce(tstInfo.nonce.value) : null;

  // The check that makes storing the token worth anything: a token is only evidence about the
  // data whose digest it carries. An authority returning a well-formed token over something
  // else would otherwise be filed as proof of the wrong thing.
  if (expectDigestHex && digestHex !== expectDigestHex.toLowerCase()) {
    // Printed in full rather than truncated. Two different digests routinely share a prefix,
    // and an error that renders them identically is worse than no error at all.
    throw new Error(
      `RFC 3161: this token attests to different data and is not evidence about this locker.\n` +
        `  token covers: ${digestHex}\n` +
        `  expected:     ${expectDigestHex.toLowerCase()}`
    );
  }

  // What the digest check cannot catch: a *previously issued genuine* token over this same
  // root. Collections repeat over a locker that has not changed, so the same root is stamped
  // again and again — which is precisely the condition a replay needs. The nonce is what ties
  // a response to the request that asked for it, so an unchecked nonce means the freshness of
  // every attestation rests on trusting the transport.
  if (expectNonce) {
    const sent = normaliseNonce(expectNonce);
    if (!nonceHex) {
      // Silence is not agreement. The nonce is OPTIONAL in TSTInfo, so an authority may omit
      // it — but having asked, a response that does not answer is not one this can treat as
      // fresh. Reported rather than shrugged at, because a token accepted here is filed as
      // evidence.
      throw new Error(
        'RFC 3161: a nonce was sent and the token carries none, so this response cannot be tied to ' +
          'this request. A token over the right digest may still be an earlier one replayed.'
      );
    }
    if (nonceHex !== sent) {
      throw new Error(
        `RFC 3161: the token answers a different request.\n  token nonce: ${nonceHex}\n  sent:        ${sent}`
      );
    }
  }

  return { granted: true, status: Number(status), statusText, genTime, digestHex, nonceHex, token: der };
}

/**
 * Requests a token from a Time Stamping Authority over HTTP.
 *
 * The authority is never defaulted. Which third party a compliance programme trusts to attest
 * its evidence is a decision that belongs to the programme, and quietly picking one would put
 * an unreviewed dependency in the chain of custody.
 */
export async function requestTimestamp(digestHex, { url, timeoutMs = 15000, fetchImpl = fetch } = {}) {
  if (!url) {
    throw new Error(
      'No Time Stamping Authority configured. Set evidence.tsa_url in the profile or KSI_TSA_URL in the ' +
        'environment. This is deliberately not defaulted: which third party attests your evidence is a ' +
        'decision for the programme, not for this tool.'
    );
  }

  // Generated here rather than left to buildRequest`s default, because the caller has to keep
  // the value to compare against what comes back. A nonce nobody retains is a nonce nobody can
  // check, which is what it was before.
  const nonce = randomBytes(8);
  const request = buildRequest(digestHex, { nonce });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query', 'content-length': String(request.length) },
      body: request,
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Time Stamping Authority ${url} returned HTTP ${res.status}.`);
    const der = Buffer.from(await res.arrayBuffer());
    const parsed = parseResponse(der, { expectDigestHex: digestHex, expectNonce: nonce });
    if (!parsed.granted) {
      throw new Error(`Time Stamping Authority refused the request: ${parsed.statusText}${parsed.detail ? ` — ${parsed.detail}` : ''}`);
    }
    return { ...parsed, authority: url };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verifies a stored token against the digest it should cover.
 *
 * Deliberately narrow, and the narrowness is the honest part: this confirms the token is
 * well-formed, was granted, and attests to *this* digest. It does not verify the authority's
 * signature, which needs its certificate chain — run `openssl ts -verify -in MANIFEST.tsr
 * -data MANIFEST.json -CAfile <tsa-ca.pem>` for that. Reporting a signature as verified when
 * nothing checked it would be the same overstatement the content hash made before the chain.
 */
export function verifyToken(der, expectDigestHex, { expectNonce = null } = {}) {
  try {
    const parsed = parseResponse(der, { expectDigestHex, expectNonce });
    return {
      ok: parsed.granted,
      genTime: parsed.genTime,
      digestHex: parsed.digestHex,
      nonceHex: parsed.nonceHex,
      // Checking a stored token's nonce needs the value that was sent, which lives in the
      // manifest rather than in the token. Reported so a caller that did not supply it cannot
      // read this result as a freshness check it did not perform.
      nonceVerified: Boolean(expectNonce),
      signatureVerified: false,
      note: 'Token is well-formed and covers this digest. The authority signature is not verified here; use openssl ts -verify.',
    };
  } catch (err) {
    return {
      ok: false,
      genTime: null,
      digestHex: null,
      nonceHex: null,
      nonceVerified: false,
      signatureVerified: false,
      note: err.message,
    };
  }
}
