import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';

import {
  encode,
  integer,
  nullValue,
  octetString,
  oid,
  parse,
  readGeneralizedTime,
  readInteger,
  sequence,
  TAG,
} from '../src/evidence/der.mjs';
import { buildRequest, parseResponse, requestTimestamp, verifyToken } from '../src/evidence/timestamp.mjs';

/**
 * Trusted timestamping closes the fourth property of defensible evidence, and it was the
 * weakest one here: `collectedAt` was required to come from a trusted source and nothing
 * verified it, so in practice a bundle asserted its own age.
 *
 * The DER assertions below are against values that can be checked by hand from the
 * specification, because a hand-rolled encoder that is subtly wrong would produce requests a
 * real authority rejects — and the failure would surface in production rather than here.
 */

const DIGEST = 'b3'.repeat(32);

/** A granted TimeStampResp over `digest`, shaped like a real CMS-wrapped token. */
function grantedResponse(digest, genTime = '20260818164500Z') {
  const tstInfo = sequence(
    integer(1),
    oid('1.3.6.1.4.1.13762.3'),
    sequence(sequence(oid('2.16.840.1.101.3.4.2.1'), nullValue()), octetString(Buffer.from(digest, 'hex'))),
    integer(4242n),
    encode(TAG.GENERALIZED_TIME, Buffer.from(genTime, 'ascii'))
  );
  const token = sequence(oid('1.2.840.113549.1.7.2'), encode(0xa0, sequence(octetString(tstInfo))));
  return sequence(sequence(integer(0)), token);
}

/* ------------------------------------------------------------------------- DER */

// Checkable against the specification by hand. A subtly wrong encoder produces requests a
// real authority rejects, and that failure belongs here rather than in production.
test('DER primitives encode to the bytes the specification requires', () => {
  assert.equal(oid('2.16.840.1.101.3.4.2.1').toString('hex'), '0609608648016503040201', 'the SHA-256 OID');
  assert.equal(integer(0).toString('hex'), '020100');
  assert.equal(integer(127).toString('hex'), '02017f');
  assert.equal(integer(128).toString('hex'), '02020080', 'a leading zero, or 0x80 reads back negative');
  assert.equal(encode(TAG.OCTET_STRING, Buffer.alloc(200)).subarray(0, 3).toString('hex'), '0481c8', 'long-form length');
});

test('the parser rejects the encodings DER does not permit rather than guessing', () => {
  assert.throws(() => parse(Buffer.from([0x30, 0x80, 0x00, 0x00])), /indefinite length/);
  assert.throws(() => parse(Buffer.from([0x30, 0x05, 0x01])), /claims 5 bytes/);
});

test('a generalized time is read only in the UTC form DER mandates', () => {
  assert.equal(readGeneralizedTime({ value: Buffer.from('20260818164500Z') }), '2026-08-18T16:45:00Z');
  assert.equal(readGeneralizedTime({ value: Buffer.from('20260818164500.5Z') }), '2026-08-18T16:45:00.5Z');
  assert.throws(() => readGeneralizedTime({ value: Buffer.from('20260818164500+0100') }), /not a DER GeneralizedTime in UTC/);
});

/* --------------------------------------------------------------------- request */

test('the request is a well-formed TimeStampReq over the digest it was given', () => {
  const req = buildRequest(DIGEST, { nonce: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]) });
  const node = parse(req);
  assert.equal(node.tag, TAG.SEQUENCE);
  assert.equal(readInteger(node.children[0]), 1n, 'version 1');
  assert.equal(node.children[1].children[1].value.toString('hex'), DIGEST, 'the imprint is the digest');
  assert.equal(node.children[3].value[0], 0xff, 'certReq true, so the token carries the certificate');
});

test('a digest that is not SHA-256 is refused rather than sent', () => {
  assert.throws(() => buildRequest('ab'.repeat(20)), /A SHA-256 digest is 32 bytes/);
});

/* -------------------------------------------------------------------- response */

test('a granted response yields the attested time and the digest it covers', () => {
  const parsed = parseResponse(grantedResponse(DIGEST), { expectDigestHex: DIGEST });
  assert.equal(parsed.granted, true);
  assert.equal(parsed.genTime, '2026-08-18T16:45:00Z');
  assert.equal(parsed.digestHex, DIGEST);
});

// The check that makes storing a token worth anything. A token is evidence only about the
// data whose digest it carries; one over something else would otherwise be filed as proof.
test('a token over different data is refused, not filed', () => {
  assert.throws(
    () => parseResponse(grantedResponse('cc'.repeat(32)), { expectDigestHex: DIGEST }),
    (err) => {
      assert.match(err.message, /attests to different data/);
      // Both digests in full. Two different digests routinely share a prefix, and an error
      // that truncates them to the same sixteen characters is worse than no error.
      assert.ok(err.message.includes('cc'.repeat(32)), 'names the digest the token covers');
      assert.ok(err.message.includes(DIGEST), 'names the digest that was expected');
      return true;
    }
  );
});

test('a refusal carries its status and reason instead of throwing', () => {
  const rejected = sequence(sequence(integer(2), encode(0x0c, Buffer.from('policy not supported', 'utf8'))));
  const parsed = parseResponse(rejected);
  assert.equal(parsed.granted, false);
  assert.equal(parsed.statusText, 'rejected');
  assert.equal(parsed.detail, 'policy not supported');
});

test('verifyToken reports what it checked and, pointedly, what it did not', () => {
  const result = verifyToken(grantedResponse(DIGEST), DIGEST);
  assert.equal(result.ok, true);
  assert.equal(result.genTime, '2026-08-18T16:45:00Z');
  assert.equal(result.signatureVerified, false, 'the authority signature is not checked here and must not claim to be');
  assert.match(result.note, /openssl ts -verify/);

  const wrong = verifyToken(grantedResponse(DIGEST), 'dd'.repeat(32));
  assert.equal(wrong.ok, false);
});

/* ------------------------------------------------------------------ the request */

test('a timestamp is requested over the wire and validated against what was sent', async () => {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const imprint = parse(Buffer.concat(chunks)).children[1].children[1].value;
    res.writeHead(200, { 'content-type': 'application/timestamp-reply' });
    res.end(grantedResponse(imprint.toString('hex')));
  });
  await new Promise((resolve) => server.listen(0, resolve));

  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const attestation = await requestTimestamp(DIGEST, { url });
    assert.equal(attestation.granted, true);
    assert.equal(attestation.digestHex, DIGEST);
    assert.equal(attestation.authority, url);
  } finally {
    server.close();
  }
});

// Which third party attests a compliance programme's evidence is a decision for the
// programme. Quietly picking one would put an unreviewed dependency in the chain of custody.
test('no authority is defaulted', async () => {
  await assert.rejects(() => requestTimestamp(DIGEST, {}), /No Time Stamping Authority configured/);
});

test('an authority that refuses is reported as a refusal rather than a timestamp', async () => {
  const server = createServer((req, res) => {
    res.writeHead(200);
    res.end(sequence(sequence(integer(2), encode(0x0c, Buffer.from('unsupported hash', 'utf8')))));
  });
  await new Promise((resolve) => server.listen(0, resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    await assert.rejects(() => requestTimestamp(DIGEST, { url }), /refused the request: rejected — unsupported hash/);
  } finally {
    server.close();
  }
});
