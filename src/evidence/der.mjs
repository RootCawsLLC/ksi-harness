/**
 * The smallest DER reader and writer that RFC 3161 needs.
 *
 * A time-stamp request is a four-field ASN.1 structure and a response is a signed CMS blob,
 * so writing the request by hand costs about sixty lines and reading the parts of the
 * response that matter costs about the same. That is cheaper than adding a general-purpose
 * ASN.1 dependency to a repository whose whole argument is that its supply chain is small
 * enough to reason about — and this module is deliberately not a general-purpose ASN.1
 * implementation. It handles definite-length DER only, which is all RFC 3161 permits.
 */

export const TAG = Object.freeze({
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
  SET: 0x31,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
});

/* --------------------------------------------------------------------- writing */

/** DER length octets: short form under 128, long form above it. */
function encodeLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function encode(tag, value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

export const sequence = (...parts) => encode(TAG.SEQUENCE, Buffer.concat(parts));

/**
 * A DER INTEGER. Two's complement and minimally encoded, so a leading zero is prepended
 * when the high bit is set — otherwise a positive value reads back as negative.
 */
export function integer(value) {
  let bytes;
  if (typeof value === 'bigint' || typeof value === 'number') {
    let n = BigInt(value);
    if (n === 0n) bytes = [0];
    else {
      bytes = [];
      while (n > 0n) {
        bytes.unshift(Number(n & 0xffn));
        n >>= 8n;
      }
    }
  } else {
    bytes = [...value];
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return encode(TAG.INTEGER, Buffer.from(bytes));
}

export const octetString = (buf) => encode(TAG.OCTET_STRING, buf);
export const boolean = (value) => encode(TAG.BOOLEAN, Buffer.from([value ? 0xff : 0x00]));
export const nullValue = () => encode(TAG.NULL, Buffer.alloc(0));

/** Encodes a dotted OID. The first two arcs share a byte; the rest are base-128, high bit set on continuation. */
export function oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const bytes = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    if (arc === 0) {
      bytes.push(0);
      continue;
    }
    const chunk = [];
    let n = arc;
    while (n > 0) {
      chunk.unshift(n & 0x7f);
      n >>>= 7;
    }
    for (let i = 0; i < chunk.length - 1; i += 1) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return encode(TAG.OID, Buffer.from(bytes));
}

/* --------------------------------------------------------------------- reading */

function decodeLength(buf, offset) {
  const first = buf[offset];
  if (first === undefined) throw new Error('DER: truncated length');
  if (first < 0x80) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0) throw new Error('DER: indefinite length is not permitted');
  if (offset + 1 + count > buf.length) throw new Error('DER: truncated long-form length');
  let length = 0;
  for (let i = 0; i < count; i += 1) length = length * 256 + buf[offset + 1 + i];
  return { length, next: offset + 1 + count };
}

/**
 * Parses one DER element and, when it is constructed, its children.
 *
 * Returns `{ tag, value, children, start, end }`. Constructed elements keep their raw value
 * as well as the parsed children, because a CMS eContent is an OCTET STRING whose contents
 * are themselves DER and has to be re-parsed rather than walked.
 */
export function parse(buf, offset = 0) {
  if (offset >= buf.length) throw new Error('DER: read past end of buffer');
  const tag = buf[offset];
  const { length, next } = decodeLength(buf, offset + 1);
  const end = next + length;
  if (end > buf.length) throw new Error(`DER: element claims ${length} bytes and only ${buf.length - next} remain`);

  const value = buf.subarray(next, end);
  const constructed = (tag & 0x20) !== 0;
  const node = { tag, value, start: offset, end, children: [] };

  if (constructed) {
    let cursor = next;
    while (cursor < end) {
      const child = parse(buf, cursor);
      node.children.push(child);
      cursor = child.end;
    }
  }
  return node;
}

/** Every node in the tree, depth-first, including the root. */
export function walk(node) {
  const out = [node];
  for (const child of node.children) out.push(...walk(child));
  return out;
}

/** First node matching a predicate, depth-first. */
export function find(node, predicate) {
  for (const candidate of walk(node)) {
    if (predicate(candidate)) return candidate;
  }
  return null;
}

export function readInteger(node) {
  let n = 0n;
  for (const byte of node.value) n = (n << 8n) | BigInt(byte);
  return n;
}

/**
 * Reads an ASN.1 GeneralizedTime into an ISO 8601 string.
 *
 * DER requires UTC with a trailing Z and no fractional-second trailing zeros, so the
 * accepted shape is narrow on purpose: anything else is a token this code should not
 * pretend to understand.
 */
export function readGeneralizedTime(node) {
  const text = node.value.toString('ascii');
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text);
  if (!match) throw new Error(`DER: "${text}" is not a DER GeneralizedTime in UTC`);
  const [, y, mo, d, h, mi, s, frac] = match;
  return `${y}-${mo}-${d}T${h}:${mi}:${s}${frac ? `.${frac}` : ''}Z`;
}
