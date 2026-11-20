import { createHash } from 'node:crypto';

/** Deterministic key order, so the hash of unchanged content does not change. */
export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, k) => {
        if (value[k] !== undefined) acc[k] = canonicalize(value[k]);
        return acc;
      }, {});
  }
  return value;
}

/** SHA-256 over the canonical JSON form. */
export function canonicalSha256(value) {
  return createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex');
}
