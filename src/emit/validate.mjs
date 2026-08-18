import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

import { VENDOR_DIR } from '../catalog/rules.mjs';

/**
 * Validation of emitted artifacts against FedRAMP's own published schemas.
 *
 * This is the part that makes "machine-readable first" a claim rather than an aspiration.
 * Rule FRC-CSO-JSN requires submitted JSON to validate against FedRAMP's schemas, so the
 * harness validates before writing and fails the run rather than producing a file that would
 * be rejected on submission. Finding out at emit time is cheap; finding out at submission
 * time is not.
 *
 * Every vendored schema is registered by its `$id` so the cross-file `$ref`s into
 * fedramp-common-definitions resolve locally, with no network fetch at validation time.
 */

let cached;

function buildValidator() {
  const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);

  const dir = join(VENDOR_DIR, 'schemas');
  const registered = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    const schema = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    if (!schema.$id) continue;
    // The consolidated-rules schema describes the ruleset itself, not an emitted artifact, and
    // registering it here would just be noise in the resolver.
    if (schema.$id.includes('consolidated-rules')) continue;
    ajv.addSchema(schema, schema.$id);
    registered.push({ id: schema.$id, file, title: schema.title });
  }
  return { ajv, registered };
}

export function validator() {
  if (!cached) cached = buildValidator();
  return cached;
}

/** Schema `$id` for a FedRAMP artifact kind, e.g. `ocr` or `sdr`. */
export const SCHEMA_IDS = Object.freeze({
  sdr: 'https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json',
  ocr: 'https://fedramp.gov/schemas/fedramp-ongoing-certification-report-schema-2026-06-24.json',
  overview: 'https://fedramp.gov/schemas/fedramp-certification-package-overview-schema-2026-06-24.json',
  scn: 'https://fedramp.gov/schemas/fedramp-significant-change-notifications-schema-2026-06-24.json',
  vdr: 'https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json',
  incident: 'https://fedramp.gov/schemas/fedramp-incident-report-schema-2026-06-24.json',
});

export function validateArtifact(kind, document) {
  const id = SCHEMA_IDS[kind];
  if (!id) throw new Error(`No FedRAMP schema registered for "${kind}". Known: ${Object.keys(SCHEMA_IDS).join(', ')}`);

  const { ajv } = validator();
  const validate = ajv.getSchema(id);
  if (!validate) throw new Error(`Schema ${id} is not vendored. Run: npm run vendor:sync`);

  const ok = validate(document);
  return {
    ok,
    kind,
    schema_id: id,
    errors: (validate.errors ?? []).map((e) => ({
      path: e.instancePath || '/',
      keyword: e.keyword,
      message: e.message,
      params: e.params,
    })),
  };
}

/** Throws with every violation listed, for use on the write path. */
export function assertValid(kind, document) {
  const result = validateArtifact(kind, document);
  if (!result.ok) {
    const detail = result.errors.map((e) => `  ${e.path} ${e.message}`).join('\n');
    throw new Error(`Emitted ${kind} does not validate against ${result.schema_id}:\n${detail}`);
  }
  return document;
}
