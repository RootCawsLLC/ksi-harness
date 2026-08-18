#!/usr/bin/env node
/**
 * Vendors the FedRAMP machine-readable sources and pins them by content hash.
 *
 * Why vendor at all, rather than fetching at runtime: a certification package is an
 * assertion about a specific ruleset on a specific date. If the harness fetched the rules
 * live, re-running last quarter's report against this quarter's rules would silently
 * change what was claimed, and the artifact would stop being reproducible. So the ruleset
 * is a pinned dependency and moving to a new one is a reviewable commit.
 *
 * Why pin by hash and not by the upstream `version` field: `version` is FedRAMP's
 * editorial version, and the repository can be pushed without it changing. The hash is the
 * only thing that tells us whether the bytes we reasoned about are the bytes upstream has.
 *
 *   node scripts/vendor-sync.mjs verify   # offline: vendored bytes match PINNED.json
 *   node scripts/vendor-sync.mjs check    # online:  upstream still matches the pin
 *   node scripts/vendor-sync.mjs sync     # online:  refresh vendored bytes + rewrite pin
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VENDOR = join(ROOT, 'vendor', 'fedramp');
const PIN_PATH = join(VENDOR, 'PINNED.json');

const RAW = 'https://raw.githubusercontent.com';

/**
 * The vendored set. Deliberately small: the rules file and the artifact schemas are the
 * only upstream material this harness treats as authoritative. FedRAMP's own AGENTS.md
 * says the rest of its repository is "supporting infrastructure ... not the rules", so
 * vendoring more would import material we would then have to disclaim.
 */
export const SOURCES = [
  {
    id: 'rules',
    repo: 'FedRAMP/rules',
    ref: 'main',
    remote: 'fedramp-consolidated-rules.json',
    local: 'fedramp-consolidated-rules.json',
  },
  {
    id: 'rules-schema',
    repo: 'FedRAMP/rules',
    ref: 'main',
    remote: 'schemas/fedramp-consolidated-rules.schema.json',
    local: 'schemas/fedramp-consolidated-rules.schema.json',
  },
  ...[
    'fedramp-common-definitions-schema-2026-06-24.json',
    'fedramp-security-decision-record-schema-2026-06-24.json',
    'fedramp-ongoing-certification-report-schema-2026-06-24.json',
    'fedramp-certification-package-overview-schema-2026-06-24.json',
    'fedramp-significant-change-notifications-schema-2026-06-24.json',
    'fedramp-vulnerability-detail-report-schema-2026-06-24.json',
    'fedramp-incident-report-schema-2026-06-24.json',
    'fedramp-assessor-information-schema-2026-06-24.json',
    'fedramp-advisor-information-schema-2026-06-24.json',
    'fedramp-accepted-vulnerability-info-schema-2026-06-24.json',
    'fedramp-historical-ver-activity-schema-2026-06-24.json',
  ].map((f) => ({
    id: f.replace(/^fedramp-|-schema-\d{4}-\d{2}-\d{2}\.json$/g, ''),
    repo: 'FedRAMP/schemas',
    ref: 'main',
    remote: f,
    local: join('schemas', f),
  })),
];

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const urlFor = (s) => `${RAW}/${s.repo}/${s.ref}/${s.remote}`;

async function fetchSource(source) {
  const url = urlFor(source);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status} ${res.statusText}`);
  return Buffer.from(await res.arrayBuffer());
}

export function readPin() {
  if (!existsSync(PIN_PATH)) throw new Error(`No pin file at ${PIN_PATH}. Run: npm run vendor:sync`);
  return JSON.parse(readFileSync(PIN_PATH, 'utf8'));
}

/** Offline. Confirms the vendored bytes are the bytes the pin claims. */
export function verify() {
  const pin = readPin();
  const problems = [];
  for (const source of SOURCES) {
    const entry = pin.sources[source.id];
    const path = join(VENDOR, source.local);
    if (!entry) {
      problems.push(`${source.id}: absent from PINNED.json`);
      continue;
    }
    if (!existsSync(path)) {
      problems.push(`${source.id}: pinned but not vendored at ${source.local}`);
      continue;
    }
    const actual = sha256(readFileSync(path));
    if (actual !== entry.sha256) {
      problems.push(`${source.id}: vendored bytes do not match pin (${actual.slice(0, 12)} != ${entry.sha256.slice(0, 12)})`);
    }
  }
  return { ok: problems.length === 0, problems, pin };
}

/** Online. Reports which pinned sources upstream has moved past. */
export async function check() {
  const pin = readPin();
  const moved = [];
  for (const source of SOURCES) {
    const entry = pin.sources[source.id];
    const upstream = sha256(await fetchSource(source));
    if (!entry || upstream !== entry.sha256) {
      moved.push({ id: source.id, pinned: entry?.sha256 ?? null, upstream, url: urlFor(source) });
    }
  }
  return { ok: moved.length === 0, moved };
}

/** Online. Refreshes the vendored bytes and rewrites the pin. */
export async function sync() {
  const sources = {};
  for (const source of SOURCES) {
    const body = await fetchSource(source);
    const path = join(VENDOR, source.local);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, body);
    sources[source.id] = {
      repo: source.repo,
      ref: source.ref,
      path: `vendor/fedramp/${source.local.replace(/\\/g, '/')}`,
      url: urlFor(source),
      bytes: body.length,
      sha256: sha256(body),
    };
  }

  // The rules file carries its own editorial version; record it so a human reading the pin
  // can tell at a glance which ruleset the repository is reasoning about.
  const rules = JSON.parse(readFileSync(join(VENDOR, 'fedramp-consolidated-rules.json'), 'utf8'));
  const pin = {
    $comment:
      'Written by scripts/vendor-sync.mjs. Hand edits defeat the point: the hashes are what make a ' +
      'generated certification artifact reproducible against a known ruleset.',
    vendored_at: new Date().toISOString(),
    rules_version: rules.info?.version ?? null,
    rules_last_updated: rules.info?.last_updated ?? null,
    sources,
  };
  writeFileSync(PIN_PATH, `${JSON.stringify(pin, null, 2)}\n`, 'utf8');
  return pin;
}

const isMain =
  process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href;

if (isMain) {
  const mode = process.argv[2] ?? 'verify';
  try {
    if (mode === 'verify') {
      const { ok, problems, pin } = verify();
      if (!ok) {
        console.error('Vendored FedRAMP sources do not match PINNED.json:');
        for (const p of problems) console.error(`  - ${p}`);
        process.exit(1);
      }
      console.log(`Vendored sources verified against pin (rules ${pin.rules_version}, ${Object.keys(pin.sources).length} files).`);
    } else if (mode === 'check') {
      const { ok, moved } = await check();
      if (!ok) {
        console.error(`Upstream has moved past the pin for ${moved.length} source(s):`);
        for (const m of moved) console.error(`  - ${m.id}: ${m.url}`);
        console.error('\nRun `npm run vendor:sync` then `npm run drift` to see what changed in the rules.');
        process.exit(1);
      }
      console.log('Pin is current with upstream.');
    } else if (mode === 'sync') {
      const pin = await sync();
      console.log(`Vendored ${Object.keys(pin.sources).length} sources; rules version ${pin.rules_version} (${pin.rules_last_updated}).`);
    } else {
      console.error(`Unknown mode "${mode}". Use verify | check | sync.`);
      process.exit(2);
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
