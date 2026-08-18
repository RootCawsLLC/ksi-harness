import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Access to the pinned FedRAMP Consolidated Rules.
 *
 * Everything downstream reads the ruleset through this module so there is exactly one
 * place that knows where the bytes live and what shape they have. The rules file is
 * FedRAMP's declared source of truth (see its AGENTS.md); this harness never restates
 * rule content in its own files, it resolves it from here at run time. That is what keeps
 * a ruleset bump from turning into a hunt through hand-copied strings.
 */

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const VENDOR_DIR = join(ROOT, 'vendor', 'fedramp');

let cached;

export function loadRules({ path } = {}) {
  if (!path && cached) return cached;
  const file = path ?? join(VENDOR_DIR, 'fedramp-consolidated-rules.json');
  const rules = JSON.parse(readFileSync(file, 'utf8'));

  for (const section of ['info', 'FRD', 'FRR', 'KSI', 'CTL']) {
    if (!rules[section]) {
      throw new Error(
        `Pinned rules file is missing the "${section}" section. This harness targets the ` +
          `Consolidated Rules for 2026 shape (info/FRD/FRR/KSI/CTL); a file without it is ` +
          `either a different artifact or an upstream restructure that needs a code change.`
      );
    }
  }
  if (!path) cached = rules;
  return rules;
}

export function loadPin() {
  return JSON.parse(readFileSync(join(VENDOR_DIR, 'PINNED.json'), 'utf8'));
}

/** Identifies the ruleset every generated artifact was reasoned about. Stamped into output. */
export function rulesProvenance() {
  const rules = loadRules();
  const pin = loadPin();
  return {
    version: rules.info.version,
    last_updated: rules.info.last_updated,
    title: rules.info.title,
    sha256: pin.sources.rules.sha256,
    source_url: pin.sources.rules.url,
    vendored_at: pin.vendored_at,
  };
}

/**
 * FedRAMP Definitions, keyed by the term rather than the FRD id.
 *
 * KSI indicators cite terms ("Persistently", "Machine-Based Information Resources") whose
 * FedRAMP meaning is narrower than the plain-language reading. FedRAMP's guidance is
 * explicit that the definition wins, so anything that renders an indicator statement for a
 * human resolves its terms through here.
 */
export function definitions() {
  const rules = loadRules();
  const out = new Map();
  for (const bucket of Object.values(rules.FRD.data ?? {})) {
    for (const [id, entry] of Object.entries(bucket ?? {})) {
      if (!entry?.term) continue;
      const record = { id, term: entry.term, definition: entry.definition, alts: entry.alts ?? [] };
      out.set(entry.term.toLowerCase(), record);
      for (const alt of record.alts) out.set(String(alt).toLowerCase(), record);
    }
  }
  return out;
}

/**
 * Requirements from an FRR process document, flattened.
 *
 * The rule tree is process -> applicability -> subset -> requirement id, and requirements
 * either carry a single statement plus `force`, or a `varies_by_class` object. Flattening
 * keeps that shape visible instead of collapsing it, because `force` (MUST vs SHOULD vs
 * MAY) is the field that decides whether a gap is a finding or a preference.
 */
export function requirements(process, { framework = '20x', klass } = {}) {
  const rules = loadRules();
  const doc = rules.FRR[process];
  if (!doc) throw new Error(`No FRR process "${process}". Known: ${Object.keys(rules.FRR).join(', ')}`);

  const out = [];
  for (const [applicability, subsets] of Object.entries(doc.data ?? {})) {
    if (applicability !== 'all' && applicability !== framework) continue;
    for (const [subset, reqs] of Object.entries(subsets ?? {})) {
      for (const [id, req] of Object.entries(reqs ?? {})) {
        const variant = klass ? req.varies_by_class?.[klass] : undefined;
        if (req.varies_by_class && klass && !variant) continue;
        out.push({
          id,
          process,
          applicability,
          subset,
          statement: variant?.statement ?? req.statement,
          force: variant?.force ?? req.force,
          artifacts: variant?.artifacts ?? req.artifacts,
          controls: req.controls,
          varies_by_class: Boolean(req.varies_by_class),
        });
      }
    }
  }
  return out;
}
