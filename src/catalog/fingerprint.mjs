import { createHash } from 'node:crypto';

import { normaliseControlId } from './ksi.mjs';
import { definitions, loadRules } from './rules.mjs';

/**
 * What a route's reasoning was written against, reduced to short hashes.
 *
 * A route in routes.yaml is prose about particular indicator text: a sufficiency argument, a
 * list of gaps, a reason something is manual. When FedRAMP rewords the indicator that prose may
 * stop being true, and nothing about a passing check would reveal it. So each route records the
 * fingerprint of the indicator it was reviewed against, and validation fails when the pinned
 * ruleset no longer matches. Drift reports the same comparison between two rulesets; both call
 * this function, because a gate and a report that disagree about "changed" would let a bump
 * through that the report flagged, or block one it called clean.
 *
 * Two fields, because each one invalidates something different and the error has to say which:
 *
 *  - `text`: the statement, its per-class variants, the FedRAMP-defined terms it cites, and what
 *    those terms mean. The meaning is the part that matters. A route reasoning about cadence
 *    leans on FRD-PER's definition of "persistently", not on the word, and FedRAMP can redefine a
 *    term without touching any indicator that cites it.
 *  - `controls`: the 800-53 mappings and FedRAMP's CTL entries for them (the organization-defined
 *    values and guidance). Mappings are carried straight into the SDR and OSCAL output (ADR 0004),
 *    and Rev5 material and some route prose rest on the CTL values: KSI-SVC-SIN's TLS floor leans on
 *    what the sc-13 entry does and does not say. Both are what the output attaches to the route,
 *    so they share one acknowledgement. A separate field fired on every mapping change that
 *    reached a control with an entry, which is a second renewal for the same event; drift still
 *    reports which of the two moved.
 *
 * Only meaning is hashed. Display names, `updated` changelogs, alternate spellings and FedRAMP's
 * own rendering hints are left out, because a gate that fires on bookkeeping teaches people to
 * renew stamps without reading. Hashes are over raw entries, not ones resolved for a class,
 * because one routes.yaml is validated at every class and its stamps cannot depend on which one.
 */

const hash = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);

export const REVIEW_FIELDS = Object.freeze(['text', 'controls']);

/** CTL entries keyed by normalised control id, so `SC-07` meets an indicator's `sc-7`. */
export function ctlIndex(rules = loadRules()) {
  const out = new Map();
  for (const family of Object.values(rules.CTL ?? {})) {
    for (const [id, entry] of Object.entries(family ?? {})) {
      const { guidance = null, parameters = null, varies_by_class = null } = entry ?? {};
      out.set(normaliseControlId(id), { guidance, parameters, varies_by_class });
    }
  }
  return out;
}

/**
 * The fingerprint of one indicator, read against the ruleset it came from. A cited term with no
 * definition hashes as null rather than being dropped, so one appearing later is a change.
 * A mapped control with no CTL entry contributes nothing beyond its id; an entry appearing later
 * still changes the hash, because it joins the list.
 */
export function reviewFingerprint(indicator, { defs, ctl }) {
  const terms = [...(indicator.terms ?? [])].sort();
  const controls = [...(indicator.controls ?? [])].sort();
  return {
    text: hash({
      statement: indicator.statement ?? null,
      varies_by_class: indicator.varies_by_class ?? null,
      terms: terms.map((t) => {
        const d = defs.get(t.toLowerCase());
        return [t, d ? { definition: d.definition ?? null, note: d.note ?? null } : null];
      }),
    }),
    controls: hash({
      mappings: controls,
      parameters: controls.filter((c) => ctl.has(normaliseControlId(c))).map((c) => [c, ctl.get(normaliseControlId(c))]),
    }),
  };
}

/** Every indicator's fingerprint in a ruleset, keyed by id. Defaults to the pinned one. */
export function reviewFingerprints(rules = loadRules()) {
  const context = { defs: definitions(rules), ctl: ctlIndex(rules) };
  const out = new Map();
  for (const node of Object.values(rules.KSI ?? {})) {
    for (const [id, indicator] of Object.entries(node.indicators ?? {})) {
      out.set(id, reviewFingerprint(indicator, context));
    }
  }
  return out;
}
