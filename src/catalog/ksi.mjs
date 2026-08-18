import { definitions, loadRules } from './rules.mjs';

/**
 * The Key Security Indicator catalog, normalised for programmatic use.
 *
 * Two things this module deliberately does not do:
 *
 *  - It does not store a copy of the indicator text. Every field is resolved from the
 *    pinned ruleset on demand. A hand-maintained mirror of 46 statements is a mirror that
 *    goes stale, and a stale KSI catalog is worse than none because it reads as current.
 *  - It does not flatten `varies_by_class`. Five indicators are optional at Class B and
 *    required at Class C, so "how many KSIs are there" has no class-free answer, and any
 *    coverage percentage computed without a class is meaningless.
 */

/**
 * Certification classes that exist in the 2026 Consolidated Rules.
 *
 * D is absent on purpose rather than by omission: FedRAMP High has no 20x path, it stays
 * on Rev5, and a Class D pilot is targeted for FY27. Accepting `d` here would let a caller
 * generate a package for a class FedRAMP will not take.
 */
export const CLASSES = Object.freeze(['a', 'b', 'c']);

/** Indicators whose statement is prefixed `**Optional:**` are not mandatory for that class. */
const OPTIONAL_PREFIX = /^\s*\*\*Optional:\*\*\s*/;

function resolveStatement(indicator, klass) {
  if (!indicator.varies_by_class) {
    return { statement: indicator.statement, varies: false, source: 'statement' };
  }
  if (!klass) {
    return { statement: indicator.statement ?? null, varies: true, source: 'unresolved' };
  }
  const variant = indicator.varies_by_class[klass];
  if (!variant) {
    // The indicator varies by class and says nothing about this one. Treat as not
    // applicable rather than inheriting the base statement, which would invent a
    // requirement FedRAMP did not state for this class.
    return { statement: null, varies: true, source: 'absent-for-class' };
  }
  return { statement: variant.statement, varies: true, source: `varies_by_class.${klass}` };
}

/**
 * One indicator resolved for a class.
 *
 * `optional` is derived from the `**Optional:**` marker in the statement text, which is
 * how the ruleset encodes it for KSIs — there is no `force` field on an indicator the way
 * there is on an FRR requirement. That derivation is recorded in `optional_basis` so a
 * reader can see it is read out of prose rather than read off a field.
 */
export function resolveIndicator(id, { klass } = {}) {
  const rules = loadRules();
  const theme = id.split('-')[1];
  const themeNode = rules.KSI[theme];
  const indicator = themeNode?.indicators?.[id];
  if (!indicator) throw new Error(`No such Key Security Indicator: ${id}`);

  const { statement, varies, source } = resolveStatement(indicator, klass);
  const optional = statement != null && OPTIONAL_PREFIX.test(statement);

  return {
    id,
    theme,
    theme_name: themeNode.name,
    theme_status: themeNode.status,
    name: indicator.name,
    statement: statement == null ? null : statement.replace(OPTIONAL_PREFIX, ''),
    applicable: statement != null,
    optional,
    optional_basis: varies
      ? optional
        ? `derived from the "**Optional:**" marker in ${source}`
        : `no optional marker in ${source}`
      : 'indicator does not vary by class',
    varies_by_class: varies,
    statement_source: source,
    controls: [...(indicator.controls ?? [])],
    terms: [...(indicator.terms ?? [])],
    updated: indicator.updated ?? [],
  };
}

/** Every indicator id in the ruleset, theme-ordered. */
export function allIndicatorIds() {
  const rules = loadRules();
  return Object.keys(rules.KSI)
    .sort()
    .flatMap((theme) => Object.keys(rules.KSI[theme].indicators ?? {}).sort());
}

/** The catalog resolved for one class. */
export function catalog({ klass = 'c' } = {}) {
  if (!CLASSES.includes(klass)) {
    throw new Error(
      `Unknown certification class "${klass}". The 2026 Consolidated Rules define ${CLASSES.join('/')} ` +
        `for 20x; High (Class D) has no 20x path and stays on Rev5.`
    );
  }
  const indicators = allIndicatorIds().map((id) => resolveIndicator(id, { klass }));
  return {
    klass,
    indicators,
    themes: themes(),
    counts: {
      total: indicators.length,
      applicable: indicators.filter((i) => i.applicable).length,
      mandatory: indicators.filter((i) => i.applicable && !i.optional).length,
      optional: indicators.filter((i) => i.applicable && i.optional).length,
    },
  };
}

export function themes() {
  const rules = loadRules();
  return Object.entries(rules.KSI)
    .map(([short, node]) => ({
      short,
      id: node.id,
      name: node.name,
      status: node.status,
      indicator_count: Object.keys(node.indicators ?? {}).length,
    }))
    .sort((a, b) => a.short.localeCompare(b.short));
}

/**
 * NIST 800-53 control ids an indicator maps to, and the reverse index.
 *
 * The reverse direction is the load-bearing one. Because every indicator carries its
 * 800-53 mappings, a control-keyed framework can be scored transitively from KSI evidence
 * without re-authoring anything — which is the whole argument for treating CJIS as an
 * 800-53 overlay rather than a separate programme. See docs/adr/0004-crosswalk-direction.md.
 */
export function controlIndex() {
  const byControl = new Map();
  for (const id of allIndicatorIds()) {
    const { controls } = resolveIndicator(id);
    for (const control of controls) {
      if (!byControl.has(control)) byControl.set(control, []);
      byControl.get(control).push(id);
    }
  }
  return byControl;
}

/**
 * FedRAMP's parameter values and guidance for a control, from the ruleset's CTL section.
 *
 * CTL is the Rev5 bridge and it is easy to miss — it is not described in FedRAMP's own
 * AGENTS.md. It carries organisation-defined parameter values (an ODP FedRAMP has already
 * decided, e.g. AC-6(1) applies to "all functions not publicly accessible") and
 * clarifying guidance. Anything generating Rev5 material needs it; ignoring it means
 * emitting a package with unfilled ODPs.
 */
export function controlOverlay(controlId) {
  const rules = loadRules();
  const family = controlId.split(/[-(.]/)[0].toUpperCase();
  const node = rules.CTL[family];
  if (!node) return null;

  // CTL keys are dashed and zero-padded (AC-06-01) while KSI mappings use the OSCAL-style
  // dotted form (ac-6.1). Normalise both to compare.
  const want = normaliseControlId(controlId);
  for (const [key, value] of Object.entries(node)) {
    if (normaliseControlId(key) === want) return { control_id: key, family, ...value };
  }
  return null;
}

/** `ac-6.1`, `AC-06-01` and `AC-6(1)` all normalise to `ac-6.1`. */
export function normaliseControlId(raw) {
  const parts = String(raw)
    .toLowerCase()
    .replace(/[()]/g, '.')
    .split(/[-.]/)
    .filter(Boolean);
  const [family, ...rest] = parts;
  return [family, ...rest.map((p) => String(Number(p)))].join('.').replace(/^([a-z]+)\./, '$1-');
}

/** Resolves the FedRAMP-defined terms an indicator cites. */
export function termsFor(id) {
  const defs = definitions();
  return resolveIndicator(id).terms.map((term) => defs.get(term.toLowerCase()) ?? { term, definition: null });
}
