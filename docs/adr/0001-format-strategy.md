# ADR 0001 — Machine-readable first, format-pluggable

**Status:** accepted · **Date:** 2026-08-18

## Context

A control-monitoring tool has to decide what it authors in. The obvious candidate is OSCAL: it is
NIST-maintained, it has a model for everything, and there is a real ecosystem around it.

For FedRAMP 20x specifically, it is the wrong primary target.

- 20x requires JSON valid against **FedRAMP's own schemas**. Rule `FRC-CSO-JSN` in the 2026
  Consolidated Rules describes them as "lightweight and flexible… a minimum set of structured
  information." The source of truth is [`FedRAMP/rules`](https://github.com/FedRAMP/rules) and
  [`FedRAMP/schemas`](https://github.com/FedRAMP/schemas), both actively maintained.
- The 20x artifacts are **SDR, OCR, SCN and VDR**. The Security Decision Record replaces the SSP.
  None of them is an OSCAL model.
- [RFC-0024](https://www.fedramp.gov/rfcs/0024/) does not mandate OSCAL, and says so directly: it
  "applies only to the FedRAMP Rev5 process and does not apply to FedRAMP 20x." Even within Rev5,
  `LMR-FRX-LAF` lists OSCAL as one approved format among several, conditional on the project
  "being maintained and responsive to industry input," and adds that industry is "strongly
  encouraged to create innovative solutions that can compete with or replace OSCAL."
- The adoption numbers are the strongest signal. FedRAMP processed 100+ Rev5 authorizations in
  2025 with **zero OSCAL submissions**, and no Phase 1 20x pilot participant used OSCAL for
  machine-readable materials.

The counter-argument is real and worth stating. Governance moved from NIST to an industry
foundation with a serious steering committee, the Control Mapping Model landed in OSCAL 1.2.0, and
multi-framework reuse — 800-53 seeding catalogs for Australia's ASD ISM, Singapore, Canada, Japan
— is a genuine win that FedRAMP's lightweight schemas do not attempt.

The practitioner critique is equally real, and it is about authoring rather than about the schema.
Greg Elin's formulation is the one that has stuck: "To produce a single valid OSCAL SSP, an author
must first construct a complete, interlocking set of objects… **There is no valid partial OSCAL.**
This made OSCAL an all-or-nothing proposition, and most chose nothing." Defense Unicorns dropped
OSCAL in Lula 2 because it "proved too complex for most teams to work with effectively." NIST's
Michaela Iorga answers that this is "not an issue with the OSCAL schema (aka the language
itself)" but with the state of the toolchain — which is a fair distinction and also, from a
team's point of view, a difference without a consequence.

Thoughtworks captured the situation neatly: OSCAL sat at **Assess** in Radar Vol. 33 and was
dropped in Vol. 34, while "continuous compliance" is rated **Adopt**. The practice graduated. The
format did not.

## Decision

**Model control state in an internal schema. Emit every external format from it. Never author any
of them by hand.**

Concretely:

1. The evidence bundle (`schemas/evidence-bundle.schema.json`) is the primitive. It belongs to
   this project and is designed for one job: recording what a single automated check observed,
   over what population, with what result.
2. `src/evidence/state.mjs` folds bundles, the routing map and the pinned catalog into one
   control state.
3. Every emitter is `emit(state, options) -> document`. Emitters cannot reach the locker, the
   collectors, or the ruleset. Adding a format is a new projection, not another traversal.
4. FedRAMP 20x SDR and OCR are the primary targets, validated against the vendored schemas before
   anything is written.
5. **An OSCAL emitter ships alongside them**, behind the same interface.

## Why keep OSCAL at all

Because the format question is not settled and this is the cheap way to be wrong about it.

Rev5 requires a machine-readable package at initial certification from 30 September 2026 and does
not stop accepting new certifications until 11 June 2027, with the grace period running to
30 September 2027. Customers ask for OSCAL regardless of what FedRAMP takes. Vanta — itself 20x
Class C certified — shipped OSCAL export in February 2026 while also shipping in-product KSI
mappings, which is exactly this hedge.

The OSCAL emitter is roughly 200 lines because the state model does the work. If FedRAMP reverses
course, or a customer standardises on OSCAL, the cost is a projection rather than a rewrite. If
20x stays as it is, the cost of having kept it was 200 lines.

## Consequences

- The internal schema is one more thing to maintain, and it is not a standard. Accepted: it is
  small, it is versioned, and it is the only part of the system that is genuinely ours.
- The OSCAL output is deliberately lossy in one direction. OSCAL's vocabulary is `satisfied` /
  `not-satisfied`; the coverage model here has four levels. Collapsing four into two discards the
  distinction that matters most, so the emitter states the remaining gap in the finding text
  rather than letting `satisfied` imply completeness. See ADR 0002.
- A schema change upstream breaks emission loudly, at emit time, rather than at submission time.
  That is the intended failure mode and it is why `npm run vendor:verify` runs before anything is
  generated.

## What would change this decision

- FedRAMP mandating OSCAL for 20x. RFC-0024 currently excludes it explicitly.
- The authoring problem being solved by something that is not a commercial platform. Every
  proposed fix for OSCAL's complexity is currently a product, including from vendors who publish
  their own critiques of it.
