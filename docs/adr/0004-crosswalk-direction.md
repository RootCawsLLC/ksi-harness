# ADR 0004 — Crosswalk from indicators to controls, not the reverse

**Status:** accepted · **Date:** 2026-08-18

## Context

The target is not one framework. A provider selling into US government ends up holding some
combination of FedRAMP 20x, GovRAMP, CJIS, CMMC, plus whatever ISO and SOC work the commercial
side already needs. The naive response is a crosswalk matrix per pair, which is quadratic and goes
stale the moment any framework revises.

There is a much better structural fact available, and it is easy to miss.

**Every KSI in the ruleset already carries its NIST 800-53 Rev 5 control mappings.** `KSI-IAM-ELP`
lists 34 of them. That is FedRAMP's own mapping, published in the file this harness pins, and it
means 800-53 is available as a pivot without anyone authoring a crosswalk.

The second fact makes it valuable. **CJIS Security Policy v6.0 restructured onto the 800-53 Rev 5
catalog**, using 800-53 identifiers verbatim across 18 control families, each with a P1–P4
priority. v6.1 (25 June 2026) continues it. Practically: if you run an 800-53 Moderate programme,
most CJIS control text is inherited rather than re-authored. What CJIS genuinely adds is
fingerprint-based personnel screening, the Security Addendum in Appendix H, and agency-held keys —
a short list of real deltas rather than a new framework.

GovRAMP points the same way. Since 15 July 2026 a GovRAMP assessment within the previous twelve
months satisfies FedRAMP's Class A alternative-framework prerequisite, and the GovRAMP
CJIS-Aligned Task Force maintains a CJIS 6.0 → GovRAMP Moderate overlay. Its own machine-readable
artifacts are Excel workbooks, so nothing can be consumed from it directly, but the control
substrate is shared.

## Decision

Treat **800-53 Rev 5 as the pivot** and derive everything else from the indicator mappings the
ruleset already publishes.

- `controlIndex()` in `src/catalog/ksi.mjs` builds the reverse index: control id → the indicators
  that touch it. 209 controls, from the pinned file, computed rather than authored.
- Control ids are normalised before comparison. The ruleset uses two dialects for the same
  control — KSI mappings use the OSCAL-style dotted form (`ac-6.1`) and the CTL section uses a
  dashed zero-padded form (`AC-06-01`) — and nothing crosswalks until those converge.
- `controlOverlay()` reads the **CTL** section, which carries FedRAMP's organisation-defined
  parameter values and clarifying guidance. CTL is easy to miss: it is not described in FedRAMP's
  own `AGENTS.md`. Anything generating Rev5 material needs it, and ignoring it means emitting a
  package with unfilled ODPs.

The direction matters. Collect evidence against **indicators**, then score a control-keyed
framework transitively. The reverse — collecting per framework — means collecting the same evidence
several times and reconciling the copies.

Consequently, adding CJIS is not a new collection programme. It is a profile that selects controls
from the existing index, plus explicit handling of the genuine deltas, which are personnel and
contractual rather than technical and therefore `manual` routes under ADR 0002.

## The CMMC trap, stated so it is not walked into

CMMC is **legally pinned to NIST 800-171 Rev 2** — 32 CFR 170.2 incorporates the February 2020
revision by reference. `usnistgov/oscal-content` ships **only 800-171 r3**, and there is no r2
OSCAL catalog and no 800-171 profile at any revision. NIST publishes OSCAL for the revision that
does not legally apply.

Anyone doing OSCAL-based CMMC work must author their own catalog. Combined with CMMC Phase 2 being
suspended on 13 July 2026 — program managers may designate only Level 1 (Self) or Level 2 (Self),
no waivers, with a Reform Task Force report due around mid-September 2026 — CMMC is explicitly out
of scope here. Spending engineering effort on it now is a bad trade, and saying that is a position
rather than an omission.

## Consequences

- The mapping is only as good as FedRAMP's own, and it is not audited here. That is the right
  trade: FedRAMP's published mapping is the defensible one to rely on, and re-deriving it would be
  inventing disagreement with the authority.
- Transitive scoring is weaker than direct assessment. A control reached through an indicator
  inherits that indicator's coverage level and its stated gap, so a `partial` indicator cannot
  produce a fully evidenced control. The coverage honesty model carries through the crosswalk
  rather than being laundered by it.
- Controls no indicator touches are simply absent from the index. For a Rev5 package that absence
  is a real gap and should be reported as one — the 20x KSI set is not a superset of 800-53
  Moderate.
