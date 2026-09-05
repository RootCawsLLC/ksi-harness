# ADR 0002 — Four coverage levels, and a written argument for the top one

**Status:** accepted · **Date:** 2026-08-18 · **Amended by** [ADR 0011](0011-sufficiency-is-boundary-dependent.md)

## Context

Every compliance automation tool converges on the same picture: a list of controls, a status per
control, a percentage at the top. The percentage is the product. It is also where the dishonesty
lives, and the mechanism is not fraud — it is a category error repeated until nobody notices.

The error is treating "a check passed" as "the requirement is met."

Take `KSI-CED-RAT`, which asks whether security training was **effective** across four named
cohorts. Any learning management system exposes completion percentages through an API. Wiring that
up and marking the indicator green takes an afternoon and is completely wrong: completion is not
effectiveness, and effectiveness is a judgment about whether behavior changed. The check would
pass forever. The indicator would never have been evidenced. This is the most tempting false pass
in the entire catalog, and a tool optimized for coverage percentage will take it.

The same shape recurs everywhere. `KSI-SVC-SIN` says information is "encrypted or otherwise
secured from unwanted access **or modification**." A collector can enumerate buckets and volumes
and confirm encryption at rest. It has then evidenced part of one half of the claim: not
encryption in transit, not key custody — which is the part a federal customer actually asks about
— and not integrity at all. Reporting that as a pass on `KSI-SVC-SIN` is not a rounding error.

Lula 2's README says the thing out loud, and it is worth quoting against one's own enthusiasm:
"automated tests alone were insufficient for real compliance verification." That cuts against
naive compliance-as-code, including this project.

## Decision

Every applicable indicator carries a declared coverage level in `src/routes/routes.yaml`, and each
level demands a different argument before the validator will accept it.

| Level | Means | Required |
|---|---|---|
| `automated` | Checks settle the claim with nothing material left over | `checks`, `cadence`, **`sufficiency`** — a written argument |
| `partial` | Real automated evidence that does not settle the claim | `checks`, `cadence`, **`unautomated`** — what it does not establish |
| `manual` | Automation is the wrong instrument, by decision | `cadence`, **`manual_evidence`**: `owner`, `artifact`, `why_not_automated` |
| `unaddressed` | Nothing yet, admitted | **`reason`** and **`next`** |

Four properties make this more than a labeling convention:

1. **A route claiming a check no collector implements is a validation error.** Coverage cannot be
   manufactured out of intent. `src/routes/routes.mjs` resolves every declared check against the
   collector registry.
2. **`automated` requires prose.** Not a flag — an argument that the declared checks leave nothing
   material out. If that argument cannot be written, the honest level is `partial`. The friction is
   the point.
3. **`partial` requires the gap in writing**, and the gap is printed in the coverage report and
   carried into the SDR narrative. Partial coverage with no stated gap reads as full coverage to
   anyone scanning a table.
4. **`unaddressed` requires a named next step.** A gap with no next step is a gap nobody owns.

The state model refuses to go further. `src/evidence/state.mjs` reports what the coverage
declaration is, what the evidence says, and whether the claimed cadence is borne out — and stops.
It never reports that an indicator is *met*. That is a judgment a person signs.

## The number this produces today

> **Amended 2026-08-19 by [ADR 0011](0011-sufficiency-is-boundary-dependent.md). The numbers below
> are the ones this decision produced on the day it was made, and are kept as written.**
>
> The zero held for as long as sufficiency was treated as a property of an indicator. Once it was
> recognized as a property of a *boundary*, `KSI-CNA-DFP` became promotable: the count is now 1
> against a single-provider profile and still 0 against a wider one, because the route resolves
> back to `partial` where its condition does not hold.
>
> The guard moved with it. `tests/routes.test.mjs` no longer asserts a zero — it asserts what the
> zero stood for, that no route claims sufficiency unconditionally and that every route claiming
> it states its gap elsewhere. Read the paragraph below as the reasoning, not as the current count.

**Zero of 46 applicable indicators are `automated`**, against 11 implemented checks and 20
indicators with real passing automation behind them.

That is not a placeholder. It is what happens when the bar for "automated" is a written argument
that nothing material is missing, and nobody has yet been able to write one. A test asserts the
count is zero, so promoting an indicator has to be a deliberate edit that breaks the build and
makes someone justify it.

A conventional tool would render the same evidence as somewhere north of 40% coverage.

## Consequences

- The headline number is unimpressive, and that is the intended result. A report whose worst
  number is visible at the top is a report a reviewer can use.
- Maintaining the gap prose is real work, and it goes stale if nobody edits it. Mitigated by
  making `partial` unusable without it, so the work cannot be skipped, only done badly.
- Mapping four levels onto FedRAMP's three (`Implemented`, `Partially Implemented`,
  `Not Implemented`) loses information in one direction only: nothing reaches `Implemented` while
  a gap is stated, and a test enforces it. `manual` and `partial` both land on
  `Partially Implemented`, which is FedRAMP's vocabulary being coarser than ours, not us rounding
  up.
- OSCAL's `satisfied` / `not-satisfied` is coarser still. The emitter carries the remaining gap in
  the finding text so `satisfied` cannot be read as complete.

## Alternatives rejected

- **A numeric confidence score per indicator.** Invented precision. "0.72 covered" is less
  informative than a sentence naming what is missing, and far easier to average into meaninglessness.
- **Binary pass/fail, as most tools do.** This is the thing being argued against.
- **Only shipping indicators that can be fully automated.** Would silently drop the 14 indicators
  that are genuinely judgment calls, which is the same overstatement by omission.
