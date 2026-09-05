# ADR 0011 — Sufficiency is a property of a boundary, not of an indicator

**Status:** accepted · **Date:** 2026-08-19

## Context

[ADR 0002](0002-coverage-honesty.md) set the bar for `automated`: a written argument that the
declared checks settle the indicator with nothing material left over. It predicted the level would
be rare. It turned out to be empty — zero of 46, for as long as the routing map has existed — and
the README made a virtue of that, correctly, because a zero earned by refusing to overclaim is
worth more than a percentage earned by not looking closely.

Attempting the first promotion showed the zero was measuring something other than what everyone
assumed.

Filtering all 46 by what makes the argument *impossible* rather than merely hard leaves four:
only four indicators invoke no FedRAMP-defined term, and therefore carry no `FRD-PER`
"persistently" obligation and no `FRD-IRS`/`FRD-MBI` breadth widening their population past what a
profile declares. Of those four:

- **`KSI-IAM-APM`** is permanently blocked. "Passwordless *when feasible*" is a documented human
  judgment, and no API reports feasibility.
- **`KSI-SVC-SIN`** is blocked by population. "Information" has no enumerable denominator, and
  "otherwise secured from unwanted modification" is an unbounded integrity claim.
- **`KSI-IAM-AAM`** is unaddressed and needs an identity-provider collector first.
- **`KSI-CNA-DFP`** — "the functionality and privileges for infrastructure and services are
  strictly defined" — was the only live candidate.

Its privilege clause was already settled: `gcp.iam.privileged-access` asserts that no principal
holds a primitive role **and that every binding conferring broad privilege is enumerated together
with the members it grants it to**. Enumeration is what "strictly defined" means. Only the
functionality clause was open, and it was closable — `serviceusage.googleapis.com` reports exactly
which service APIs are enabled on a project, which is not a proxy for the functional surface but
the surface itself, since an API that is not enabled cannot be called by anyone.

**And the argument still could not be written**, for a reason that had nothing to do with the
evidence: AWS has no equivalent enumeration. Services are not "enabled" on an AWS account; they are
callable in any region unless an SCP forbids it. The same two checks that settle the indicator for
a GCP estate leave a real, nameable gap on an estate that includes AWS.

Declared globally — the only thing `routes.yaml` could express — the honest answer was `partial`.
Including for every boundary where `partial` is demonstrably false.

## Decision

**An `automated` route declares the boundary its argument holds for, and the level a report shows
is the level the route resolves to against the profile being assessed.**

```yaml
coverage: automated
sufficiency:
  holds_when:
    providers_within: [gcp]
  argument: >
    ...
unautomated:
  - >
    On a boundary that includes AWS, functionality definition is unevidenced because ...
```

Four rules make this more than a conditional flag.

### 1. Both halves are mandatory

A route claiming `automated` must carry the argument **and** the gap. Where the condition does not
hold the route *is* a partial route, and [ADR 0002](0002-coverage-honesty.md) already established
that a partial with no stated gap reads as full coverage to anyone scanning a table. The same
route has to be honest in both worlds, so the validator refuses one without the other.

### 2. Prose alone is refused

`sufficiency` as a bare string is a validation error, with a message saying why. An argument that
does not state which boundary it is an argument about is the assumption that made every argument
unwritable, and it should not be quietly expressible.

### 3. Unresolvable resolves to partial

A coverage report run without a profile cannot evaluate the condition, so it reports `partial`.
Crediting automation that cannot be confirmed to apply is the same move as calling an unverified
bucket an evidence vault ([ADR 0006](0006-evidence-durability.md)), and the default has to fall on
the side that understates.

### 4. Vacuous satisfaction is refused

A profile declaring no provider at all satisfies "declares nothing outside this set" trivially. An
indicator evidenced over an empty boundary has not been evidenced, which is the same rule the
bundle contract applies to zero decidable items ([ADR 0003](0003-evidence-bundle-contract.md)),
applied one level up.

The condition vocabulary is deliberately one entry — `providers_within`. A general expression
language would make conditions unreviewable, and the point of this file is that the argument is
readable by a person.

## Consequences

- **`KSI-CNA-DFP` is the first indicator to reach `automated`**, and only for a boundary whose
  providers can enumerate their own service surface. `examples/skylark.profile.yaml` is that
  boundary and exists to demonstrate it; `examples/northwind.profile.yaml` declares AWS as well and
  resolves the same route to `partial` with its gap shown. **The same routing map, two boundaries,
  two different true answers** — which is the whole claim of this ADR in one command.
- **The headline is still `automated 0` by default**, because the default has no profile. That is
  not a face-saving default; it is rule 3.
- **The test that asserted zero was replaced rather than deleted.** The zero was never the property
  worth protecting — it was a symptom of the real one. The test now asserts that no route claims
  sufficiency unconditionally and that every route claiming it states its gap elsewhere, which is
  what the zero stood for and survives being right.
- **Coverage reports are now profile-relative and must say which profile.** A report that omits it
  is ambiguous in a way it was not before. `state.profile` already carried the service name; the
  resolved and declared levels are both emitted (`coverage` and `declared_coverage`) so a reader can
  see that a route was written to be automated and did not qualify here.
- **This makes promotion easier, and that is the risk.** The friction ADR 0002 deliberately built
  is now avoidable by narrowing a condition until the argument becomes true — `providers_within` of
  exactly the provider you happen to run. The defense is that the argument is still prose a person
  reads, and a condition narrow enough to be dishonest is visible in the same diff. It is worth
  watching whether the `automated` count climbs faster than the arguments get better.
- **Nothing else was promoted.** Three of the four candidates remain blocked for reasons that are
  now recorded above rather than rediscovered each time somebody asks why the number is low.
