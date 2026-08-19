# ADR 0009 — Model the authorization boundary as a product mode, not a perimeter

**Status:** accepted · **Date:** 2026-08-18

## Context

Every scope construct in this harness began as an infrastructure one: accounts, projects, regions,
repositories. The profile declares them, collectors iterate them, and populations are enumerated from
them.

That works when the authorization boundary is drawn around resources. It does not work when the
boundary is drawn around a **capability**:

> Text to speech, speech to text and agents, in zero-retention mode only, with third-party model and
> telephony integrations out of scope and off by default.

Nothing in that sentence is an account or a region. The same cluster, the same buckets and the same
service accounts serve both the authorized capability and the unauthorized one, and which is which is
decided by a feature flag. **That boundary moves when the flag moves**, and a harness enumerating
infrastructure will not notice — it will keep reporting on the same resources, with the same results,
after the assessed scope has changed underneath it.

This is not an edge case for AI providers specifically; it is the normal shape of a boundary for any
product authorized in one mode and sold in several.

Two failure modes follow, and they pull in opposite directions:

- **Enumerate everything.** The report describes systems outside the authorization. It overstates the
  assessment surface, and it buries real findings in noise about resources nobody is claiming.
- **Filter to a hand-maintained list.** The report silently omits whatever nobody remembered to add.
  This is the more dangerous one, because the result *looks clean* — the omission is invisible in
  exactly the way a shrinking denominator is invisible in a boolean
  ([ADR 0003](0003-evidence-bundle-contract.md)).

## Decision

**Boundary membership is declared as a selector on the resource itself, and every enumerated resource
is partitioned into exactly one of three states.**

The selector is a label on GCP or a tag on AWS, named in the profile. Partitioning is total: every
resource the enumeration returns lands in one bucket and no resource lands in two.

| State | Condition |
|---|---|
| `in` | Carries the selector with an in-scope value |
| `out` | Carries it with an out-of-scope value |
| `unattributed` | Carries neither |

### The third state is the entire point, and it fails

A resource nobody has attributed is **not evidence of anything, in either direction**. It is a
resource whose boundary membership is unknown, and an authorization boundary with unknown members is
not a boundary.

So `unattributed` is graded as a finding rather than quietly excluded or quietly included. This is the
same rule the population contract applies to an unexplained gap: the honest answer to "is this in
scope?" is sometimes "nobody has said", and that answer has to be visible. Both of the failure modes
above are avoided by refusing to guess, and by making the cost of not deciding fall on the report
rather than on the reader.

It also makes the mechanism self-maintaining in the right direction. A new resource created without
the label appears as a finding on the next collection, which is precisely the case a hand-maintained
list misses forever.

### An incomplete declaration is refused, not defaulted

`loadBoundary` throws rather than filling in blanks:

- **`boundary.description` is required.** Every artifact this harness emits quotes it, and a boundary
  nobody can describe in prose is one nobody agreed.
- **A selector is required** — `gcp_label` or `aws_tag`. Without one there is nothing to partition by,
  and defaulting would silently produce a boundary the harness invented.
- **An `out_of_scope` entry requires `excluded_by` and `attested_by`.** Excluding a capability from an
  authorization is a decision with a person behind it.

A boundary the harness guessed at is worse than no boundary, because every population downstream
inherits the guess without anyone having decided it.

## What this deliberately cannot do

**It cannot verify that an out-of-scope capability is actually switched off.**

"Third-party LLM integrations are off by default" is a claim about product configuration, not about
infrastructure, and no cloud API answers it. There is no read that distinguishes a feature flag set
to false from a feature flag that does not exist.

Those entries therefore require a named attester and are recorded as attested exclusions — the same
discipline the `manual` coverage level applies to indicators, applied to scope. They are kept out of
the pass rate rather than counted as passing, because an exclusion somebody vouched for is not a
control somebody tested.

This is the honest limit of the model: it can tell you that every resource has been attributed and by
whom, and it cannot tell you the attribution is true.

## Consequences

- **A declared capability with no attributed resource fails on its own terms.** A boundary claiming to
  cover a capability that nothing in the estate carries the label for is a declaration nobody
  implemented, and it is more likely to be a stale profile than an empty product.
- **Resources outside the boundary leave the assessment surface rather than passing.** They are not
  graded green; they are not graded. A pass rate computed over out-of-scope infrastructure would be a
  different number about a different system.
- **With no boundary declared, nothing changes.** Every resource is graded and nothing is silently
  excluded, so adding a boundary can only ever narrow scope explicitly — it can never quietly narrow
  it by being absent.
- **The label becomes load-bearing infrastructure.** Boundary membership now depends on tags being
  applied correctly and on nobody removing them, which is a real operational dependency and arguably a
  control in its own right. Org Policy constraints requiring labels are the preventive counterpart,
  and pairing them is the pattern from [ADR 0005](0005-preventive-and-detective.md).
- **The enumeration still comes from infrastructure.** The selector decides membership; it does not
  decide what gets enumerated. A capability running somewhere the profile does not declare is outside
  what this can see, which is a scoping decision the profile still owns
  ([ADR 0004](0004-crosswalk-direction.md) covers why nothing is discovered from the environment).
