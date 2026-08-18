# ADR 0003 — The evidence bundle, and why population reconciliation is the whole thing

**Status:** accepted · **Date:** 2026-08-18

## Context

The unit of evidence in most compliance tooling is a check result: an identifier, a boolean, a
timestamp. It is not enough, and the reason is specific.

A check that says "all IAM users have MFA" has answered a question about a set. If the set was
built by an API call that silently paginated once and stopped, or that returned partial results
because one of three accounts denied `iam:GenerateCredentialReport`, then the check has verified
the claim over an unknown subset and reported a pass. Nothing in a boolean records that. The
failure is invisible precisely when it matters most, because a permission gap and a clean
environment produce the same green tick.

This is not hypothetical. It is the normal failure mode of evidence collection at scale, and it is
why a programme can show a 100% pass rate that means nothing.

The bundle contract here is carried over from `RootCawsLLC/grc-wizard`, where it was built against
a SOC 2 control set and shaken out in live runs. What changed for FedRAMP 20x is the key: a bundle
is keyed by `check_id` and carries the **set** of indicators it contributes to, rather than one
control id.

## Decision

An evidence bundle is a self-contained record of one check's execution, and three invariants are
enforced in `buildBundle` rather than left to each collector.

### 1. `result` is derived from `items`, never passed in

A collector cannot assert a verdict. It reports what it examined, item by item, and the result
falls out:

```
errors present                    -> error
any item failed                   -> fail
population incomplete             -> warn   (ceiling, see below)
any item warned                   -> warn
otherwise                         -> pass
```

A check carrying failing items cannot report a pass. The field a caller might set is ignored, and
a test asserts that.

### 2. An incomplete population can never be a pass

The ceiling is `warn`. A claim verified over an unknown subset has not been verified, and there is
no amount of passing items that changes it.

### 3. An unexplained population gap is refused outright

Every bundle declares `expected`, `examined` and `source_of_truth`. When `examined ≠ expected`,
`buildBundle` **throws** unless a `reconciliation` string explains the difference. An unexplained
gap is not evidence, so it is not permitted to become one.

The distinction the reconciliation forces is the useful one: "three accounts denied
`iam:GenerateCredentialReport`" is a permissions finding, while "two roles are service-linked and
cannot carry a policy" is a scoping decision. Both are gaps. Only one is a problem, and a boolean
cannot tell them apart.

### Supporting properties

- **Content hash over canonical JSON.** Keys are sorted before hashing, so an unchanged control
  hashes identically across runs and the locker is diff-quiet. A control that did not change
  produces no diff; one that did produces exactly one.
- **`collected_at` is a required argument**, not `Date.now()`. The executing runner's clock is not
  an acceptable evidence timestamp, and requiring the caller to pass one keeps that decision
  visible instead of hidden behind a default.
- **`unimplementedBundle`** exists so an unwritten check cannot be mistaken for a passing one. It
  reports `error` over a zero-item population, which is exactly what it is.
- **Fixture-derived bundles are marked** `scope.fixture = true`, and that marker is carried all the
  way into the emitted SDR's validation text. Demo evidence that could pass for live evidence is
  the most embarrassing possible failure of a tool like this.

## Many-to-many, deliberately

A bundle declares `ksis: [...]`, not `ksi: "..."`.

A Key Security Indicator is a capability claim broad enough that no single check settles it, and
one check frequently contributes to several. `aws.config.recorder-state` bears on `KSI-CNA-EIS`,
`KSI-MLA-EVC` and `KSI-SVC-ACM`, and each of those needs different additional evidence before
anything could be claimed. Modelling that edge as one-to-one would force either duplicate
collection or a lie about scope.

The indicator-level judgement is therefore assembled in `src/routes` and `src/evidence/state.mjs`,
and it is deliberately **not** something a check can make about itself. A collector reports; the
routing map decides what that is worth.

## Consequences

- Collectors are more work to write. Every one has to establish its own denominator from an
  authoritative source and account for anything it could not reach. That is the cost, and it buys
  the only property that makes the evidence worth keeping.
- Bundles are large. A run over a real boundary produces per-item detail, not a summary. Accepted:
  an assessor asking "which resources" should get an answer, and storage is cheap relative to a
  certification cycle.
- Some checks legitimately cannot complete their population, and they land on `warn` permanently
  until the access is fixed. That is the correct reading and it puts the permissions gap on the
  report instead of in a log.
