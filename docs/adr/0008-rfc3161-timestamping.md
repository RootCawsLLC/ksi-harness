# ADR 0008 — Have a third party attest when the evidence existed

**Status:** accepted · **Date:** 2026-08-18

## Context

Defensible evidence is conventionally described as having four properties: integrity, authenticity,
timeliness and completeness. Three of them were built here early. Timeliness was the weakest by some
distance, and it was weak in a way that looked finished.

`buildBundle` requires `collectedAt`, and its own comment states the value must come from a trusted
source rather than the executing runner's clock. **Nothing verified that, because nothing could.** In
practice CI passed `new Date()`. Every bundle therefore asserted its own age, which is the precise
shape of unverified claim this repository refuses everywhere else — a control reporting on itself.

The hash chain does not help. It establishes **order**: bundle N+1 carries the hash of bundle N, so
no bundle can be inserted into the middle of a check's history after the fact. What it cannot
establish is **when**, because every timestamp in the chain comes from the same untrusted clock. A
locker generated in one afternoon and dated across six months is internally consistent, verifies
cleanly, and is indistinguishable from six months of monitoring.

That matters because the thing being evidenced is frequently *recurrence*. Indicators using FedRAMP's
defined term "persistently" are claims about collection having happened repeatedly over time. If the
times are self-asserted, the claim is self-asserted.

## Decision

**Obtain an RFC 3161 token over the manifest root after each collection.**

A Time Stamping Authority signs a hash together with its own time. That converts "this evidence
claims to be from Tuesday" into "a third party attests this data existed by Tuesday" — a claim whose
falsification requires the authority's key rather than the runner's clock.

### The root is stamped, not each bundle

One network call per collection rather than one per check, and it loses nothing: the manifest names
every bundle hash and every chain head, so a token over the root attests that the entire locker *in
that state* existed at that time.

It also produces a better claim than per-bundle stamping would. Consecutive runs **bracket** each
bundle — collected after the previous run's attested time and before this one's. A bounded interval
established by two independent attestations is tighter and more honest than a self-asserted instant,
and it degrades gracefully: a missed run widens the bracket rather than invalidating it.

### DER is encoded by hand

`src/evidence/der.mjs` implements the ASN.1 subset RFC 3161 needs — roughly 170 lines. The
alternative was a dependency, and this is a supply-chain tool: `github.supply-chain.dependency-alerts`
and the third-party register both exist to make dependencies accountable, so adding one to a
cryptographic path in order to run a compliance harness would be an odd trade to make silently.

The encoder is verified against the specification's own structures rather than against itself —
the SHA-256 OID, long-form lengths, and integer encodings all have tests asserting the exact bytes.
`parseResponse` locates TSTInfo by shape rather than by offset, so a response with optional fields
present or absent parses the same way.

### No authority is defaulted

`--tsa URL` is required and has no fallback. Which third party attests a programme's evidence is a
decision for the programme: it introduces an external dependency, a jurisdiction, an availability
requirement and a trust relationship. Quietly picking one would place all four in a compliance
pipeline without anyone deciding, which is precisely the class of unreviewed dependency
`KSI-SCR-MIT` exists to surface.

## Being explicit about what is not verified

`verifyToken` checks that the response is well-formed, that `PKIStatus` was granted, that it carries
a TSTInfo with a generalized time and a SHA-256 imprint, and that **the imprint equals the digest the
token is being verified against**. That last one is the check that matters: a token over different
data is refused rather than filed.

It reports:

```
signatureVerified: false
```

**Verifying the authority's signature requires its certificate chain, and the harness does not have
one.** It says so rather than reporting a checkmark that means less than a reader would assume.

This is deliberate and slightly uncomfortable: a token whose signature nobody checked is a strong
audit artifact and a weak cryptographic proof. It is still worth having — the authority holds a
signed record of the same root, so the token is verifiable *by someone*, later, with the chain in
hand. What would not be acceptable is implying that verification already happened. A `warn` that
names the gap is the same answer this harness gives everywhere else it cannot decide
([ADR 0002](0002-coverage-honesty.md)).

A refusal from the authority — `PKIStatus` rejection, an unavailable service — is reported as a
refusal with its status and reason, not thrown away and not silently retried into a gap.

**A second gap is open and worth naming rather than discovering later.** `buildRequest` sends a
random nonce, which exists so that a response can be tied to the request that asked for it, and
nothing compares the nonce in the response against the one sent. Since the imprint is checked, a
substituted token still has to be over the same digest — so this is not a hole through which
arbitrary evidence passes. What it leaves open is *replay*: a previously obtained genuine token over
the same root would verify, which matters precisely because collections repeat over an unchanged
locker. Checking it is a small change; asserting it was checked when it was not would be the larger
error, so it is recorded here as a known limitation until it is closed.

## Consequences

- **Timeliness now has a named mechanism, and `collectedAt` is still the runner's clock.** The token
  does not correct the value inside each bundle; it bounds it externally. Reading a bundle's
  `collected_at` as attested would be wrong, and the token is what makes the difference checkable.
- **This adds a network dependency to the collection path.** The authority can be slow or down. It is
  a separate `ksi timestamp` command and a separate workflow step for that reason — a failed
  attestation must not discard a successful collection.
- **The token is stored in the locker**, which means it shares the locker's fate. That is the
  Existence problem, and it is handled by [ADR 0006](0006-evidence-durability.md) and
  [ADR 0007](0007-anchor-log.md) rather than here. The anchor benefits in return: the authority
  independently observed the same root, so anchor and token corroborate each other.
- **A fifth property surfaced while building this.** Integrity, authenticity, timeliness and
  completeness all quietly assume the evidence still exists. Nothing in the conventional four
  survives deletion, which is why there are now two ADRs about it.
