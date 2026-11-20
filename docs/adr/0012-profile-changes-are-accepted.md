# ADR 0012 — The profile is recorded with the evidence, and a change to it is accepted

**Status:** accepted · **Date:** 2026-11-20

## Context

Every list in a profile is a denominator. The accounts and regions, the repositories, the ports
meant to be public and the remediation windows are what each check measures against, and the
harness declares scope rather than discovering it ([ADR 0004](0004-crosswalk-direction.md)). That
makes the profile the most consequential input a run has, and before this decision the evidence did
not record it.

A bundle's `scope` records what was examined, not what used to be. The anchor log
([ADR 0007](0007-anchor-log.md)) records how much evidence there was, not what it was measured
against. So a run under a narrower profile, with a region dropped, a repository removed or a
provider section deleted, produced evidence as internally consistent as the run before it. The
chain held, the manifest verified, the anchor grew, and the denominator had shrunk without anyone
deciding it should. The harness refuses an unexplained gap in a population; it had no equivalent
for an unexplained change to the declaration that defines every population.

## Decision

**The profile is identified in the evidence.** Every bundle carries `profile_sha256`, the SHA-256 of
the canonical form of the parsed profile it was graded against, inside its hashed body. Every
anchor entry records the profile its run used.

**A changed profile is refused until a person accepts it.** `ksi verify --anchor --profile`
reports `profile_changed` before anything is collected. `ksi publish` and `appendAnchor` refuse to
record a changed profile, so the rule holds even for a pipeline that skips verify. The only way a
new profile enters the log is `ksi anchor accept --profile <profile> --reason "..."`, which writes
the same `accepted` block a root acceptance does: who, why and when.

**The acceptance is part of the pipeline, not an improvisation.** `ccm.yml` runs it from the
`accept_profile_change` input of a manual run, after the anchor is restored and before verify, so
the entry carries the actor and the run URL. The workflow is: change the profile through review,
then dispatch the run with the reason. A scheduled run that meets an unaccepted change stops with a
message naming that input. A recovery path that exists only in someone's memory gets improvised
carelessly by whoever wants the build green, which is the lesson ADR 0007's root acceptance was
built on.

**A log that has never recorded a profile accepts the first one**, and says so. There is nothing to
have changed from, and every log written before this decision is in that state.

## Alternatives rejected

**Fail only when the boundary shrinks.** Tempting, because shrinking is the threat, and it fails on
inspection. Adding a public port or lengthening a remediation window is structurally an addition
and loosens the checks, while removing a port from `public_ports` is a narrowing that tightens them. Classifying changes as safe or unsafe is the judgment this puts in front of a
person, and a classifier would make it in advance, for every change, without reading any of them.

**Hash only the boundary-relevant keys.** Same flaw, one level down. It decides ahead of time that
contacts, alerting or thresholds cannot weaken the evidence. Some of them do, and the ones that
seem not to are cheap to accept. The cost of hashing everything is an acceptance for an edit that
did not matter, which is a sentence; the cost of hashing too little is a change nobody saw.

**Hash the file.** Comments and layout are not changes to what the evidence claims, and a rule that
fires on a reworded comment trains people to accept without reading. The hash is over the parsed
document with keys in canonical order.

**Thread the hash through every collector.** The runner stamps it onto each bundle before writing
and recomputes the content hash with the same function `buildBundle` uses. That happens before the
bundle is written or chained onto, so no earlier version exists for the new hash to disagree with,
and a new collector cannot forget it.

## Open

**Storing the profile itself, not only its hash.** The hash proves the profile changed and when.
A content-addressed copy in the locker would let `verify` or `ksi diff` say what changed, and give
an assessor the exact declaration a bundle was graded against. It would also publish the profile
with the evidence. Profiles keep secrets in environment variables by convention (`url_env`,
`token_env`), but nothing enforces that, and a pasted token would leave with the locker. Deferred
until either the convention is judged strong enough or a check refuses secret-looking values first.

## Consequences

- Any edit to a profile costs one acceptance with a reason, and the anchor log becomes the history
  of the boundary: what it was measured against, who changed it, and why.
- An acceptance is persisted only when the run that made it publishes its anchor. A run that fails
  after accepting has to be dispatched again.
- One acceptance covers the root and the profile together when both changed. The command's output
  states which of the two the entry changed, so accepting a profile change cannot silently also
  accept an unexplained root.
- Removing a section from a profile needs an acceptance like any other change. That matters most
  where a missing section takes a provider out of the boundary: the removal cannot go unrecorded.
