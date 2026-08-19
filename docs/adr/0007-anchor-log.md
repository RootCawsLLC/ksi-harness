# ADR 0007 — Record how much evidence there was, somewhere the locker's owner does not control

**Status:** accepted · **Date:** 2026-08-18

## Context

[ADR 0006](0006-evidence-durability.md) makes deletion impossible by putting the locker in write-once
storage. That closes the gap in exactly one place, and evidence does not stay in one place.

A locker is cloned into a CI working directory, restored from a branch, mirrored for a DR exercise,
exported for an assessor, and copied to a laptop before a meeting. Every one of those copies is
deletable even when the original is not, and every one of them still passes `ksi verify`, because a
chain proves the internal consistency of whatever it is handed.

There are also two cases where the store's guarantee is simply absent:

- **The store is misconfigured.** `ksi store` refuses GOVERNANCE mode and unlocked retention, but only
  when somebody runs it. A programme that declared a store and never verified it has a claim, not a
  control.
- **The store is not used at all.** The default is the local filesystem, which promises nothing.

In all of these, an assessor receives a locker in which every bundle verifies, every chain is intact,
and a third of the history is missing with nothing to indicate it ever existed. The failure is
undetectable from inside the artifact, because the artifact is exactly what was edited.

## Decision

**After each collection, append one line recording how much evidence there was — to a log held
outside the locker.**

Each entry carries the manifest root, the bundle count, and the **per-check run counts**, plus the
hash of the entry before it:

```json
{"schema":"ksi-harness/evidence-anchor/1","anchored_at":"…","root_sha256":"…",
 "bundle_count":42,"checks":{"aws.iam.mfa-coverage":3,…},"previous_sha256":"…"}
```

JSON Lines, because appending must never rewrite what is already there.

Four properties do the work.

### The per-check run counts, not just the root

A root alone detects that the locker changed, which is true after every legitimate collection and
therefore useless. The run counts are what make *shrinkage* visible: a check that had three runs and
now has one is a specific, nameable finding rather than a hash that no longer matches.

### The log is chained

Each entry hashes the one before it, so the log cannot be silently trimmed to match a truncated
locker. Without this, an attacker who removes evidence removes the anchor entries that recorded it
and the two agree again.

### Three findings, kept distinct

| Finding | What it means |
|---|---|
| `root_unknown` | A manifest root no anchor entry ever recorded — evidence from somewhere else, or a locker rebuilt wholesale |
| `shrunk` | Fewer runs than were anchored — history removed from a check that still exists |
| `missing_check` | A check the anchor knows and the locker no longer contains at all |

Collapsing these into one "mismatch" would lose the distinction between a locker that was replaced,
one that was trimmed, and one that had a whole check dropped — three different conversations.

### Growth is never a finding

A locker is supposed to grow. A rule that treated any divergence as tampering would fire on every
successful collection and be switched off inside a week, which is how a control becomes decoration.

## Where it lives is the design, not a deployment detail

`evidence.anchor_log` is a path, and the entire value of the mechanism is determined by where that
path resolves.

Held in a different account, a different project, or a file the assessor keeps, it detects a deletion
nobody disclosed. **Held inside the locker it protects, it is removed by whatever removes the
evidence**, and the mechanism reduces to a longer way of storing a hash beside its own data — the
exact failure that made content hashes insufficient in the first place
([ADR 0003](0003-evidence-bundle-contract.md)).

The profile comment says so, and this ADR says so, because nothing in the code can enforce it. A
path is a path.

### This repository does not achieve it, and that is worth stating plainly

`ccm.yml` sets `ANCHOR_LOG` to `.locker/anchor.jsonl` and `LOCKER` to `.locker/evidence`. The anchor
sits beside the evidence rather than inside it, which reads like separation and is not: `locker-sync
publish` commits the whole of `.locker` and pushes it, so **the anchor and the evidence reach the
same branch in the same commit and come back together on restore.** Anyone able to rewrite that
branch rewrites both.

So on this repository the anchor detects evidence lost *by accident* — a bad restore, a shallow
clone, a fetch that dropped history, a deletion nobody intended — and does not detect deliberate
truncation by someone holding push access. The first set is common and worth catching. The second is
the threat the design is written against, and it is not covered here.

Repointing the path alone would have made things quietly worse rather than better: anything outside
`.locker` is written after collection and never restored, so every run would start from a fresh
checkout, find no anchor, and report a clean reconciliation forever — the same
structurally-unfalsifiable shape as the cadence bug, in different clothes.

So the anchor is **plumbed rather than repointed**. `scripts/anchor-sync.mjs` fetches it from its own
repository before verification and appends it back after publication, under `KSI_ANCHOR_TOKEN` — a
credential that cannot write the evidence. Set `KSI_ANCHOR_REPO` and the separation is real; leave it
unset and the co-located default applies, and the script **prints which mode is in force on every
run** rather than leaving it to this document.

Two refusals in that script matter more than the transport:

- **A half-configured anchor stops the run.** `KSI_ANCHOR_REPO` without a token falls back to nothing
  — falling back to the co-located default would silently restore the weakness the second repository
  was added to remove.
- **An anchor that shrank is never published.** `publish` writes the local file over the remote one,
  so a truncated local anchor would overwrite the longer remote record — destroying the evidence of
  truncation with the very command meant to preserve it. Since the log is chained, a lost entry is
  not a missing line but a break that makes every later entry unverifiable.

### What the separation is, and what it is not

**This is separation of storage and credential, not separation of control.** Both credentials are
referenced by one workflow in one repository, so whoever can modify that workflow — or add a secret
to it — can write both sides. Someone with push access to the default branch is not stopped by this;
they are stopped by branch protection, which is a different control with different failure modes.

What it does stop is narrower and still worth having: a principal who can write the *evidence branch*
cannot rewrite the anchor, a restored or exported copy of the locker is reconciled against a record
that did not travel with it, and deleting the evidence does not delete the account of how much of it
there was.

Genuine independence would need the anchor appended by something the evidence writer cannot influence
at all — an append-only endpoint that rejects rewrites regardless of caller, or an assessor's own
copy. The RFC 3161 token ([ADR 0008](0008-rfc3161-timestamping.md)) is the closest thing here to that
property already, because the authority independently observed the same root.

**This repository still runs in the co-located mode**, because a repository whose only subject is
itself has no second trust domain to reach for. The difference is that the mode is now a
configuration choice that announces itself, rather than a property the documentation claimed and the
deployment did not have.

## What it deliberately does not prove

**The anchor cannot establish its own completeness.** Nothing self-contained can: a log and its own
integrity check share a fate, so an attacker with write access to both produces a consistent pair.
This is the same limit the hash chain has, moved one level out.

It earns its place by changing what has to survive. Protecting megabytes of bundles in an
adversary-resistant location is a real infrastructure project; protecting one append-only line per
run is a file. Shrinking the thing that must be safe is the whole contribution.

It gets one piece of external corroboration for free: the RFC 3161 token is taken over the same
manifest root ([ADR 0008](0008-rfc3161-timestamping.md)), so a third party independently observed
that value at that time. An anchor entry and a timestamp token agreeing on a root neither party could
have chosen after the fact is a stronger position than either alone.

## Consequences

- `ksi verify --anchor FILE` performs the reconciliation. **Without the flag it is not checked**, and
  `verify` says so explicitly rather than reporting a clean bill of health over an unexamined
  question — the same refusal to imply coverage that governs the coverage report
  ([ADR 0002](0002-coverage-honesty.md)).
- `ksi publish` writes the entry from the state the run actually produced, after collection and
  before the locker is pushed, so the recorded counts are the ones a later run will be compared
  against.
- The scheduled workflow verifies the restored locker against the anchor **before** collecting.
  Collecting on top of a locker that has already been truncated would extend a chain that already
  lies, and every subsequent run would inherit it.
- A first run has nothing to reconcile against, and reports that rather than passing. An empty anchor
  log is reported as empty, not treated as agreement.
- **The log is a disclosure risk of its own.** Check ids and run counts are far less sensitive than
  bundles — no account ids, no resource names, no findings — but the shape of a programme's
  monitoring is still information. It is small enough to keep private easily, which is the point.
