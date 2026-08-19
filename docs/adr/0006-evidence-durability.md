# ADR 0006 — Put the locker in write-once storage, and make the backend prove it

**Status:** accepted · **Date:** 2026-08-18

## Context

Four mechanisms in this repository protect the evidence locker, and all four protect it against the
same thing.

The per-check hash chain means an edited bundle invalidates every bundle after it. `MANIFEST.json`
pins every chain head at a point in time. Keyless cosign binds the manifest to a workflow identity.
An RFC 3161 token binds it to an attested time ([ADR 0008](0008-rfc3161-timestamping.md)). Each is
real, and each defends against **alteration**.

All four are stored inside `.evidence/`. So the locker is defended against everything except being
removed:

```bash
# delete two-thirds of a check's history, regenerate the manifest, then:
ksi verify --evidence .evidence
#   Every bundle verifies and every chain is intact.
```

Clean, because a chain proves the consistency of what remains and can say nothing about what is
gone — and the signed manifest that would have caught it sits in the same directory as the bundles,
so whoever deleted them deletes it too.

This is not a hypothetical attacker. The ordinary version is a retention policy nobody read, a
lifecycle rule on a bucket, a `terraform destroy` in the wrong workspace, or a well-meant cleanup of
"old JSON". The result is identical: an assessor asks for six months of history and receives three,
with every integrity check passing over what is left.

FedRAMP indicators using the word "persistently" are claims about a record that continues to exist.
A control that cannot survive its own evidence being deleted has not been evidenced persistently; it
has been evidenced as of today.

## Decision

**The locker declares where it lives, and a backend claiming immutability has to prove it.**

`evidence.store` in the profile selects a backend. Each states what it guarantees rather than
implying it, using one of three levels:

| `DURABILITY` | Meaning |
|---|---|
| `none` | Anything with write access can alter or delete it |
| `versioned` | Prior states are recoverable, but a deletion is still a deletion |
| `write-once` | Objects cannot be deleted or overwritten before their retention expires |

Three rules follow.

### 1. The default makes no claim, and says so

With no `evidence.store` declared, the store is the local filesystem at `none`. `describe()` reports
that, so a coverage report generated from it cannot imply durability nobody configured. Its
`assertImmutable()` refuses outright rather than returning success — a store that cannot be write-once
must never be mistakable for one that is.

### 2. `assertImmutable()` reads the backend and refuses two configurations that look immutable

This is the load-bearing part. **A bucket with Object Lock and a bucket without are indistinguishable
from the client.** Writing to either succeeds identically, which is precisely how an ordinary bucket
comes to be described as an evidence vault in a package nobody re-checked.

- **S3 Object Lock in GOVERNANCE mode is refused.** It reads as "Object Lock: enabled" in the
  console, in a screenshot and in a package, and any principal holding `s3:BypassGovernanceRetention`
  can override it. A retention an administrator can lift does not survive the administrator being the
  problem. COMPLIANCE or nothing. Versioning and a default retention rule are checked alongside it,
  because a bucket can satisfy two of the three and remain freely deletable.
- **An unlocked GCS retention policy is refused.** GCS has no separate mode; an unlocked policy is
  simply removable by whoever set it. Same failure, different words.

The decision logic is `s3RetentionProblems()` and `gcsRetentionProblems()` — pure functions over what
the API returned, separated from the calls that fetch it. A refusal reachable only through a live
cloud call is a refusal nothing can prove still works, which is the same unfalsifiability the
population contract exists to prevent ([ADR 0003](0003-evidence-bundle-contract.md)).

### 3. Publishing never overwrites and never deletes

`publish()` uploads only objects not already present. An existing object is skipped rather than
re-put: under Object Lock a re-put creates a *new version* rather than failing, which would silently
double storage and make the version history misleading about how often evidence changed.

## Three outcomes, not two

`ksi store` reports `verified write-once`, `NOT write-once`, or `UNVERIFIED`.

The third was added after the second was wrong. An expired credential produced:

```
NOT write-once:
s3://… has no Object Lock configuration (CredentialsProviderError). Object Lock can
only be enabled at bucket creation, so this bucket cannot be made write-once — …
```

That is a finding about a bucket the run never reached. It would send someone to recreate storage
that may be entirely correct, and — worse in a report — lets a properly configured store be written
up as broken. It is the same conflation the GCP collectors disambiguate out of a 403, one cloud over.

Credential, permission and connectivity errors are now separated from answers, and reported as
`UNVERIFIED`. It still exits non-zero: an unchecked guarantee is not a passed check either.

## Consequences

- **Object Lock cannot be retrofitted.** It is enabled only at bucket creation, so an existing
  evidence bucket cannot be upgraded — the refusal names this and says to create a new bucket and
  republish, because the alternative is a guarantee that silently isn't one.
- **This repository does not use it.** `examples/self.profile.yaml` declares no store, so `ksi
  publish` reports `0 object(s) published` and durability comes from the locker branch instead. That
  is correct for a repository whose only subject is itself and whose every collected fact is already
  public. On a real boundary the same line would mean the locker never reached the vault, which is
  worth knowing before reading it as success.
- **Prevention is not detection.** Write-once storage stops deletion in one place. Evidence gets
  copied, mirrored, restored into a working directory and handed to assessors, and every copy is
  deletable even when the original is not. That is the other half, and it is
  [ADR 0007](0007-anchor-log.md).
- **The retention period is now a compliance decision with a deadline.** `retain_until` cannot be
  shortened once set, which is the point, and means picking it badly is expensive in the direction of
  paying for storage rather than in the direction of losing evidence.
