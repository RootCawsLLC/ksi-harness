# Changelog

## Unreleased

A review found that three of the properties this repository argues for in its README were not
actually delivered by the code. Each of the first three entries below closes one of those gaps.

### The cadence mechanism now has history to work on

`ccm.yml` checked the repository out fresh, collected into a gitignored directory, and uploaded the
locker as an artifact nothing ever read back. Every scheduled run therefore began from an empty
locker. `observedIntervalDays` needs two runs to report an interval at all, so every cadence
assessment reported "only one run so far", `cadence_unmet` was structurally zero, and the argument
that a scheduled collection evidences FRD-PER — load-bearing for 26 of the 46 indicators — rested
on history the pipeline discarded each morning.

- The locker is restored before collection and republished after, on its own branch, via
  `scripts/locker-sync.mjs`. The clone is deliberately not shallow.
- The restored locker is verified before anything is added to it.
- Reports are still uploaded as artifacts; the evidence itself is no longer only there, because an
  artifact that expires cannot be the retention story for an indicator whose cadence is annual.

### The population reconciliation can now fail

Nine of the eleven checks derived `expected` and `examined` from the same array — `items` was
`things.map(...)` and `expected` was `things.length` — so the two could never disagree, `complete`
was true by construction, and the invariant that a claim verified over an unknown subset has not
been verified could not fire. Only the policy gate did it properly.

- `examined` is computed in `buildBundle` from the items. `expected` is the only number a collector
  supplies and must come from an enumeration made before grading.
- `population.enumerated_from` is required in practice and names that enumeration, so the
  completeness claim is reviewable instead of implied.
- `population.unexamined` itemises what the enumeration named and the check could not reach, with a
  reason each. The reconciliation string is composed from it.
- Each check now reconciles against something independent: the credential report against
  `iam:ListUsers`, branch protection against the profile's declared repositories, security groups
  against the declared regions, principals against the pre-grading listing.

### Evidence is now tamper-evident rather than corruption-evident

`integrity.content_sha256` was computed over the bundle and stored inside it, so anyone editing a
bundle recomputed it in the same motion. It detected careless edits and nothing else, while the
README described it as tamper detection.

- Each bundle carries `chain.previous_sha256`, in the hashed body rather than in the integrity
  block, linking it to the previous bundle for the same check. An edit now invalidates every later
  bundle.
- `writeManifest` pins every chain head at a point in time, so a locker rewritten end to end —
  which produces a perfectly consistent chain — is still detectable.
- `ccm.yml` signs the manifest with keyless cosign, bound to the workflow identity. A signature
  this repository's own code could forge would prove nothing about this repository's own code.
- `ksi verify` checks content hashes, chains and the manifest root.

### Fixed

- **A population that decided nothing reported `pass`.** `deriveResult` had no guard for zero
  decidable items, so a region with no security groups, a window in which every commit was a merge
  commit, or a token that could see no repositories produced an empty, complete, failure-free
  population and a green tick. The ceiling is now `warn`, and the checks that can name the empty
  subject do.
- **A second collection on the same day silently destroyed the first.** Bundles were named
  `<YYYY-MM-DD>.json`, so a failing morning run vanished behind a passing afternoon one with
  nothing left to show it happened. Filenames now carry the full timestamp and a hash prefix.
- **An unreadable pull-request lookup was recorded as an unreviewed commit.** In
  `github.change.pr-review`, a 403 on `/commits/{sha}/pulls` or on a reviews listing left `pulls`
  empty, which graded as "pushed directly to main with no pull request" — manufacturing a security
  finding out of a token scope. Unresolved review history is now a `warn` that names the reason.
- **An unreachable repository was reported as an unprotected branch.** The branch-protection
  endpoint answers 404 both for "no classic protection" and "not visible to you"; the two were
  collapsed into a synthesised record with zero required approvals. A repository probe separates
  them, and an unreachable repository is now a population gap.
- **`grantsWildcard` had three false negatives and one false positive.** Any `Condition` at all
  disqualified a grant, so `aws:RequestedRegion` — which constrains nothing about who holds admin —
  cleared a wildcard administrator; only elevation-bound conditions (`aws:MultiFactorAuthPresent`
  and friends) do that now. `NotAction` was read as `Action`, so allow-everything-except-a-few was
  invisible. Privilege-escalation actions on `Resource: "*"` (`iam:PassRole`,
  `iam:CreatePolicyVersion`, the attach/put family) were reported as unprivileged. And a user under
  a permissions boundary was reported as a standing administrator; it is now a warning that names
  the boundary this check has not read.
- **One corrupt bundle took down the whole report.** `readLocker` now reports unparseable files
  instead of throwing.
- **`pages()` could loop forever** on a service that echoed its own pagination token.

### Added

- **Cross-account collection.** `perAccount` assumes a declared `aws.collector_role` in each
  account the profile names; an account that cannot be assumed into becomes a named population gap
  rather than an absence. Previously the IAM collector refused more than one account and the others
  silently reported the ambient account's evidence, so a multi-account boundary — which is nearly
  all of them — could not be collected at all.
- **`ksi diff`** — what regressed, what was fixed, and what lost population completeness between
  two points in the locker. Item-level, because a check that was failing before and is failing now
  shows a flat result while the resource that failed may have been remediated and another broken.
- **`ksi verify`** — content hashes, chains, and the signed manifest root.
- **An SCN emitter.** The Significant Change Notification schema was already vendored and already
  registered in the ajv resolver with no emitter behind it. It takes a declared change record
  (`examples/change.scn.yaml`) and resolves the mechanical half — which indicators the change
  touches, which 800-53 controls they carry, what the evidence says about each today.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, a pull-request template, dependabot for both
  ecosystems, and `npm audit` in CI.

### Changed

- `continuous` is no longer an alias for `daily` in the cadence vocabulary. It could not have been
  distinguished before, because bundles were named by date.
- AWS SDK optional dependencies are pinned to a floor version rather than `^3.x`.
- Collector versions bumped to `2.0.0` where the population contract changed, so a bundle from
  before this release is not silently compared against one from after it.

## 0.1.0

Initial release. Continuous control monitoring for FedRAMP 20x: the consolidated rules pinned as
source of truth, eleven checks across AWS, GitHub and the IaC pipeline, a routing map whose
coverage claims are validated against the check registry, and schema-valid SDR, OCR and OSCAL
assessment-results emitters.
