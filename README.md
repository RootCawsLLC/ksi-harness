# ksi-harness

Continuous control monitoring for **FedRAMP 20x**. It pins FedRAMP's own machine-readable rules as
the source of truth, collects live cloud evidence with population reconciliation, gates
infrastructure changes before merge, and emits schema-valid 20x artifacts.

It is also an argument about how compliance automation should report, which is the part that took
longer than the code.

```bash
npm install
npm run demo          # end to end against fixtures, no credentials needed
```

---

## The headline number is zero, and that is the point

```
FedRAMP Consolidated Rules 2026.07.14.01  ·  Class C
46 applicable indicators of 46 in the ruleset

automated      0
partial       20
manual        14
unaddressed   12
```

There are 11 implemented checks and 20 indicators with real, passing, chain-verified automated
evidence behind them. A conventional tool would render that as somewhere north of 40% coverage.

This one reports **zero automated**, because an indicator only reaches `automated` when someone
writes an argument that its checks leave nothing material out — and nobody has been able to write
one yet. A test asserts the count stays zero, so promoting an indicator has to be a deliberate edit
that breaks the build and makes someone justify it.

Consider `KSI-CED-RAT`, which asks whether security training was **effective** across four named
cohorts. Every LMS exposes completion percentages through an API. Wiring that up and marking the
indicator green takes an afternoon, and is entirely wrong: completion is not effectiveness. The
check would pass forever and the indicator would never have been evidenced. That is the most
tempting false pass in the catalog, and a tool optimised for a coverage percentage will take it.

So this one declares, for all 46 indicators, exactly how each is evidenced and what the evidence
does not establish. Full reasoning in [ADR 0002](docs/adr/0002-coverage-honesty.md).

## Why not OSCAL

**FedRAMP 20x does not use OSCAL**, and building on it here would be the wrong call.

Rule `FRC-CSO-JSN` requires JSON valid against FedRAMP's own lightweight schemas.
[RFC-0024](https://www.fedramp.gov/rfcs/0024/) states plainly that it "applies only to the FedRAMP
Rev5 process and does not apply to FedRAMP 20x." FedRAMP processed 100+ Rev5 authorizations in 2025
with **zero OSCAL submissions**, and no Phase 1 20x pilot used it. Thoughtworks kept OSCAL at
*Assess* through Radar Vol. 33 and dropped it in Vol. 34, while rating "continuous compliance"
*Adopt*. The practice graduated; the format did not.

Not deprecated — decisively de-emphasized. Excluded from the future path, demoted on the legacy
path, and openly inviting replacements: `LMR-FRX-LAF` says industry is "strongly encouraged to
create innovative solutions that can compete with or replace OSCAL."

**So this harness is machine-readable first and format-pluggable.** Control state lives in an
internal schema. FedRAMP 20x SDR and OCR are the primary emitters, validated against the vendored
schemas before writing. **An OSCAL emitter ships beside them**, behind the same interface, because
Rev5 runs to September 2027, customers ask for OSCAL regardless, and the emitter is 200 lines when
the state model does the work. Reasoning, including the counter-case for OSCAL, in
[ADR 0001](docs/adr/0001-format-strategy.md).

---

## What it does

```
FedRAMP/rules + FedRAMP/schemas        pinned by sha256, drift-checked
        │
        ▼
  catalog (46 indicators, 10 themes, 209 controls, 195 definitions)
        │
        ├── routes.yaml ──────────── coverage declaration + written gaps
        │
        ▼
  collectors ── AWS · GitHub · pipeline ──► evidence bundles (hash-chained, signed)
        │                                    population reconciliation
        ▼
  control state ──┬──► FedRAMP 20x SDR    (ajv-validated)
                  ├──► FedRAMP 20x OCR    (ajv-validated)
                  ├──► FedRAMP 20x SCN    (ajv-validated, from a declared change)
                  ├──► OSCAL assessment-results
                  ├──► coverage report (Markdown + JSON)
                  └──► change report, locker-over-time (Markdown + JSON)

  policy/rego ──► conftest gate, pre-merge ──► folded back in as evidence
```

### The ruleset is pinned, not fetched

`vendor/fedramp/` holds the consolidated rules and all ten FedRAMP schemas, pinned by SHA-256 in
`PINNED.json`. Nothing is restated in this repository's own files — indicator text, control
mappings and parameter values are resolved from the pinned file at run time, so a ruleset bump does
not turn into a hunt through hand-copied strings.

```bash
npm run vendor:verify   # fails if a vendored file no longer matches its pin
npm run drift           # compares the pin against upstream, names the routes affected
```

Drift in the upstream ruleset is a distinct failure from drift in the environment, and it is the
one nobody watches. A new indicator, or a changed statement, silently invalidates the routing map
and every narrative generated from it.

### Evidence bundles, and the invariant that matters

A check that reports "all IAM users have MFA" has answered a question about a set. If that set came
from an API call that silently stopped paginating, or that returned partial results because one of
three accounts denied `iam:GenerateCredentialReport`, the check verified the claim over an unknown
subset and reported a pass. A boolean cannot record that, and a permission gap and a clean
environment produce the same green tick.

So every bundle declares `expected`, `examined`, `enumerated_from` and `source_of_truth`, and five
invariants are enforced centrally rather than per collector:

1. **`result` is derived from `items`, never passed in.** A check carrying failing items cannot
   report a pass.
2. **An incomplete population can never be a pass.** The ceiling is `warn`.
3. **An unexplained population gap throws.** `examined ≠ expected` requires either an itemised
   `unexamined` list or a written `reconciliation`, because "three accounts denied the call" is a
   permissions finding while "two roles are service-linked and cannot carry a policy" is a scoping
   decision — and both are invisible in a boolean.
4. **A population that decided nothing can never be a pass.** Zero decidable items — every item
   `not-applicable`, or no items at all — means the assertion was never exercised, so the ceiling
   is `warn` however clean the rest looks.
5. **`examined` is computed from the items, so `expected` is the only number a collector supplies**
   — and it has to come from an enumeration made *before* grading, named in `enumerated_from`.

The fifth is the one that took a second pass to get right, and it is worth being explicit about
because this section previously described a property the code did not have. Nine of the eleven
checks derived both ends of the population from the same array: `items` was `principals.map(...)`
and `expected` was `principals.length`. Those cannot disagree. `complete` was true by construction,
and invariant 2 — the thing this whole section is an argument for — could not fire on any check
that mattered. Only the policy gate did it properly, walking the working tree for its denominator
and reading the report only for its numerator.

The denominator now comes from somewhere other than the numerator in every check: the credential
report is reconciled against `iam:ListUsers`, branch protection against the repositories the profile
declares, security groups against the declared regions, principals against the listing taken before
any policy document was fetched. A user created since the credential report was last generated is a
named gap rather than a quietly smaller denominator.

```
warn  aws.iam.privileged-access  (8 item(s))  [8/9 examined]
      role/LegacyOps — AccessDenied on iam:ListAttachedRolePolicies
```

Invariant 4 was a real hole rather than a hypothetical one. `aws.network.ingress-exposure` over an
account with no security groups returned `pass` with zero items; so did `github.change.pr-review`
over a window in which every commit was a merge commit. Both are the empty-set pass this project
exists to refuse, arriving through the one door nobody had closed. Details in
[ADR 0003](docs/adr/0003-evidence-bundle-contract.md).

### The evidence is chained, because a hash stored beside its own data proves very little

Every bundle is content-hashed over canonical JSON, so an unchanged control produces no diff and a
changed one produces exactly one. That is worth having, and it is *not* tamper detection — which
this README used to claim it was. The hash sits inside the file it covers, so anyone editing a
bundle recomputes it in the same motion. It catches corruption and careless edits, and nothing
adversarial.

So every bundle also carries `chain.previous_sha256`, in the hashed body rather than in the
integrity block, linking it to the previous collection for the same check. Editing one bundle now
invalidates every bundle after it:

```bash
ksi verify --evidence .evidence --manifest .evidence/MANIFEST.json
```

```
chain  aws.iam.mfa-coverage run 1 (2026-08-18T14:10:52Z):
       expected previous 2ef042a5c9f1, stored 8b95a73a04e2
```

A chain only proves internal consistency, and anyone who rewrites a locker end to end produces a
perfectly consistent chain with a different head. So `MANIFEST.json` pins every chain head at a
point in time, and `ccm.yml` signs it with keyless cosign bound to the workflow's own identity — a
signature this repository's code cannot forge, which is the only kind worth anything here.

One file per collection, named by timestamp and hash prefix rather than by date. Two runs in a day
used to produce one file, so a failing morning run disappeared behind a passing afternoon one with
nothing left to show it had happened, in a locker whose entire premise is that the history *is* the
evidence.

### 11 checks across three families

| Check | Indicators |
|---|---|
| `aws.iam.mfa-coverage` | KSI-IAM-APM |
| `aws.iam.privileged-access` | KSI-CNA-DFP · KSI-IAM-ELP · KSI-IAM-JIT |
| `aws.logging.trail-integrity` | KSI-CMT-LMC · KSI-MLA-LET · KSI-MLA-OSM |
| `aws.logging.log-access` | KSI-MLA-ALA |
| `aws.network.ingress-exposure` | KSI-CNA-MAT · KSI-CNA-RNT · KSI-CNA-ULN |
| `aws.data.encryption-at-rest` | KSI-SVC-SIN |
| `aws.config.recorder-state` | KSI-CNA-EIS · KSI-MLA-EVC · KSI-SVC-ACM |
| `github.change.pr-review` | KSI-CMT-LMC · KSI-CMT-VTD |
| `github.change.branch-protection` | KSI-CMT-RMV · KSI-CMT-RVP |
| `github.supply-chain.workflow-pinning` | KSI-SCR-MIT · KSI-SVC-VRI |
| `pipeline.iac.policy-gate` | KSI-CMT-VTD · KSI-CNA-EIS · KSI-MLA-EVC |

The mapping is many-to-many on purpose. A KSI is a capability claim broad enough that no single
check settles it, and one check often bears on several. A route claiming a check no collector
implements is a **validation error** — coverage cannot be manufactured out of intent.

### Preventive and detective, paired

Every rule in `policy/rego/terraform.rego` names the indicator it enforces, and that indicator also
has a collector. The same claim is gated before merge and verified after deploy, because a gate
cannot see a security group edited in the console and a collector cannot stop the edit.

Then the gate's own result is folded back in as an evidence bundle. That step is usually skipped: a
red X in a pipeline is a real control, but a run log that ages out is not evidence of one, and
`KSI-MLA-EVC` singles out infrastructure as code *especially* — which no collector reading deployed
state can evidence.

The gate enumerates its population **from the working tree, not from the report**. Counting the
report's own entries would make the reconciliation circular: a file skipped by a bad `--policy`
path would simply not appear, and the gate would report clean over a shrinking denominator.

```bash
npm run policy    # opa unit tests, then the gate, then the negative control
```

`policy/terraform/violations/` is non-conforming on purpose and the run **fails if it comes back
clean**. That is not decoration. Writing these policies produced two bugs that both showed green:
rules reading the wrong input shape so every positive-form rule matched nothing, and an IAM rule
that missed the string form `"Action": "*"` — the most common way to write a full administrative
grant. Twenty unit tests passed throughout, because the fixtures were hand-written JSON in the
shape I assumed rather than the shape conftest emits. See
[ADR 0005](docs/adr/0005-preventive-and-detective.md).

### It says what it cannot decide

The gate reads Terraform configuration, so `policy = jsonencode({...})` — how nearly everyone
writes an IAM policy — arrives as an unresolved expression. Rather than pass quietly, it reports:

```
WARN  KSI-IAM-ELP: the policy document on aws_iam_role_policy.reader is built by an unresolved
      expression and was not evaluated. Run this gate against `terraform show -json` plan output
      to decide it.
```

A silent pass and a clean result would be indistinguishable, and that is the difference between a
control and a decoration. The policies already accept plan input.

---

## Usage

```bash
ksi catalog --class c                    # the indicator catalog for a certification class
ksi explain KSI-IAM-APM                  # statement, FedRAMP-defined terms, controls, routing
ksi checks                               # every check and the indicators claiming it
ksi routes validate                      # the routing map against catalog + registry
ksi collect --profile P [--fixture DIR]  # run collectors, write bundles
ksi coverage --md out/coverage.md        # the coverage report
ksi diff [--from TS] [--to TS]           # what moved in the evidence between two points
ksi verify [--manifest FILE]             # content hashes, chains, and the signed manifest root
ksi emit sdr --overview-uri URI          # sdr | ocr | scn | oscal-ar
ksi drift                                # upstream ruleset drift, and the routes affected
```

`ksi emit scn` additionally takes `--change FILE`. A Significant Change Notification is a statement
about an *intended* change — its type, its rationale, its timeline — and none of that is observable
in configuration, so generating it from evidence drift would be inventing a decision nobody made.
The change record (`examples/change.scn.yaml`) carries the judgements; the emitter resolves the half
that is mechanical and easy to get wrong: which indicators the change touches, which 800-53 controls
those indicators carry, and what the evidence says about each of them today. A change proposed while
the indicators it touches are already failing is a different filing from the same change proposed
from a clean baseline, and the reviewer should not need a second document to find that out.

The **profile** (`examples/northwind.profile.yaml`) is where the boundary is *declared*. Nothing
discovers scope from the environment — a deliberate constraint, not a missing feature. If collection
enumerated whatever it could see, a new account or repository would join the authorization boundary
without anyone deciding it should, and the evidence would quietly redefine what was certified.

Class C is the practical ceiling: **Class D does not exist yet.** High has no 20x path and stays on
Rev5, with a pilot targeted for FY27. `CLASSES` rejects `d` rather than letting anyone generate a
package for a class FedRAMP will not accept.

### Live runs

```bash
export AWS_REGION=us-east-1 GITHUB_TOKEN=ghp_...
ksi collect --profile examples/northwind.profile.yaml --out .evidence
```

AWS credentials come from the standard chain; prefer OIDC and a read-only role. A permanent CI
access key would fail two of this harness's own checks, which is worth sitting with.

A boundary of more than one account needs `aws.collector_role` in the profile — a read-only role
this harness assumes in each account — and the run is refused without it. The refusal is the point:
collecting several accounts on one ambient credential files the same account's evidence under every
account id in the boundary, producing a complete-looking report over accounts nobody visited. An
account the role cannot be assumed into becomes a named gap in every affected population:

```
warn  aws.iam.mfa-coverage  (6 item(s))  [6/7 examined]
      account/210987654321 — could not assume arn:aws:iam::210987654321:role/KsiHarnessReadOnly
```

This is also where the population reconciliation earns its keep in practice rather than in
principle. Three accounts declared, two collected, one denied is exactly the case the whole contract
was written for, and it was unreachable while cross-account collection did not exist.

`ksi collect` exits non-zero when a collector could not run at all, so a credentials failure cannot
pass as a quiet, evidence-free success.

### This repository is one of its own subjects

Fixtures prove the grader works. They do not prove it survives a real API, so the GitHub half runs
against `ksi-harness` itself:

```bash
export GITHUB_TOKEN=$(gh auth token)
ksi collect --profile examples/self.profile.yaml --only github --out .evidence-live
```

```
fail  github.change.pr-review
pass  github.change.branch-protection
pass  github.supply-chain.workflow-pinning
```

**The two change-management checks disagree, and that is the entire argument for running both.**
`main` genuinely does require a review, dismiss stale approvals on new commits, include
administrators, and permit no bypass actor — so `branch-protection` passes on evidence nobody
authored. `pr-review` fails anyway, and it fails in two distinguishable ways:

- `Pushed directly to main with no pull request` — the commits that built this repository, made
  before the protection existed. No settings change makes them retroactively reviewed.
- `Merged via #N with no approving review` — a change that *did* go through a pull request and pass
  every required check, merged by an administrator who temporarily lifted the admin requirement
  because a solo maintainer cannot approve their own pull request.

**The second one is the interesting one: the harness caught its own author bypassing its own gate.**
Nothing in the branch protection settings records that this happened. The setting was restored
within seconds and reads as fully compliant now, and the only durable trace is in the commit
history — which is exactly where this check looks.

A harness that read only the configuration would report this repository as fully controlled. Reading
the settings tells you what is *supposed* to happen; reading the commits tells you what did. The gap
between the two is where unreviewed code lives, and it is why both checks exist rather than
whichever is cheaper to collect. It is also why `KSI-CMT-VTD` carries **bypass rate** as a named
unautomated gap in `routes.yaml` rather than a silent omission: that number is the one an assessor
should ask for, and this repository's own is not zero.

The failure is left standing. Making it green would mean rewriting history or trimming the
population, and both are worse than a report that says what happened.

---

## Continuous, on a schedule

`.github/workflows/`:

| Workflow | What it does |
|---|---|
| `ci.yml` | Verify the pin, validate routes, lint the workflows, audit the dependency tree, 185 tests, then collect twice → verify the chain → report → diff → emit → schema-validate end to end |
| `policy.yml` | OPA unit tests, the gate with its negative control, then the gate result as an evidence bundle. Checkov findings are advisory, but its execution is verified |
| `ccm.yml` | Restore the locker, collect via OIDC, report, diff against the last collection, sign the manifest, publish the locker, and raise an issue when evidence stops supporting a claim |

The schedule is itself the control. Several indicators use the word "persistently" — which FedRAMP
*defines* rather than leaving to the reader — and a check that runs when someone remembers to run it
does not satisfy it. The harness records collection history and compares the observed interval
against each route's declared cadence, so an unreliable schedule surfaces as a cadence failure in
the report rather than as an absence nobody notices. Event-driven cadences are exempt rather than
passed: a per-incident review is not overdue because no incident happened.

**That mechanism did not work, and the way it failed is worth writing down.** The scheduled workflow
checked the repository out fresh, collected into a gitignored directory, and uploaded the locker as
an artifact that nothing ever read back. Every run therefore started from an empty locker.
`observedIntervalDays` needs two runs to report an interval at all, so every cadence assessment
returned the same thing:

```
KSI-CMT-LMC  claimed daily · met: true · observed_interval_days: null
             "Fresh (0.0 days old); only one run so far, so the interval is not yet established"
```

`cadence_unmet` was structurally zero. It could not have been anything else. The code was right, the
argument was right, and the pipeline threw away the one input the argument depended on — which is a
more instructive failure than a wrong comparison would have been, because everything looked green.

The locker is now restored before collection and republished afterwards, on its own branch, by
`scripts/locker-sync.mjs`. The clone is deliberately not shallow: the locker's own history is the
evidence of recurrence, and a depth-1 clone would discard it while appearing to work. The restored
locker is verified before anything is added to it, because collecting on top of a broken chain
extends a chain that already lies.

A branch is the default because this repository monitors *itself*, where every fact in the locker is
already public. **It is the wrong default for a real boundary.** A bundle names accounts, roles,
buckets and failing resources — an accurate inventory of where a boundary is weakest — so point
`KSI_EVIDENCE_BRANCH` at nothing and send the locker to a private append-only store instead. S3 with
Object Lock is the obvious one.

### What changed since the last collection

```bash
ksi diff --evidence .evidence --md out/diff.md
```

The question a coverage report cannot answer. Item-level rather than result-level, because a check
that was failing before and is failing now shows a flat result while the specific resource that
failed may have been remediated and a different one broken — two findings and one fix, not a
straight line. It separates a resource that was *fixed* from one that simply left the population,
and it reports a population that stopped being complete even when the verdict did not move, which is
the regression a result-only diff hides entirely: the same answer over a smaller subject.

`ccm.yml` decides live-versus-fixture **once, explicitly, and says which it used**. Falling back to
fixtures silently would put demo data in a locker that everything downstream treats as real. Every
fixture bundle is marked `scope.fixture = true`, and the marker is carried into the emitted SDR's
validation text.

---

## Tests

```bash
npm test          # 185 tests
npm run policy    # policy unit tests + gate + negative control (39 Rego tests)
```

The suite is written to test the refusals, not the happy path: that a bundle cannot report an
unearned pass, that the routes validator rejects each way a declaration can drift into optimism,
that an empty locker yields `no-evidence` rather than a clean bill of health, that stale evidence
fails its cadence, that the emitted SDR never says `Implemented` while a gap is stated, and that
this repository's own workflows pass the action-pinning check it ships.

`tests/population.test.mjs` exists specifically because the reconciliation used to be unfalsifiable.
Every test in it hands a check an enumeration naming more than the grading could reach and asserts
the gap survives into the bundle — a credential report missing a user `iam:ListUsers` returned, a
repository the profile declares that the API would not answer for, a principal whose policies were
denied. If a future change reverts a denominator to `items.length`, those tests are what notices,
because everything else about such a check still looks correct.

The same file pins the two directions a permission gap must not be read as: a check that could not
decide anything reports `warn` rather than `pass`, and a commit whose review history could not be
read reports `warn` rather than `fail`. The second one was a live bug — an unreadable
`/commits/{sha}/pulls` response graded as "pushed directly to main with no pull request", turning a
token scope into a security finding.

Catalog assertions run against the **pinned** ruleset rather than remembered numbers, so a ruleset
bump is expected to move them. That is one of the places the harness notices the ground moved.

---

## Decisions

| | |
|---|---|
| [0001](docs/adr/0001-format-strategy.md) | Machine-readable first, format-pluggable — and why not OSCAL |
| [0002](docs/adr/0002-coverage-honesty.md) | Four coverage levels, and a written argument for the top one |
| [0003](docs/adr/0003-evidence-bundle-contract.md) | The evidence bundle, and why population reconciliation is the whole thing |
| [0004](docs/adr/0004-crosswalk-direction.md) | Crosswalk from indicators to controls, not the reverse |
| [0005](docs/adr/0005-preventive-and-detective.md) | Pair every gate with a collector, and keep the gate's output as evidence |

## What this is not

- **Not a certification.** It produces schema-valid artifacts; it does not produce an authorization.
  `ksiAssessment` is left for the assessor and deliberately not generated — writing it would be the
  exact conflict of interest a 3PAO exists to remove.
- **Not complete.** 12 indicators are `unaddressed`, each with a stated reason and a named next
  step. Two are blocked on distribution rather than effort: CIS Benchmarks sit behind member
  distribution and cannot be vendored into a public repository.
- **Not a substitute for judgement.** Lula 2's README, worth quoting against one's own enthusiasm:
  "automated tests alone were insufficient for real compliance verification." That cuts against
  naive compliance-as-code, including this.
- **No real evidence is committed to this branch.** A bundle names accounts, roles, buckets and
  failing resources — an accurate inventory of where a boundary is weakest. `.evidence/` is
  gitignored. The scheduled run publishes its locker to a separate `evidence` branch, which is
  acceptable *here* because this repository's only subject is itself and every fact it collects is
  already public. For any real boundary, unset `KSI_EVIDENCE_BRANCH` and point the locker at a
  private append-only store; retention is a compliance property rather than housekeeping, so it
  needs somewhere durable and write-once rather than somewhere convenient.

## Scope notes

**CJIS** is an 800-53 Rev 5 overlay, not a new programme. v6.0 restructured onto the Rev 5 catalog
using 800-53 identifiers verbatim; the genuine deltas — fingerprint-based personnel screening, the
Appendix H Security Addendum, agency-held keys — are personnel and contractual, so they are `manual`
routes. There is no central certifying body, so it repeats per state CSA.

**CMMC is out of scope, deliberately.** It is legally pinned to 800-171 **Rev 2** (32 CFR 170.2
incorporates the February 2020 revision by reference) while `usnistgov/oscal-content` ships only
**Rev 3** — NIST publishes OSCAL for the revision that does not legally apply, and there is no Rev 2
catalog at all. Phase 2 was suspended on 13 July 2026, with only Level 1 (Self) and Level 2 (Self)
designatable. Spending engineering effort there now is a bad trade.

## Licence

Apache-2.0. The evidence bundle contract is carried over from `RootCawsLLC/grc-wizard`, where it was
built against a SOC 2 control set and shaken out in live runs.
