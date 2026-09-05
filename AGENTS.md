# Working in this repository

Notes for anyone — human or agent — changing this code. FedRAMP ships an `AGENTS.md` in
[`FedRAMP/rules`](https://github.com/FedRAMP/rules) for the same reason: the ruleset is meant to be
read by machines, and so is this.

## The one rule

**Never let a check report a pass it has not earned.**

Every other convention here follows from that. A compliance tool that overstates is worse than no
tool, because it manufactures confidence that survives until an assessor tests it. If a change makes
the numbers look better, the first question is whether it made them more true.

## Ground truth lives in `vendor/`, not in this code

Indicator text, control mappings, FedRAMP-defined terms and organization-defined parameter values
are resolved from the pinned ruleset at run time.

- **Do not restate rule content in source, tests, or docs.** Resolve it through
  `src/catalog/rules.mjs`. A hand-copied statement is a statement that goes stale while reading as
  current.
- Changing the pin is `npm run vendor:sync`, never a manual edit. `PINNED.json` records the hash and
  `npm run vendor:verify` fails the build if a vendored file drifts from it.
- Catalog tests assert against the pinned ruleset on purpose. A ruleset bump is *expected* to move
  them — that is one of the places the harness notices the ground moved. Do not write assertions
  designed to survive any ruleset.
- `CTL` is easy to miss: it holds FedRAMP's parameter values and is not described in FedRAMP's own
  `AGENTS.md`. Anything generating Rev5 material needs it.

## Adding a collector

1. Create `src/collectors/<provider>/<domain>.mjs` exporting `VERSION`, `PATH`, `CHECKS` and
   `collect()`.
2. Keep grading **pure and exported** — `gradeX(data)` taking plain data and returning
   `{ items, population, metric }`. Fetching stays separate. This is what makes a collector testable
   without credentials, and every existing one follows it.
3. Establish the population from an **authoritative source**, and name it in `source_of_truth`. Not
   "what the API returned" — what the complete set is. When you cannot reach all of it, set
   `population.reconciliation`; `buildBundle` throws on an unexplained gap, which is intended.
4. Add a fixture under `fixtures/collectors/`. Every check must be demonstrable offline.
5. Register in `src/collectors/registry.mjs`.
6. Add a route in `src/routes/routes.yaml`, or `ksi routes validate` fails: a check no route claims
   is evidence collected for nothing.

### Statuses mean specific things

| Status | Use when |
|---|---|
| `pass` | The item satisfies the assertion |
| `fail` | It does not |
| `warn` | Something is wrong but not a violation of *this* assertion — or you could not fully verify it |
| `not-applicable` | The assertion does not apply, and the item must leave the denominator |

`not-applicable` is not a polite `pass`. A service-linked role that cannot carry a policy is
not-applicable; a role that could and does not is a `fail`. Getting this wrong inflates the pass
rate, which is the failure mode this whole design exists to prevent.

## Adding an emitter

Implement `emit(state, options) -> document` and register it in `src/emit/index.mjs`.

Emitters read **only** the control state. They may not reach the evidence locker, the collectors, or
the ruleset. If an emitter needs something the state does not carry, add it to the state — that
constraint is the entire format-pluggability argument (ADR 0001) and it is what makes adding or
replacing a format cheap.

Validate against a vendored schema on the write path if one exists. Failing at emit time is free;
failing at submission time is not.

## Adding a policy rule

1. Name the indicator in the message text: `KSI-SVC-SIN: <resource> <what is wrong>`. The pipeline
   collector recovers indicator ids from finding text, so the prefix is load-bearing, not a comment.
2. Handle **both input shapes**. `resources(kind)` normalizes conftest's HCL parse and
   `terraform show -json` plan output. Do not read `input.resource` directly.
3. Write the triggering **and** non-triggering case. Derive fixtures from real `conftest parse`
   output, not from the shape you assume — hand-written fixtures in an assumed shape are how this
   file previously had twenty passing tests over policies that matched nothing.
4. If configuration alone cannot decide it, `warn` that it was not evaluated. Do not stay silent. A
   silent pass and a clean result must never be indistinguishable.
5. `npm run policy` runs the unit tests, the gate, and the negative control. The negative control
   directory is non-conforming on purpose and the run fails if it comes back clean.

## Coverage levels are a contract

Read [ADR 0002](docs/adr/0002-coverage-honesty.md) before touching `routes.yaml`.

- `automated` requires a written `sufficiency` argument that the checks leave nothing material out,
  **and the argument must name the boundary it holds for** — sufficiency is a property of a boundary,
  not of an indicator (ADR 0011). Where the condition does not hold the route resolves back to
  `partial` and reports the gap underneath it, so a promotion never widens a claim by accident.
  `KSI-CNA-DFP` is the only indicator that qualifies today. The count was zero for as long as the
  routing map existed and that zero was worth more than a percentage — but it was a symptom of the
  property, not the property itself, so do not read the 1 as permission for a second.
  `tests/routes.test.mjs` guards the property directly now: every `automated` route carries an
  argument, a non-empty `holds_when`, and an `unautomated` gap for everywhere else. A promotion
  missing any of the three fails there. Promote deliberately, in the same commit, argument written.
- `partial` requires `unautomated` naming what the checks do not establish. Write it for a sceptical
  reader who will quote it back. It is printed in the coverage report and carried into the SDR.
- `manual` requires an owner, an artifact and why automation is the wrong instrument. Manual is a
  decision, not a backlog item; otherwise it is `unaddressed` wearing a better label.
- `unaddressed` requires a `reason` and a `next`. A gap with no next step is a gap nobody owns.

## Commit guards

`npm run setup` pins the commit identity in local config and arms `.githooks/pre-commit`, which
enforces it. Those are different jobs: `git -c user.name=...` walks straight past local config,
and a fresh clone or a new worktree has none until somebody runs setup. Before this hook existed,
`.githooks/` here was an empty untracked directory and `core.hooksPath` was unset, so commits were
checked by nothing at all.

The hook refuses three things:

- an author name that is not `RootCawsLLC` (or `$KSI_GIT_LOGIN`);
- an address that is not a GitHub noreply for that login — the owning account rejects pushes
  exposing a private address, and such a commit has to be rewritten rather than fixed forward;
- a commit in the **primary checkout**. Work belongs in a linked worktree, one per session, so two
  sessions cannot share an index. `node ~/.claude/scripts/worktree.mjs add ksi-harness <branch>`
  makes one; `ALLOW_PRIMARY_COMMIT=1` is the deliberate exception. Staged changes survive a
  refusal.

**`.githooks/` must stay tracked.** `core.hooksPath` is the relative path `.githooks`, resolved by
git against each working tree — so an untracked hooks directory exists only in the checkout that
created it, and every linked worktree silently runs no hooks at all.

## Things that will get reverted

- Marking an indicator `automated` without the argument.
- Deriving a population from the tool's own output rather than from an independent source of truth.
- Catching an error and returning an empty result — that turns a failure into a pass. Report it.
- Defaulting `collectedAt` to `Date.now()`. The runner's clock is not an evidence timestamp.
- Committing real evidence bundles. They name accounts, roles, buckets and failing resources.
- Unpinned GitHub Actions. This repository ships `github.supply-chain.workflow-pinning` and a test
  asserts its own workflows pass it.

## Commands

```bash
npm run setup            # pin the commit identity AND arm .githooks (local config only)
npm test                 # 430 tests
npm run policy           # policy unit tests + gate + negative control
npm run vendor:verify    # the ruleset pin still matches
npm run routes:validate  # routing map against catalog and registry
npm run demo             # the whole path against fixtures
npm run drift            # upstream ruleset drift and the routes affected
```

### Recovering an anchor gap

`verify` runs before collection and the anchor is written after publication, so a run whose locker
root is in no anchor entry dies before reaching the step that would record it. Fail-closed is
correct; the state used to have no exit, and a run that got past `verify` and then failed to push
the anchor widened the gap it had just failed to close.

```bash
ksi anchor accept --evidence .evidence --anchor .anchors/log.jsonl --reason "why this root is sound"
```

The reason is required and is the point: it is the entire evidential content of a person overriding
a control. The entry it writes carries `accepted`, so a reader can tell an asserted root from a
witnessed one — and acceptance does **not** suppress a later `shrunk` finding.

## Style

Prose in comments and documents explains **why**, never what the next line does. If a decision was
non-obvious, or a tempting alternative is wrong, say so where the reader will hit it — most comments
here exist because a plausible-looking approach would be a silent-pass bug, and the comment is the
only thing that stops someone from reintroducing it.
