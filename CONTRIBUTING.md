# Contributing

```bash
npm install
npm test           # 185 tests
npm run policy     # OPA unit tests, the gate, and its negative control
npm run demo       # end to end against fixtures
```

Node 22 or later. The AWS SDK is an optional dependency; everything except a live AWS collection
installs and tests without it.

## The one rule

**A change may not make it easier for this harness to report a control as satisfied when it is
not.** Every other convention here follows from that, and a pull request that improves ergonomics
at the cost of that property will be turned down however pleasant the diff is.

Concretely, the reviewer is looking for:

- **The population denominator does not come from the graded items.** If `expected` is
  `things.length` and `items` is `things.map(...)`, the two cannot disagree, `complete` is true by
  construction, and the reconciliation is arithmetic pretending to be evidence. `expected` has to
  come from an enumeration made before grading, and `population.enumerated_from` has to say which.
  This was wrong in nine of the eleven original checks, which is why it is the first thing checked.
- **A check that could not decide anything does not pass.** `not-applicable` items leave the
  denominator; a population of nothing but them reports `warn`.
- **A permission failure is never a finding, and never a pass.** "I was not allowed to look" is a
  third answer. It belongs in `population.unexamined` with a reason, or in a `warn` item that names
  the missing scope.
- **The result is derived, never asserted.** Nothing outside `buildBundle` decides a `result`.

## Adding a check

1. Write the grading function as a pure function of fetched data. It returns `{ items, population,
   metric }` and does not compute `examined` or `complete` — the bundle contract does that, and two
   authorities on completeness is one too many.
2. Add it to `CHECKS` in the collector and register the collector in `src/collectors/registry.mjs`.
3. Add a fixture under `fixtures/collectors/`. Fixtures should exercise failure as well as success;
   a fixture set that only passes proves nothing about the grading.
4. Route it in `src/routes/routes.yaml`. `ksi routes validate` will refuse a route that claims a
   check no collector implements, and refuse a coverage level without the argument that level
   requires.
5. Write the tests as refusals. The suite is deliberately weighted toward what the code declines to
   do rather than toward the happy path.

## Coverage levels

`automated` requires a written `sufficiency` argument saying why the declared checks leave nothing
material out. A test asserts the count of `automated` indicators stays zero, so promoting one is a
deliberate edit that breaks the build and makes someone justify it in review. That test is not an
oversight and PRs that delete it will be closed.

If you cannot write the sufficiency argument, the honest level is `partial` with the gap named in
`unautomated`. Read [ADR 0002](docs/adr/0002-coverage-honesty.md) before arguing otherwise.

## Commits and pull requests

- The default branch requires review. `github.change.pr-review` reads the commit history rather
  than the settings, so an administrator merging their own work shows up in this repository's own
  coverage report. That is intentional and the finding is left standing.
- Third-party actions are pinned to commit revisions. A test asserts it against this repository's
  own workflows, so a tag will fail CI.
- Vendored FedRAMP files are pinned by SHA-256 in `vendor/fedramp/PINNED.json`. Never edit one by
  hand; run `npm run vendor:sync` and review the diff, which is the point at which someone should
  notice that an indicator's text changed.

## What is deliberately not here

`ksiAssessment` is not generated, and a PR adding it will not be merged. Producing an assessment of
evidence this same tool collected is the conflict of interest a 3PAO exists to remove.
