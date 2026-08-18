## What this changes

<!-- One paragraph. What moved, and why. -->

## Evidence integrity checklist

Everything downstream of a bundle inherits whatever that bundle claims, so these are the questions
review actually turns on. Delete any line that genuinely does not apply and say why.

- [ ] No new path to an unearned `pass`. If this adds or changes a check: the population's
      `expected` comes from an enumeration made **before** grading, not from the graded items, and
      `population.enumerated_from` says which.
- [ ] No new path to a manufactured finding. A permission error, a rate limit or an unreadable
      resource lands in `population.unexamined` or a `warn` that names the missing scope — never in
      a `fail`.
- [ ] A population that decides nothing still cannot report a pass.
- [ ] `result` is still derived in `buildBundle` and asserted nowhere else.
- [ ] Route changes: any move toward `automated` carries a written `sufficiency` argument, and any
      `partial` names its gap in `unautomated`.
- [ ] Tests added are refusals — what the code now declines to do — not only happy paths.
- [ ] `npm test` and `npm run policy` pass locally.

## Anything a reviewer should look at twice

<!-- The bit you are least sure about. -->
