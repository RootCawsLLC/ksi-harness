# ADR 0005 — Pair every gate with a collector, and keep the gate's output as evidence

**Status:** accepted · **Date:** 2026-08-18

## Context

Compliance-as-code splits into two activities that are usually built by different people and never
reconciled.

**Policy gates** run in CI and stop a change from shipping: OPA/Rego, conftest, checkov, trivy.
They are preventive, they are fast, and they only see what goes through the pipeline.

**Evidence collection** queries deployed state on a schedule and reports what is actually there.
It is detective, it sees everything including changes made by hand, and it cannot stop anything.

Each has a blind spot the other covers, and the blind spots are not symmetrical. A gate cannot see
a security group edited in the console. A collector cannot prevent the edit, and by the time it
reports, the exposure has existed for up to a collection interval. Neither is sufficient, and a
programme that has one usually reports as though it had both.

There is a third problem specific to gates, and it is the one that turns a working control into no
evidence at all: **a red X in a pipeline run is not retained**. The run log ages out. Next quarter,
asked to demonstrate that infrastructure was validated before deployment, there is a workflow file
and nothing else. `KSI-MLA-EVC` singles out infrastructure as code "especially" — and IaC is
evaluated before it is ever deployed, so a collector reading deployed state cannot evidence it.

## Decision

Three rules.

### 1. Every policy rule names the indicator it enforces

Rules in `policy/rego/terraform.rego` carry the indicator id in the message text:

```
KSI-SVC-SIN: aws_ebs_volume.scratch sets encrypted = false.
```

The same indicator has a detective check in `src/collectors`. `KSI-SVC-SIN` is gated by the
encryption rules and evidenced by `aws.data.encryption-at-rest`. The claim is enforced before merge
and verified after deploy, and both point at the same line in the routing map.

### 2. The gate's own output becomes an evidence bundle

`src/collectors/pipeline/policy-gate.mjs` reads the conftest JSON report and produces a bundle on
the same contract as every other collector, routed to `KSI-CMT-VTD`, `KSI-CNA-EIS` and
`KSI-MLA-EVC`.

One design choice in it matters more than the rest. **The population is enumerated from the working
tree, not from the report.** Counting the files conftest reported on would make the reconciliation
circular: a file skipped because of a bad `--policy` path, an ignore rule, or a directory nobody
added to the workflow simply would not appear, and the gate would report a clean pass over a
shrinking denominator. Globbing the declared roots independently is what makes "every file was
evaluated" falsifiable. A file present in a gated root but absent from the report is reported as
`warn` — not a pass, not a fail, because the gate has nothing to say about it — and it makes the
population incomplete, which under ADR 0003 caps the bundle at `warn`.

### 3. The gate is tested against deliberately failing input

`policy/terraform/violations/` is non-conforming on purpose, and `npm run policy` **fails if that
directory comes back clean**.

This is not defensive decoration. Writing this policy suite produced two bugs that both presented
as green:

- Rules read `input.resource[kind][name]` as the resource body. Terraform's JSON shape wraps each
  body in an array, so every positive-form rule matched nothing. The single negative-form rule
  (`not encryption_configured`) kept firing, so the suite looked alive. Twenty unit tests passed,
  because the test fixtures were hand-written JSON in the shape I assumed rather than the shape
  conftest emits.
- The IAM wildcard rule normalised `Action` and `Resource` for arrays and objects but not for the
  string form. `"Action": "*"` — the most common way to write a full administrative grant —
  matched nothing.

Both are silent-pass bugs in a control whose entire purpose is to not silently pass. A negative
control is the cheapest available defence, and the unit tests are now derived from real
`conftest parse` output.

## Being honest about what a gate can decide

The gate reads Terraform **configuration**, so any attribute whose value comes from a variable, a
local, or a module output arrives as an unresolved `${...}` string. The most consequential case is
`policy = jsonencode({...})`, which is how almost everyone writes an IAM policy — and it is
precisely where a wildcard grant would hide.

Rather than pass quietly, the gate emits a warning that says the document was not evaluated and
names the fix (`terraform show -json` plan output, which the policies already accept). A silent
pass and a clean result would be indistinguishable, and that distinction is the difference between
a control and a decoration.

This is why the routes credit this layer as `partial` and never as sufficient on its own.

## Consequences

- Checkov's **findings** are advisory (`soft_fail`), because they are not mapped to indicators and
  an unmapped finding cannot be reported as KSI evidence — gating on it would mean blocking on
  something this harness cannot account for. It runs to catch what the hand-written policies miss,
  and its JSON and SARIF output is retained.
- Checkov's **execution** is not advisory. The first version of this pipeline used the published
  `checkov-action`, which pinned a years-old image, rejected the output flags it was handed, exited
  on an argument error, and still reported success — so the scanner was absent behind a green tick.
  Checkov is now installed from a pinned release and the report is checked for having actually
  evaluated the tree, with the same negative control the conftest gate uses: the non-conforming
  fixtures must fail it. "Found nothing" and "never ran" look identical in a passing pipeline, so
  the difference has to be asserted rather than assumed.
- Bypasses are still invisible. A gate that can be skipped with an administrator merge is only as
  strong as its bypass rate, and that number is the one an assessor should ask for. It is named as
  an unautomated gap on `KSI-CMT-VTD` rather than quietly omitted.
- The two halves are not yet reconciled. A resource can pass the gate as code and drift afterwards,
  and nothing links a deployed resource back to the IaC revision that produced it. Also stated as a
  gap rather than glossed.
