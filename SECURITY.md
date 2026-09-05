# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/RootCawsLLC/ksi-harness/security/advisories/new)
rather than in a public issue. Expect an acknowledgment within three working days.

If you would rather not use GitHub, the repository's `SECURITY_CONTACT` variable names an address.

## What counts as a vulnerability here

This is a compliance harness, so the interesting failures are not the usual ones. A tool that
crashes has failed loudly. A tool that reports a control as satisfied when it is not has failed in
the way that matters, because everything downstream — the coverage report, the SDR's implementation
status, an assessor's reliance — inherits the claim.

**Treated as security issues, in priority order:**

1. **Any path to an unearned `pass`.** A check that reports success over a population it did not
   examine, a `not-applicable` that should have been a `fail`, a population whose `expected` can be
   derived from its own `items` so the completeness test can never fail, a permission error read as
   an absent configuration. These are the bugs this repository exists to avoid and they are
   reported as vulnerabilities rather than as defects.
2. **Any path to a manufactured finding.** The mirror image, and no less wrong: reading "the token
   cannot see this" as "this is misconfigured" turns a scope problem into a security conclusion.
3. **Evidence integrity.** A way to alter a stored bundle without breaking either its content hash
   or its check's hash chain, or to rewrite a locker so that a signed manifest still verifies.
4. **Credential or evidence disclosure.** Anything that writes a credential into a bundle, a
   report, a log line or an emitted artifact. Bundles legitimately name accounts, roles, buckets and
   failing resources; they must never name a secret.
5. Conventional issues — injection, path traversal, dependency vulnerabilities with a reachable
   path.

**Not security issues:** a check being too strict, a coverage level someone disagrees with, or a
route whose stated gap you think is understated. Those are ordinary issues, and welcome ones.

## Scope

The harness reads. It has no write path to any monitored system, and a collector that needed one
would be a design error rather than a feature. Run it with a read-only role.

`ksiAssessment` is deliberately not generated. Producing an assessment for evidence this same tool
collected would be the conflict of interest a 3PAO exists to remove, and a version that generated
it would be a security problem in the sense that matters most here.

## Handling evidence

An evidence bundle is an accurate inventory of where a boundary is weakest: the accounts, the roles
with standing privilege, the buckets that are readable, the security groups that are open. Treat a
locker as sensitive.

- `.evidence/` is gitignored. The default workflow publishes a locker to a branch only because this
  repository monitors *itself*, where every fact collected is already public. That default is
  wrong for any real boundary — point `KSI_EVIDENCE_BRANCH` at nothing and send the locker to a
  private append-only store instead. S3 with Object Lock is the obvious one.
- Fixture bundles carry `scope.fixture = true` and say `NOT REAL EVIDENCE` in their source string.
  If you find a path where fixture output can be mistaken for a live collection, that is a
  reportable issue under (1) above.
