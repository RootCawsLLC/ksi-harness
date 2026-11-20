import { canonicalSha256 } from './canonical.mjs';

/**
 * The identity of the profile a run was graded against.
 *
 * Every list in a profile is a denominator: the accounts, regions, repositories and ports that
 * evidence is measured against, and the thresholds it is graded by. A run against a narrower
 * profile produces evidence that is just as internally consistent, and nothing in a bundle's
 * own scope shows what was dropped, because scope records what was examined and not what used
 * to be. So the profile is identified in every bundle and every anchor entry, and a change to it
 * has to be accepted, with a reason, before a run will collect under it (see anchor.mjs).
 *
 * The hash is over the parsed profile, not the file. Comments, key order and whitespace are not
 * changes to what the evidence claims; any changed value is, including contacts and alerting.
 * Hashing the whole document rather than "the parts that matter" is deliberate: deciding which
 * changes weaken the evidence is the judgment this exists to put in front of a person. Adding a
 * public port or lengthening a remediation window looks like an addition and loosens the checks.
 */
export function profileSha256(profile) {
  if (profile == null) return null;
  return canonicalSha256(profile);
}
