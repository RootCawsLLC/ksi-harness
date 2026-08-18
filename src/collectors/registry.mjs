import * as awsConfig from './aws/config.mjs';
import * as awsData from './aws/data.mjs';
import * as awsIam from './aws/iam.mjs';
import * as awsLogging from './aws/logging.mjs';
import * as awsNetwork from './aws/network.mjs';
import * as boundaryAttribution from './boundary/attribution.mjs';
import * as gcpData from './gcp/data.mjs';
import * as gcpIam from './gcp/iam.mjs';
import * as gcpLogging from './gcp/logging.mjs';
import * as gcpNetwork from './gcp/network.mjs';
import * as gcpPolicy from './gcp/policy.mjs';
import * as githubChange from './github/change.mjs';
import * as githubDependencies from './github/dependencies.mjs';
import * as githubSupplyChain from './github/supply-chain.mjs';
import * as pipelinePolicyGate from './pipeline/policy-gate.mjs';
import * as thirdpartyRegister from './thirdparty/register.mjs';

/**
 * Every implemented collector.
 *
 * This module is what makes the routing map falsifiable. `validateRoutes` resolves each
 * declared check against `CHECK_IDS`, so a route cannot claim automation that no code
 * provides — the coverage report is bounded by what is actually here rather than by what
 * someone intended to write. Registering a collector is therefore the deliberate act of
 * saying its checks exist.
 */
export const COLLECTORS = Object.freeze([
  awsIam,
  awsLogging,
  awsNetwork,
  awsData,
  awsConfig,
  gcpIam,
  gcpLogging,
  gcpNetwork,
  gcpData,
  gcpPolicy,
  boundaryAttribution,
  githubChange,
  githubSupplyChain,
  githubDependencies,
  thirdpartyRegister,
  pipelinePolicyGate,
]);

export const ALL_CHECKS = Object.freeze(
  COLLECTORS.flatMap((collector) =>
    collector.CHECKS.map((check) => Object.freeze({ ...check, collector, path: collector.PATH, version: collector.VERSION }))
  )
);

export const CHECK_IDS = new Set(ALL_CHECKS.map((c) => c.id));

export const CHECKS_BY_ID = new Map(ALL_CHECKS.map((c) => [c.id, c]));

/** Which collector family a check belongs to, used to skip families with no credentials. */
export function providerOf(checkId) {
  return checkId.split('.')[0];
}

/** Duplicate check ids across collectors would make evidence ambiguous; a test asserts this is empty. */
export function duplicateCheckIds() {
  const seen = new Set();
  const duplicates = new Set();
  for (const check of ALL_CHECKS) {
    if (seen.has(check.id)) duplicates.add(check.id);
    seen.add(check.id);
  }
  return [...duplicates];
}
