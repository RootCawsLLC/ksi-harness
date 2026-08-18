import { buildBundle } from '../../evidence/bundle.mjs';
import { api, endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/data.mjs';

export const CHECKS = [
  {
    id: 'gcp.data.encryption-at-rest',
    ksis: ['KSI-SVC-SIN'],
    fixture: 'gcp-storage',
    assertion:
      'Every bucket and persistent disk in scope is encrypted at rest, and the key custody for each is recorded ' +
      'so customer-managed and provider-held keys are distinguishable.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades encryption at rest, recording key custody rather than punishing provider-held keys.
 *
 * Everything in GCS and Persistent Disk is encrypted at rest unconditionally — there is no
 * unencrypted state to find, which makes a naive "is it encrypted" check vacuous on GCP in a
 * way it is not on AWS. The question that actually has an answer is *who holds the key*, and
 * that is what a federal customer asks. So a Google-managed key passes and is recorded as
 * provider-held; a CMEK passes and is recorded with its key name.
 *
 * The failure this check can genuinely find is a bucket the profile declares as requiring
 * customer-managed keys that does not have one. That declaration lives in the profile, which
 * is what turns "note the key custody" into a testable claim rather than an inventory.
 */
export function gradeEncryptionAtRest(storage, { scopeId = 'project', cmekRequired = [], unexamined = [] } = {}) {
  const items = [];

  for (const bucket of storage.buckets ?? []) {
    const cmek = bucket.default_kms_key ?? null;
    const mustHaveCmek = cmekRequired.includes(bucket.name);
    if (mustHaveCmek && !cmek) {
      items.push({
        id: `bucket/${bucket.name}`,
        status: 'fail',
        detail: 'Declared as requiring a customer-managed key but is encrypted with a Google-managed key',
        observed: { customer_managed_key: false, declared_cmek_required: true },
      });
      continue;
    }
    items.push({
      id: `bucket/${bucket.name}`,
      status: 'pass',
      detail: cmek ? `Encrypted with a customer-managed key (${cmek})` : 'Encrypted with a Google-managed key, provider-held',
      observed: { customer_managed_key: Boolean(cmek), key: cmek },
    });
  }

  for (const disk of storage.disks ?? []) {
    const cmek = disk.kms_key ?? null;
    items.push({
      id: `disk/${disk.name}`,
      status: 'pass',
      detail: cmek ? 'Encrypted with a named KMS key' : 'Encrypted with a Google-managed key, provider-held',
      observed: { customer_managed_key: Boolean(cmek) },
    });
  }

  const enumerated = (storage.buckets?.length ?? 0) + (storage.disks?.length ?? 0);
  items.unshift(
    enumerated > 0
      ? {
          id: `scope/${scopeId}`,
          status: 'pass',
          detail: `${enumerated} storage resource(s) enumerated; ${items.filter((i) => i.observed?.customer_managed_key).length} under customer-managed keys`,
        }
      : {
          id: `scope/${scopeId}`,
          status: 'warn',
          detail:
            'No buckets or disks were enumerated in this project. Nothing here distinguishes a project that ' +
            'genuinely holds no storage from a listing that was filtered or denied.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + enumerated + unexamined.length,
      unexamined,
      source_of_truth: 'storage:buckets.list and compute:disks.aggregatedList, with encryption configuration read per resource',
      enumerated_from: 'storage.buckets.list and compute.disks.aggregatedList per declared project, counted before any encryption configuration was read',
    },
    metric: { metric_id: 'gcp.storage.customer_managed_keys', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchStorage(projectId, token) {
  const buckets = [];
  const unexamined = [];

  const listed = await paginate(endpoint('storage', `/b?project=${projectId}`), 'items', { token });
  if (!listed.ok) throw new Error(listed.classification?.detail ?? `storage.buckets.list failed with HTTP ${listed.status}`);
  for (const b of listed.items) {
    buckets.push({ name: b.name, default_kms_key: b.encryption?.defaultKmsKeyName ?? null });
  }

  const disksRes = await api(endpoint('compute', `/projects/${projectId}/aggregated/disks`), { token });
  const disks = [];
  if (!disksRes.ok) {
    unexamined.push({
      id: `project/${projectId}/disks`,
      reason: disksRes.classification?.detail ?? `compute.disks.aggregatedList failed with HTTP ${disksRes.status}`,
    });
  } else {
    for (const scope of Object.values(disksRes.body?.items ?? {})) {
      for (const d of scope.disks ?? []) {
        disks.push({ name: d.name, kms_key: d.diskEncryptionKey?.kmsKeyName ?? null });
      }
    }
  }

  return { buckets, disks, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const check = CHECKS[0];
  const common = {
    collectorPath: PATH,
    collectorVersion: VERSION,
    collectedAt,
    sourceCommit,
    checkId: check.id,
    ksis: check.ksis,
    assertion: check.assertion,
    previousHash: previousHashes.get(check.id)?.hash ?? null,
    chainIndex: previousHashes.get(check.id)?.index ?? 0,
  };
  const cmekRequired = profile?.gcp?.cmek_required_buckets ?? [];

  if (fixture) {
    const data = loadFixture(fixture, 'gcp-storage');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'gcp-storage', { cmek_required_buckets: data.cmek_required ?? [] }),
        ...gradeEncryptionAtRest(data, {
          scopeId: data.project,
          cmekRequired: data.cmek_required ?? [],
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const storage = await fetchStorage(project.id, token);
    return gradeEncryptionAtRest(storage, { scopeId: project.id, cmekRequired, unexamined: storage.unexamined });
  });

  return [
    buildBundle({
      ...common,
      scope: { projects: projects.map((p) => p.id), cmek_required_buckets: cmekRequired },
      ...mergeGraded(parts, {
        sourceOfTruth: 'storage.buckets.list and compute.disks.aggregatedList in each declared project',
        enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'gcp.storage.customer_managed_keys', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
