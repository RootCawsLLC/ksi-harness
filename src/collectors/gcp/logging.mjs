import { buildBundle } from '../../evidence/bundle.mjs';
import { api, endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/logging.mjs';

export const CHECKS = [
  {
    id: 'gcp.logging.audit-config',
    ksis: ['KSI-CMT-LMC', 'KSI-MLA-LET'],
    fixture: 'gcp-audit-config',
    assertion:
      'Every service the profile declares as in scope for audit has Data Access read and write logging enabled, ' +
      'with no exempted members.',
  },
  {
    id: 'gcp.logging.sink-integrity',
    ksis: ['KSI-MLA-ALA', 'KSI-MLA-OSM'],
    fixture: 'gcp-log-sinks',
    assertion:
      'Audit logs are routed to a destination outside the project that produces them, that destination retains ' +
      'them under a locked policy, and no principal outside the declared readers can read it.',
  },
];

/* ------------------------------------------------------------------- grading */

/** Data Access log types. ADMIN_WRITE is always on and cannot be disabled; these are the ones that default to off. */
export const DATA_ACCESS_TYPES = Object.freeze(['DATA_READ', 'DATA_WRITE']);

/**
 * Grades the project audit configuration against the services the profile declares.
 *
 * The denominator is the declared list, which is what makes this check evidence for
 * KSI-MLA-LET rather than an inventory of whatever happened to be configured. The indicator
 * asks for a maintained list of resources and event types that *will* be logged, reviewed to
 * ensure the activities occur — so the list belongs in the profile as a statement of intent,
 * and the check reconciles reality against it. Reading the audit config and reporting what
 * it contains would answer a different and much weaker question.
 *
 * Data Access logs are off by default on GCP. That default is the single most common reason
 * an investigation finds no record of a read, and it is why a project can look thoroughly
 * logged while producing nothing about who accessed what.
 *
 * An exempted member is graded as a failure of the whole service entry rather than noted.
 * An exemption removes a principal from the audit trail silently — the config still reads as
 * enabled, and the logs simply do not mention them.
 */
export function gradeAuditConfig(auditConfigs, { projectId, declaredServices = [], unexamined = [] } = {}) {
  const byService = new Map(auditConfigs.map((c) => [c.service, c]));
  const all = byService.get('allServices');

  const enabledFor = (service, logType) => {
    for (const config of [all, byService.get(service)]) {
      const entry = (config?.auditLogConfigs ?? []).find((c) => c.logType === logType);
      if (entry) return entry;
    }
    return null;
  };

  const items = declaredServices.map((service) => {
    const missing = [];
    const exempted = [];
    for (const logType of DATA_ACCESS_TYPES) {
      const entry = enabledFor(service, logType);
      if (!entry) missing.push(logType);
      else if (entry.exemptedMembers?.length) exempted.push(`${logType}: ${entry.exemptedMembers.join(', ')}`);
    }

    if (missing.length) {
      return {
        id: `service/${service}`,
        status: 'fail',
        detail:
          `${missing.join(' and ')} not enabled. These default to off on GCP, so no record exists of who read or ` +
          `wrote data through this service.`,
        observed: { missing },
      };
    }
    if (exempted.length) {
      return {
        id: `service/${service}`,
        status: 'fail',
        detail: `Data Access logging is enabled but members are exempted, which removes them from the trail silently — ${exempted.join('; ')}`,
        observed: { exempted },
      };
    }
    return { id: `service/${service}`, status: 'pass', detail: 'Data Access read and write logging enabled with no exemptions' };
  });

  items.unshift(
    all
      ? {
          id: `project/${projectId}`,
          status: 'pass',
          detail: 'An allServices audit configuration is present, so a service added tomorrow inherits logging',
        }
      : {
          id: `project/${projectId}`,
          status: 'fail',
          detail:
            'No allServices audit configuration. Logging is enumerated service by service, so any service enabled ' +
            'after this list was written produces no Data Access record until someone remembers to add it.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + declaredServices.length + unexamined.length,
      unexamined,
      source_of_truth: 'cloudresourcemanager:projects.getIamPolicy auditConfigs, plus one project-level claim',
      enumerated_from:
        'the services declared in the profile as in scope for audit logging, counted before the audit ' +
        'configuration was read — the declaration is the list KSI-MLA-LET asks to be maintained',
    },
    metric: { metric_id: 'gcp.logging.services_with_data_access_logging', value: passRate(items), unit: 'ratio' },
  };
}

/** A sink destination that leaves the project boundary, which is what makes it tamper-resistant. */
export function destinationIsExternal(destination, projectId) {
  if (!destination) return false;
  return !destination.includes(`/projects/${projectId}/`);
}

/**
 * Grades log routing and the access model on the destination.
 *
 * Two claims, and they fail differently. A sink that writes back into the project it audits
 * is not tamper-resistant, because whoever can alter the project can alter its own record —
 * that is KSI-MLA-OSM. A destination readable by principals outside the declared set is a
 * least-privilege failure on log data, which is KSI-MLA-ALA and a distinct problem.
 */
export function gradeSinkIntegrity(sinks, { projectId, declaredReaders = [], unexamined = [] } = {}) {
  const items = sinks.map((sink) => {
    const problems = [];
    if (!destinationIsExternal(sink.destination, projectId)) {
      problems.push('destination is inside the project it audits, so the record is alterable by whoever can alter the project');
    }
    if (sink.disabled) problems.push('sink is disabled and is routing nothing');
    if (!sink.retention?.locked) {
      problems.push(
        sink.retention?.days
          ? `retention of ${sink.retention.days} day(s) is set but not locked, so it can be shortened`
          : 'destination has no retention policy'
      );
    }
    const outsiders = (sink.readers ?? []).filter((r) => !declaredReaders.includes(r));
    if (outsiders.length) problems.push(`readable by ${outsiders.join(', ')}, which the profile does not declare`);

    return problems.length
      ? { id: `sink/${sink.name}`, status: 'fail', detail: problems.join('; '), observed: { destination: sink.destination, outsiders } }
      : {
          id: `sink/${sink.name}`,
          status: 'pass',
          detail: 'Routes outside the project, retained under a locked policy, readable only by declared principals',
        };
  });

  items.unshift(
    sinks.length > 0
      ? { id: `project/${projectId}`, status: 'pass', detail: `${sinks.length} log sink(s) configured` }
      : {
          id: `project/${projectId}`,
          status: 'fail',
          detail:
            'No log sink is configured, so audit logs live only in the default _Required and _Default buckets ' +
            'inside this project and age out on their own schedule.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + sinks.length + unexamined.length,
      unexamined,
      source_of_truth: 'logging:sinks.list per project, with the destination bucket retention and IAM resolved for each',
      enumerated_from: 'logging.sinks.list for the project, counted before any destination was resolved',
    },
    metric: { metric_id: 'gcp.logging.tamper_resistant_sinks', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

/** Services whose Data Access logs matter by default, when the profile declares none. */
export const DEFAULT_AUDITED_SERVICES = Object.freeze([
  'storage.googleapis.com',
  'iam.googleapis.com',
  'cloudkms.googleapis.com',
  'secretmanager.googleapis.com',
  'bigquery.googleapis.com',
]);

async function fetchAuditConfigs(projectId, token) {
  const res = await api(endpoint('crm', `/projects/${projectId}:getIamPolicy`), { token, method: 'POST' });
  if (!res.ok) throw new Error(res.classification?.detail ?? `projects.getIamPolicy failed with HTTP ${res.status}`);
  return res.body?.auditConfigs ?? [];
}

async function fetchSinks(projectId, token) {
  const listed = await paginate(endpoint('logging', `/projects/${projectId}/sinks`), 'sinks', { token });
  if (!listed.ok) throw new Error(listed.classification?.detail ?? `logging.sinks.list failed with HTTP ${listed.status}`);

  const sinks = [];
  const unexamined = [];
  for (const sink of listed.items) {
    const bucket = /storage\.googleapis\.com\/(.+)$/.exec(sink.destination ?? '')?.[1];
    let retention = null;
    let readers = [];

    if (bucket) {
      const meta = await api(endpoint('storage', `/b/${bucket}`), { token });
      const iam = await api(endpoint('storage', `/b/${bucket}/iam`), { token });
      if (!meta.ok || !iam.ok) {
        // The sink exists but its destination cannot be inspected. Grading it as compliant
        // would credit a retention policy nobody read.
        unexamined.push({
          id: `sink/${sink.name}`,
          reason: (meta.ok ? iam : meta).classification?.detail ?? 'destination bucket could not be read',
        });
        continue;
      }
      retention = {
        days: meta.body?.retentionPolicy?.retentionPeriod ? Number(meta.body.retentionPolicy.retentionPeriod) / 86400 : null,
        locked: Boolean(meta.body?.retentionPolicy?.isLocked),
      };
      readers = (iam.body?.bindings ?? [])
        .filter((b) => /storage\.(objectViewer|objectUser|admin|legacyBucket)/.test(b.role))
        .flatMap((b) => b.members ?? []);
    }

    sinks.push({ name: sink.name, destination: sink.destination, disabled: Boolean(sink.disabled), retention, readers });
  }
  return { sinks, unexamined };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chainOf = (checkId) => ({
    previousHash: previousHashes.get(checkId)?.hash ?? null,
    chainIndex: previousHashes.get(checkId)?.index ?? 0,
  });
  const declaredServices = profile?.gcp?.audited_services ?? DEFAULT_AUDITED_SERVICES;
  const declaredReaders = profile?.gcp?.log_readers ?? [];

  if (fixture) {
    const audit = loadFixture(fixture, 'gcp-audit-config');
    const sinkData = loadFixture(fixture, 'gcp-log-sinks');
    return [
      buildBundle({
        ...common,
        ...chainOf(CHECKS[0].id),
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'gcp-audit-config', { declared_services: audit.declared_services }),
        ...gradeAuditConfig(audit.audit_configs, {
          projectId: audit.project,
          declaredServices: audit.declared_services,
          unexamined: audit.unexamined ?? [],
        }),
      }),
      buildBundle({
        ...common,
        ...chainOf(CHECKS[1].id),
        checkId: CHECKS[1].id,
        ksis: CHECKS[1].ksis,
        assertion: CHECKS[1].assertion,
        scope: fixtureScope(fixture, 'gcp-log-sinks', { declared_readers: sinkData.declared_readers }),
        ...gradeSinkIntegrity(sinkData.sinks, {
          projectId: sinkData.project,
          declaredReaders: sinkData.declared_readers ?? [],
          unexamined: sinkData.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) => {
    const { sinks, unexamined: sinkGaps } = await fetchSinks(project.id, token);
    return {
      audit: gradeAuditConfig(await fetchAuditConfigs(project.id, token), { projectId: project.id, declaredServices }),
      sinks: gradeSinkIntegrity(sinks, { projectId: project.id, declaredReaders, unexamined: sinkGaps }),
    };
  });

  const scope = {
    projects: projects.map((p) => p.id),
    declared_audited_services: declaredServices,
    declared_log_readers: declaredReaders,
  };

  return [
    buildBundle({
      ...common,
      ...chainOf(CHECKS[0].id),
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope,
      ...mergeGraded(
        parts.map((p) => ({ scope: p.scope, graded: p.graded.audit })),
        {
          sourceOfTruth: 'the project audit configuration in each declared project',
          enumeratedFrom: 'the services declared in the profile, across the projects declared in the profile',
          metric: { metric_id: 'gcp.logging.services_with_data_access_logging', unit: 'ratio' },
          unexamined,
        }
      ),
    }),
    buildBundle({
      ...common,
      ...chainOf(CHECKS[1].id),
      checkId: CHECKS[1].id,
      ksis: CHECKS[1].ksis,
      assertion: CHECKS[1].assertion,
      scope,
      ...mergeGraded(
        parts.map((p) => ({ scope: p.scope, graded: p.graded.sinks })),
        {
          sourceOfTruth: 'logging.sinks.list with destination retention and IAM, in each declared project',
          enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
          metric: { metric_id: 'gcp.logging.tamper_resistant_sinks', unit: 'ratio' },
          unexamined,
        }
      ),
    }),
  ];
}
