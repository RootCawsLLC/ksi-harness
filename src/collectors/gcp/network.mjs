import { buildBundle } from '../../evidence/bundle.mjs';
import { endpoint, fixtureScope, loadFixture, mergeGraded, paginate, passRate, perProject } from '../lib/gcp.mjs';

export const VERSION = '1.0.0';
export const PATH = 'src/collectors/gcp/network.mjs';

export const CHECKS = [
  {
    id: 'gcp.network.ingress-exposure',
    ksis: ['KSI-CNA-MAT', 'KSI-CNA-RNT', 'KSI-CNA-ULN'],
    fixture: 'gcp-firewall-rules',
    assertion:
      'No enabled VPC firewall rule permits unrestricted inbound access on a port other than the declared public ' +
      'service ports, and no such rule applies to the whole network.',
  },
];

/* ------------------------------------------------------------------- grading */

const OPEN_V4 = '0.0.0.0/0';
const OPEN_V6 = '::/0';

export const DEFAULT_PUBLIC_PORTS = Object.freeze([80, 443]);

/** Ports a rule opens, expanded from GCP's `allowed` shape. `null` means every port. */
export function portsOpenedBy(allowed) {
  const out = [];
  for (const entry of allowed ?? []) {
    if (entry.IPProtocol === 'all') return null;
    if (!entry.ports || entry.ports.length === 0) return null;
    for (const spec of entry.ports) {
      const [from, to] = String(spec).split('-').map(Number);
      for (let p = from; p <= (to ?? from); p += 1) out.push(p);
    }
  }
  return out;
}

/**
 * Grades VPC firewall rules.
 *
 * Two GCP-specific things decide the grade and have no clean AWS analogue. A rule with no
 * `targetTags` or `targetServiceAccounts` applies to **every instance in the network**,
 * which is how a rule written for one host silently becomes a network-wide opening — that is
 * graded harder than the same ports scoped to a tag. And rule priority matters: a permissive
 * rule at a lower priority number wins over a restrictive one above it, so an open rule at
 * priority 100 is live even when a deny at 1000 looks like it covers the case.
 *
 * A disabled rule is not-applicable rather than a pass. It is latent configuration that
 * anyone can enable, and counting it as a pass would let a project improve its ratio by
 * accumulating disabled openings.
 */
export function gradeIngressExposure(rules, { publicPorts = DEFAULT_PUBLIC_PORTS, scopeId = 'project', unexamined = [] } = {}) {
  const items = rules.map((rule) => {
    const id = `firewall/${rule.name}`;
    if (rule.direction !== 'INGRESS') {
      return { id, status: 'not-applicable', detail: 'Egress rule; this check grades inbound exposure' };
    }
    if (rule.disabled) {
      return { id, status: 'not-applicable', detail: 'Rule is disabled, so it opens nothing until someone enables it' };
    }
    if ((rule.denied ?? []).length) {
      return { id, status: 'not-applicable', detail: 'Deny rule; it restricts rather than opens' };
    }

    const open = (rule.sourceRanges ?? []).filter((r) => r === OPEN_V4 || r === OPEN_V6);
    if (open.length === 0) {
      return { id, status: 'pass', detail: `Sourced from ${(rule.sourceRanges ?? []).join(', ') || 'tags or service accounts'} rather than the internet` };
    }

    const ports = portsOpenedBy(rule.allowed);
    const networkWide = !(rule.targetTags?.length || rule.targetServiceAccounts?.length);
    const beyondPublic = ports === null ? ['all ports'] : ports.filter((p) => !publicPorts.includes(p));
    const scopeNote = networkWide ? 'every instance in the network' : `targets ${(rule.targetTags ?? rule.targetServiceAccounts).join(', ')}`;

    if (beyondPublic.length === 0) {
      return {
        id,
        status: networkWide ? 'warn' : 'pass',
        detail: networkWide
          ? `Open to the internet on declared public ports only, but applies to ${scopeNote} — review that every instance is meant to be public`
          : `Open to the internet on declared public ports only, ${scopeNote}`,
        observed: { priority: rule.priority, network_wide: networkWide },
      };
    }
    return {
      id,
      status: 'fail',
      detail:
        `Unrestricted inbound on ${ports === null ? 'all ports' : beyondPublic.slice(0, 12).join(', ')}` +
        `${ports !== null && beyondPublic.length > 12 ? ` and ${beyondPublic.length - 12} more` : ''}, applying to ${scopeNote}`,
      observed: { priority: rule.priority, network_wide: networkWide, source_ranges: open },
    };
  });

  items.unshift(
    rules.length > 0
      ? { id: `scope/${scopeId}`, status: 'pass', detail: `${rules.length} firewall rule(s) enumerated for assessment` }
      : {
          id: `scope/${scopeId}`,
          status: 'warn',
          detail:
            'No firewall rules were enumerated. Every VPC carries default rules, so an empty listing describes ' +
            'the collection rather than the network.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + rules.length + unexamined.length,
      unexamined,
      source_of_truth: 'compute:firewalls.list across the declared projects, graded on direction, source and target scope',
      enumerated_from: 'compute.firewalls.list per declared project, counted before any rule was graded',
    },
    metric: { metric_id: 'gcp.network.rules_without_open_ingress', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchFirewallRules(projectId, token) {
  const listed = await paginate(endpoint('compute', `/projects/${projectId}/global/firewalls`), 'items', { token });
  if (!listed.ok) throw new Error(listed.classification?.detail ?? `compute.firewalls.list failed with HTTP ${listed.status}`);
  return listed.items;
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
  const publicPorts = profile?.gcp?.public_ports ?? profile?.aws?.public_ports ?? DEFAULT_PUBLIC_PORTS;

  if (fixture) {
    const data = loadFixture(fixture, 'gcp-firewall-rules');
    return [
      buildBundle({
        ...common,
        scope: fixtureScope(fixture, 'gcp-firewall-rules', { declared_public_ports: publicPorts }),
        ...gradeIngressExposure(data.rules, {
          publicPorts,
          scopeId: data.project,
          unexamined: data.unexamined ?? [],
        }),
      }),
    ];
  }

  const { parts, unexamined, projects } = await perProject(profile, async ({ project, token }) =>
    gradeIngressExposure(await fetchFirewallRules(project.id, token), { publicPorts, scopeId: project.id })
  );

  return [
    buildBundle({
      ...common,
      scope: { projects: projects.map((p) => p.id), declared_public_ports: publicPorts },
      ...mergeGraded(parts, {
        sourceOfTruth: 'compute.firewalls.list in each declared project',
        enumeratedFrom: 'the projects declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'gcp.network.rules_without_open_ingress', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
