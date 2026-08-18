import { buildBundle } from '../../evidence/bundle.mjs';
import { describePorts, fixtureScope, loadFixture, mergeGraded, pages, passRate, perAccount, service } from '../lib/aws.mjs';

export const VERSION = '2.0.0';
export const PATH = 'src/collectors/aws/network.mjs';

export const CHECKS = [
  {
    id: 'aws.network.ingress-exposure',
    ksis: ['KSI-CNA-MAT', 'KSI-CNA-RNT', 'KSI-CNA-ULN'],
    fixture: 'aws-security-groups',
    assertion:
      'No security group attached to a running resource permits unrestricted inbound access on a port other ' +
      'than the declared public service ports.',
  },
];

/* ------------------------------------------------------------------- grading */

const OPEN_V4 = '0.0.0.0/0';
const OPEN_V6 = '::/0';

/** Ports a public-facing service is expected to expose. Anything else open to the internet is a finding. */
export const DEFAULT_PUBLIC_PORTS = Object.freeze([80, 443]);

function openRanges(permission) {
  const v4 = (permission.IpRanges ?? []).filter((r) => r.CidrIp === OPEN_V4);
  const v6 = (permission.Ipv6Ranges ?? []).filter((r) => r.CidrIpv6 === OPEN_V6);
  return [...v4.map((r) => r.CidrIp), ...v6.map((r) => r.CidrIpv6)];
}

function coversOnly(permission, allowedPorts) {
  if (permission.IpProtocol === '-1') return false;
  const from = permission.FromPort;
  const to = permission.ToPort;
  if (from == null || to == null) return false;
  for (let port = from; port <= to; port += 1) {
    if (!allowedPorts.includes(port)) return false;
  }
  return true;
}

/**
 * Grades ingress exposure, weighting attachment over rule text.
 *
 * The distinction that earns this check its keep: an open rule on a security group attached
 * to nothing is latent risk and warns, while the same rule on a group attached to a live
 * network interface is live exposure and fails. A port-only check treats those identically
 * and so either cries wolf on unused groups or waves through a genuinely open database.
 *
 * Ports 80 and 443 open to the internet are the intended state for a public service, so they
 * pass rather than fail — but the item still records the exposure, because the reviewer of a
 * boundary needs the whole public surface enumerated, not just its errors.
 *
 * The scope-level item is not decoration. Without it, a region holding no security groups —
 * or a listing that a filter or a permission quietly emptied — produced a population that
 * was empty, complete and free of failures, which the bundle contract read as a pass. Every
 * VPC has a default security group, so zero of them is a signal about the collection rather
 * than about the network.
 */
export function gradeIngressExposure(groups, { publicPorts = DEFAULT_PUBLIC_PORTS, scopeId = 'account', unexamined = [] } = {}) {
  const items = groups.map((group) => {
    const attached = (group.attachments ?? []).length;
    const findings = [];

    for (const permission of group.IpPermissions ?? []) {
      const open = openRanges(permission);
      if (open.length === 0) continue;
      const description = describePorts(permission.IpProtocol, permission.FromPort, permission.ToPort);
      findings.push({ description, publicService: coversOnly(permission, publicPorts) });
    }

    if (findings.length === 0) {
      return { id: `sg/${group.GroupId}`, status: 'pass', detail: 'No unrestricted inbound rule' };
    }

    const beyondPublic = findings.filter((f) => !f.publicService);
    const summary = findings.map((f) => f.description).join(', ');

    if (attached === 0) {
      return {
        id: `sg/${group.GroupId}`,
        status: 'warn',
        detail: `Unrestricted inbound (${summary}) but attached to nothing — latent, not live`,
        observed: { attachments: 0, rules: summary },
      };
    }
    if (beyondPublic.length === 0) {
      return {
        id: `sg/${group.GroupId}`,
        status: 'pass',
        detail: `Unrestricted inbound limited to declared public ports (${summary}) on ${attached} attachment(s)`,
        observed: { attachments: attached, rules: summary },
      };
    }
    return {
      id: `sg/${group.GroupId}`,
      status: 'fail',
      detail: `Unrestricted inbound on ${beyondPublic.map((f) => f.description).join(', ')} with ${attached} live attachment(s)`,
      observed: { attachments: attached, attached_to: group.attachments, rules: summary },
    };
  });

  items.unshift(
    groups.length > 0
      ? { id: `scope/${scopeId}`, status: 'pass', detail: `${groups.length} security group(s) enumerated for assessment` }
      : {
          id: `scope/${scopeId}`,
          status: 'warn',
          detail:
            'No security groups were enumerated here. Every VPC carries a default security group, so an empty ' +
            'listing describes the collection rather than the network — a filtered query, a region with no VPC, ' +
            'or a permission this credential does not hold.',
        }
  );

  return {
    items,
    population: {
      expected: 1 + groups.length + unexamined.length,
      unexamined,
      source_of_truth: 'ec2:DescribeSecurityGroups resolved against ec2:DescribeNetworkInterfaces for attachment',
      enumerated_from: 'the regions declared in the profile, counted before any of them was queried',
    },
    metric: { metric_id: 'aws.ec2.security_groups_without_open_ingress', value: passRate(items), unit: 'ratio' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchSecurityGroups(region, credentials) {
  const { client, sdk } = await service('ec2', region, credentials);
  const groups = await pages(client, sdk.DescribeSecurityGroupsCommand, {}, (r) => r.SecurityGroups);
  const interfaces = await pages(client, sdk.DescribeNetworkInterfacesCommand, {}, (r) => r.NetworkInterfaces);

  const byGroup = new Map();
  for (const eni of interfaces) {
    for (const group of eni.Groups ?? []) {
      if (!byGroup.has(group.GroupId)) byGroup.set(group.GroupId, []);
      byGroup.get(group.GroupId).push({
        interface_id: eni.NetworkInterfaceId,
        type: eni.InterfaceType,
        description: eni.Description,
        attached_to: eni.Attachment?.InstanceId ?? eni.Attachment?.InstanceOwnerId ?? null,
      });
    }
  }
  return groups.map((g) => ({ ...g, attachments: byGroup.get(g.GroupId) ?? [] }));
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const publicPorts = profile?.aws?.public_ports ?? DEFAULT_PUBLIC_PORTS;
  const chain = {
    previousHash: previousHashes.get(CHECKS[0].id)?.hash ?? null,
    chainIndex: previousHashes.get(CHECKS[0].id)?.index ?? 0,
  };

  if (fixture) {
    const data = loadFixture(fixture, 'aws-security-groups');
    return [
      buildBundle({
        ...common,
        ...chain,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-security-groups', { declared_public_ports: publicPorts }),
        ...gradeIngressExposure(data.security_groups, {
          publicPorts,
          scopeId: `${data.account}/${data.region}`,
        }),
      }),
    ];
  }

  // Regions are enumerated from the profile and each one that cannot be read becomes a named
  // gap. Dropping an unreachable region would shrink the denominator to the regions that
  // answered, which is how a boundary reports clean over the half of itself it could see.
  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, regions, credentials }) => {
    const groups = [];
    const regionGaps = [];
    for (const region of regions) {
      try {
        groups.push(...(await fetchSecurityGroups(region, credentials)));
      } catch (err) {
        regionGaps.push({ id: `region/${region}`, reason: err.message });
      }
    }
    return gradeIngressExposure(groups, { publicPorts, scopeId: account.id, unexamined: regionGaps });
  });

  return [
    buildBundle({
      ...common,
      ...chain,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: {
        accounts: accounts.map((a) => a.id),
        collector_role: profile?.aws?.collector_role ?? null,
        declared_public_ports: publicPorts,
      },
      ...mergeGraded(parts, {
        sourceOfTruth: 'ec2:DescribeSecurityGroups per declared region, resolved against ec2:DescribeNetworkInterfaces',
        enumeratedFrom: 'the accounts and regions declared in the profile, counted before any was queried',
        metric: { metric_id: 'aws.ec2.security_groups_without_open_ingress', unit: 'ratio' },
        unexamined,
      }),
    }),
  ];
}
