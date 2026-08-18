import { buildBundle } from '../../evidence/bundle.mjs';
import { fixtureScope, loadFixture, mergeGraded, perAccount, service } from '../lib/aws.mjs';

export const VERSION = '2.0.0';
export const PATH = 'src/collectors/aws/config.mjs';

export const CHECKS = [
  {
    id: 'aws.config.recorder-state',
    ksis: ['KSI-CNA-EIS', 'KSI-MLA-EVC', 'KSI-SVC-ACM'],
    fixture: 'aws-config',
    assertion:
      'A configuration recorder is running over all resource types including global ones, is delivering to a ' +
      'channel without error, and has at least one active evaluation rule.',
  },
];

/* ------------------------------------------------------------------- grading */

/**
 * Grades the continuous-assessment service that three indicators lean on.
 *
 * The two failure modes worth separating: a recorder that exists but is not recording, and a
 * recorder that is recording a subset of resource types. The second is the dangerous one,
 * because every downstream evaluation looks healthy while being silent about whatever was
 * excluded — a partial recorder produces a confident report over an undisclosed subset,
 * which is the same defect as an unreconciled population.
 *
 * `lastStatus` deliberately does not collapse into a boolean. AWS reports delivery failure
 * separately from recording state, and a recorder that is recording but not delivering is
 * generating evidence nobody can read.
 */
export function gradeRecorderState(config, accountId, { unexamined = [] } = {}) {
  const items = [];
  const recorders = config.recorders ?? [];

  for (const recorder of recorders) {
    const problems = [];
    if (!recorder.recording) problems.push('recorder is not recording');
    if (!recorder.all_supported) problems.push('not recording all supported resource types');
    if (!recorder.include_global_resource_types) {
      problems.push('global resource types excluded, so IAM changes are unrecorded');
    }
    if (recorder.last_error_code) problems.push(`last status error: ${recorder.last_error_code}`);

    items.push(
      problems.length
        ? { id: `recorder/${recorder.name}`, status: 'fail', detail: problems.join('; '), observed: recorder }
        : { id: `recorder/${recorder.name}`, status: 'pass', detail: 'Recording all supported and global resource types' }
    );
  }

  const channels = config.delivery_channels ?? [];
  items.push(
    channels.length
      ? { id: 'delivery-channel', status: 'pass', detail: `${channels.length} delivery channel(s) configured` }
      : {
          id: 'delivery-channel',
          status: 'fail',
          detail: 'No delivery channel, so recorded configuration is not persisted anywhere durable',
        }
  );

  const ruleCount = config.active_rule_count ?? 0;
  items.push(
    ruleCount > 0
      ? { id: 'evaluation-rules', status: 'pass', detail: `${ruleCount} active evaluation rule(s)`, observed: { count: ruleCount } }
      : {
          id: 'evaluation-rules',
          status: 'fail',
          detail:
            'Recording without any active evaluation rule. Configuration is being captured but nothing is ' +
            'assessing it, which is inventory rather than the persistent assessment the indicator asks for',
        }
  );

  items.unshift(
    recorders.length
      ? { id: `account/${accountId}`, status: 'pass', detail: `${recorders.length} configuration recorder(s) present` }
      : { id: `account/${accountId}`, status: 'fail', detail: 'No configuration recorder in this account' }
  );

  return {
    items,
    population: {
      // recorders + the account claim + the delivery-channel claim + the rules claim
      expected: recorders.length + 3 + unexamined.length,
      unexamined,
      source_of_truth:
        'config:DescribeConfigurationRecorders with config:DescribeConfigurationRecorderStatus, ' +
        'config:DescribeDeliveryChannels, and config:DescribeConfigRules',
      enumerated_from:
        'config:DescribeConfigurationRecorders, counted before any recorder status was resolved, plus the three ' +
        'account-level claims this check always makes',
    },
    metric: { metric_id: 'aws.config.active_rules', value: ruleCount, unit: 'count' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchConfig(region, credentials) {
  const { client, sdk } = await service('config', region, credentials);

  const described = await client.send(new sdk.DescribeConfigurationRecordersCommand({}));
  const statuses = await client.send(new sdk.DescribeConfigurationRecorderStatusCommand({}));
  const statusByName = new Map((statuses.ConfigurationRecordersStatus ?? []).map((s) => [s.name, s]));

  const recorders = (described.ConfigurationRecorders ?? []).map((recorder) => {
    const status = statusByName.get(recorder.name) ?? {};
    return {
      name: recorder.name,
      all_supported: Boolean(recorder.recordingGroup?.allSupported),
      include_global_resource_types: Boolean(recorder.recordingGroup?.includeGlobalResourceTypes),
      recording: Boolean(status.recording),
      last_status: status.lastStatus ?? null,
      last_error_code: status.lastErrorCode ?? null,
    };
  });

  const channels = await client.send(new sdk.DescribeDeliveryChannelsCommand({}));

  // Config rules paginate on NextToken but the command shape differs from the EC2 family, so
  // the loop is written out rather than routed through pages().
  let token;
  let activeRules = 0;
  do {
    const page = await client.send(new sdk.DescribeConfigRulesCommand({ NextToken: token }));
    activeRules += (page.ConfigRules ?? []).filter((r) => r.ConfigRuleState === 'ACTIVE').length;
    token = page.NextToken;
  } while (token);

  return {
    recorders,
    delivery_channels: (channels.DeliveryChannels ?? []).map((c) => ({ name: c.name, s3_bucket: c.s3BucketName })),
    active_rule_count: activeRules,
  };
}

/* ------------------------------------------------------------------- collect */

export async function collect({ profile, collectedAt, fixture, sourceCommit, previousHashes = new Map() }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };
  const chain = {
    previousHash: previousHashes.get(CHECKS[0].id)?.hash ?? null,
    chainIndex: previousHashes.get(CHECKS[0].id)?.index ?? 0,
  };

  if (fixture) {
    const data = loadFixture(fixture, 'aws-config');
    return [
      buildBundle({
        ...common,
        ...chain,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-config'),
        ...gradeRecorderState(data, data.account, { unexamined: data.unexamined ?? [] }),
      }),
    ];
  }

  const { parts, unexamined, accounts } = await perAccount(profile, async ({ account, region, credentials }) =>
    gradeRecorderState(await fetchConfig(region, credentials), account.id)
  );

  return [
    buildBundle({
      ...common,
      ...chain,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: { accounts: accounts.map((a) => a.id), collector_role: profile?.aws?.collector_role ?? null },
      ...mergeGraded(parts, {
        sourceOfTruth: 'the AWS Config recorder, delivery channel and rule state in each declared account',
        enumeratedFrom: 'the accounts declared in the profile, counted before any of them was reached',
        metric: { metric_id: 'aws.config.active_rules', unit: 'count' },
        unexamined,
      }),
    }),
  ];
}
