import { buildBundle } from '../../evidence/bundle.mjs';
import { callerIdentity, fixtureScope, loadFixture, resolveAccounts, service } from '../lib/aws.mjs';

export const VERSION = '1.0.0';
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
export function gradeRecorderState(config, accountId) {
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
      expected: recorders.length + 3,
      examined: items.length,
      source_of_truth:
        'config:DescribeConfigurationRecorders with config:DescribeConfigurationRecorderStatus, ' +
        'config:DescribeDeliveryChannels, and config:DescribeConfigRules',
    },
    metric: { metric_id: 'aws.config.active_rules', value: ruleCount, unit: 'count' },
  };
}

/* ------------------------------------------------------------------ fetching */

async function fetchConfig(region) {
  const { client, sdk } = await service('config', region);

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

export async function collect({ profile, collectedAt, fixture, sourceCommit }) {
  const common = { collectorPath: PATH, collectorVersion: VERSION, collectedAt, sourceCommit };

  if (fixture) {
    const data = loadFixture(fixture, 'aws-config');
    return [
      buildBundle({
        ...common,
        checkId: CHECKS[0].id,
        ksis: CHECKS[0].ksis,
        assertion: CHECKS[0].assertion,
        scope: fixtureScope(fixture, 'aws-config'),
        ...gradeRecorderState(data, data.account),
      }),
    ];
  }

  const accounts = resolveAccounts(profile);
  const region = accounts[0].regions?.[0] ?? 'us-east-1';
  const identity = await callerIdentity(region);

  return [
    buildBundle({
      ...common,
      checkId: CHECKS[0].id,
      ksis: CHECKS[0].ksis,
      assertion: CHECKS[0].assertion,
      scope: { account: identity.account, credential_arn: identity.arn, region },
      ...gradeRecorderState(await fetchConfig(region), identity.account),
    }),
  ];
}
