import { execFileSync } from 'node:child_process';

import { decide, LABEL, readFingerprint, renderBody, TITLE } from '../../scripts/ccm-issue.mjs';
import { SEVERITY } from './notification.mjs';

/**
 * Where a notification goes.
 *
 * Every sink here is stateless except the GitHub one, and that distinction decides the
 * behavior rather than being an implementation detail. A stateless sink — a webhook, a chat
 * message — can only append, so it must fire on *transitions* or it becomes a daily repeat
 * of yesterday's news. A stateful sink owns something it can revise, so it reconciles: it
 * updates a living issue when the finding set changes and closes it when the controls
 * recover, which is the half of escalation most implementations skip. An alert that cannot
 * stand down is only half a control.
 *
 * No sink is defaulted. Compliance findings name failing controls and the resources behind
 * them, so where they are delivered is a decision about who sees an inventory of a boundary's
 * weakest points — not something a tool should guess. `ksi notify` refuses without a declared
 * sink and suggests `stdout` for a dry run.
 */

/* ------------------------------------------------------------------------ stdout */

/** Prints. Always available, and the right way to see what would be sent before sending it. */
export function stdoutSink() {
  return {
    kind: 'stdout',
    stateful: false,
    describe: () => ({ kind: 'stdout', target: 'the console', why: 'A dry run. Nothing leaves this process.' }),
    async deliver(notification) {
      const { context } = notification;
      console.log(`[${notification.severity}] ${notification.title}`);
      console.log(`  mode ${context.mode} · profile ${context.profile}${context.runUrl ? ` · ${context.runUrl}` : ''}`);
      for (const line of notification.summary.split('\n')) console.log(`  ${line}`);
      return { delivered: true, target: 'stdout' };
    },
  };
}

/* ----------------------------------------------------------------------- webhook */

/**
 * A JSON POST to a declared URL. The answer when the receiving stack is not known.
 *
 * The payload is the notification itself rather than a shape borrowed from one vendor,
 * because anything that can receive a webhook can reshape JSON, and guessing at a vendor's
 * schema is how an integration breaks silently when that vendor changes it.
 */
export function webhookSink({ url, headers = {} }) {
  return {
    kind: 'webhook',
    stateful: false,
    describe: () => ({ kind: 'webhook', target: redact(url), why: 'A JSON POST of the notification, for whatever receives it to reshape.' }),
    async deliver(notification, { fetchImpl = fetch } = {}) {
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(notification),
      });
      if (!res.ok) throw new Error(`Webhook ${redact(url)} returned HTTP ${res.status}.`);
      return { delivered: true, target: redact(url) };
    },
  };
}

/* ------------------------------------------------------------------------- slack */

const SLACK_COLOUR = { failing: '#B60205', recovered: '#2D6A4F', clean: '#5A6673' };

/** Slack incoming webhook. A concrete example of reshaping, and a common enough target to ship. */
export function slackSink({ url, channel = null }) {
  return {
    kind: 'slack',
    stateful: false,
    describe: () => ({ kind: 'slack', target: redact(url), why: 'An incoming webhook message, colored by severity.' }),
    async deliver(notification, { fetchImpl = fetch } = {}) {
      const { context } = notification;
      const detail = [
        `*${notification.title}*`,
        '```',
        notification.summary,
        '```',
        `mode \`${context.mode}\` · profile \`${context.profile}\``,
        context.runUrl ? `<${context.runUrl}|run>` : null,
      ]
        .filter(Boolean)
        .join('\n');

      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ...(channel ? { channel } : {}),
          attachments: [{ color: SLACK_COLOUR[notification.severity] ?? SLACK_COLOUR.clean, text: detail, mrkdwn_in: ['text'] }],
        }),
      });
      if (!res.ok) throw new Error(`Slack webhook returned HTTP ${res.status}.`);
      return { delivered: true, target: 'slack' };
    },
  };
}

/* ------------------------------------------------------------------ github issue */

/**
 * One living issue, opened when a control is demonstrably not working and closed when it
 * recovers.
 *
 * Wraps the decision logic that already existed rather than reimplementing it, so the
 * recovery path and the fingerprint suppression keep their existing tests. This is the only
 * stateful sink, which is why it is the only one that can close anything.
 */
export function githubIssueSink({ repo = null } = {}) {
  const gh = (args, { allowFailure = false } = {}) => {
    const full = repo ? [args[0], '--repo', repo, ...args.slice(1)] : args;
    try {
      return execFileSync('gh', full, { encoding: 'utf8' });
    } catch (err) {
      if (allowFailure) return null;
      // Never swallowed. A monitoring run that cannot escalate has to fail loudly, or it
      // becomes a green tick asserting that nothing was wrong.
      throw new Error(`gh ${full.join(' ')} failed: ${err.stderr?.trim() || err.message}`);
    }
  };

  return {
    kind: 'github-issue',
    stateful: true,
    describe: () => ({ kind: 'github-issue', target: repo ?? 'the current repository', why: 'A living issue, updated when the finding set changes and closed when it recovers.' }),

    async deliver(notification) {
      const existingRaw = gh(['issue', 'list', '--label', LABEL, '--state', 'open', '--json', 'number,body', '--limit', '1']);
      const [existing] = JSON.parse(existingRaw || '[]');
      const { action, reason } = decide({ findings: notification.findings, existing: existing ?? null });

      if (action === 'none') return { delivered: false, action, reason };

      const body = renderBody({
        findings: notification.findings,
        mode: notification.context.mode,
        profile: notification.context.profile,
        runUrl: notification.context.runUrl,
        generatedAt: notification.context.generatedAt,
      });

      if (action === 'create') {
        const labels = gh(['label', 'list', '--json', 'name'], { allowFailure: true });
        if (!labels || !JSON.parse(labels).some((l) => l.name === LABEL)) {
          gh(['label', 'create', LABEL, '--description', 'Raised by a scheduled control monitoring run', '--color', 'B60205']);
        }
        const url = gh(['issue', 'create', '--title', TITLE, '--body', body, '--label', LABEL]);
        return { delivered: true, action, reason, target: url.trim() };
      }
      if (action === 'update') {
        gh(['issue', 'edit', String(existing.number), '--body', body]);
        gh(['issue', 'comment', String(existing.number), '--body', `${reason}.\n\n${notification.summary}`]);
        return { delivered: true, action, reason, target: `#${existing.number}` };
      }
      gh(['issue', 'close', String(existing.number), '--comment', `Closing: ${reason}.`]);
      return { delivered: true, action, reason, target: `#${existing.number}` };
    },
  };
}

/* -------------------------------------------------------------------- resolution */

/** Hides a webhook secret in anything printed or stored. Most webhook URLs are credentials. */
export function redact(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}/…`;
  } catch {
    return '(unparseable url)';
  }
}

export function resolveSink(profile, { override = null } = {}) {
  const declared = override ? { kind: override } : profile?.alerting?.sink;
  if (!declared?.kind) {
    throw new Error(
      'No alerting sink is declared. Compliance findings name failing controls and the resources behind them, ' +
        'so where they are delivered is a decision about who sees an inventory of a boundary\'s weakest points — ' +
        'not something this tool should guess. Set alerting.sink in the profile, or pass --sink stdout for a dry run.'
    );
  }

  switch (declared.kind) {
    case 'stdout':
      return stdoutSink();
    case 'webhook': {
      const url = process.env[declared.url_env ?? 'KSI_ALERT_WEBHOOK'] ?? declared.url;
      if (!url) throw new Error(`alerting.sink is webhook but neither ${declared.url_env ?? 'KSI_ALERT_WEBHOOK'} nor alerting.sink.url is set.`);
      return webhookSink({ url, headers: declared.headers ?? {} });
    }
    case 'slack': {
      const url = process.env[declared.url_env ?? 'KSI_SLACK_WEBHOOK'] ?? declared.url;
      if (!url) throw new Error(`alerting.sink is slack but neither ${declared.url_env ?? 'KSI_SLACK_WEBHOOK'} nor alerting.sink.url is set.`);
      return slackSink({ url, channel: declared.channel ?? null });
    }
    case 'github-issue':
      return githubIssueSink({ repo: declared.repo ?? null });
    default:
      throw new Error(`Unknown alerting.sink.kind "${declared.kind}". Known: stdout, webhook, slack, github-issue.`);
  }
}

/**
 * Whether this notification should be delivered to this sink.
 *
 * The whole point of the module, in four lines. A stateless sink fires only on a transition,
 * because it can only append and a control failing for forty days is not forty pieces of
 * news. A stateful sink always gets the notification, because only it can decide to close
 * something — and deciding to close requires being told about a run where nothing changed.
 */
export function shouldDeliver(notification, sink, { always = false } = {}) {
  if (always || sink.stateful) return true;
  if (notification.severity === SEVERITY.CLEAN && !notification.changed) return false;
  return notification.changed;
}
