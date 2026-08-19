# ADR 0010 — Alert on transition, not on state

**Status:** accepted · **Date:** 2026-08-18

## Context

The escalation this repository already had was sound in the part that is usually wrong. It narrowed
to controls that **ran and failed** rather than everything the coverage report lists, and it
suppressed repeats by fingerprinting the finding set. Both matter: the failure mode they avoid is a
daily message that is ninety percent "still not collected", and a channel people have muted is
alerting that looks present and does nothing.

What it could not do was say **what changed**. "The set of failing controls changed" is true and
nearly useless — the reader still has to diff two tables by eye to find the one control that started
failing this morning. A notification that requires the recipient to reconstruct its own news is a
notification that gets read once.

`ksi diff` already computes exactly that difference over the locker. It was being generated as a
report and never used for escalation, so the pipeline was producing the answer and throwing it away.

The wider problem is the one every monitoring system eventually has. A control failing for forty days
is one piece of news and thirty-nine reasons to stop reading. Alerting on **state** guarantees the
second; alerting on **transition** is the only version that stays legible long enough to be acted on.

## Decision

**A notification is built from the current findings for authority and the locker diff for narrative,
and it fires when something moved.**

`transitions()` maps a check whose result changed back to the indicators that claim it, yielding two
sets: indicators that newly acquired a failing check (`opened`) and those that lost their last one
(`closed`). Transitions through `warn` count in both directions — `warn → fail` is a transition into
failure and `fail → warn` is a transition out of it; neither is a no-op.

Severity is `failing`, `recovered`, or `clean`. **`recovered` is its own severity** because standing
down is news: an alerting system that can raise and never close is half a control, and the half it is
missing is the one that tells you the work is done.

The summary separates the two, and never restates the table:

```
Newly failing:
  KSI-CNA-EIS — aws.config.recorder-state started failing
Still failing (reported when they started): KSI-CMT-LMC, KSI-IAM-APM, …
```

`changed` is derived from the transitions rather than from stored state, so no additional state has
to be kept correct. The locker already knows what happened; nothing else needs to remember.

### Whether to deliver depends on what the sink can do

The whole module reduces to four lines, and the distinction they encode is not an implementation
detail:

```js
export function shouldDeliver(notification, sink, { always = false } = {}) {
  if (always || sink.stateful) return true;
  if (notification.severity === SEVERITY.CLEAN && !notification.changed) return false;
  return notification.changed;
}
```

A **stateless** sink — a webhook, a chat message — can only append. It must fire on transitions or it
becomes a daily repeat of yesterday's news.

A **stateful** sink owns something it can revise. It always receives the notification, including on
runs where nothing changed, **because deciding to close a standing issue requires being told that
nothing is wrong any more**. A quiet run is information to the only sink that can act on it.

### No sink is defaulted

`ksi notify` refuses without a declared sink.

A finding names a failing control and the resources behind it. Delivered somewhere, that is an
accurate inventory of where a boundary is weakest — so where it lands is a decision about who sees
that, not something a tool should guess. `--sink stdout` prints what would be sent, which is the
right way to look before sending.

Webhook URLs are redacted everywhere they are printed or stored, because most of them are
credentials.

## The bug that testing the fix caught

`diffLocker` defaults to comparing a check's **first** collection against its **last**. That is right
for a report a person reads — "what has changed since this locker began" — and wrong for alerting in
a way that is entirely silent.

A control that broke on Tuesday and was fixed on Wednesday is **invisible** across the full span:
both endpoints are green, and everything interesting happened in between. Wiring alerting to the
default would have suppressed **every recovery** the system ever had, producing exactly the
raise-but-never-stand-down failure this ADR exists to avoid — while looking correct in every test
that only checked new failures.

Hence the `latest` option, comparing a check's two most recent collections, and three tests pinning
the direction so it cannot be reverted quietly.

It is worth recording because the bug was in the *fix*, not in the code being fixed, and it was
reachable only by testing the direction nobody thinks to test: not "does it alert?" but "does it stop
alerting, and does it say so?"

## Consequences

- **A monitoring run that cannot escalate fails loudly.** A non-2xx from a webhook throws; a failed
  `gh` invocation throws. Swallowing either would turn an undelivered alert into a green tick
  asserting that nothing was wrong — the same silent-success shape as a collector that never ran
  ([ADR 0005](0005-preventive-and-detective.md)).
- **The GitHub issue sink wraps the existing decision logic** rather than reimplementing it, so the
  recovery path and fingerprint suppression keep their existing tests. It remains the only stateful
  sink, and therefore the only one that can close anything.
- **The first run cannot alert.** One collection is not a trend; `diff` reports nothing to compare and
  `notify` correctly declines. A pipeline that discards its locker between runs is permanently in
  this state and permanently silent, which is a property of the pipeline rather than of the
  environment — and the reason the locker is restored before every scheduled collection.
- **Transitions are computed per check, not per indicator.** An indicator claimed by two checks opens
  when either starts failing and closes only when the last one recovers, which follows from the
  routing map rather than from a rule in this module.
- **Severity is not priority.** Nothing here decides which failing control matters most; it reports
  what moved. Ranking findings would require a risk model this harness does not have and should not
  invent.
