# Derived metrics: emit natively, or query the log twin?

Every blob-sourced signal already has a log twin (see [Signals](signals.md)). Some of
those signals also get a **natively-emitted graph2otel counter** derived from the same
event stream — `entra.graph_activity.requests` (#128), `entra.signin.count` (#187). Most
do not, and should not. This page documents the heuristic that decides which side of that
line a candidate signal falls on.

> **graph2otel ships no recording rules (#297).** Both of the ones it used to ship are
> **retired**, on measurement rather than preference — see
> [Why the recording rules were retired](#why-the-recording-rules-were-retired) at the end
> of this page before proposing another one. The answer for a signal that does not clear
> the native-emission bar is a LogQL `count by` over the log twin, which costs nothing and
> cannot go quietly stale.

This only applies to blob-sourced signals with no Graph poll route. A signal with a Graph
route gets its metric from the poll, fresh, with no recency gate needed — #128 and this
heuristic are scoped to blob-only signals (see #131).

## The heuristic

Grafana Cloud bills on active series (#105). A natively-emitted counter is **permanent
series cost** — it exists for the life of the collector, whether or not anyone ever
queries it. That cost has to be justified against the free alternative: a LogQL
`count by (...)` over the log twin, run ad hoc or as a dashboard panel. The question is
never "would a counter be useful" — a counter is always useful — it's whether the signal
clears the bar that makes a permanent series cheaper than a LogQL query.

**Emit natively from graph2otel when the signal is high-volume and alert-latency-critical:**

- High volume means a `count by` over the raw log twin is itself an expensive query at
  alert-evaluation cadence — `entra.graph_activity.requests` is ~150k rows/week; scanning
  that on every alert tick does not scale the way a pre-aggregated counter does.
- Alert-latency-critical means the metric feeds an alert rule that must not scan logs to
  evaluate — 401/403/429/5xx spikes on `entra.graph_activity.requests` are
  token-misuse/recon/throttle signals where evaluation latency matters.
- Both `entra.graph_activity.requests` (#128) and `entra.signin.count` (#187) clear this
  bar: high volume, and both feed alert rules.

**Query the log twin directly when the signal is low-volume and the use case is
retention/dashboard convenience, not latency-critical alerting:**

- `intune.compliance_alert` is the reference case: ~0.6 events/hour (#128 §4.3). A LogQL
  `count by` over that volume is free at any evaluation cadence — there is no query-cost
  argument for a permanent counter.
- Other candidates in this category: directory audits, provisioning events. Neither is
  high-volume enough on a typical tenant to justify graph2otel owning a permanent series
  for it, and a dashboard panel running the LogQL `count by` answers the same question at
  query time.
- **A recording rule looks like the obvious middle ground and is not.** It materializes
  the same aggregate on Grafana's evaluation schedule, at the operator's cost rather than
  graph2otel's — but it introduces a second, invisible correctness surface: the rule's
  query window has to overlap its source's *event times*, and for a blob-derived stream it
  does not. That is not a tuning problem; see the retirement note below.

**The trade-off, stated flat:** every natively-emitted counter is permanent active-series
cost graph2otel owns forever, on every tenant, whether or not it is ever queried. It only
earns that cost by beating "just query the log twin with LogQL" on one of: alerting
latency (the query is too expensive to run at alert cadence), retention beyond Loki's log
retention window, or a dashboard that must not scan logs. That is #128's bar, and it
applies to every future candidate, not just the ones already decided.

## Worked example: `intune.compliance_alert`

Rejected as a graph2otel-emitted counter in #128 (§4.3): ~0.6 events/hour on a live
tenant, so a LogQL `count by` answers "how many compliance alerts, broken down by type"
for free — there is no volume or latency argument for a permanent counter here.

The log twin already carries everything the recording rule needs as structured metadata
(`event_name`, `alert_type`, `operating_system`, `scenario_name` — see
`docs/collectors.md` for the full `intune.compliance_alert` attribute set). Per
[Signals](signals.md#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels),
attributes on a graph2otel log record are **Loki structured metadata, not stream
labels** — only `service_name` is a stream label. So the query must select the stream
first, then filter on the attribute with a `|` label-filter:

```logql
count_over_time(
  {service_name="graph2otel"}
    | event_name=`intune.compliance_alert`
  [1h]
)
```

...and, grouped for the recording rule below:

```logql
sum by (tenant_id, alert_type, operating_system, scenario_name) (
  count_over_time(
    {service_name="graph2otel"}
      | event_name=`intune.compliance_alert`
    [1h]
  )
)
```

A `{event_name="intune.compliance_alert"}` stream selector would match zero rows
silently — the label-filter-after-selector form above is required, exactly as documented
for every other graph2otel log query.

### The panel query, not a recording rule

Put that LogQL straight on a dashboard panel or an ad-hoc Explore query. There is nothing to
provision, nothing to keep in sync with the catalog, and nothing that can silently stop
producing data.

Deduplication: the underlying log twin is at-least-once (~2.7-4% duplicate rate,
[Signals](signals.md#deduplicating-blob-sourced-records-azure-delivers-at-least-once)).
A raw `count_over_time` over the stream inherits that over-count. For a low-volume signal
this is immaterial (the same reasoning #128 applies to the native counters' at-least-once
behavior); if a use case ever needs exact counts, dedupe on the twin's identity key before
counting.

**Choose the range from the source's event-time lag, not from habit.** A blob-derived
stream replays historical records, so "recent by event time" and "recently ingested" differ
by days. `intune.compliance_alert` was measured at 3.3-7.0 days of event-time lag (median
5.97, n=223, `live-measured 2026-07-27, #297`), so a `[1h]` range over it returns nothing
at all — see the retirement note below, where exactly that mistake was shipped.

## Worked example: `intune.enrollment_event`

`intune.enrollment_event` is the **Graph-only** enrollment-troubleshooting log source (a
`WindowCollector` over `GET /deviceManagement/troubleshootingEvents`, not a blob signal). It
therefore cannot take the blob `Derive` seam at all, and per [#131] Graph WindowCollectors
emit zero metrics — so a natively-emitted `intune.enrollment_event.count` is not available
by construction (this is why #189 could not be built as a `Derive` wiring job). A LogQL query
over its log twin is how you get an enrollment-failure rate without touching the collector
engine:

```logql
sum by (tenant_id, enrollment_type, operating_system, failure_category) (
  count_over_time(
    {service_name="graph2otel"}
      | event_name=`intune.enrollment_event`
    [1h]
  )
)
```

The twin emits one record **per failed enrollment** (it is failures-only — there is no
success record), so the count is already an enrollment-failure count; `enrollment_type`,
`operating_system`, and `failure_category` are bounded structured-metadata attributes on it.
Widen the range to the tenant's observed lag before reading anything into an empty result.

This signal also had a recording rule (#189) and it is retired: on the m7kni tenant
`intune.enrollment_event` produced no rows at all over a 7-day window, so the rule had no
source to record from. See below.

## Why the recording rules were retired

graph2otel used to ship two Grafana-managed Loki recording rules —
`intune_compliance_alert_count` and `intune_enrollment_failure_count`, created by #188/#189.
Both are **retired** (#297, 2026-07-27) and no recording rule ships in this repository in
any form. `grafana/build_rules.py` gates their return: a committed YAML or JSON file
carrying a top-level Grafana `record` block fails the build, whatever it is called.

**They recorded nothing for 30+ days while reporting `health: ok`.** Measured, read-only, on
a live tenant:

```
count(count_over_time(intune_compliance_alert_count[30d]))   -> EMPTY
count(count_over_time(intune_enrollment_failure_count[30d])) -> EMPTY
```

Both evaluated hourly, in 0.4s, with no error, and wrote no series ever.

**The cause is structural, not a bug to fix.** `relativeTimeRange: {from: 3600, to: 0}` with
`count_over_time(...[1h])` selects the last hour of **event time**. Blob-ingested Intune
compliance alerts do not have event times in the last hour — across 223 sampled records the
newest was 3.31 days old, the median 5.97 days, the oldest 6.95 days, and **zero** fell
within either the rule's 1h window or even 24h. The rule was not missing late stragglers; it
was incapable of seeing its data source at all. `intune.enrollment_event` returned nothing
over 7 days on that tenant, so the second rule had no source either.

Widening the window to `[7d]` would "work" by recomputing a 7-day range every hour over data
that never changes, re-recording identical counts, with duplicate and cost semantics that
would then have to be measured — cost with no consumer. Keying the derivation on ingestion
time instead would contradict the standing rule that a record's timestamp is its event time
and never its arrival time.

**Nothing consumed their output.** The central cardinality limiter (#235) plus the per-entity
log twins already answer "how many" via a LogQL `count by`, free, with no materialized
series. So retirement lost no capability.

**The generalisable lesson, which is the reason this note is this long:** a green tick is not
evidence of data. Both rules were healthy, fast, error-free and useless, and no count gate
could have revealed it — the live and repository inventories agreed on two rules and
disagreed on nothing. Only querying for the metric they were supposed to write found it.
Before adding any derived-metric mechanism, check that its window can actually overlap its
source's event times.

