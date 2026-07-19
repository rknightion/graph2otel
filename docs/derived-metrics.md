# Derived metrics: emit natively, or recording rule over the log twin?

Every blob-sourced signal already has a log twin (see [Signals](signals.md)). Some of
those signals also get a **natively-emitted graph2otel counter** derived from the same
event stream — `entra.graph_activity.requests` (#128), `entra.signin.count` (#187). Most
do not, and should not. This page documents the heuristic that decides which side of that
line a candidate signal falls on, and gives the recording-rule pattern for the ones that
don't clear the bar.

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

**Use a Loki recording rule over the log twin when the signal is low-volume and the use
case is retention/dashboard convenience, not latency-critical alerting:**

- `intune.compliance_alert` is the reference case: ~0.6 events/hour (#128 §4.3). A LogQL
  `count by` over that volume is free at any evaluation cadence — there is no query-cost
  argument for a permanent counter.
- Other candidates in this category: directory audits, provisioning events. Neither is
  high-volume enough on a typical tenant to justify graph2otel owning a permanent series
  for it; a recording rule gives the same materialized-series convenience (fast
  dashboards, longer retention than the raw logs) without graph2otel paying the
  active-series cost.
- A recording rule is a **scheduled LogQL query, remote-written to Mimir** by the Loki
  ruler. Zero graph2otel emission — graph2otel never sees this metric exist. The
  materialized series lives entirely in the Loki/Mimir stack, and its cost is the
  operator's to opt into per rule, not a standing cost graph2otel bakes into every
  collector.

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
[Signals](signals.md#querying-the-logs-in-loki--attributes-are-structured-metadata-not-stream-labels),
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
sum by (alert_type, operating_system, scenario_name) (
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

### Recording rule definition (Loki ruler)

Loki's ruler evaluates a LogQL query on a schedule and remote-writes the result to Mimir
as a regular Prometheus series — the same mechanism as a Mimir/Prometheus recording rule,
just with a LogQL expression instead of PromQL. Shape:

```yaml
groups:
  - name: graph2otel-derived-metrics
    interval: 1h
    rules:
      - record: intune_compliance_alert_count
        expr: |
          sum by (alert_type, operating_system, scenario_name) (
            count_over_time(
              {service_name="graph2otel"}
                | event_name=`intune.compliance_alert`
              [1h]
            )
          )
```

- `interval: 1h` matches the `[1h]` range in the query — evaluate no more often than the
  window you're counting over, or the materialized series double-counts overlapping
  windows.
- `record:` follows the Prometheus recording-rule naming convention
  (`<namespace>_<metric>_<unit or _count>`), not graph2otel's own OTLP dot-notation — this
  series never passes through graph2otel or OTLP, so graph2otel's naming/normalization
  rules ([Signals](signals.md#otlp--prometheus-name-normalization)) don't apply to it; it
  is named directly as it will appear in Mimir.
- The ruler remote-writes the result into Mimir like any other recording rule; once
  materialized it queries and dashboards exactly like a native metric, with none of the
  cost graph2otel would have paid to emit it natively.

Deduplication: the underlying log twin is at-least-once (~2.7-4% duplicate rate,
[Signals](signals.md#deduplicating-blob-sourced-records--azure-delivers-at-least-once)).
A raw `count_over_time` over the stream inherits that over-count exactly as a manual
LogQL count would. For a low-volume alerting signal this is immaterial (the same
reasoning #128 applies to the native counters' at-least-once behavior); if a use case
ever needs exact counts, dedupe on the twin's identity key before counting rather than
building that into the recording rule.

## Open deliverable: ship manifests, or document as examples?

Not yet decided whether to ship recording-rule manifests in-repo (e.g. via `gcx` /
rules-as-code, alongside the shipped [dashboards](https://github.com/rknightion/graph2otel/tree/main/dashboards))
or keep them as documented examples an operator adapts by hand. **Default: documented
examples, as above** — graph2otel does not currently own or deploy any Loki ruler
configuration, and shipping manifests would be a new deployment surface (ruler config
format, remote-write target, per-tenant `service_name`/label substitution) with its own
maintenance cost. Revisit if a second or third recording-rule candidate (directory
audits, provisioning) makes copy-paste-and-edit painful enough to justify templating.
