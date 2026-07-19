# Recording rules (rules-as-code)

**Grafana-managed** recording rules that materialize graph2otel's low-volume, blob-sourced
log twins into Prometheus metrics — for signals that don't clear the "emit a native counter"
bar (see [`docs/derived-metrics.md`](../docs/derived-metrics.md) for the heuristic). Each rule
runs a LogQL `count_over_time` against the Loki logs datasource on Grafana's evaluation
schedule and writes the result into Prometheus.

These are **Grafana-managed** rules (Grafana Alerting provisioning API, `record` block) — **not**
Loki/Mimir data-source-managed ruler rules. `type=recording` on the rule confirms it.

| file | metric | log twin (`event_name`) | group-by labels |
| --- | --- | --- | --- |
| `intune-compliance-alert-count.json` | `intune_compliance_alert_count` | `intune.compliance_alert` | `alert_type, operating_system, scenario_name` |
| `intune-enrollment-failure-count.json` | `intune_enrollment_failure_count` | `intune.enrollment_event` | `enrollment_type, operating_system, failure_category` |

## Where these are deployed

The m7kni Grafana stack (gcx context `m7kni`), folder **"graph2otel derived metrics"**
(`folderUID` in each JSON), rule group **`blob-derived`** at a **3600s (1h)** evaluation
interval. The `folderUID`, `datasourceUid` (`grafanacloud-logs`), and `targetDatasourceUid`
(`grafanacloud-prom`) in the JSON are specific to that stack; on a different stack, create a
folder and substitute its UID and the local Loki/Prometheus datasource UIDs.

## Apply

```sh
# 1. Create the folder (once); note its uid and put it in each rule's folderUID.
gcx api /api/folders -d '{"title":"graph2otel derived metrics"}'

# 2. Create each rule (POST is idempotent per title only if you pass a fixed uid; without one,
#    a repeat POST creates a DUPLICATE — check `gcx alert rules list` after).
gcx api /api/v1/provisioning/alert-rules -X POST -d @recording-rules/intune-compliance-alert-count.json
gcx api /api/v1/provisioning/alert-rules -X POST -d @recording-rules/intune-enrollment-failure-count.json

# 3. Set the group evaluation interval to match the [1h] range in the query.
gcx api /api/v1/provisioning/folder/<folderUID>/rule-groups/blob-derived \
  -X PUT -d '{"title":"blob-derived","interval":3600}'
```

## Verify

```sh
# rules present + type=recording + no error (state=inactive/health=unknown until first eval)
gcx api "/api/prometheus/grafana/api/v1/rules?folder_uid=<folderUID>" \
  --jq '.data.groups[].rules[] | .name + " type=" + .type + " health=" + (.health//"?") + " err=" + (.lastError//"none")'
```

A healthy tenant emits zero compliance-alert / enrollment-failure events, so the recorded
series are empty (`noDataState: OK`) until an event occurs — that is the expected steady
state, not a fault. The rule exists to capture the metric *when* one happens.
