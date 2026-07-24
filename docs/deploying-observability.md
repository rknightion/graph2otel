# Deploying the observability assets

graph2otel ships three kinds of Grafana asset, each in its own top-level
directory:

| Directory | Assets | Format | Target Grafana Cloud folder |
| --- | --- | --- | --- |
| `dashboards/` | 6 dashboards (**generated**) | raw Grafana dashboard JSON (top-level `uid`) | folder of your choice |
| `alerts/` | 10 alert rules + 1 contact-point/policy file | Grafana **file-provisioning** YAML (`apiVersion: 1` + `groups:`) | `graph2otel` |
| `recording-rules/` | 2 recording rules | Grafana-managed rule objects (provisioning API JSON) | `graph2otel derived metrics` |

The `gcx` CLI is the reproducible deploy path documented here. There is **no
GitSync flow in this repo today** — if one is later adopted, document its repo
and path in this file so a successor can reproduce the production deploy.

> `gcx` targets whichever Grafana Cloud stack its context points at. Select it
> first (`gcx config` / `gcx context`); the m7kni reference deploy uses the
> `m7kni` context. All the commands below are stack-scoped by that context.

## Dashboards

The six dashboards are plain Grafana dashboard JSON — each has a stable
top-level `uid` that is also its slug:

| File | UID / slug | Title |
| --- | --- | --- |
| `dashboards/intune-fleet-overview.json` | `intune-fleet-overview` | Intune Fleet Overview |
| `dashboards/entra-compliance-overview.json` | `graph2otel-entra-compliance` | graph2otel: Entra ID compliance overview |
| `dashboards/m365-services-overview.json` | `graph2otel-m365-services` | graph2otel: Microsoft 365 services overview |
| `dashboards/defender-security-overview.json` | `graph2otel-defender-security` | graph2otel: Defender security posture |
| `dashboards/purview-compliance-overview.json` | `graph2otel-purview-compliance` | graph2otel: Purview data governance |
| `dashboards/graph2otel-self-observability.json` | `graph2otel-self-obs` | graph2otel / Self-Observability |

Push each with `gcx dashboards` (the UID is the update key):

```bash
# First time — create by file:
for f in dashboards/*.json; do gcx dashboards create -f "$f"; done

# Subsequent updates — update by UID:
gcx dashboards update intune-fleet-overview          -f dashboards/intune-fleet-overview.json
gcx dashboards update graph2otel-entra-compliance    -f dashboards/entra-compliance-overview.json
gcx dashboards update graph2otel-m365-services       -f dashboards/m365-services-overview.json
gcx dashboards update graph2otel-defender-security   -f dashboards/defender-security-overview.json
gcx dashboards update graph2otel-purview-compliance  -f dashboards/purview-compliance-overview.json
gcx dashboards update graph2otel-self-obs            -f dashboards/graph2otel-self-observability.json
```

You can also import any of them in the Grafana UI: **Dashboards → New →
Import**, upload the JSON.

### They are GENERATED — do not hand-edit them

`dashboards/*.json` is built by `grafana/build_dashboard.py` from
`grafana/boards/*.py` and `spec/signal-catalog.json`, and `make grafana-check`
(a required CI leg) fails on a hand-edited file. To change a panel, edit the
board module and run `make dashboard`. See
[`grafana/AUTHORING.md`](../grafana/AUTHORING.md).

The same gate fails when a metric graph2otel emits reaches no panel at all, so
the dashboards cannot silently fall behind the collectors: `spec/signal-catalog.json`
is itself generated from what the collectors' tests actually emit, with no human
step between a new collector and the gate noticing it.

### Log panels need a Loki datasource

Every dashboard carries a **Logs** row (#162) built on
`{service_name="graph2otel"} | event_name=…`, which needs a **Loki** datasource
selected in the `Loki datasource` dropdown. Without one those panels say so
rather than looking broken; the metric panels are unaffected.

Log attributes are Loki **structured metadata**, not stream labels — only
`service_name` is a stream label. `{event_name="entra.signin"}` matches zero rows
silently. See [signals.md](signals.md#querying-the-logs-in-loki--attributes-are-structured-metadata-not-stream-labels).

### Datasource UID — nothing to substitute

Each dashboard carries a **`datasource` template variable** (type
`datasource`), so the Prometheus/Mimir datasource is chosen at view time from
the variable's dropdown — there is **no hardcoded datasource UID to edit in the
file** before import. The only concrete UIDs in the JSON are the dashboard's
own `uid` (above) and Grafana's built-in `-- Grafana --` datasource (used for
annotations); leave both as-is.

## Alert rules

`alerts/graph2otel-alerts.yaml` is Grafana **file-provisioning** schema
(`apiVersion: 1` + `groups:`), not a `grafana.app` resource manifest — so it is
applied through Grafana's HTTP **provisioning API** (which `gcx api` proxies),
Terraform (`grafana_rule_group` / `grafana_contact_point` /
`grafana_notification_policy`), or Grizzly. It is **not** a
`gcx resources push` target (that command consumes `rules.alerting.grafana.app`
resource manifests, which these files are not).

The rules land in the Grafana Cloud folder **`graph2otel`**.

```bash
# Create the folder once (note its uid):
gcx api /api/folders -X POST -d '{"title":"graph2otel"}'

# Apply the rule group + contact point / policy via the provisioning API:
gcx api /api/v1/provisioning/alert-rules   -X POST -d @alerts/graph2otel-alerts.yaml
gcx api /api/v1/provisioning/contact-points -X POST -d @alerts/graph2otel-contactpoints.yaml
```

**Datasource UID substitution:** every `expr` in `graph2otel-alerts.yaml` uses
the portable default `datasourceUid: "grafanacloud-prom"`. Replace it with your
actual Prometheus/Mimir datasource UID (`gcx datasources list`, or Connections
→ Data sources in the UI) before applying if yours differs.

See [`alerts/README.md`](../alerts/README.md) for the per-rule rationale,
thresholds, the OTLP→Prometheus metric-name normalization, and the
multi-tenant grouping model. Replace the no-op contact point with a real
receiver before relying on these to page anyone.

## Recording rules

`recording-rules/*.json` are individual Grafana-managed rule objects, applied
through the same provisioning API and landing in the folder
**`graph2otel derived metrics`**, rule group `blob-derived` at a 1h evaluation
interval:

```bash
# 1. Create the folder once; put its uid into each rule's folderUID.
gcx api /api/folders -X POST -d '{"title":"graph2otel derived metrics"}'

# 2. Create each rule (a repeat POST without a fixed uid creates a DUPLICATE —
#    check `gcx alert rules list` afterwards).
gcx api /api/v1/provisioning/alert-rules -X POST -d @recording-rules/intune-compliance-alert-count.json
gcx api /api/v1/provisioning/alert-rules -X POST -d @recording-rules/intune-enrollment-failure-count.json

# 3. Set the group interval to match the [1h] range in the query.
gcx api /api/v1/provisioning/folder/<folderUID>/rule-groups/blob-derived \
  -X PUT -d '{"title":"blob-derived","interval":3600}'
```

**Datasource UID substitution:** each rule JSON pins `datasourceUid`
(`grafanacloud-logs`, the Loki source it queries) and `targetDatasourceUid`
(`grafanacloud-prom`, the Prometheus sink it writes to), plus a `folderUID`.
All three are stack-specific — substitute your local Loki/Prometheus datasource
UIDs and the folder UID from step 1.

See [`recording-rules/README.md`](../recording-rules/README.md) for the metric
↔ log-twin mapping and verification queries.

## If GitSync is adopted later

This repo has no GitSync (git-to-Grafana) flow today; the `gcx` commands above
are the deploy path. If a GitSync repo is later adopted for these assets,
document its repository and the target paths for the dashboards / alert rules /
recording rules here, so the production deploy stays reproducible from this
file alone.
