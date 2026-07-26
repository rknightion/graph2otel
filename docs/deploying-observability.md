# Deploying the observability assets

graph2otel ships three kinds of Grafana asset, each in its own top-level
directory. The generated inventory is drift-gated at
**6 dashboards, 14 alert rules, and 2 recording rules**:

| Directory | Assets | Format | Target Grafana Cloud folder |
| --- | --- | --- | --- |
| `dashboards/` | 6 dashboards (**generated**) | raw Grafana dashboard JSON (top-level `uid`) | folder of your choice |
| `alerts/` | 14 alert rules (**generated**) + 1 contact-point/policy file | Grafana **file-provisioning** YAML (`apiVersion: 1` + `groups:`) | `graph2otel` |
| `recording-rules/` | 2 recording rules (**generated**) | Grafana-managed rule objects (provisioning API JSON) | `graph2otel derived metrics` |

The `gcx` CLI is the reproducible deploy path documented here. There is **no
GitSync flow in this repo today** — if one is later adopted, document its repo
and path in this file so a successor can reproduce the production deploy.

> `gcx` targets whichever Grafana Cloud stack its context points at. Select it
> first (`gcx config` / `gcx context`); the m7kni reference deploy uses the
> `m7kni` context. All the commands below are stack-scoped by that context.

## Dashboards

The dashboards are plain Grafana dashboard JSON — each has a stable
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
[`grafana/AUTHORING.md`](https://github.com/rknightion/graph2otel/blob/main/grafana/AUTHORING.md).

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
silently. See [signals.md](signals.md#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels).

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

The alert-rule file is generated from the `RULES` list in
`grafana/build_rules.py`; do not hand-edit it. Change the builder, run
`make rules`, then run `make grafana-check`. The contact-point/policy file is
hand-authored and remains the operator-owned deployment seam.

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

See [`alerts/README.md`](https://github.com/rknightion/graph2otel/blob/main/alerts/README.md) for the per-rule rationale,
thresholds, the OTLP→Prometheus metric-name normalization, and the
multi-tenant grouping model. Replace the no-op contact point with a real
receiver before relying on these to page anyone.

## Recording rules

`recording-rules/*.json` are individual Grafana-managed rule objects, applied
through the same provisioning API and landing in the folder
**`graph2otel derived metrics`**, rule group `blob-derived` at a 1h evaluation
interval:

The two JSON files are generated from the `RECORDING` list in
`grafana/build_rules.py`; do not hand-edit them. Change the builder, run
`make rules`, then run `make grafana-check`.

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

See [`recording-rules/README.md`](https://github.com/rknightion/graph2otel/blob/main/recording-rules/README.md) for the metric
↔ log-twin mapping and verification queries.

## Read-only semantic canary

`make grafana-check` proves that generated Grafana assets and their query
vocabulary agree with the repository. It does not prove that a selected live
datasource accepts those queries or returns the required labels. The opt-in
semantic canary covers that live boundary without changing Grafana:

```bash
make grafana-canary \
  GRAFANA_CONTEXT=<gcx-context> \
  GRAFANA_PROMETHEUS_DATASOURCE=<prometheus-uid> \
  GRAFANA_LOKI_DATASOURCE=<loki-uid>
```

The versioned probe set is
[`spec/grafana-semantic-canary.json`](../spec/grafana-semantic-canary.json).
The runner first verifies each datasource's type, then executes representative
PromQL and structured-metadata LogQL queries and reads back one stable alert
rule's evaluator health. It makes no create, update, or delete request.

The JSON receipt distinguishes:

- `nonempty` from an explicitly permitted `healthy_empty`;
- `unexpected_empty` from a backend query error;
- missing required labels from valid empty results;
- wrong datasource selection from invalid query syntax;
- evaluator errors and never-evaluated rules from healthy rule read-back.

Exit `0` means every semantic probe passed, exit `1` means the backend answered
but a semantic assertion failed, and exit `2` means the manifest, `gcx`,
authentication, transport, or response shape failed operationally.

Only collector availability is required to return data. Optional log,
histogram, and recording signals may be healthy-empty. In particular, the
recording probe does not claim completeness for late-queryable records; see
[#297](https://github.com/rknightion/graph2otel/issues/297).

The repository does not schedule this command or carry a live credential.
Selecting a target, provisioning a least-privilege read-only credential,
choosing receipt retention, and owning failure routing are deployment decisions.
Offline manifest/runner tests are already part of `make grafana-check`; run the
narrow lane with `make grafana-canary-check`.

## Dashboard performance baseline

The policy-free #309 baseline records the generated estate's current shape:
panel and row counts, expanded/collapsed rows, query panels and targets,
instant/range modes, expression bytes, and repeated expressions.

```bash
make grafana-performance-baseline > baseline.json
```

An optional live lane renders each stable dashboard UID serially through the
configured `gcx` context:

```bash
python3 grafana/performance_baseline.py \
  --live-context <gcx-context> \
  --since 6h \
  --width 1920 \
  --height 1080 \
  --repeat 1 \
  --var datasource=<prometheus-uid> \
  --var loki_datasource=<loki-uid> \
  --var tenant=<tenant-selection> \
  > baseline.json
```

Live snapshots use concurrency 1 and a temporary directory that is removed
after measurement. The receipt records runtime variable **names**, never their
values. Each elapsed value is end-to-end Grafana Image Renderer time: renderer
startup, datasource work, dashboard execution, image construction, and transfer
are all included. It is not a backend-query-latency measurement, and repeat 1
is not labelled cold or warm.

This tool records evidence; it does not choose a performance policy. Numeric
overview/explorer budgets, allowed variance, waiver review, CI/deployment
credentials, and failure routing remain #309 decisions after #302 freezes the
dashboard topology. Offline tests run under `make grafana-check`; the narrow
lane is `make grafana-performance-check`.

## If GitSync is adopted later

This repo has no GitSync (git-to-Grafana) flow today; the `gcx` commands above
are the deploy path. If a GitSync repo is later adopted for these assets,
document its repository and the target paths for the dashboards / alert rules /
recording rules here, so the production deploy stays reproducible from this
file alone.
