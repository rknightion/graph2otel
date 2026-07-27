# Deploying the observability assets

graph2otel ships three kinds of Grafana asset, each in its own top-level
directory. The generated inventory is drift-gated at
**1 dashboard, 14 alert rules, 2 recording rules, and 5 paused detection examples**:

| Directory | Assets | Format | Target Grafana Cloud folder |
| --- | --- | --- | --- |
| `dashboards/` | 1 dashboard (**generated**) | Grafana **v2 dynamic dashboard** resource (`dashboard.grafana.app/v2`) | folder of your choice |
| `alerts/` | 14 alert rules (**generated**) | Grafana **file-provisioning** YAML (`apiVersion: 1` + `groups:`) | `graph2otel` |
| `alerts/` | 5 detection examples (**generated**, all **paused**) | same file-provisioning YAML, separate group | `graph2otel detections` |
| `recording-rules/` | 2 recording rules (**generated**) | Grafana-managed rule objects (provisioning API JSON) | `graph2otel derived metrics` |

The `gcx` CLI is the reproducible deploy path documented here. There is **no
GitSync flow in this repo today** — if one is later adopted, document its repo
and path in this file so a successor can reproduce the production deploy.

> `gcx` targets whichever Grafana Cloud stack its context points at. Select it
> first (`gcx config` / `gcx context`); the m7kni reference deploy uses the
> `m7kni` context. All the commands below are stack-scoped by that context.

## The dashboard

**Requires Grafana 13.0.0 or newer.** `dashboards/graph2otel.json` is a Grafana
**v2 dynamic dashboard** (`apiVersion: dashboard.grafana.app/v2`), which uses tab
layouts and conditional rendering. Those do not exist in earlier Grafana, and the
minimum version is asserted by a test rather than only stated here.

One dashboard covers the whole estate. `metadata.name` is its identity — a v2
resource has no top-level `uid`:

| File | `metadata.name` | Top-level tabs |
| --- | --- | --- |
| `dashboards/graph2otel.json` | `graph2otel` | Overview · Entra · Intune · Defender · M365 · Purview · Self-obs |

Each domain tab holds nested leaf tabs, one per section, so the estate is 60 leaf
tabs rather than six separate dashboards to keep in sync.

Push it with `gcx dashboards` (`metadata.name` is the update key):

```bash
# First time — create by file:
gcx dashboards create -f dashboards/graph2otel.json

# Subsequent updates — update by name:
gcx dashboards update graph2otel -f dashboards/graph2otel.json
```

You can also import it in the Grafana UI: **Dashboards → New → Import**, upload
the JSON.

### Deep links

Both URL forms are stable and measured against Grafana 13:

- A single panel: `/d/graph2otel?viewPanel=<numeric panel id>`. The parameter
  keys on the panel's numeric `id`, **not** on its element name.
- A tab: `/d/graph2otel?dtab=<Tab-Slug>`, and a leaf tab as
  `?dtab=<Domain-Slug>&<Domain-Slug>-dtab=<Leaf-Slug>`. A slug is the tab title
  with spaces replaced by hyphens.

`from`/`to` and `var-*` are preserved alongside either form.

### Tabs hide only on positive evidence of absence

A domain tab is hidden when the availability census positively reports every one
of its collectors as `disabled` or `covered` — the two states that mean
intentional absence. A collector that is `starting`, `healthy_empty`, `limited`,
`blocked`, `degraded`, `failed` or `startup_failed` keeps its tab **visible**: a
failure you cannot see is worse than an empty panel.

If the census is missing **entirely** — wrong Prometheus datasource, no tenant
selected, exporter not running — every tab stays visible instead of hiding. An
absent census means *unknown*, never *disabled*, so the dashboard must not render
blank without explanation. The `Overview` tab is never conditional for the same
reason.

### They are GENERATED — do not hand-edit them

`dashboards/graph2otel.json` is built by `grafana/build_dashboard.py` from
`grafana/boards/*.py` and `spec/signal-catalog.json`, and `make grafana-check`
(a required CI leg) fails on a hand-edited file. To change a panel, edit the
board module and run `make dashboard`. See
[`grafana/AUTHORING.md`](https://github.com/rknightion/graph2otel/blob/main/grafana/AUTHORING.md).

The same gate fails when a metric graph2otel emits reaches no panel at all, so
the dashboards cannot silently fall behind the collectors: `spec/signal-catalog.json`
is itself generated from what the collectors' tests actually emit, with no human
step between a new collector and the gate noticing it.

### Log panels need a Loki datasource

Every domain tab carries a **Logs** leaf tab (#162) built on
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
Terraform (`grafana_rule_group`), or Grizzly. It is **not** a
`gcx resources push` target (that command consumes `rules.alerting.grafana.app`
resource manifests, which these files are not).

The alert-rule file is generated from the `RULES` list in
`grafana/build_rules.py`; do not hand-edit it. Change the builder, run
`make rules`, then run `make grafana-check`. graph2otel ships **no** contact
point, notification policy, or route — see
[Operator-owned routing](#operator-owned-routing) below for the receiver side
of the deployment, which is entirely yours to own.

The rules land in the Grafana Cloud folder **`graph2otel`**.

```bash
# Create the folder once (note its uid):
gcx api /api/folders -X POST -d '{"title":"graph2otel"}'

# Apply the rule group via the provisioning API:
gcx api /api/v1/provisioning/alert-rules -X POST -d @alerts/graph2otel-alerts.yaml
```

**Datasource UID substitution:** every `expr` in `graph2otel-alerts.yaml` uses
the portable default `datasourceUid: "grafanacloud-prom"`. Replace it with your
actual Prometheus/Mimir datasource UID (`gcx datasources list`, or Connections
→ Data sources in the UI) before applying if yours differs.

See [`alerts/README.md`](https://github.com/rknightion/graph2otel/blob/main/alerts/README.md) for the per-rule rationale,
thresholds, the OTLP→Prometheus metric-name normalization, and the
multi-tenant grouping model.

## Operator-owned routing

graph2otel provisions **alert rules only**. It ships no contact point,
notification policy, or route in any form — deciding who gets paged, how
alerts are grouped, and on what timing is an explicit operator decision that
a public repository cannot make on your behalf, because a Grafana stack has
exactly one notification-policy tree and provisioning one takes ownership of
it (#293). A repository-content gate
(`grafana/tests/test_build_rules.py::TestNoRoutingAssetsShipped`) rejects any
future YAML/JSON committed under `alerts/` or `recording-rules/` that looks
like one — a top-level `contactPoints`, `policies`, `notification_policies`,
`receiver`, `routes`, or `route` key — so this cannot silently regress.

Instead, every generated rule carries a stable, documented label set to route
on (#296):

| Label | Mandatory? | Values | Meaning |
| --- | --- | --- | --- |
| `pipeline` | yes | `graph2otel` (constant) | Ownership. Every rule this repository generates carries it, so a route can be scoped to "graph2otel and nothing else" without matching on anything more fragile. |
| `severity` | yes | `critical`, `warning` | Paging urgency. |
| `source` | yes | `entra`, `intune`, `m365`, `purview`, `defender`, `mdca`, `graph2otel` | The Microsoft workload the rule is about (or `graph2otel` for the exporter's own self-observability, throttle, and record-integrity signals) — route a whole domain to the team that owns it. |
| `category` | yes | `credential-expiry`, `compliance`, `self-observability`, `record-integrity`, `throttle`, `mdca-discovery` | The failure class within a domain. |
| `component` | **no** | `apple-token`, `certificate` | A finer distinction than `source` allows, present **only** on the two Intune credential-expiry rules that need it: `g2o-intune-apple-token-expiry-critical` and `g2o-intune-cert-expiry-critical`. Absent on every other rule — do not write a route that assumes it exists. |

A worked example — a child route under your existing policy tree that sends
every graph2otel rule to a dedicated receiver, without touching anything else
already in that tree:

```yaml
routes:
  - receiver: "your-graph2otel-receiver"
    matchers:
      - pipeline = graph2otel
    group_by: ["alertname", "tenant_id"]
    continue: false
```

Nest further routes under it matching `severity`, `source`, or `category` for
finer-grained receivers (for example `severity = critical` to a pager,
everything else to chat) — those three labels are mandatory on every rule, so
a route keyed on them never silently stops matching. `component` is present
on two rules only; do not key a route on it without a fallback receiver for
the other twelve.

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

### Scheduled execution

[`.github/workflows/grafana-canary.yml`](https://github.com/rknightion/graph2otel/blob/main/.github/workflows/grafana-canary.yml)
runs this daily (05:12 UTC) and on manual dispatch, authenticating as the
least-privilege `graph2otel-semantic-canary` service account (Viewer role) via
`gcx login`. The JSON receipt is uploaded as a workflow artifact
(`grafana-semantic-canary-receipt`, 30-day retention) on every run, and the
job summary states which of the three exit codes fired. The run failing **is**
the notification surface — this repository ships no external notifier,
webhook, or contact point for this canary either (same #293/#296 decision as
[Operator-owned routing](#operator-owned-routing) above).

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

## Scheduled render baseline

[`.github/workflows/grafana-render-baseline.yml`](https://github.com/rknightion/graph2otel/blob/main/.github/workflows/grafana-render-baseline.yml)
runs the live half of the #309 baseline daily (07:07 UTC) and on manual
dispatch, authenticating with the **same** least-privilege
`graph2otel-semantic-canary` service account (Viewer role, id 36) `gcx login`
already uses for [the semantic canary](#read-only-semantic-canary) above — no
second credential is provisioned. It renders the single v2 `graph2otel`
dashboard through `gcx dashboards snapshot` and uploads the JSON receipt as a
workflow artifact (`grafana-render-baseline-receipt`, 90-day retention —
longer than the canary's 30, because this lane exists to build a **latency
distribution across many runs**, not to answer pass/fail on one). The run
failing **is** the notification surface; this repository ships no external
notifier, webhook, or contact point here either.

```bash
make grafana-performance-render GRAFANA_CONTEXT=<gcx-context>
```

Render parameters are fixed so runs are comparable over time: 6h range,
1920x1080, dark theme, UTC, serial (`--concurrency 1`), `datasource` and
`loki_datasource` set to the portable Grafana Cloud defaults
(`grafanacloud-prom` / `grafanacloud-logs`), and `tenant` set to Grafana's
own template-variable "All" token (`$__all`) to match the `tenant` variable's
`multi` + `includeAll` declaration in `grafana/builder.py`.

### Per-tab measurement is NOT possible today — what this lane measures instead

The v2 estate is one dashboard with 7 top-level tabs and 60 leaf tabs, reached
by the `dtab` / `<Domain-Slug>-dtab` URL query parameters described under
[Deep links](#deep-links) above. `gcx dashboards snapshot --help` was checked
directly (`gcx version v0.6.0`) for a way to pass them through: its only
parameterisation hooks are `--var` ("Dashboard template variable overrides",
e.g. `--var cluster=prod`) and `--panel <id>` (render one panel by numeric id
instead of the full dashboard). `dtab` is a plain URL navigation parameter,
**not** a dashboard template variable, so `--var` cannot set it, and there is
no flag that accepts an arbitrary query string. So this lane measures the one
thing the command can actually measure: a whole-dashboard render, which is
the default (first) top-level tab's cost end to end — not a per-leaf
breakdown of all 60 tabs. If `gcx` later grows a way to pass `dtab` through
(or an equivalent per-tab render mode), that is the point to revisit this
limitation; it is not expected to change on its own.

### A snapshot of a missing dashboard does NOT fail — read this before trusting an exit code

Live-measured 2026-07-27 against `grafana.m7kni.com`: `gcx dashboards get
<name>` correctly 404s for a dashboard that does not exist
(`{"error":{"summary":"404 NotFound", ...}}`, exit 1), but `gcx dashboards
snapshot <name>` of that same missing name **exits 0** and silently renders
Grafana's own "Dashboard not found" page as a PNG — indistinguishable from a
real render by exit code or file presence alone. For that reason
`grafana/performance_baseline.py` always checks existence with `gcx
dashboards get` **before** attempting a snapshot, and reports a distinct
`skipped_absent` status (with the dashboard's name and a human-readable
message) rather than either measuring the error page as if it were real
content or reporting a performance failure. `skipped_absent` is one of the
outcomes bucketed under exit `0` below.

### Exit codes and the deliberately unset latency budget

`grafana/performance_baseline.py` exits `0` (pass), `1` (a configured latency
budget was breached), or `2` (operational error — gcx, authentication,
transport, or a render failed before any measurement completed). Exit `0`
covers **three** distinct outcomes, all equally "not a failure": a
successfully measured render, `skipped_absent` (the dashboard is not yet
published), and `not_configured` (no budget has been set — see below). These
are recorded in the receipt's `live.budget.status` field so a reader can tell
them apart without re-deriving which one fired.

**No numeric render-latency budget is configured, on purpose.** #309 exists
specifically to avoid picking a threshold from a single measurement. The
plumbing for one already exists — `performance_baseline.py --budget-seconds`
and `make grafana-performance-render`'s
`GRAFANA_PERFORMANCE_BUDGET_SECONDS` — and compares every measured attempt's
`elapsed_seconds` against it, but both default to unset, and this workflow
does not pass a value. Once this workflow's own artifact history gives a
maintainer a real distribution to choose from, setting
`GRAFANA_PERFORMANCE_BUDGET_SECONDS` in the workflow (or passing
`--budget-seconds` by hand) is the whole activation step; no other code
change is expected.

Offline tests for this half also run under `make grafana-performance-check`.

## If GitSync is adopted later

This repo has no GitSync (git-to-Grafana) flow today; the `gcx` commands above
are the deploy path. If a GitSync repo is later adopted for these assets,
document its repository and the target paths for the dashboards / alert rules /
recording rules here, so the production deploy stays reproducible from this
file alone.
