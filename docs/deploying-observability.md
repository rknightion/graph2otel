# Deploying the observability assets

graph2otel ships two kinds of Grafana asset, each in its own top-level
directory. The generated inventory is drift-gated at
**1 dashboard, 15 alert rules, and 11 paused detection examples**:

| Directory | Assets | Format | Target Grafana Cloud folder |
| --- | --- | --- | --- |
| `dashboards/` | 1 dashboard (**generated**) | Grafana **v2 dynamic dashboard** resource (`dashboard.grafana.app/v2`) | folder of your choice |
| `alerts/rules/` | 15 alert rules (**generated**) | Grafana **App Platform** `AlertRule` (`rules.alerting.grafana.app/v0alpha1`) | `graph2otel` |
| `alerts/rules/` | 11 detection examples (**generated**, all **paused**) | same, separate rule group | `graph2otel detections` |

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

`alerts/rules/*.yaml` are **Grafana App Platform** resources —
`rules.alerting.grafana.app/v0alpha1`, kind `AlertRule` — one manifest per rule,
identified by `metadata.name` (the stable rule UID). They are generated from the
`RULES` and `DETECTIONS` lists in `grafana/build_rules.py`; do not hand-edit them.
Change the builder, run `make rules`, then `make grafana-check`.

The classic `/api/v1/provisioning/*` representation was **removed**, not kept as a
fallback: those endpoints are deprecated upstream, a committed `apiVersion: 1` +
`groups:` bundle is rejected with HTTP 400 when posted as an individual object,
and a repeated classic POST created duplicate rules with fresh UIDs. Two generated
representations would also be two things to gate, and would drift.

### Deploy

```bash
make rules-push GRAFANA_CONTEXT=<gcx-context>

# also deploy the PAUSED portable detection pack (its own folder):
make rules-push GRAFANA_CONTEXT=<gcx-context> INCLUDE_DETECTIONS=1

# read-only: does the stack still match the repository?
make rules-readback GRAFANA_CONTEXT=<gcx-context>
```

`GRAFANA_CONTEXT` is a `gcx` **context name**, not a server hostname — check
`gcx config view` if unsure. The context is pinned on every call rather than
inherited: an ambient current-context pointing at a different stack returns a
complete-looking inventory with none of your resources in it, which reads exactly
like everything having been deleted.

The target folder must already exist (`--folder-title`, default `graph2otel`); the
deploy does not create folders, and refuses to guess if two folders share the
title.

### Why a deploy tool and not a bare `gcx resources push`

Four things about this API are not guessable, and each one was found by pushing
rather than by reading documentation. They are why `grafana/rules_deploy.py`
exists:

1. **`grafana.app/folder` is a stack-specific UID**, so the committed manifests
   carry the token `REPLACE_WITH_FOLDER_UID` and the tool resolves a real UID from
   a folder *title*. The token is deliberately loud: pushing an unresolvable
   folder UID fails with `403 Forbidden` and creates nothing, whereas *omitting*
   the annotation silently files every rule in the General folder.
2. **The push needs `--omit-manager-fields`.** Without it the update is refused
   with `409 Conflict: cannot update with provided provenance 'api', needs 'api'`
   — a message that contradicts itself.
3. **Each manifest must declare `grafana.com/provenance: api`.** Without it:
   `409 Conflict: cannot update with provided provenance '', needs 'api'`. It also
   makes the rule read-only in the Grafana UI, which is correct for a generated
   asset — a UI edit would silently diverge from this repository until the next
   push overwrote it.
4. **`Ok`, not `OK`.** The App Platform enum is
   `["NoData","Ok","Alerting","KeepLast"]`. The classic API accepted `OK`, so this
   is a real difference between the two representations; the generator maps it.

### Read-back proves content, not counts

A push reporting success is not a deployment that matches source. `rules-readback`
compares the **projected content** of every rule against the stack field by field
— title, `for`, `noDataState`, `execErrState`, `trigger`, labels, annotations and
the whole `expressions` map.

Counting is not enough, and this is not hypothetical. Before this existed, the
repository had been diverging from the stack for the whole of the #375 programme:
two rules were missing entirely (detectable by counting), the evaluator-error fix
from #298 was still `Ok` live, the interval-aware staleness threshold from #299 was
still a fixed `3600`, and the runbook annotations from #307 were absent on all 19
rules. Every one of those except the missing pair is a rule that is **present with
stale content**, which no count can ever reveal.

The comparison needs no duration or default normalization, on purpose: the
generator emits the server's exact spellings (Go durations like `5m0s`, a zero
`for` omitted entirely, `intervalMs`/`maxDataPoints` on every expression node).
A normalization step is somewhere a real difference can hide.

Exit `0` means the stack matches, `1` means it drifted, `2` means the tool could
not run.

### One known limitation, stated rather than hidden

**This API cannot place a rule it just created into a named group.** Creating with
a group is refused (`cannot set group when creating a new rule`) and so is adding
one afterwards (`cannot set group when updating un-grouped rule`). `RuleSequence`
is not a way around it — it requires at least one recording rule, and this
repository ships none (#297).

The consequence is cosmetic but you should know it: a newly created rule sits in
its folder outside the named group. It evaluates on exactly the right cadence,
because `spec.trigger.interval` is per-rule. The read-back reports those rules
under `ungrouped` with status `matched_content_ungrouped` — a clean pass, since
their content matches — rather than either hiding them or calling them drift. Move
them into the group by hand in the Grafana UI if the grouping matters to you.

**Datasource UID substitution:** every query uses the portable Grafana Cloud
default `grafanacloud-prom`. Replace it if your Prometheus/Mimir datasource UID
differs (`gcx datasources list`, or Connections → Data sources).

See [`alerts/README.md`](https://github.com/rknightion/graph2otel/blob/main/alerts/README.md) for the per-rule rationale,
thresholds, the OTLP→Prometheus metric-name normalization, and the multi-tenant
grouping model.

## Operator-owned routing

graph2otel provisions **alert rules only**. It ships no contact point,
notification policy, or route in any form — deciding who gets paged, how
alerts are grouped, and on what timing is an explicit operator decision that
a public repository cannot make on your behalf, because a Grafana stack has
exactly one notification-policy tree and provisioning one takes ownership of
it (#293). A repository-content gate
(`grafana/tests/test_build_rules.py::TestNoRoutingAssetsShipped`) rejects any
future YAML/JSON committed under `alerts/` that looks
like one — a top-level `contactPoints`, `policies`, `notification_policies`,
`receiver`, `routes`, or `route` key — so this cannot silently regress.

Instead, every generated rule carries a stable, documented label set to route
on (#296):

| Label | Mandatory? | Values | Meaning |
| --- | --- | --- | --- |
| `pipeline` | yes | `graph2otel` (constant) | Ownership. Every rule this repository generates carries it, so a route can be scoped to "graph2otel and nothing else" without matching on anything more fragile. |
| `severity` | yes | `critical`, `warning` | Paging urgency. |
| `source` | yes | `entra`, `intune`, `m365`, `purview`, `defender`, `mdca`, `graph2otel` | The Microsoft workload the rule is about (or `graph2otel` for the exporter's own self-observability, throttle, and record-integrity signals) — route a whole domain to the team that owns it. |
| `category` | yes | `credential-expiry`, `compliance`, `self-observability`, `record-integrity`, `throttle`, `mdca-discovery`, `identity-threat` | The failure class within a domain. **`identity-threat` is carried by every one of the 11 paused detections** and by no health rule, so it is the single matcher that separates security content from exporter health — route it to a security responder, not to whoever owns graph2otel. This value was missing from this table while the detections already carried it. |
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
the other thirteen.

## Recording rules: none, deliberately

graph2otel ships **no recording rules**. The two it used to ship are retired
(#297) because a 1h event-time query window can never overlap a blob-derived
source whose records are days old — measured at 3.3-7.0 days of lag, they
recorded nothing for 30+ days while reporting `health: ok`. A LogQL `count by`
over the log twin answers the same question at query time, for free. See
[Derived metrics](derived-metrics.md#why-the-recording-rules-were-retired).

`grafana/build_rules.py` fails the build if a recording rule reappears in any
committed asset, so this is a gate rather than a convention.

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

Only collector availability is required to return data. Optional log and
histogram signals may be healthy-empty. The log-twin probe looks back **7
days** rather than one hour, because the blob-derived stream it queries was
measured at 3.3-7.0 days of event-time lag — a 1h lookback would pass green
while being structurally incapable of matching a row, which is precisely how
the retired recording rules went unnoticed for a month
([#297](https://github.com/rknightion/graph2otel/issues/297)).

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

### Exit codes and the breakage tripwire

`grafana/performance_baseline.py` exits `0` (pass), `1` (a configured latency
budget was breached), or `2` (operational error — gcx, authentication,
transport, or a render failed before any measurement completed). Exit `0`
covers **three** distinct outcomes, all equally "not a failure": a
successfully measured render, `skipped_absent` (the dashboard is not yet
published), and `not_configured` (no budget has been set — see below). These
are recorded in the receipt's `live.budget.status` field so a reader can tell
them apart without re-deriving which one fired.

**The configured 30s budget is a breakage tripwire, not a tuned performance
threshold**, and the difference matters. It is not a percentile, is not derived
from a distribution, and says nothing about what good looks like. Measured
renders sit near 6s (5.09–7.01s across the six v1 dashboards on 2026-07-26;
5.93s for the single v2 dashboard on 2026-07-27), so 30s is about 5x the
observed cost and will not fire on ordinary variance, a cold renderer, or a slow
morning.

What it catches is the failure this lane can actually have: a render that has
stopped working — runaway query fan-out, a hanging renderer, a datasource timing
out behind the dashboard. Those cost tens of seconds, not a few hundred extra
milliseconds.

If you want a real percentile-based budget, this workflow's artifact history is
where it comes from, and `GRAFANA_PERFORMANCE_BUDGET_SECONDS` in the workflow
(or `--budget-seconds` by hand) is the one thing to change. **Do not tighten it
toward the observed figure without that history** — a threshold set just above
the last measurement is how a lane starts crying wolf, and an alert that fires on
correct data is worse than no alert.

The **static** per-leaf ceiling remains the gate that catches the realistic
regression, and it needs no credentials: `LEAF_PANEL_CEILING = 24`, enforced on
every `make grafana-check`, with the largest leaf currently at 18.

Offline tests for this half also run under `make grafana-performance-check`.

## If GitSync is adopted later

This repo has no GitSync (git-to-Grafana) flow today; the `gcx` commands above
are the deploy path. If a GitSync repo is later adopted for these assets,
document its repository and the target paths for the dashboards and alert rules
here, so the production deploy stays reproducible from this file alone.
