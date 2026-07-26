# Authoring graph2otel's dashboards

`dashboards/*.json` is **generated**. Do not edit it — `make grafana-check` fails on a
hand-edited file. Edit `grafana/boards/*.py` and run `make dashboard`.

```sh
make dashboard       # regenerate dashboards/*.json
make grafana-check   # the gate: coverage + log coverage + freshness + structure
```

Pure standard-library `python3`. Nothing to install, which is why the CI job has no
`setup-python` step.

## The pieces

| path | role |
| --- | --- |
| `spec/signal-catalog.json` | **generated** — every metric and log event graph2otel emits, with its Prometheus name, unit, aggregation kind, additivity, domain, attribute keys and emitting packages |
| `internal/signalcatalog/` | the Go package that generates it, by aggregating every `internal/**/testdata/signals.json` owned by a signal gate |
| `grafana/catalog.py` | reads the catalog; `metrics_referenced_by()` is what the coverage gate counts with |
| `grafana/builder.py` | `Builder` — panels, queries, layout, the LogQL selector, the two expression corpora |
| `grafana/boards/*.py` | one module per dashboard; **data, not code** |
| `grafana/waivers.json` | metrics deliberately off every panel, with a reason each |
| `grafana/build_dashboard.py` | orchestrator, CLI, and every gate |
| `grafana/tests/` | `unittest` structural gates, run by `make grafana-check` |

## Where the catalog comes from, and why nobody maintains it

`internal/signalcapture` captures what each gated package's dedicated fixture **actually
emits** into `testdata/signals.json`, and `scripts/regen-generated.sh` regenerates those
goldens. `internal/signalcatalog` merges them into `spec/signal-catalog.json`, which
`scripts/regen-generated.sh catalog` also regenerates and `TestSignalCatalogInSync`
gates.

So the chain from "a package emits a metric" to "the dashboard gate knows about it" has
**no human step**. That is the whole design: a hand-kept catalog rots exactly where it
matters — on the package that just landed — and a gate reading a rotted catalog
reports coverage it does not have.

## Adding a metric to a dashboard

One line in the right `SECTIONS` entry:

```python
SECTIONS = [
    ("Managed devices and inventory", [
        "intune.devices.count",                       # everything derived
        ("Enrollment type overview",                  # several metrics, one panel
         ["intune.devices.overview.enrolled_device_count",
          "intune.devices.overview.mdm_enrolled_device_count"],
         {"viz": "timeseries"}),                      # builder overrides
    ]),
]
```

Name the **OTEL** metric (`intune.devices.count`), never the Prometheus name. Everything
else comes from the catalog:

- **the query name** — the OTLP→Prometheus normalized form (`intune_devices_count`);
- **the aggregation** — `sum` when the metric is additive, `avg` when it is not. A score,
  a ratio, a percentage or a duration must never be summed: the sum of four thousand
  health scores is a number nobody measured (#235);
- **the grouping** — the metric's real attribute keys, minus an `x_id` that has an
  `x_name` twin. Tenant-scoped metrics always retain `tenant_id`, including when a
  panel supplies an explicit `by` override, so selecting several tenants cannot blend
  them into one series;
- **counters** get `rate(...[$__rate_interval])`, **histograms** get
  `histogram_quantile(0.95, sum by (le, …) (rate(…_bucket[…])))`;
- **the title** — derived from the metric name unless you pass one.

A misspelled metric name is a `KeyError` at build time, not an empty panel someone
notices in six months.

### Overrides

`{"viz": "table" | "stat" | "timeseries" | "bargauge" | "heatmap", "by": [...],
"w": 1..24, "h": N, "desc": "...", "quantile": 0.95, "legends": [...]}`.

Prefer `table` for anything whose *value* is an identifier rather than a quantity —
version numbers, priorities, info gauges, enum ladders. A time series of a version number
is noise.

### Hand-written PromQL

`b.raw(title, [expr, ...])` exists for expressions the catalog cannot express.
Coverage still comes from **reading the expression**, not from a claim, so a raw panel
credits exactly the metrics its text really names. Use it sparingly.

## Log panels (#162)

```python
LOGS = [
    {"kind": "logs",  "event": "entra.signin", "title": "Failed sign-ins",
     "filters": ["status_error_code!=`0`"], "w": 24, "h": 12},
    {"kind": "rate",  "event": "entra.signin", "title": "Failure rate by error code",
     "by": ["status_error_code"], "filters": ["status_error_code!=`0`"]},
    {"kind": "table", "event": "entra.risk_detection", "title": "Risk by type",
     "by": ["risk_event_type", "risk_level"]},
]
```

**You never write a stream selector.** `Builder._selector()` builds it, because
`{event_name="entra.signin"}` matches **zero rows, silently** — every graph2otel log
attribute is Loki *structured metadata* and `service_name` is the only stream label
(#90). `docs/signals.md` calls the wrong form "the single most common way to get a rule
that silently never fires", and the doc paragraph has not been enough: the shipped alert
rules and 74 dashboard queries were both built on a false belief about these labels
(#143, #158, #160). So the shape is enforced in code and asserted by
`test_no_stream_selector_on_an_attribute`.

Event names are validated against the catalog, and `kind: "table"` uses range + reduce
rather than an instant `topk` — an instant query materializes one series per distinct
value before `topk` runs, which walks into Loki's series cap on any wide range.
Rate and table aggregations always group by `tenant_id`, and their legends name the
tenant. Do not remove that grouping to produce a global rollup; add a separately titled
panel whose global scope is explicit instead.

Log panels declare the Loki datasource variable, say in their description that they need
it, and carry a `noValue` message so an operator with no Loki sees an explanation rather
than a panel that looks broken.

**Coverage is gated per DOMAIN, not per event.** There are 133 distinct log event names;
one panel each would be an unusable dashboard and a gate nobody could satisfy, so it
would be waived wholesale within a week. Every domain that has a log-shaped signal —
`entra`, `intune`, `m365`, `purview`, `defender`, `mdca`, `graph2otel` — must ship at
least one log panel.

## Waivers

A metric that is deliberately on no panel goes in `waivers.json` with a reason. The gate
also fails on a waiver whose metric no longer exists, and on a waiver with an empty
reason. A gate with no escape hatch gets disabled the first time it blocks something
urgent; a gate with an *undocumented* escape hatch is not a gate.

You almost never need one — see the `_readme` in that file for the two classes that look
like they belong there and do not.

## Adding a dashboard

Write `boards/<name>.py` with `UID`, `TITLE`, `DESCRIPTION`, `TAGS`, `TENANT_METRIC`
(a Prometheus name that exists, for the tenant dropdown's `label_values`),
`AVAILABILITY_PATTERN`, `SECTIONS`, and optionally `LOGS` and `extra(b)`. The
availability pattern selects the logical collector IDs shown in the generated
**Signal availability** table; declare it explicitly rather than inferring a collector
ID from a signal-catalog package path. Use `None` only when the dashboard owns an
equivalent availability presentation, as the self-observability board does.

Every Prometheus query panel gets a neutral `noValue` explanation that points to that
table. Stat panels default to no color so an empty or unmapped value cannot inherit
Grafana's green base threshold; evidence-backed colors belong in an explicit panel
mapping or threshold.

Then add `("boards.<name>", "<file>.json")` to `BOARDS` in
`build_dashboard.py`. `test_no_orphan_dashboard_files` fails if a renamed board leaves
its old JSON behind.

## Self-observability uses the same catalog

Scheduler, transport, exporter and limiter packages own dedicated signal fixtures just
like collectors. `GoldenPaths` discovers every gated package, and the command-level
source coverage test rejects a production package that emits a `graph2otel.*` metric
without installing a gate. `boards/selfobs.py` therefore reads names, units, kinds,
descriptions, attributes and tenant/process scope from the generated catalog. It
hand-authors presentation only.

## Metric names are a convention, not a byte-exact promise

graph2otel is OTLP-only — there is no Prometheus endpoint to read real names off, so the
names only exist after a backend normalizes them. The derivation in
`internal/signalcatalog.PrometheusName` reproduces the OpenTelemetry Prometheus
translator with metric suffixes enabled, which is what Grafana Cloud runs, and its
`[live]` test cases were verified against a live Grafana Cloud Mimir. Some pipelines
preserve original names or omit suffixes; adjust one clause if yours differs.
