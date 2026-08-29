# Authoring graph2otel's dashboards

`dashboards/graph2otel.json` is **generated**. Do not edit it — `just grafana-check`
fails on a hand-edited file. Edit `grafana/boards/*.py` and run `just dashboard`.

The whole estate is ONE Grafana **v2 dynamic dashboard** (`dashboard.grafana.app/v2`,
Grafana 13+): a root `TabsLayout` of seven tabs, each domain tab a nested `TabsLayout`
of leaf tabs. You do not author any of that shape. **One `b.row()` call becomes one leaf
tab**, and its panels are packed into a 24-column grid — so a board module still just
declares rows of panels and never writes a coordinate, a tab, or a layout kind.

```sh
just dashboard       # regenerate dashboards/graph2otel.json
just grafana-check   # the gate: coverage + log coverage + freshness + structure
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
| `grafana/logquery.py` | typed LogQL filters and group keys, validated against the catalog (#306) |
| `grafana/pivots.py` | the entity investigation pivots: which identifiers pivot, what they reach, and the gates on both (#305) |
| `grafana/presentation.py` | the audited presentation registry: units, value mappings, thresholds, keyed by catalog metric (#304) |
| `grafana/v2.py` | v1→v2 panel translation, layout primitives, and the manifest gates (#399) |
| `grafana/boards/*.py` | one module per dashboard; **data, not code** |
| `grafana/waivers.json` | metrics deliberately off every panel, with a reason each |
| `grafana/build_dashboard.py` | orchestrator, CLI, and every gate |
| `grafana/tests/` | `unittest` structural gates, run by `just grafana-check` |

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
- **the title** — derived from the metric name unless you pass one;
- **the unit** — the UCUM unit's Grafana equivalent, made per-second for a
  counter, and taken from the presentation registry where that registry has an
  opinion (see below).

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

## Units, mappings and thresholds live in one audited registry (#304)

`grafana/presentation.py` owns them, keyed by catalog metric. A board module
names *which metric a panel is about* and never states how it is coloured. Two
alternatives were rejected by maintainer decision: `spec/signal-catalog.json`
stays wire-derived and takes no presentation opinion (it is generated from Go
goldens, so a colour written there is overwritten or forces the Go generator to
own colour choices it has no evidence for), and per-board overrides would let the
same metric drift between boards with nothing to audit.

**An uncited threshold cannot be constructed.** `Thresholds` and `Mappings`
refuse an empty `evidence`, and the evidence is appended to the panel description
behind `Colour meaning:` — so the operator looking at the red panel can read why
it is red, and the build gate can prove on the shipped manifest that no coloured
panel is uncited. Adding a colour by hand somewhere else fails
`presentation.manifest_violations`.

**Absence of a threshold is not neutrality.** Every panel previously omitted
`fieldConfig.defaults.thresholds`, and Grafana then supplies its own — a green
base with red at 80 — so an inventory count of 95 devices rendered red. Neutral
has to be written down, and it now is, on every panel including log panels. The
gate has no exemption list on purpose: an exemption list is a second thing to
audit, and the first entry never comes back out.

The registry thresholds **five** metrics out of 331 panels, and that restraint is
the deliverable. "How many ownerless Teams is too many" and "what EPSS
probability is unacceptable" are policy judgements an operator makes, not facts
this repository has evidence for — they get neutral colouring and a log twin. A
threshold belongs here only where the *source* defines the operational state: a
scrape consuming its whole poll interval, an exporter failure that has not
recovered, a level Microsoft itself calls degradation.

### Counters say and format a rate

Every `sum` instrument is plotted through `rate()`, so both a count unit and a
count-shaped title describe a quantity the panel is not showing.
`m365.message_trace.bytes` was the worst case: bytes/sec formatted as `bytes`.
Derived titles are fixed automatically by `rate_title()`; a hand-passed title
that describes a count fails the build, because auto-rewriting prose produces
gibberish (`"Microsoft API drift — a response no longer matches what a collector
expects rate"`).

`b.raw()` derives its unit from the metrics its expression names, for the same
reason its coverage is read from the expression: a hand-typed unit is a second
place for a fact to drift, and it had drifted on every hand-written rate panel in
self-observability. Pass `unit=` only to override, and `about="<metric>"` to pull
that metric's cited mapping and threshold.

The one trap, and why `plots_a_rate()` is not a substring test:
`histogram_quantile(0.95, sum by (le) (rate(x_bucket[…])))` contains `rate(` but
its result is in the **bucket's** unit — seconds, not seconds per second. A naive
check relabels every latency panel in the estate.

## Log panels (#162)

```python
from logquery import f

LOGS = [
    {"kind": "logs",  "event": "entra.signin", "title": "Failed sign-ins",
     "filters": [f("status_error_code", "ne", "0")], "w": 24, "h": 12},
    {"kind": "rate",  "event": "entra.signin", "title": "Failure rate by error code",
     "by": ["status_error_code"], "filters": [f("status_error_code", "ne", "0")]},
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

### Filters and group keys are typed and validated (#306)

`f(key, op, value)` builds a filter; `op` is one of `eq` / `ne` / `re` / `nre`. **A bare string is
refused.** Both filter keys and `by` group keys are checked against the event's real attribute set,
overlaid with `tenant_id` and `ingest_transport`, which the emitter stamps on every record whether or
not the event's catalog row lists them.

This closes a real gap rather than adding ceremony. LogQL has no schema, so a misspelled attribute —
`status_erorr_code` for `status_error_code` — was a perfectly valid pipeline stage that matched
**nothing, silently, forever**. Same class of bug as #143, #158 and #160, and an earlier version of
this file claimed build-time validation that only ever covered metric and event *names*. Mutation
tests in `tests/test_logquery.py` prove a misspelled filter key and a misspelled group key each fail
the build independently.

When the typed model genuinely cannot express something — a regex alternation chain, `line_format`,
`unwrap` — use the escape, which is deliberately expensive:

```python
from logquery import Raw

Raw("line_format `{{.user_principal_name}}`",
    keys=["user_principal_name"],           # validated exactly like a typed filter
    reason="line_format has no typed equivalent")
```

It must declare every attribute it references and state why. The rejected alternative was a raw string
plus a key extractor: that extractor becomes a partial LogQL parser, which either misses constructs and
silently validates nothing, or rejects valid queries.

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

## Entity investigation pivots (#305)

Six entity kinds pivot: **device**, **application/service principal**, **account**,
**email message**, **security alert**, **security incident**. Each gets a free-text input
variable (`pivot_device`, `pivot_app`, …) and one collapsed row on the **Overview** tab
holding two panels — *which signals name this X* and *every record naming this X* — over
every cataloged log event that carries the identifier. Declarations live in
`grafana/pivots.py::ENTITIES`; nothing about a pivot is written in a board module.

They are on Overview rather than on a tab of their own because **Overview is the one tab
that is never conditional**, and a `dtab` into conditioned-away content renders a
completely blank body with no message (measured, #399). The seven-tab topology frozen by
#399 is unchanged.

**A pivot is navigation. It is not a join and not a correlation verdict**, and every
generated panel says so. Some identifiers are also source-scoped: `device_id` is Intune's
managed-device id on `intune.*` and Defender's machine id on `defender.*`, which are
different namespaces for the same machine — graph2otel does not map between them.

### The three-part declaration, and why each part exists

```python
Entity(
    kind="message", title="email message", variable="pivot_message",
    input_label="Email message (network or internet message id)",
    meaning="…what the identifier IS…",         # shown on the input and the panels
    direction="this message's delivery verdict, attachments, URLs and clicks, …",
    keys=("network_message_id", "internet_message_id"),      # one query target each
    anchors=(("defender.email", "network_message_id"), …),   # the promise, gated
    also_named_by=("message_trace_id", "email_cluster_id"),  # the documented gap, gated
)
```

- **`keys` drive the query; the event set is DERIVED** — every cataloged log event carrying
  that key. Declaring the events would mean a new collector emitting `network_message_id`
  silently stayed outside the pivot.
- **`anchors` are what fails.** With a fully derived set, an event losing the attribute just
  drops out and the build stays green while the pivot quietly stops reaching that signal.
  An anchor is a `(event, key)` pair the pivot *promises* to reach, so #305's "generation
  fails if a referenced event or attribute disappears" has something to fail on. Four
  sabotages prove it: a renamed attribute on an anchor event, an attribute renamed
  everywhere, a deleted anchor event, and a deleted documented synonym each fail
  `build_dashboard.py --check` and name the key.
- **`also_named_by` is the gap, made visible.** Keys that name the same entity and are
  deliberately not queried — a directory object id is not a UPN, and mixing value shapes
  into one input makes an empty result ambiguous. They are printed in the panel description
  and gated, because a documented synonym the catalog no longer has makes that note a lie.

Sabotage a copy rather than the real catalog:
`python3 build_dashboard.py --check --catalog /tmp/mutated.json`. A non-default catalog
never writes, so a sabotage run cannot ship its own mutation.

### The empty-input trap

In LogQL an absent structured-metadata key compares **equal to the empty string**, so
`| device_id=`$pivot_device`` with an unset variable matches every record that has *no*
device_id — the pivot would dump the whole estate instead of showing nothing. Every target
therefore also requires the key to be non-empty (`| device_id=~`.+``), which makes an empty
input match nothing by construction. Both filters are typed, so both keys are validated.

### Links in

Every generated log panel gets one **panel link** per entity kind its event can name,
derived from the event's own attribute keys — so a panel cannot advertise a pivot its
records cannot feed. The link states the identifier's meaning and the direction ("this
device's compliance, configuration … records"), carries `from`/`to` and
`${__all_variables}` so tenant and time survive, and targets `?dtab=Overview`. Two gates,
because resolving is not the same as being about the right thing:

- the `dtab` slug must name a real tab — a wrong slug is ignored **silently** and falls
  back to the first tab, so clicking it cannot catch the mistake;
- **signal agreement**: the panel's own query must name an event that really carries one of
  that entity's keys. This is the check a numeric panel id cannot make, and the reason
  #307 keys its links on `(tab, panel title)`.

An identifier an analyst never holds — an incident id is read off an alert record, never
typed from memory — declares `linked_from=("alert",)`, and the alert pivot's own panels
carry the link. Every entity must be reachable from at least one link or the build fails.

**Identifiers never become metric labels.** A pivot input cannot come from a query
variable, because `label_values()` reads metric labels and per-entity identifiers are
deliberately not metric labels (#112). A test asserts both halves: no cataloged metric
carries an identifier, and no PromQL expression in the estate names one.

## Waivers

A metric that is deliberately on no panel goes in `waivers.json` with a reason. The gate
also fails on a waiver whose metric no longer exists, and on a waiver with an empty
reason. A gate with no escape hatch gets disabled the first time it blocks something
urgent; a gate with an *undocumented* escape hatch is not a gate.

You almost never need one — see the `_readme` in that file for the two classes that look
like they belong there and do not.

## Adding a domain tab

Write `boards/<name>.py` with `DOMAIN` (the short tab title, which is also its URL
slug), `DESCRIPTION`, `AVAILABILITY_PATTERN`, `SECTIONS`, and optionally `LOGS` and
`extra(b)`. There is no per-board `UID` or `TENANT_METRIC`: the estate has one
`metadata.name` and one tenant dropdown, backed by the availability census so it
populates even when a domain is switched off. The
availability pattern selects the logical collector IDs shown in the generated
**Signal availability** table; declare it explicitly rather than inferring a collector
ID from a signal-catalog package path. Use `None` only when the dashboard owns an
equivalent availability presentation, as the self-observability board does.

Every Prometheus query panel gets a neutral `noValue` explanation that points to that
table. Stat panels default to no color so an empty or unmapped value cannot inherit
Grafana's green base threshold; evidence-backed colors come from the presentation
registry and nowhere else.

Then add `"boards.<name>"` to `BOARDS` in `build_dashboard.py`, in the order you want
the tabs to appear.

### The presence contract — get this wrong and the dashboard renders blank

A domain tab hides only on **positive evidence of intentional absence**: every one of
its collectors reported `disabled` or `covered` by the availability census. Everything
else — `starting`, `healthy_empty`, `limited`, `blocked`, `degraded`, `failed`,
`startup_failed` — stays visible, because a failure an operator cannot see is worse than
an empty panel, and healthy-empty is a correct steady state for several collectors.

Two hard rules the generator enforces so you cannot get this wrong by hand:

- **Never write a presence sentinel as a value threshold.** `Builder.sentinel()` refuses
  a `query_result(... > 0)` query. A `> 0` sentinel hides a live-but-idle collector by
  conflating *absent* with *present but zero*.
- **Every conditional element carries the census escape**, and its group condition is
  always `or`. If the census is missing entirely, everything stays visible. `condition()`
  refuses to build a presence condition without the escape, and the build gate re-checks
  both properties on the assembled manifest — a hand-built `and` group is false in the
  normal healthy state and would hide every tab silently.

## Adding a panel-construction feature

Panel constructors return **v1-shaped dicts**, which `grafana/v2.py` translates into v2
elements at render time. That is deliberate: it keeps ~45 board-module sites that mutate
`panel["fieldConfig"]` working, and keeps v2 layout knowledge out of every board module.
So a new panel type is written in the v1 shape like its neighbours, and only
`v2.panel_element` knows about `vizConfig`.

Two translation traps, both of which validate clean server-side and fail only at render
time, so `v2.py` handles them and its tests pin them:

- A **transformation** is `{kind, group, spec:{options}}` in v2, not v1's `{id, options}`.
- The **datasource moves into each query**, so nothing should read a panel-level
  `datasource` after translation.

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
