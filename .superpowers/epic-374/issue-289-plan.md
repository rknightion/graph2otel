# Issue #289 — collector/transport volume and cost attribution

## Decision receipt and validated premise

**Status:** implementation-ready after correcting two disproved premises. #268
owns exporter callback health only; #289 owns a separate transport tracker.
The portable exact byte quantity is post-compression OTLP payload bytes accepted
by the client transport, not full HTTP/gRPC/TLS/network wire bytes. No
maintainer decision remains because the instruction is to use the recommended
truthful contract.

The 2026-07-26 decision is binding:

- Count **exact logical source records** and **emitted points** per
  `tenant_id` / collector / transport.
- Count **exact process-level** post-compression OTLP payload bytes and exporter
  retries. Full network wire bytes are not portable from the exporter APIs. A
  collector-level payload-cost allocation is an **estimate**, never an exact fact.
- Pricing is disabled by default. Enabling it requires operator-provided
  currency, version, source, effective timestamp, and rates; no vendor price
  is embedded.
- Pricing data is observational only: it must never sample, disable, delay,
  throttle, drop, or otherwise enforce a collector budget.

The code confirms #269 is the source-record truth already: its frozen
`graph2otel.record.outcomes{tenant_id,collector,ingest_transport,outcome}`
counter has unit `{record}` and its `fetched` outcome is the exact logical
source-row count. It also confirms that `otelEmitter.Throughput()` counts
points only after the cardinality limiter, but only process-wide. Therefore
#289 must add a collector-bound emitter **inside** that limiter; a wrapper
outside it would count points which the limiter later drops and would be
wrong.

The original “manual replay” wording cannot be implemented in this runtime:
#382’s accepted replay workflow is isolated and log-only and explicitly
forbids metrics. #289 will classify normal scheduler work as
`steady_state` or `cold_start_backfill`; it reserves `manual_replay` for a
future replay-owned, non-metric receipt but does not claim to count it. This is
a scope correction, not an unresolved decision.

## Scope

In scope: exact normal-runtime source/point volume, exact process transmitted
payload bytes and exporter retries owned by #289, an explicitly estimated cost projection,
read-only budget visibility, admin JSON/UI, generated config/docs/catalog and
self-observability dashboard coverage.

Out of scope: vendor price discovery, billing reconciliation, collector
throttling or automated budget action, durable per-run history, backend
acceptance semantics (#268), availability state (#292), and #382 replay
implementation.

## Frozen data contract

### Exact volume

Do not relabel #269’s frozen outcome metric. Add a derived
`graph2otel.ingest.source_records` counter from the same completed-run snapshot
so traffic class is queryable without changing #269 series identity. A
reconciliation test makes the new view equal `record.outcomes{outcome="fetched"}`.

Add these counters from a bounded attribution snapshot, emitted on the existing
60-second self-observability report cadence:

| Source metric | Unit | Bounded attributes | Meaning |
| --- | --- | --- | --- |
| `graph2otel.ingest.emitted_points` | `{point}` | `tenant_id`, `collector`, `ingest_transport`, `signal` (`metric` or `log`), `traffic_class` (`steady_state`, `cold_start_backfill`) | Exact calls which survived the central limiter and reached the SDK: one each for Counter/Gauge/UpDownCounter/Histogram, one per retained GaugeSnapshot point, and one per LogEvent. |
| `graph2otel.ingest.source_records` | `{record}` | `tenant_id`, `collector`, `ingest_transport`, `traffic_class` | Exact `recordoutcome.Snapshot.Counts.Fetched`, emitted once at completed normal scheduler runs. It is a derived traffic-class view of #269, not a second lifecycle authority. |
| `graph2otel.otlp.transmitted_payload.bytes` | `By` | `signal` (`metrics` or `logs`) | Exact post-compression OTLP payload bytes accepted by the client transport on every actual send; excludes protocol and network framing. |
| `graph2otel.otlp.retry_attempts` | `{retry}` | `signal` (`metrics` or `logs`) | Exact second-and-later exporter retry-loop attempts; redirects and transparent connection retries are not exporter retries. |

`traffic_class` is chosen by the scheduler before a run: snapshot work and a
window with a checkpoint are `steady_state`; a window with no checkpoint and a
non-empty first window is `cold_start_backfill`. Shutdown-cancelled runs emit
neither #269 nor #289 volume. A zero-row source still emits its completed-run
point total (normally zero) but adds zero source-record counter value. Neither
attribute may carry a collector-provided string, request URL, record/entity ID,
error, or raw transport payload.

### Cost and budget (read-only estimate)

Add `cost:` to the root config, defaulting to disabled:

```yaml
cost:
  enabled: false
  currency: ""
  version: ""
  source: ""
  effective_at: ""
  period: 30d
  budget_microunits: 0
  rates:
    source_record_microunits: 0
    metric_point_microunits: 0
    log_record_microunits: 0
    transmitted_payload_byte_microunits: 0
```

One microunit is `10^-6` of the configured currency unit, so integer counters
and cost arithmetic are exact and no floating point/locale rounding becomes a
billing claim. `budget_microunits: 0` means “show the projection, no budget
comparison.” `period` defaults to `30d`; it only annualises the observed burn
for display and never changes scheduling.

When `cost.enabled` is false, no cost metrics or cost card are emitted. When it
is true, validation requires: upper-case three-letter ASCII `currency`; nonblank
`version` and `source`; an RFC3339 `effective_at`; `period > 0`; all four rates
present and non-negative; and a non-negative budget. Invalid/missing metadata
is a startup error naming the exact `cost.*` key. Currency, version and source
are admin metadata, not metric labels except the bounded configured `currency`
and `price_version` on the estimate below.

Add only this cost metric:

`graph2otel.ingest.cost.projected` — gauge, unit `{microunit}`, labels
`tenant_id`, `collector`, `ingest_transport`, `currency`, `price_version`, and
`attribution="estimated"`.

For each report interval, calculate the collector’s exact source-record,
metric-point and log-point components from its delta. Allocate the process
transmitted-payload-byte component proportionally to that collector’s exact emitted-point
share for the same interval; retain an explicit bounded
`collector="_unattributed"`, `ingest_transport="process"` row for process
self-observability/export traffic with no collector share. The sum of all
collector plus unattributed projections must equal the process projection for
the same interval. The UI, metric description, docs, and every panel title must
say **estimated**; no label or prose may call per-collector payload cost exact.
The budget is a ratio/display of this estimated period projection only; it has
no callback into a scheduler, limiter, Graph client, or exporter.

## Runtime design and file ownership

1. **Transport seam — #289-owned and separate from #268.** Add a
   concurrency-safe immutable transport snapshot for per-signal transmitted
   payload bytes and exporter retries. gRPC uses public interceptor/stats hooks.
   HTTP carries the smallest pinned exporter observer patch so the existing
   exporter remains owner of proxy, TLS/mTLS, timeout, compression and retry
   configuration; `WithHTTPClient` is forbidden because it overrides those
   semantics. `internal/telemetry/volume.go` owns a bounded,
   mutex/atomic-safe attribution accumulator and a collector-bound emitter;
   `internal/telemetry/volume_test.go` owns its behavioural and race tests.

2. **Preserve limiter truth.** Add a provider factory such as
   `CollectorEmitter(tenant, collector string, transport Transport, class
   TrafficClass) Emitter`, wired as attribution -> limiter -> tenant/transport
   decorators so attribution sees exactly the points forwarded after central
   clipping. The accumulator must not count the volume/cost self-metrics it
   emits. It must forward the tenant-scoped GaugeSnapshot private seam and all
   six Emitter methods without changing `internal/telemetry/types.go`.

3. **Bind each scheduler run.** `internal/collector/scheduler.go` owns the
   run-class resolver (checkpoint presence and window selection) and calls the
   provider’s collector-emitter factory through a narrow injected function,
   retaining ordinary test emitters. `internal/collector/selfobs.go` owns
   record/point snapshot emission and must use the un-attributed scheduler
   emitter for its own self-observability, avoiding recursive counting.
   `internal/collector/selfobs_test.go` and `scheduler_test.go` own the
   accounting, phase, shutdown, snapshot-point and limiter-survival tests.
   `internal/semconv/attrs.go` and `attrs_test.go` are the single owner of the
   new bounded attribute keys; serialize that tiny shared edit after #292's
   availability attributes rather than creating competing string literals.

4. **Cost configuration and calculation.** `internal/config/config.go` and
   `internal/config/config_test.go` own `CostConfig`, fixed-microunit parsing,
   defaults and validation. `cmd/graph2otel/main.go` is the sole composition
   owner: pass validated rates to the provider, include cost reporting in the
   existing self-observation ticker, and never pass a budget into a collector
   or rate limiter. `internal/telemetry/cost.go` and `cost_test.go` own
   interval deltas, deterministic largest-remainder payload allocation,
   overflow-safe microunit arithmetic and the unavoidable `_unattributed` row.

5. **Admin is serial after #292.** Once the staged #292 change is committed,
   #289 owns its additive capacity view in `internal/admin/status.go`,
   `internal/admin/sampler.go`, `internal/admin/page.html.tmpl`, and their
   tests. `/api/status.json` exposes the operator-supplied price metadata,
   exact process delivery totals, exact per-collector volume, projected
   microunits, period and budget ratio. The HTML shows an “estimate, not
   invoice” capacity card/table and renders no cost data while disabled. Raw
   exporter errors, tokens, endpoints and rate-input secrets never appear.

## Strict TDD sequence (RED receipts before implementation)

1. Add failing `internal/telemetry/volume_test.go` cases for one point per
   synchronous method, every GaugeSnapshot element, one LogEvent, concurrent
   emission, and a limiter-dropped point. Run
   `go test -race ./internal/telemetry -run 'Test.*(Volume|Attribution)'` and
   record that the missing attribution factory/accumulator is the failure.

2. Add failing collector tests for a checkpointed window, a no-checkpoint
   cold-start window, snapshot collection, a zero-row run, and shutdown
   cancellation. Run
   `go test -race ./internal/collector -run 'Test.*(TrafficClass|Volume)'`;
   only then add the scheduler binding and self-observation emitter.

3. Add failing config tests for disabled defaults, each missing enabled
   metadata key, malformed effective timestamp/currency, negative rates/budget,
   zero/non-zero period, environment overrides, and exact error paths. Run
   `go test ./internal/config -run 'Test.*Cost'` before adding the config type
   and validation.

4. Add failing transport and telemetry tests
   proving bytes/retries are process-only, collector allocation reconciles with
   the process cost, a zero-share interval remains unattributed, and overflow
   fails closed to a bounded diagnostic rather than wrapping. Run
   `go test -race ./internal/telemetry -run 'Test.*(Cost|Delivery|Volume)'`.

5. Add failing admin JSON/render/sampler tests for disabled cost, exact volume
   rows, estimated wording, metadata redaction, period/budget ratio and no
   enforcement side effect. Run
   `go test ./internal/admin -run 'Test.*(Capacity|Cost|Volume)'` before the
   serial #292-following UI edit.

6. Regenerate package signal captures only after the runtime tests are green;
   then run the normal drift gates below. Do not hand-edit generated catalog,
   env reference or dashboard JSON.

## Generated artefacts and documentation

Owned source inputs:

- `config.example.yaml` (complete commented `cost:` schema),
  `docs/configuration.md` (read-only semantics, microunits, allocation and
  validation), and `docs/signals.md` (exact-versus-estimated query contract).
- `internal/collector/testdata/signals.json` and
  `internal/telemetry/testdata/signals.json` through their signal-capture tests.
- `grafana/boards/selfobs.py` and `grafana/tests/test_build_dashboard.py` for
  exact-volume/process-delivery/capacity panels and explicit estimate wording.

Generated outputs to refresh and review, never hand-edit:

- `docs/env-vars.md` via `scripts/regen-generated.sh envref` after
  `config.example.yaml`.
- `docs/collectors.md` via `scripts/regen-generated.sh collectordoc` when the
  collector self-observability capture changes its generated signal inventory;
  preserve #292's availability table in that same serial regeneration.
- `spec/signal-catalog.json` through the package signal goldens and catalog
  gate.
- `dashboards/graph2otel-self-observability.json` via `make dashboard`.

No new alert or recording rule is justified: price inputs are operator
assumptions and budgets are non-enforcing. `alerts/graph2otel-alerts.yaml` and
`recording-rules/*.json` must remain unchanged; `make grafana-check` is the
proof that no stale/generated rule artifact was introduced.

## Shared seams, sequencing, and risks

| Neighbor | Shared seam | Required handling |
| --- | --- | --- |
| #268 | OTLP exporter wrappers, provider self-observation and `cmd/graph2otel/main.go` | #268 owns callback health; #289 owns context correlation and transport volume in a separate snapshot. Never infer retries from callbacks or turn delivery degradation into readiness failure. |
| #292 | `cmd/graph2otel/tenants.go`, scheduler wiring, `internal/admin/*`, collector catalog, self-observability dashboard and `spec/signal-catalog.json` | Let the staged availability work land first. Keep its `collector.transport` availability contract separate from #289’s existing `ingest_transport` volume dimension. One serial wiring/regeneration pass only. |
| #380 | `README.md`, `docs/configuration.md`, `docs/signals.md`, `docs/env-vars.md`, generated collector docs | #289 owns only the new capacity/cost truth; hand #380 exact generated counts/paths rather than concurrently rewriting broad operator docs. |
| #382–#389 | `manual_replay` vocabulary | Do not make #289 emit replay metrics: #382 forbids them. Record the capability boundary in #289 docs and leave replay-local delivery/volume receipts to their tracker. |

Primary risks are falsely calling an allocation exact, attributing pre-limiter
points, recursive self-metering, high-cardinality price labels, float/overflow
currency errors, and a cost card becoming a hidden scheduler control. The
contracts and RED tests above directly cover each one.

## Final verification and completion receipt

Run, in order, after regeneration:

```sh
go test -race ./internal/telemetry ./internal/collector ./internal/config ./internal/admin
go test -race ./...
make check
make grafana-check
git diff --check
```

Review the generated catalog to confirm the exact labels/units above, inspect
the dashboard only through its Python source plus regenerated JSON, and verify
the admin JSON with pricing disabled and with a complete synthetic enabled
configuration. Before closing #289, record the #268 delivery-snapshot commit
consumed, #292 base commit, local gate receipts, generated-artifact diff, and
the explicit statement that budgets changed no collector behaviour.

## Open questions

None. The remaining work is ordered implementation, not a policy fork.
