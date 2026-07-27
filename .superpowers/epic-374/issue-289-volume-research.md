# Issue #289 volume/accounting seam research

## Verdict

Implement the logical-volume half of #289 on the pinned base
`d6d960d009524a185ef0d40247a716f86cac24e3`, but correct the current scratch
plan before coding:

1. Do **not** add `graph2otel.ingest.records`. It would duplicate #269's exact
   source-record truth. Extend the existing
   `graph2otel.record.outcomes{tenant_id,collector,ingest_transport,outcome}`
   counter with one bounded `traffic_class` dimension instead. Its
   `outcome="fetched"` series is the requested exact logical source-record
   count; all seven outcomes continue to reconcile within each traffic class.
2. Count emitted points with a collector-bound emitter placed **behind the
   shared cardinality limiter and in front of the concrete OTEL emitter**.
   This is the only location that observes the exact points which survived
   clipping.
3. Keep scheduler/provider self-observability on the existing un-attributed
   emitter. Report the accumulated point counters through that path. This makes
   the accounting metric unable to account for itself.
4. Do not implement wire-byte cost or retry cost against #268's current
   `DeliverySnapshot`. The landed #268 contract has callback
   attempts/successes/failures only. It has no wire-byte or retry fields, and
   its exporter wrapper cannot observe either fact.

There is no remaining maintainer decision in #289. The one maintainer comment
freezes exact source records and emitted points, exact process-level wire bytes
and retries, estimated-only collector wire cost, and operator-supplied pricing
which can never enforce a budget.

## Evidence from the pinned code

- `internal/collector/selfobs.go:141-185` emits #269's immutable
  `recordoutcome.Snapshot` directly. `outcome="fetched"` is already the exact
  source-row count; emitting a second source-record metric would create two
  authorities.
- `internal/recordoutcome/recordoutcome.go` freezes the equations
  `fetched = mapped + filtered + dropped + errored` and
  `mapped = emitted + deduped`. One source record counts once even when it
  produces several metric points or a metric plus a log twin.
- `internal/telemetry/provider.go:256-273` wires
  `Provider.Emitter()` as `limiter.Wrap(otelEmitter)`.
  `cmd/graph2otel/tenants.go:690-722` then wraps transport and tenant outside
  that limiter. Therefore the limiter already sees the final tenant stamp.
- `internal/telemetry/limit.go:538-572` forwards accepted synchronous metric
  calls and all logs to its wrapped emitter. Dropped synchronous points never
  reach it. `limit.go:260-282` forwards only the retained/folded
  `GaugeSnapshot` slice.
- `internal/telemetry/emitter.go:85-297` defines the current process throughput
  semantics: one metric point per synchronous method call, one per snapshot
  element, and one per log event. The new attributed count should use the same
  point definition, but at the post-limiter boundary rather than process-wide.
- `internal/collector/scheduler.go:241-325` preserves partial and panic progress
  and emits #269 accounting for them. Lines 264-269 deliberately suppress all
  run accounting when the process context cancels the run during shutdown.
- `internal/telemetry/delivery.go:33-54` proves #268's public snapshot has no
  bytes or retries. `delivery.go:237-315` wraps SDK exporter callbacks, so it
  observes one callback result, not transport-internal retry attempts or
  compressed protocol bytes.

## Frozen logical-volume contract

### Existing source-record metric, extended rather than duplicated

Keep the metric name and unit:

```text
graph2otel.record.outcomes
unit: {record}
labels: tenant_id, collector, ingest_transport, outcome, traffic_class
```

`traffic_class` has a closed set:

- `steady_state`
- `cold_start_backfill`
- `manual_replay` (reserved for #382's replay-owned receipt; the normal
  scheduler does not emit it)

The scheduler emits the new label on every nonzero #269 outcome. The two #269
equations must hold independently for every
`tenant_id/collector/ingest_transport/traffic_class` tuple. Existing PromQL
which selects or groups by `outcome`, collector, tenant, or transport continues
to match; this is one intentional bounded extension of the frozen #269 series
identity.

Also add `traffic_class` to `graph2otel.scrape.outcomes`. That is not a second
source-record count. It is needed so a completed zero-row cold-start run remains
visible even though every record counter delta is zero and therefore omitted.
Do not add the class to unrelated scrape duration/success gauges or payload
type-mismatch/event-lag signals.

### New emitted-point metric

```text
graph2otel.ingest.emitted_points
unit: {point}
labels: tenant_id, collector, ingest_transport, signal, traffic_class
signal values: metric, log
```

Meaning: exact graph2otel emitter handoffs after the central cardinality
limiter, not backend acceptance.

- `Counter`, `Gauge`, `UpDownCounter`, `Histogram`, and `HistogramCtx`: one
  metric point per call forwarded by the limiter.
- `GaugeSnapshot`: one metric point per element in the final slice forwarded
  by the limiter. A dropped tail contributes zero. A folded tail contributes
  the actual retained plus `other` points forwarded, not its pre-fold row
  count.
- `LogEvent`: one log point. Logs are intentionally not clipped.
- An empty snapshot contributes zero.
- The event-lag histogram emitted by `WithEventLag` is a real collector-caused
  OTLP point and is counted. Scheduler scrape/outcome metrics and the
  `emitted_points` reporting metric are not collector-bound and are not
  counted.

Do not call this backend delivery, export success, wire records, or accepted
ingest. #268 owns the later exporter callback boundary.

### Relationship between source records and points

The metrics are intentionally not equal:

- `record.outcomes{outcome="fetched"}` counts logical source records once.
- `record.outcomes{outcome="emitted"}` counts source records for which the
  mapper handed useful telemetry to the facade; it remains #269's pre-limiter
  lifecycle fact.
- `ingest.emitted_points` counts the actual post-limiter point calls. One
  emitted source record can create zero post-limiter points, one point, or
  several points.

This separation is the useful reconciliation: source lifecycle remains #269's
one-record truth, while #289 measures its telemetry expansion/clipping result.
Do not manufacture an equality between them.

## Traffic-class resolution

Resolve the class before invoking a collector:

- Every `SnapshotCollector` run is `steady_state`. It is an inventory snapshot,
  not a cursor replay.
- A `WindowCollector` run with no source checkpoint is
  `cold_start_backfill`.
- A `WindowCollector` run with a source checkpoint is `steady_state`, including
  ordinary at-least-once overlap and outage catch-up.

This definition is exact for the current collectors: every registered initial
lookback is less than or equal to its `MaxWindow`, so the no-checkpoint window
contains the complete configured cold-start lookback rather than only the
first slice of a multi-tick backfill. Add a guard test over registered window
annotations so a future `InitialLookback > MaxWindow` cannot silently make
later cold-start slices appear steady. If that relationship is ever allowed,
persist a cold-start target in `CheckpointStore`; do not guess from elapsed
wall time.

`manual_replay` is not emitted by this scheduler. #382's accepted replay path
is isolated and log-only. Its future receipt can use the reserved value without
making normal runtime claim replay coverage it does not have.

## Exact runtime seam

Add these types in `internal/telemetry/volume.go`:

```go
type TrafficClass string

const (
    TrafficSteadyState      TrafficClass = "steady_state"
    TrafficColdStartBackfill TrafficClass = "cold_start_backfill"
    TrafficManualReplay     TrafficClass = "manual_replay"
)

type Attribution struct {
    TenantID    string
    Collector   string
    Transport   Transport
    TrafficClass TrafficClass
}

type VolumeRow struct {
    Attribution
    MetricPoints uint64
    LogPoints    uint64
}
```

`Provider` owns one `VolumeTracker` and exposes:

```go
func (p *Provider) CollectorEmitter(a Attribution) Emitter
func (p *Provider) Volume() []VolumeRow
```

The factory's concrete chain must be:

```go
WithTenant(
    WithTransport(
        p.limiter.Wrap(newVolumeEmitter(p.emitter, p.volume, attribution)),
        attribution.Transport,
    ),
    attribution.TenantID,
)
```

Read calls from outside to inside:

```text
collector/event-lag
  -> tenant stamp
  -> transport stamp
  -> shared limiter
  -> volume emitter
  -> concrete OTEL emitter
```

This order is load-bearing:

- outside the limiter counts points later dropped;
- inside the concrete emitter cannot retain collector identity;
- a separate limiter per collector changes #235's global arbitration;
- wrapping `p.Emitter()` would apply the limiter twice.

All factory-created limiter wrappers share `p.limiter`; only the tiny
collector-bound volume wrapper differs.

Inject the provider method into `collector.Scheduler` as a narrow function,
not as a concrete `*telemetry.Provider` dependency:

```go
type EmitterFactory func(telemetry.Attribution) telemetry.Emitter
func WithEmitterFactory(EmitterFactory) SchedulerOption
```

The default remains the scheduler's current emitter so collector tests and
external package users do not require a Provider. Production passes
`provider.CollectorEmitter`.

For window collectors, move the checkpoint read/classification ahead of
emitter construction and pass the already-computed window into collection.
Do not read the store twice: a mutable store result changing between class
selection and `nextWindow` would make the class describe a different run.

## Concurrency and reporting

The collector/transport/class key set is bounded by configured tenants,
registered collectors, the seven transport constants, and three traffic
classes.

Recommended implementation:

- Create/find one row when `CollectorEmitter` is bound.
- Store metric/log totals in per-row `atomic.Uint64` fields; the hot point path
  then performs no global-map lock and no allocation.
- Guard row-map creation and deterministic snapshot sorting with a mutex.
- Guard report cursors separately. A report loads cumulative atomics and emits
  only the delta since the prior report. Points emitted after a load naturally
  fall into the next interval; none are lost or duplicated.
- Serialize concurrent periodic/final reports.

Emit `graph2otel.ingest.emitted_points` from the existing process-level
`Provider.ReportSelfObs` path, after taking the tracker snapshot. That path is
not wrapped by a collector-bound volume emitter, so the report cannot increment
itself. Do not add a metric-name prefix exclusion or a context flag; correct
composition makes recursion structurally impossible.

The admin surface reads cumulative `Volume()` rows directly. It must not
reconstruct them from periodically exported counter deltas.

## Partial runs and shutdown

Point accounting increments immediately after the limiter forwards a call.
It is not transactional at collector-run completion:

- A partial/error/panic run retains every point handed off before failure and
  retains #269's completed-run outcome summary. This is the desired exact
  partial-run accounting.
- A shutdown-cancelled run keeps every point already handed off, because those
  points cannot be rolled back. It continues to emit no #269
  `record.outcomes`/`scrape.outcomes`, status, or availability update, preserving
  the existing scheduler shutdown contract.

That shutdown asymmetry must be documented and tested. Buffering points and
discarding them on cancellation would make the emitted-point total false;
emitting a synthetic source-run outcome would break #269's intentional
shutdown semantics.

After tenant schedulers drain, perform one final serialized volume report
before the OTEL providers shut down. Otherwise up to 60 seconds of exact
in-memory deltas disappear on a clean stop. Make the ordering visible in
`cmd/graph2otel/main.go` tests:

```text
cancel tenants -> wait for scheduler goroutines -> final volume report
-> Provider.Shutdown/flush
```

An abrupt process kill can still lose SDK-buffered telemetry; that is outside
the emitter-handoff contract and is not solved by a counter.

## Wire/retry seam correction

The current scratch plan says #289 can consume exact bytes/retries from #268.
That is false at this base.

Current `DeliverySignal` has:

- export attempts;
- export successes/failures;
- force-flush/shutdown failures;
- state and latest bounded failure metadata.

It has no byte or retry counters. The wrapper surrounds the SDK exporter's
`Export` callback. HTTP/gRPC serialization, compression, and retry loops happen
inside that exporter, so counting the callback payload or callback attempts
would be an estimate mislabeled as exact.

Before the cost/wire portion of #289 can start, land a separate tested
protocol-level seam which supplies exact transmitted payload bytes and
transport retry attempts for HTTP, gRPC, and stdout, or explicitly narrow
supported protocols. Extend `DeliverySnapshot` only after that seam exists.
Do not:

- call protobuf marshal size a wire byte count;
- count an SDK `Export` callback as a retry;
- infer retries from failures;
- attribute exact wire bytes to a collector.

Collector allocation remains estimated and must retain an unattributed process
remainder for self-observability and all other non-collector traffic.

## Exact file/interface ownership

Logical-volume core:

- `internal/telemetry/volume.go` — bounded types, tracker, volume emitter,
  report logic.
- `internal/telemetry/volume_test.go` — method, limiter, concurrency,
  recursion, report-delta tests.
- `internal/telemetry/provider.go` — tracker ownership, collector factory,
  `Volume`, report orchestration.
- `internal/telemetry/provider_internal_test.go` — exact production decorator
  order and process-report bypass.
- `internal/telemetry/snapshot_tenant_test.go` — existing compile-visible
  tenant-snapshot forwarding gate automatically covers the new decorator.

Scheduler/source truth:

- `internal/collector/scheduler.go` — factory injection, one checkpoint read,
  class resolution, partial/shutdown behavior.
- `internal/collector/selfobs.go` — add class to existing record/scrape outcome
  attributes; do not add a source-record metric.
- `internal/collector/scheduler_test.go` — class and lifecycle tests.
- `internal/semconv/attrs.go` / `attrs_test.go` —
  `AttrTrafficClass = "traffic_class"`.
- `cmd/graph2otel/tenants.go` — pass `provider.CollectorEmitter`; remove no
  existing scheduler self-observation emitter.
- `cmd/graph2otel/main.go` and tests — periodic plus post-drain final report.

Generated/runtime inventory:

- `internal/collector/testdata/signals.json`
- `internal/telemetry/testdata/signals.json`
- `spec/signal-catalog.json` through its generator/gates
- `docs/signals.md`
- `grafana/boards/selfobs.py` and generated dashboard/tests

The cost config/admin/UI work should remain a later serial lane after exact
wire/retry instrumentation exists. It should not block landing logical volume.

## Compile-visible omissions to prevent

`volumeEmitter` embeds `Emitter`, so it can compile while silently promoting a
method it forgot to count. Add an AST drift gate equivalent to
`TestEveryEmitterMethodIsLimited`:

```text
TestEveryEmitterMethodIsVolumeAccounted
```

It must parse `types.go` and require `volumeEmitter` to declare all seven
methods. Do not change `internal/telemetry/types.go`; the existing facade is
sufficient.

The new decorator must also declare:

```go
func (e *volumeEmitter) gaugeSnapshotFor(
    tenant, name, unit, desc string,
    points []GaugePoint,
)
```

It counts `len(points)` and calls `snapshotFor` with the same tenant scope.
The existing `TestEveryEmitterDecoratorForwardsTheSnapshotTenant` will fail if
this private method is omitted.

Other compile-visible gates:

- a closed-value test for all `TrafficClass` values;
- a provider-order test proving tenant stamps reach the shared limiter and
  final snapshot scope reaches the base emitter;
- a registry test proving every window collector keeps
  `InitialLookback <= MaxWindow` while the no-checkpoint-only cold-start
  classification is in force;
- signal-catalog assertions proving no `graph2otel.ingest.records` metric was
  introduced.

## RED test sequence

1. Add telemetry RED tests first:

   ```sh
   go test -race ./internal/telemetry -run \
     'Test.*(Volume|CollectorEmitter|VolumeAccounted)'
   ```

   Required cases:

   - one point for every synchronous method without Histogram double-counting;
   - one per final snapshot point and zero for an empty snapshot;
   - additive folded and non-additive dropped snapshot tails count only the
     final forwarded slice;
   - limiter-dropped synchronous points count zero;
   - one log point;
   - event-lag histogram plus timestamped log count as two real points;
   - concurrent collectors/tenants/classes under `-race`;
   - repeated reports emit deltas once;
   - reporting `emitted_points` does not change the tracker;
   - private tenant snapshot scope survives;
   - all `Emitter` methods are explicitly overridden.

2. Add collector RED tests:

   ```sh
   go test -race ./internal/collector -run \
     'TestScheduler_.*(TrafficClass|Volume|Shutdown|Partial)'
   ```

   Required cases:

   - snapshot is `steady_state`;
   - no-checkpoint window is `cold_start_backfill`;
   - checkpointed window is `steady_state`;
   - cold zero-row run is visible through `scrape.outcomes`;
   - partial and panic runs retain both source outcomes and emitted points;
   - shutdown after one emitter handoff keeps the point but emits no source/run
     outcome;
   - one store read controls class and window;
   - every outcome equation reconciles independently by class;
   - no registered initial lookback can span multiple max windows.

3. Add provider/composition RED tests:

   ```sh
   go test -race ./internal/telemetry ./cmd/graph2otel -run \
     'Test.*(CollectorEmitter|VolumeReport|ShutdownOrder)'
   ```

   Prove the exact chain, shared limiter identity, process self-observation
   bypass, periodic report, and final post-drain/pre-shutdown report.

4. Refresh generated captures only after runtime green, then run:

   ```sh
   go test -race ./...
   make check
   make grafana-check
   git diff --check
   ```

## Rejected alternatives

- **New `graph2otel.ingest.records`:** duplicates #269's fetched truth and
  creates two counters which can drift.
- **Counting outside the limiter:** charges points which graph2otel dropped.
- **Changing the `Emitter` interface:** unnecessary and forces every collector
  test double to change; a provider factory plus in-package decorator is
  sufficient.
- **Per-collector limiter:** destroys #235's shared global budget.
- **Transactional point commit at run completion:** loses points already
  emitted by partial/shutdown runs and is therefore not exact.
- **Sending volume self-metrics through the collector-bound wrapper:** creates
  recursive self-metering.
- **Treating #268 callback attempts as retries or payload size as wire bytes:**
  changes an exact claim into an estimate.

## Decision prompt status

No maintainer decision is needed for this seam. A new prompt is required only
if implementation wants to weaken one of the accepted exact claims—for example
supporting wire metrics for HTTP but not gRPC, or replacing exact retries with
export-callback attempts. Those are product-scope changes and must not be
silently chosen.
