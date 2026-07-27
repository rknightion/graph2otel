# #289 deterministic cost-math implementation report

## Outcome

Implemented the pure telemetry-local cost calculation core in
`/tmp/graph2otel-289.Y9NQNW`.

Owned files only:

- new `internal/telemetry/cost.go`
- new `internal/telemetry/cost_test.go`

No config, provider, admin, command, scheduler, collector, documentation, or
transport implementation file was edited by this lane.

## Frozen API

```go
func ProjectCosts(
    rows []VolumeRow,
    transport OTLPTransportSnapshot,
    rates CostRates,
    observedInterval, period time.Duration,
) (CostProjection, error)
```

`CostRates` uses the frozen non-negative integer fields:

- `SourceRecordMicrounits`
- `MetricPointMicrounits`
- `LogRecordMicrounits`
- `TransmittedPayloadByteMicrounits`

The implementation consumes `VolumeRow.LogPoints`, not the transient
`LogRecords` spelling seen while the shared volume lane was still landing.

`CostRow` preserves tenant, collector, ingest transport, and traffic class as
strings. Every row carries `attribution="estimated"`. The synthetic process
row uses `collector="_unattributed"` and `ingest_transport="process"` without
broadening the runtime `telemetry.Transport` enum.

## Arithmetic contract implemented

- Source-record, metric-point, and log-point interval components use exact
  `uint64` microunit multiplication.
- Metrics and logs transmitted-payload bytes are added into the exact process
  interval delta. Retry attempts remain exact transport telemetry but are not
  assigned an invented price.
- Metrics payload bytes are allocated only across metric points; logs payload
  bytes are allocated only across log points. Each signal uses deterministic
  largest remainder independently, so no signal subsidizes the other.
- `CostRow.AllocatedMetricPayloadBytes` and
  `CostRow.AllocatedLogPayloadBytes` preserve the two allocations.
  `AllocatedPayloadBytes` is their checked sum for compatibility.
- Equal remainders are broken by the final bounded attribution sort key, so
  shuffled input produces byte-identical output.
- Duplicate `VolumeRow` attribution keys are aggregated with checked addition
  before costing.
- Same-signal payload bytes with no emitted-point share are retained on the
  single explicit `_unattributed` / `process` row.
- Every interval row sum exactly equals the process interval projection.
- Interval costs retain all traffic classes. Period projection includes only
  `steady_state`; `cold_start_backfill`, `manual_replay`, empty, unknown, and
  synthetic process traffic remain visible in interval rows but project zero.
- Period projection takes explicit positive observed and configured durations,
  rounds the recurring process total half-up using integer arithmetic, and
  distributes row rounding by deterministic largest remainder among
  steady-state rows. Row projections therefore exactly equal the recurring
  process period projection.
- All multiply, add, aggregation, allocation, and period-projection paths check
  overflow. Intermediate multiply/divide uses `math/bits` 128-bit arithmetic,
  so a large representable result does not fail merely because `a*b` exceeds
  64 bits.
- Overflow fails closed with `ErrCostOverflow`. Wrapped diagnostics contain
  only a bounded operation name and never tenant/collector values.
- The core has no scheduler, limiter, exporter, provider, or budget-enforcement
  callback.

## Strict TDD receipt

RED:

```text
go test ./internal/telemetry -run TestProjectCosts -count=1

undefined: CostRates
undefined: ProjectCosts
undefined: CostProjection
undefined: CostRow
undefined: CostAttributionEstimated
FAIL github.com/rknightion/graph2otel/internal/telemetry [build failed]
```

The shared `VolumeRow` and `OTLPTransportSnapshot` seams were present; the
failure was the missing cost core.

The adversarial semantic tests then failed against the first implementation:

```text
metric-only row received 5 of 10 metric bytes
log-only row received 6 of 1 log bytes
same-signal bytes without a point share produced no unattributed row
cold/manual/empty/unknown rows projected non-zero cost
mixed steady+cold process projection was 202, want 2
```

These failures exposed pooled cross-signal allocation and projection of
exceptional traffic. The corrected implementation separates signal allocation
and projects only recurring steady-state rows.

GREEN after the corrections:

```text
go test ./internal/telemetry -run TestProjectCosts -count=1
ok github.com/rknightion/graph2otel/internal/telemetry 0.433s
```

Tests cover:

- exact per-component interval costs;
- per-signal process payload allocation and reconciliation;
- deterministic largest-remainder allocation under shuffled input;
- explicit same-signal unattributed payload with no point share;
- traffic-class preservation and estimated labels;
- zero projection for cold-start, manual-replay, empty, unknown, and synthetic
  process traffic;
- recurring-only projection for mixed steady-state and exceptional rows;
- duplicate attribution aggregation;
- half-up period rounding and exact row/process reconciliation;
- invalid zero/negative observed interval and period;
- component multiplication overflow;
- emitted-point sum overflow;
- transport-byte sum overflow;
- payload-cost overflow;
- period-projection overflow;
- bounded, attribution-free overflow errors.

## Fresh owned-lane verification

After the semantic corrections:

```text
go test -race ./internal/telemetry -run TestProjectCosts -count=1
ok github.com/rknightion/graph2otel/internal/telemetry 1.482s

go test -race ./internal/telemetry
ok github.com/rknightion/graph2otel/internal/telemetry 1.526s

go vet ./internal/telemetry
exit 0

golangci-lint run --allow-parallel-runners ./internal/telemetry/...
0 issues.

git diff --check
exit 0
```

`gofmt` was applied to both owned files.

## Integration status

The earlier concurrent transport-hook failure is resolved. The full telemetry
package race run is green. No remaining owned-lane concern is known.

No files were staged or committed, and there was no push or GitHub mutation.
