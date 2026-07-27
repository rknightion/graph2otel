# Issue #289 scheduler/source-record implementation receipt

## Outcome

Implemented the scheduler-owned traffic classification and exact source-record
seams in `/tmp/graph2otel-289.Y9NQNW`.

No commit, push, staging, GitHub write, generated-file edit, or production
wiring edit was made.

## Contract implemented

- Added `semconv.AttrTrafficClass = "traffic_class"`.
- Added `collector.WithEmitterFactory(func(telemetry.Attribution)
  telemetry.Emitter)`.
- Added `collector.WithSourceRecordRecorder(func(telemetry.Attribution,
  uint64))`.
- Snapshot runs bind `telemetry.TrafficClassSteadyState`.
- Window runs read the source checkpoint exactly once:
  - no checkpoint: `TrafficClassColdStartBackfill`;
  - checkpoint present: `TrafficClassSteadyState`.
- The scheduler never emits `TrafficClassManualReplay`; it remains reserved in
  telemetry for the replay-owned receipt.
- Collector data handoffs use the bound emitter returned by the factory.
- Event-lag observation wraps the bound data emitter, so the collector-caused
  lag point remains attributable.
- Scheduler scrape, outcome, and source-record self-observability continue to
  use the scheduler's original un-attributed emitter.
- Every completed non-shutdown run:
  - calls the source-record recorder once with
    `recordoutcome.Snapshot.Counts.Fetched`, even when the count is zero and
    even when OTLP self-observation is disabled;
  - emits `graph2otel.ingest.source_records` with unit `{record}` through the
    un-attributed self-observation emitter when self-observation is enabled.
- `source_records` labels are exactly
  `tenant_id`, `collector`, `ingest_transport`, and `traffic_class`.
- `graph2otel.record.outcomes` labels remain unchanged. Tests prove the new
  source count equals its `outcome="fetched"` value for the same immutable
  snapshot.
- A zero-row completed run emits a zero-add `source_records` point, so
  `graph2otel.scrape.outcomes` did not need a new label.
- Partial/error runs retain both their bound emitter handoffs and exact fetched
  count.
- Shutdown-cancelled runs retain data already handed to the bound emitter but
  emit no source-record metric, invoke no source-record callback, and preserve
  #269's existing outcome/status/availability suppression.

## Owned files changed

- `internal/collector/scheduler.go`
- `internal/collector/scheduler_test.go`
- `internal/collector/cold_start_traffic_test.go`
- `internal/collector/selfobs.go`
- `internal/semconv/attrs.go`
- `internal/semconv/attrs_test.go`

## Strict TDD receipts

Initial focused test command:

```sh
go test ./internal/collector ./internal/semconv -run \
  'TestScheduler_.*(SteadyState|TrafficClass|SourceRecord|PartialRunRetains|ShutdownKeeps)|TestCollectorConstants' \
  -count=1
```

Observed RED for the intended missing seams:

- `semconv.AttrTrafficClass`
- `telemetry.Attribution` and traffic-class constants
- `collector.WithEmitterFactory`
- `collector.WithSourceRecordRecorder`
- `collector.MetricSourceRecords`

After the telemetry attribution type landed and the owned implementation was
added, the same focused command passed:

```text
ok github.com/rknightion/graph2otel/internal/collector
ok github.com/rknightion/graph2otel/internal/semconv
```

Fresh verification:

```sh
go test -race ./internal/collector \
  -run '^(TestScheduler|TestSelfObs|TestEmitBuildInfo)' -count=1
# PASS

go test -race ./internal/semconv -count=1
# PASS

go vet ./internal/collector ./internal/semconv
# PASS

golangci-lint run ./internal/collector/... ./internal/semconv/...
# 0 issues

git diff --check
# PASS
```

## Expected integration task

The full collector race package has exactly one expected failure:
`TestSignalGolden` reports
`internal/collector/testdata/signals.json` is stale. The integration/generated
owner must regenerate it. The new captured entry is:

```text
name: graph2otel.ingest.source_records
unit: {record}
kind: sum
description: Count of logical source records fetched by completed collector runs, classified by traffic phase.
attributes:
  - collector
  - ingest_transport
  - tenant_id
  - traffic_class
```

No generated file was touched in this lane.

Production composition still needs to pass the provider's collector-emitter
factory and volume tracker's source-record method into the two scheduler
options. That wiring is outside this lane's ownership.

## Adversarial follow-up: persisted multi-slice cold starts

The first implementation classified a window run solely from main-checkpoint
presence. Review correctly found that `InitialLookback > MaxWindow` made only
slice one cold; slice two had an HWM and was mislabeled steady.

The scheduler now persists a fixed per-tenant/collector cold-start target under
the collision-safe internal key:

```text
\x00graph2otel/cold-start-target/<tenant-scoped main checkpoint key>
```

Corrected lifecycle:

- On the first no-checkpoint run, persist the original uncapped `now-lag`
  target before invoking the collector.
- If marker persistence fails, do not collect or advance the main HWM; emit
  `graph2otel.checkpoint.persist.errors`.
- While the marker is nonzero, keep every capped slice classified
  `cold_start_backfill`, including across scheduler reconstruction/restart.
- Anchor retries and later slices to the fixed target rather than a moving wall
  clock.
- Existing checkpoints with no marker remain `steady_state` for upgrade
  compatibility.
- After a successful main HWM reaches/passes the target, persist zero to clear
  the marker.
- If the zero-clear fails after mutating the store's in-memory map, restore the
  nonzero target, emit the existing checkpoint-persist error, and remain
  conservatively cold.
- A later scheduler retries the clear before admitting steady traffic.
- Shutdown leaves the nonzero target and no main HWM, so restart remains cold.

Additional strict RED receipt:

```sh
go test ./internal/collector \
  -run 'TestScheduler_ColdStart(Target|Marker|Shutdown)' -count=1
```

The pre-fix run failed all five intended cases:

- second and later slices became steady;
- a failed first attempt moved with the later wall clock;
- marker-set failure did not prevent collection;
- no marker existed to exercise clear failure;
- shutdown retained no cold target.

After implementation the same command passed. Fresh post-fix verification:

```sh
go test -race ./internal/collector \
  -run '^(TestScheduler|TestSelfObs|TestEmitBuildInfo)' -count=1
# PASS

go test -race ./internal/semconv -count=1
# PASS

go vet ./internal/collector ./internal/semconv
# PASS

golangci-lint run ./internal/collector/... ./internal/semconv/...
# 0 issues

git diff --check
# PASS
```

The full collector package still has only the previously recorded,
coordinator-owned signal-golden failure.

## Fail-closed follow-up: marker-clear failures

Review found one remaining false-healthy path: after the main HWM reached the
fixed cold target, a failed marker clear could leave the scheduler anchored at
that target, produce no next window, and report a healthy empty scrape.

The scheduler now treats both forms of cold-marker clear failure as workload
failures:

- A failure after the final cold slice returns a run error only after the main
  HWM has been persisted, so the run is unhealthy but does not replay data.
- A restart whose retry-clear still fails stops before creating a collector
  emitter or invoking the collector, retains the nonzero marker, and reports
  an unhealthy run rather than healthy/empty.
- When a later retry-clear succeeds, the scheduler enters steady state and the
  retained main HWM prevents replay.

Strict RED receipt:

```sh
go test ./internal/collector \
  -run '^TestScheduler_ColdStartMarkerClearFailureRemainsCold$' -count=1
```

Before the fix, the test observed exactly the false-health bug:

```text
graph2otel.scrape.success value = 1, want 0
graph2otel.scrape.outcomes ... result:empty
```

After propagating the two clear failures as `runErr`, the focused test passed.
Fresh verification:

```sh
go test -race ./internal/collector \
  -run '^(TestScheduler|TestSelfObs|TestEmitBuildInfo)' -count=1
# PASS

go test -race ./internal/semconv -count=1
# PASS

go vet ./internal/collector ./internal/semconv
# PASS

golangci-lint run ./internal/collector/... ./internal/semconv/...
# 0 issues

git diff --check -- <owned files>
# PASS
```

The full `go test -race ./internal/collector -count=1` still has only the
coordinator-owned `TestSignalGolden` failure for the new
`graph2otel.ingest.source_records` entry.
