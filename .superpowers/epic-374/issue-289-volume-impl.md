# Issue #289 logical-volume core implementation

## Outcome

Implemented the logical-volume accounting core in
`/tmp/graph2otel-289.Y9NQNW`, limited to:

- `internal/telemetry/volume.go`
- `internal/telemetry/volume_test.go`

The frozen seam is:

- `TrafficClassSteadyState = "steady_state"`
- `TrafficClassColdStartBackfill = "cold_start_backfill"`
- `TrafficClassManualReplay = "manual_replay"`
- `Attribution{TenantID, Collector, Transport, TrafficClass}`
- `VolumeRow` embedding `Attribution` with cumulative `SourceRecords`,
  `MetricPoints`, and `LogPoints`
- zero-value-safe, concurrency-safe `VolumeTracker`
- `VolumeTracker.RecordSourceRecords(attribution, n)`
- `VolumeTracker.Snapshot() []VolumeRow`
- private `newVolumeEmitter(delegate, tracker, attribution)`

`VolumeTracker` keys its map only by the four bounded attribution values. It
never stores metric names, event names, bodies, entity attributes, or raw
record data. Snapshots are fresh copies, cumulative/non-resetting, and sorted
lexicographically by tenant, collector, transport, then traffic class.

The hot path does not serialize on the tracker map:

- the map lock is held only while finding or creating a private counter row;
- each `volumeEmitter` caches that row once at construction;
- source, metric, and log totals are independent `atomic.Uint64` counters;
- `Snapshot` copies attribution/counter-pointer pairs under the map lock,
  releases it, then loads counters and sorts the result.

The decorator explicitly forwards every `Emitter` method and counts the final
points reaching this post-limiter seam:

- one metric point for each `Counter`, `Gauge`, `UpDownCounter`, `Histogram`,
  and `HistogramCtx` call;
- one metric point per final `GaugeSnapshot` element, with an empty snapshot
  adding zero;
- one log point per `LogEvent`;
- source records remain a separate explicit input through
  `RecordSourceRecords`.

The private `gaugeSnapshotFor` path forwards through `snapshotFor`, preserving
the tenant partition without double counting. The decorator also preserves
`WithEventLag`: a timestamped event reaching a volume emitter records one lag
metric point and one log point.

## TDD receipt

RED:

```text
go test ./internal/telemetry -run 'TestVolume' -count=1

internal/telemetry/volume_test.go:98:14: undefined: VolumeTracker
internal/telemetry/volume_test.go:99:17: undefined: Attribution
internal/telemetry/volume_test.go:103:17: undefined: TrafficClassSteadyState
internal/telemetry/volume_test.go:106:13: undefined: newVolumeEmitter
internal/telemetry/volume_test.go:168:12: undefined: VolumeRow
FAIL
```

GREEN:

```text
go test ./internal/telemetry -run 'TestVolume' -count=1
ok github.com/rknightion/graph2otel/internal/telemetry 0.340s
```

The tests cover:

- exact forwarding of all seven `Emitter` methods, including context and
  histogram boundaries;
- exact per-call and per-snapshot-element counts;
- empty snapshots adding zero;
- tenant-scoped `GaugeSnapshot` forwarding;
- `WithEventLag` metric/log behavior;
- source-record accumulation;
- deterministic sorting and immutable snapshot copies;
- no raw metric, event, body, or entity data in tracker rows;
- concurrent record, metric, log, and snapshot operations under the race
  detector.

### Adversarial performance review follow-up

The first implementation held one global tracker mutex across every point
increment and held it while sorting snapshots. A firehose collector could
therefore serialize unrelated collector emitters and block them behind a
snapshot sort.

RED:

```text
go test <isolated telemetry production files> volume_test.go -run \
  '^TestVolumeEmitterExistingAttributionDoesNotTakeMapLock$' -count=1

--- FAIL: TestVolumeEmitterExistingAttributionDoesNotTakeMapLock (1.00s)
    volume_test.go:435: existing attribution update blocked on the global map lock
FAIL
```

GREEN:

```text
go test <isolated telemetry production files> volume_test.go -run \
  '^TestVolumeEmitterExistingAttributionDoesNotTakeMapLock$' -count=1
ok command-line-arguments 0.289s
```

The test warms the attribution, deliberately holds the tracker map lock, and
then proves the same emitter can still forward and count a metric plus a log.
It also verifies the exact cumulative totals after releasing the lock.

## Verification

An isolated race run over every telemetry production file plus this lane's
test file passed while sibling #289 lanes were mid-TDD:

```text
go test -race <all internal/telemetry non-test .go files> \
  internal/telemetry/volume_test.go -run 'TestVolume' -count=1
ok command-line-arguments 1.390s

go vet <all internal/telemetry non-test .go files> \
  internal/telemetry/volume_test.go
PASS

golangci-lint run --allow-parallel-runners --disable=unused \
  <all internal/telemetry non-test .go files except the in-flight cost.go> \
  internal/telemetry/volume_test.go
0 issues.

git diff --check -- internal/telemetry/volume.go \
  internal/telemetry/volume_test.go
PASS
```

After the cost lane aligned to `LogPoints`, full package vet and lint passed:

```text
go vet ./internal/telemetry
PASS

golangci-lint run --allow-parallel-runners ./internal/telemetry/...
0 issues.
```

Final focused stress verification after the atomic-row refactor:

```text
go test -race ./internal/telemetry -run 'TestVolume' -count=10
ok github.com/rknightion/graph2otel/internal/telemetry 1.494s

git diff --check -- internal/telemetry/volume.go \
  internal/telemetry/volume_test.go
PASS
```

Full-package compilation reaches sibling pricing tests and is currently
blocked by their in-flight allocation/projection expectations. Full telemetry
vet and lint remain green. The coordinator owns the final integrated race gate
after those concurrent lanes settle.

## Ownership and repository state

No existing file was edited by this lane. Concurrent scheduler, config,
provider, transport, pricing, semconv, Helm, and documentation changes in the
shared worktree were not touched or reverted.

Nothing was staged, committed, pushed, or changed on GitHub.
