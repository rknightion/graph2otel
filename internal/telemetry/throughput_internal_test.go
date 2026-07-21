package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// testEmitter returns an *otelEmitter wired to a throwaway in-memory meter and
// a no-op logger. It exercises the real emit path (instrument creation and
// record calls) without any exporter, which is exactly what the throughput
// counters must be incremented from.
func testEmitter(t *testing.T) *otelEmitter {
	t.Helper()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	return newOtelEmitter(mp.Meter("test"), noop.NewLoggerProvider().Logger("test"), nil)
}

// TestThroughputCountsEveryEmitPath asserts the emit-side counters tally one
// data point per metric call, len(points) for a GaugeSnapshot, and one record
// per LogEvent. These feed the admin status page's emitted-throughput chart
// (#227), so a call path that forgets to count is a silently under-reported
// rate rather than a visible failure.
func TestThroughputCountsEveryEmitPath(t *testing.T) {
	e := testEmitter(t)

	if got := e.Throughput(); got.MetricPoints != 0 || got.LogRecords != 0 {
		t.Fatalf("fresh emitter Throughput() = %+v, want zero", got)
	}

	e.Counter("a.count", "1", "d", 1, nil)
	e.Gauge("a.gauge", "1", "d", 1, nil)
	e.UpDownCounter("a.updown", "1", "d", 1, nil)
	e.Histogram("a.hist", "1", "d", 1, []float64{1, 2}, nil)
	e.HistogramCtx(context.Background(), "a.hist", "1", "d", 1, []float64{1, 2}, nil)
	e.GaugeSnapshot("a.snap", "1", "d", []GaugePoint{{Value: 1}, {Value: 2}, {Value: 3}})
	e.LogEvent(Event{Name: "a.event", Body: "b", Timestamp: time.Unix(1700000000, 0)})
	e.LogEvent(Event{Name: "a.event", Body: "b", Timestamp: time.Unix(1700000001, 0)})

	got := e.Throughput()
	// 5 single-point metric calls + 3 snapshot points = 8.
	if got.MetricPoints != 8 {
		t.Errorf("MetricPoints = %d, want 8", got.MetricPoints)
	}
	if got.LogRecords != 2 {
		t.Errorf("LogRecords = %d, want 2", got.LogRecords)
	}
}

// TestThroughputSnapshotIsMonotonicAcrossCalls asserts Throughput reads the
// running totals rather than resetting them: the sampler differences
// consecutive snapshots, so a read that cleared the counters would make every
// rate depend on who read last.
func TestThroughputSnapshotIsMonotonicAcrossCalls(t *testing.T) {
	e := testEmitter(t)
	e.Counter("a.count", "1", "d", 1, nil)
	first := e.Throughput()
	second := e.Throughput()
	if first != second {
		t.Fatalf("consecutive Throughput() reads differ: %+v then %+v — reads must not reset", first, second)
	}
	e.Counter("a.count", "1", "d", 1, nil)
	if third := e.Throughput(); third.MetricPoints != second.MetricPoints+1 {
		t.Errorf("MetricPoints after one more emit = %d, want %d", third.MetricPoints, second.MetricPoints+1)
	}
}
