package admin

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeThroughput is a hand-driven telemetry.Throughput source: the test sets
// the running totals, so the sampler's differencing can be asserted without an
// emitter or a real export pipeline.
type fakeThroughput struct{ tp telemetry.Throughput }

func (f *fakeThroughput) Throughput() telemetry.Throughput { return f.tp }

// stepClock is a manually advanced clock so rate differencing is exact rather
// than dependent on how long the test took to run.
type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time          { return c.t }
func (c *stepClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newStepClock() *stepClock               { return &stepClock{t: time.Unix(1700000000, 0).UTC()} }

// TestSamplerFirstSampleHasNoRates asserts the first observation records the
// value series but no rate series. A rate needs a prior observation; emitting
// a 0 for the first sample would draw a throughput dip that never happened.
func TestSamplerFirstSampleHasNoRates(t *testing.T) {
	clk := newStepClock()
	s := newSampler(samplerHistoryLen, nil, &fakeThroughput{}, nil, nil, clk.now)

	s.sample()

	rt := s.runtimeInfo()
	if len(rt.GoroutinesSeries) != 1 {
		t.Errorf("GoroutinesSeries = %v, want 1 value after the first sample", rt.GoroutinesSeries)
	}
	if len(rt.HeapAllocSeries) != 1 {
		t.Errorf("HeapAllocSeries = %v, want 1 value after the first sample", rt.HeapAllocSeries)
	}
	if len(rt.GCRateSeries) != 0 {
		t.Errorf("GCRateSeries = %v, want empty until a second sample exists", rt.GCRateSeries)
	}
	tp := s.throughputInfo()
	if len(tp.MetricPointsSeries) != 0 || len(tp.LogRecordsSeries) != 0 {
		t.Errorf("throughput series = %v/%v, want both empty until a second sample exists",
			tp.MetricPointsSeries, tp.LogRecordsSeries)
	}
}

// TestSamplerThroughputRates asserts emitted totals are differenced over
// elapsed wall time, that a counter which did not move reads exactly 0, and
// that a total which appears to go backwards clamps to 0 rather than drawing a
// negative rate.
func TestSamplerThroughputRates(t *testing.T) {
	clk := newStepClock()
	src := &fakeThroughput{}
	s := newSampler(samplerHistoryLen, nil, src, nil, nil, clk.now)

	s.sample() // baseline: totals 0/0

	// 100 metric points and 20 log records over 10s -> 10/s and 2/s.
	src.tp = telemetry.Throughput{MetricPoints: 100, LogRecords: 20}
	clk.advance(10 * time.Second)
	s.sample()

	// Nothing emitted over the next 10s -> 0/s, not a repeat of the last rate.
	clk.advance(10 * time.Second)
	s.sample()

	// A total that goes backwards (it cannot in production; the sampler must
	// not draw a negative rate if it ever does).
	src.tp = telemetry.Throughput{MetricPoints: 1, LogRecords: 0}
	clk.advance(10 * time.Second)
	s.sample()

	tp := s.throughputInfo()
	wantMetric := []float64{10, 0, 0}
	wantLog := []float64{2, 0, 0}
	if !eqFloats(tp.MetricPointsSeries, wantMetric) {
		t.Errorf("MetricPointsSeries = %v, want %v", tp.MetricPointsSeries, wantMetric)
	}
	if !eqFloats(tp.LogRecordsSeries, wantLog) {
		t.Errorf("LogRecordsSeries = %v, want %v", tp.LogRecordsSeries, wantLog)
	}
	if tp.MetricPointsPerSec != 0 || tp.LogRecordsPerSec != 0 {
		t.Errorf("latest rates = %v/%v, want 0/0", tp.MetricPointsPerSec, tp.LogRecordsPerSec)
	}
	if tp.MetricPointsTotal != 1 || tp.LogRecordsTotal != 0 {
		t.Errorf("totals = %d/%d, want 1/0", tp.MetricPointsTotal, tp.LogRecordsTotal)
	}
}

// TestSamplerZeroElapsedIsNotADivideByZero asserts two samples at the same
// instant record no rate at all, rather than +Inf or NaN.
func TestSamplerZeroElapsedIsNotADivideByZero(t *testing.T) {
	clk := newStepClock()
	src := &fakeThroughput{}
	s := newSampler(samplerHistoryLen, nil, src, nil, nil, clk.now)

	s.sample()
	src.tp = telemetry.Throughput{MetricPoints: 500}
	s.sample() // no clock advance

	if got := s.throughputInfo().MetricPointsSeries; len(got) != 0 {
		t.Errorf("MetricPointsSeries = %v, want empty (elapsed was zero)", got)
	}
}

// TestSamplerFleetAggregatesAcrossTenants asserts the fleet counters sum every
// tenant's collectors: one failing collector in one tenant and one healthy in
// another must read 2 enabled / 1 failing.
func TestSamplerFleetAggregatesAcrossTenants(t *testing.T) {
	okTracker, okReg := runOnceAndTrack(t, "entra.users", nil)
	badTracker, badReg := runOnceAndTrack(t, "intune.devices", errBoom)

	clk := newStepClock()
	s := newSampler(samplerHistoryLen, nil, &fakeThroughput{}, []CollectorSource{
		{TenantID: "t1", Registry: okReg, Status: okTracker},
		{TenantID: "t2", Registry: badReg, Status: badTracker},
	}, nil, clk.now)

	s.sample()

	f := s.fleetInfo()
	if f.Enabled != 2 {
		t.Errorf("Enabled = %d, want 2", f.Enabled)
	}
	if f.Failing != 1 {
		t.Errorf("Failing = %d, want 1", f.Failing)
	}
	if f.Pending != 0 {
		t.Errorf("Pending = %d, want 0 (both collectors ran)", f.Pending)
	}
	if len(f.FailingSeries) != 1 || f.FailingSeries[0] != 1 {
		t.Errorf("FailingSeries = %v, want [1]", f.FailingSeries)
	}
	if len(f.MeanDurationSeries) != 1 {
		t.Errorf("MeanDurationSeries = %v, want 1 value", f.MeanDurationSeries)
	}
}

// TestSamplerFleetCountsUnrunCollectorsAsPending asserts a registered
// collector with no run record is pending, not failing — a starting process
// must not read as a broken one.
func TestSamplerFleetCountsUnrunCollectorsAsPending(t *testing.T) {
	reg := collector.NewRegistry()
	reg.Register(&fakeCollector{name: "entra.users"}, time.Hour)

	clk := newStepClock()
	s := newSampler(samplerHistoryLen, nil, &fakeThroughput{}, []CollectorSource{
		{TenantID: "t1", Registry: reg, Status: collector.NewStatusTracker()},
	}, nil, clk.now)
	s.sample()

	f := s.fleetInfo()
	if f.Enabled != 1 || f.Pending != 1 || f.Failing != 0 {
		t.Errorf("fleet = %+v, want enabled=1 pending=1 failing=0", f)
	}
	if f.MeanDurationMs != 0 {
		t.Errorf("MeanDurationMs = %v, want 0 with no completed runs", f.MeanDurationMs)
	}
}

// TestSamplerHeadroomTrendPerWorkload asserts each (tenant, workload) bucket
// gets its own headroom ring, so one tenant's throttling never shows on
// another's row.
func TestSamplerHeadroomTrendPerWorkload(t *testing.T) {
	clk := newStepClock()
	lim := fakeLimiter{headroom: []graphclient.WorkloadHeadroom{
		{TenantID: "t1", Workload: graphclient.WorkloadReporting, Burst: 10, Tokens: 5},
		{TenantID: "t2", Workload: graphclient.WorkloadIPC, Burst: 10, Tokens: 1},
	}}
	s := newSampler(samplerHistoryLen, nil, &fakeThroughput{}, nil, lim, clk.now)

	s.sample()
	lim.headroom[0].Tokens = 10
	clk.advance(10 * time.Second)
	s.sample()

	got := s.headroomTrend("t1", string(graphclient.WorkloadReporting))
	want := []float64{50, 100}
	if !eqFloats(got, want) {
		t.Errorf("t1/reporting headroom trend = %v, want %v", got, want)
	}
	if got := s.headroomTrend("t2", string(graphclient.WorkloadIPC)); !eqFloats(got, []float64{10, 10}) {
		t.Errorf("t2/ipc headroom trend = %v, want [10 10]", got)
	}
	if got := s.headroomTrend("t3", string(graphclient.WorkloadReporting)); got != nil {
		t.Errorf("unknown bucket trend = %v, want nil", got)
	}
}

// TestSamplerRingsAreBounded asserts the retained history is capped at the
// configured capacity — these rings are in-process introspection, so an
// unbounded one would be a slow leak in a long-lived process.
func TestSamplerRingsAreBounded(t *testing.T) {
	const capacity = 4
	clk := newStepClock()
	src := &fakeThroughput{}
	s := newSampler(capacity, nil, src, nil, nil, clk.now)

	for i := 0; i < capacity*3; i++ {
		src.tp = telemetry.Throughput{MetricPoints: uint64(i) * 10}
		clk.advance(10 * time.Second)
		s.sample()
	}

	if got := len(s.runtimeInfo().GoroutinesSeries); got != capacity {
		t.Errorf("GoroutinesSeries length = %d, want %d", got, capacity)
	}
	if got := len(s.throughputInfo().MetricPointsSeries); got != capacity {
		t.Errorf("MetricPointsSeries length = %d, want %d", got, capacity)
	}
}

// TestSamplerNilSourcesAreSafe asserts a sampler wired to nothing (no
// cardinality tracker, no throughput source, no collectors, no limiter) still
// samples the runtime without panicking — a Server built for a test, or one
// running with self-obs off, must not take the page down.
func TestSamplerNilSourcesAreSafe(t *testing.T) {
	clk := newStepClock()
	s := newSampler(samplerHistoryLen, nil, nil, nil, nil, clk.now)
	s.sample()
	clk.advance(10 * time.Second)
	s.sample()

	if got := s.runtimeInfo().Goroutines; got <= 0 {
		t.Errorf("Goroutines = %d, want a positive live count", got)
	}
	if got := s.cardinalityTrend().TotalSeries; got != 0 {
		t.Errorf("TotalSeries = %d, want 0 with no cardinality tracker", got)
	}
	if got := s.throughputInfo().MetricPointsPerSec; got != 0 {
		t.Errorf("MetricPointsPerSec = %v, want 0 with no throughput source", got)
	}
}

// TestSamplerCardinalityTrend asserts the active-series total is summed across
// every tracked metric and pushed into its own ring.
func TestSamplerCardinalityTrend(t *testing.T) {
	card := telemetry.NewCardinalityTracker()
	card.Observe("entra.users.count", telemetry.Attrs{"a": "1"})
	card.Observe("entra.users.count", telemetry.Attrs{"a": "2"})
	card.Observe("intune.devices.count", telemetry.Attrs{"a": "1"})
	card.Report(telemetrytest.New().Emitter())

	clk := newStepClock()
	s := newSampler(samplerHistoryLen, card, &fakeThroughput{}, nil, nil, clk.now)
	s.sample()

	ct := s.cardinalityTrend()
	if ct.TotalSeries != 3 {
		t.Errorf("TotalSeries = %d, want 3", ct.TotalSeries)
	}
	if len(ct.Series) != 1 || ct.Series[0] != 3 {
		t.Errorf("Series = %v, want [3]", ct.Series)
	}
}

func eqFloats(got, want []float64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
