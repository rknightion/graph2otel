package admin

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/ringbuf"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// samplerInterval is how often the in-process trend history is observed, and
// samplerHistoryLen how many observations are retained per series — 60 samples
// at 10s is the ~10-minute window the status page advertises. Both match the
// sibling exporters (opnsense-exporter, tailscale2otel) so a operator reading
// two of these pages side by side is reading the same window.
const (
	samplerInterval        = 10 * time.Second
	samplerHistoryLen      = 60
	costMinimumObservation = 2 * time.Minute
	costHistoryWindow      = samplerInterval * samplerHistoryLen
	costProjectionRefresh  = time.Minute
)

// ThroughputSource reports cumulative emitted-record totals for the throughput
// trend. *telemetry.Provider satisfies it. May be nil (the chart stays empty).
type ThroughputSource interface {
	Throughput() telemetry.Throughput
}

// headroomKey identifies one throttle bucket's trend ring. Workload is held as
// a plain string because that is what the rendered RateLimitStatus row carries.
type headroomKey struct {
	tenantID string
	workload string
}

// latest is the most recent observation, kept alongside the rings so the stat
// cards can read a scalar without re-deriving it from a series tail.
type latest struct {
	goroutines  int
	gomaxprocs  int
	heapAlloc   uint64
	numGC       uint32
	seriesTotal int
	metricTotal uint64
	logTotal    uint64
	metricRate  float64
	logRate     float64
	enabled     int
	failing     int
	pending     int
	meanDurMs   float64
}

type costObservation struct {
	at        time.Time
	volume    []telemetry.VolumeRow
	transport telemetry.OTLPTransportSnapshot
}

// sampler holds the admin page's short-term in-memory trends: the Go runtime,
// emitted throughput, active series, collector fleet health, and per-workload
// throttle headroom. It is introspection only — nothing here is ever emitted
// as OTLP, and none of it survives a restart.
//
// Everything is read from memory: runtime.ReadMemStats briefly stops the
// world, so it runs on the sampler's own ticker and never on an HTTP request.
type sampler struct {
	now      func() time.Time
	card     *telemetry.CardinalityTracker
	tp       ThroughputSource
	sources  []CollectorSource
	limiter  RateLimiter
	capacity int

	capacitySource CapacitySource
	cost           *config.CostConfig

	goroutines  *ringbuf.Ring[int]
	heapAlloc   *ringbuf.Ring[uint64]
	gcRate      *ringbuf.Ring[float64]
	seriesTotal *ringbuf.Ring[int]
	metricRate  *ringbuf.Ring[float64]
	logRate     *ringbuf.Ring[float64]
	failing     *ringbuf.Ring[int]
	meanDurMs   *ringbuf.Ring[float64]

	// mu guards last and the headroom MAP (its Rings are individually locked
	// already). The map is written only by the sampling goroutine and read by
	// HTTP handlers, so the map access itself still needs the lock.
	mu       sync.Mutex
	last     latest
	headroom map[headroomKey]*ringbuf.Ring[float64]

	// prev* are the previous observation's differencing inputs, touched only by
	// the sampling goroutine. hasPrev is false until the first sample lands: a
	// rate needs a prior observation, so the rate rings stay empty until then
	// rather than recording a 0 that never happened.
	hasPrev     bool
	prevAt      time.Time
	prevNumGC   uint32
	prevMetrics uint64
	prevLogs    uint64

	costObservations     []costObservation
	costProjection       telemetry.CostProjection
	hasCostProjection    bool
	lastCostProjectionAt time.Time
}

// newSampler builds a sampler retaining capacity observations per series. Every
// source is optional: a nil card means no active-series trend, a nil tp no
// throughput trend, nil sources no fleet trend, and a nil limiter no headroom
// trend. now injects the clock so rate differencing is testable.
func newSampler(capacity int, card *telemetry.CardinalityTracker, tp ThroughputSource,
	sources []CollectorSource, limiter RateLimiter, now func() time.Time,
) *sampler {
	if capacity < 2 {
		capacity = 2
	}
	if now == nil {
		now = time.Now
	}
	return &sampler{
		now:         now,
		card:        card,
		tp:          tp,
		sources:     sources,
		limiter:     limiter,
		capacity:    capacity,
		goroutines:  ringbuf.New[int](capacity),
		heapAlloc:   ringbuf.New[uint64](capacity),
		gcRate:      ringbuf.New[float64](capacity),
		seriesTotal: ringbuf.New[int](capacity),
		metricRate:  ringbuf.New[float64](capacity),
		logRate:     ringbuf.New[float64](capacity),
		failing:     ringbuf.New[int](capacity),
		meanDurMs:   ringbuf.New[float64](capacity),
		headroom:    map[headroomKey]*ringbuf.Ring[float64]{},
	}
}

// run samples immediately, then on every tick until ctx is canceled, so the
// page has one data point the moment the process is up rather than after a
// full interval of "collecting…". A nil sampler is a no-op.
func (s *sampler) run(ctx context.Context) {
	if s == nil {
		return
	}
	s.sample()
	t := time.NewTicker(samplerInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sample()
		}
	}
}

// sample records one observation of every tracked series. A nil sampler is a
// no-op, and every source is independently optional.
func (s *sampler) sample() {
	if s == nil {
		return
	}
	at := s.now()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	goroutines := runtime.NumGoroutine()

	s.goroutines.Add(goroutines)
	s.heapAlloc.Add(ms.HeapAlloc)

	var tp telemetry.Throughput
	if s.tp != nil {
		tp = s.tp.Throughput()
	}

	// Rates need a prior observation and a forward clock. Without both, record
	// no rate at all: a 0 would draw a dip that never happened, and a zero
	// elapsed would divide to +Inf.
	if elapsed := at.Sub(s.prevAt).Seconds(); s.hasPrev && elapsed > 0 {
		s.gcRate.Add(float64(deltaU32(ms.NumGC, s.prevNumGC)) / elapsed)
		s.metricRate.Add(float64(deltaU64(tp.MetricPoints, s.prevMetrics)) / elapsed)
		s.logRate.Add(float64(deltaU64(tp.LogRecords, s.prevLogs)) / elapsed)
	}

	seriesTotal := 0
	for _, sc := range s.card.Snapshot() {
		seriesTotal += sc.Count
	}
	s.seriesTotal.Add(seriesTotal)

	enabled, failing, pending, meanDurMs := s.aggregateFleet()
	s.failing.Add(failing)
	s.meanDurMs.Add(meanDurMs)

	s.sampleHeadroom(at)
	s.sampleCost(at)

	s.mu.Lock()
	s.last = latest{
		goroutines:  goroutines,
		gomaxprocs:  runtime.GOMAXPROCS(0),
		heapAlloc:   ms.HeapAlloc,
		numGC:       ms.NumGC,
		seriesTotal: seriesTotal,
		metricTotal: tp.MetricPoints,
		logTotal:    tp.LogRecords,
		metricRate:  lastFloat(s.metricRate),
		logRate:     lastFloat(s.logRate),
		enabled:     enabled,
		failing:     failing,
		pending:     pending,
		meanDurMs:   meanDurMs,
	}
	s.mu.Unlock()

	s.hasPrev = true
	s.prevAt = at
	s.prevNumGC = ms.NumGC
	s.prevMetrics = tp.MetricPoints
	s.prevLogs = tp.LogRecords
}

func (s *sampler) sampleCost(at time.Time) {
	if s == nil || s.capacitySource == nil || s.cost == nil || !s.cost.Enabled {
		return
	}
	if len(s.costObservations) > 0 &&
		!at.After(s.costObservations[len(s.costObservations)-1].at) {
		return
	}

	current := costObservation{
		at:        at,
		volume:    append([]telemetry.VolumeRow(nil), s.capacitySource.Volume()...),
		transport: s.capacitySource.Transport(),
	}
	s.costObservations = append(s.costObservations, current)

	cutoff := at.Add(-costHistoryWindow)
	for len(s.costObservations) > 1 && s.costObservations[0].at.Before(cutoff) {
		s.costObservations = s.costObservations[1:]
	}

	if len(s.costObservations) < 2 {
		return
	}
	baseline := s.costObservations[0]
	elapsed := at.Sub(baseline.at)
	if elapsed < costMinimumObservation {
		return
	}
	// Capacity snapshots still join the 10-second history so the rolling
	// baseline stays close to ten minutes, but a cost estimate changes no more
	// often than the 60-second metric export cadence it is modeling.
	if s.hasCostProjection && at.Sub(s.lastCostProjectionAt) < costProjectionRefresh {
		return
	}

	projection, err := telemetry.ProjectCosts(
		deltaVolumeRows(current.volume, volumeRowsByAttribution(baseline.volume)),
		deltaTransportSnapshot(current.transport, baseline.transport),
		costRatesFromConfig(s.cost.Rates),
		elapsed,
		s.cost.Period,
	)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.costProjection = projection
	s.hasCostProjection = true
	s.lastCostProjectionAt = at
	s.mu.Unlock()
}

func volumeRowsByAttribution(rows []telemetry.VolumeRow) map[telemetry.Attribution]telemetry.VolumeRow {
	byAttribution := make(map[telemetry.Attribution]telemetry.VolumeRow, len(rows))
	for _, row := range rows {
		byAttribution[row.Attribution] = row
	}
	return byAttribution
}

func deltaVolumeRows(
	current []telemetry.VolumeRow,
	previous map[telemetry.Attribution]telemetry.VolumeRow,
) []telemetry.VolumeRow {
	rows := make([]telemetry.VolumeRow, 0, len(current))
	for _, row := range current {
		prev := previous[row.Attribution]
		delta := telemetry.VolumeRow{
			Attribution:   row.Attribution,
			SourceRecords: deltaU64(row.SourceRecords, prev.SourceRecords),
			MetricPoints:  deltaU64(row.MetricPoints, prev.MetricPoints),
			LogPoints:     deltaU64(row.LogPoints, prev.LogPoints),
		}
		if delta.SourceRecords != 0 || delta.MetricPoints != 0 || delta.LogPoints != 0 {
			rows = append(rows, delta)
		}
	}
	return rows
}

func deltaTransportSnapshot(
	current, previous telemetry.OTLPTransportSnapshot,
) telemetry.OTLPTransportSnapshot {
	return telemetry.OTLPTransportSnapshot{
		Metrics: telemetry.OTLPTransportSignal{
			PayloadBytes:  deltaU64(current.Metrics.PayloadBytes, previous.Metrics.PayloadBytes),
			RetryAttempts: deltaU64(current.Metrics.RetryAttempts, previous.Metrics.RetryAttempts),
		},
		Logs: telemetry.OTLPTransportSignal{
			PayloadBytes:  deltaU64(current.Logs.PayloadBytes, previous.Logs.PayloadBytes),
			RetryAttempts: deltaU64(current.Logs.RetryAttempts, previous.Logs.RetryAttempts),
		},
	}
}

func costRatesFromConfig(rates config.CostRatesConfig) telemetry.CostRates {
	return telemetry.CostRates{
		SourceRecordMicrounits:           nonNegativeCostRate(rates.SourceRecord),
		MetricPointMicrounits:            nonNegativeCostRate(rates.MetricPoint),
		LogRecordMicrounits:              nonNegativeCostRate(rates.LogRecord),
		TransmittedPayloadByteMicrounits: nonNegativeCostRate(rates.TransmittedPayloadByte),
	}
}

func nonNegativeCostRate(rate *int64) uint64 {
	if rate == nil || *rate < 0 {
		return 0
	}
	return uint64(*rate)
}

// aggregateFleet rolls every tenant's collectors into fleet-wide counts: how
// many are registered, how many failed their last run, how many have not run
// yet, and the mean duration of the runs that have completed. A registered
// collector with no run record is pending, never failing — a process still
// starting up must not read as a broken one.
func (s *sampler) aggregateFleet() (enabled, failing, pending int, meanDurMs float64) {
	var totalMs float64
	var ran int
	for _, src := range s.sources {
		if src.Registry == nil {
			continue
		}
		runs := src.Status.Snapshot()
		for _, e := range src.Registry.Entries() {
			enabled++
			r, ok := runs[e.Collector.Name()]
			if !ok || r.Runs == 0 {
				pending++
				continue
			}
			if !r.LastSuccess {
				failing++
			}
			ran++
			totalMs += float64(r.LastDuration) / float64(time.Millisecond)
		}
	}
	if ran > 0 {
		meanDurMs = totalMs / float64(ran)
	}
	return enabled, failing, pending, meanDurMs
}

// sampleHeadroom records each live throttle bucket's headroom percentage into
// its own ring, creating the ring on first sight. Buckets are lazily created by
// the limiter, so a workload that has never been used simply has no trend.
func (s *sampler) sampleHeadroom(at time.Time) {
	if s.limiter == nil {
		return
	}
	for _, h := range s.limiter.Snapshot(at) {
		key := headroomKey{tenantID: h.TenantID, workload: string(h.Workload)}
		s.mu.Lock()
		ring, ok := s.headroom[key]
		if !ok {
			ring = ringbuf.New[float64](s.capacity)
			s.headroom[key] = ring
		}
		s.mu.Unlock()
		pct := 0.0
		if h.Burst > 0 {
			pct = h.Tokens / float64(h.Burst) * 100
		}
		ring.Add(pct)
	}
}

// runtimeInfo returns the current Go runtime snapshot plus its trend series.
func (s *sampler) runtimeInfo() RuntimeInfo {
	if s == nil {
		return RuntimeInfo{}
	}
	s.mu.Lock()
	l := s.last
	s.mu.Unlock()
	return RuntimeInfo{
		Goroutines:       l.goroutines,
		GOMAXPROCS:       l.gomaxprocs,
		HeapAllocBytes:   l.heapAlloc,
		HeapAlloc:        humanBytes(l.heapAlloc),
		NumGC:            l.numGC,
		GoroutinesSeries: s.goroutines.Values(),
		HeapAllocSeries:  s.heapAlloc.Values(),
		GCRateSeries:     s.gcRate.Values(),
	}
}

// throughputInfo returns the latest emit rates and totals plus their trends.
func (s *sampler) throughputInfo() ThroughputInfo {
	if s == nil {
		return ThroughputInfo{}
	}
	s.mu.Lock()
	l := s.last
	s.mu.Unlock()
	return ThroughputInfo{
		MetricPointsPerSec: l.metricRate,
		LogRecordsPerSec:   l.logRate,
		MetricPointsTotal:  l.metricTotal,
		LogRecordsTotal:    l.logTotal,
		MetricPointsSeries: s.metricRate.Values(),
		LogRecordsSeries:   s.logRate.Values(),
	}
}

// costInfo returns operator-supplied metadata and the latest interval
// projection. It is nil while pricing is disabled. A configured budget is
// compared for display only; this method has no control-plane dependency.
func (s *sampler) costInfo() *CostStatus {
	if s == nil || s.cost == nil || !s.cost.Enabled {
		return nil
	}
	s.mu.Lock()
	projection := s.costProjection
	hasProjection := s.hasCostProjection
	s.mu.Unlock()

	rates := costRatesFromConfig(s.cost.Rates)
	status := &CostStatus{
		Currency:        s.cost.Currency,
		Version:         s.cost.Version,
		Source:          s.cost.Source,
		EffectiveAt:     s.cost.EffectiveAt,
		Period:          s.cost.Period.String(),
		IntervalScope:   costIntervalScope,
		ProjectionScope: costProjectionScope,
		Rates: CostRatesStatus{
			SourceRecordMicrounits:           rates.SourceRecordMicrounits,
			MetricPointMicrounits:            rates.MetricPointMicrounits,
			LogRecordMicrounits:              rates.LogRecordMicrounits,
			TransmittedPayloadByteMicrounits: rates.TransmittedPayloadByteMicrounits,
		},
	}
	if s.cost.BudgetMicrounits > 0 {
		status.BudgetMicrounits = uint64(s.cost.BudgetMicrounits)
	}
	if !hasProjection {
		return status
	}

	status.ObservedIntervalSeconds = projection.ObservedInterval.Seconds()
	status.IntervalMicrounits = projection.IntervalMicrounits
	status.ProjectedPeriodMicrounits = projection.ProjectedMicrounits
	status.Rows = make([]CostRowStatus, 0, len(projection.Rows))
	for _, row := range projection.Rows {
		status.Rows = append(status.Rows, CostRowStatus{
			TenantID:                    row.TenantID,
			Collector:                   row.Collector,
			IngestTransport:             row.IngestTransport,
			TrafficClass:                row.TrafficClass,
			Attribution:                 row.Attribution,
			SourceRecordCostMicrounits:  row.SourceRecordCostMicrounits,
			MetricPointCostMicrounits:   row.MetricPointCostMicrounits,
			LogRecordCostMicrounits:     row.LogRecordCostMicrounits,
			AllocatedMetricPayloadBytes: row.AllocatedMetricPayloadBytes,
			AllocatedLogPayloadBytes:    row.AllocatedLogPayloadBytes,
			AllocatedPayloadBytes:       row.AllocatedPayloadBytes,
			PayloadCostMicrounits:       row.PayloadCostMicrounits,
			IntervalMicrounits:          row.IntervalMicrounits,
			ProjectedPeriodMicrounits:   row.ProjectedMicrounits,
		})
	}
	if status.BudgetMicrounits > 0 {
		ratio := float64(status.ProjectedPeriodMicrounits) /
			float64(status.BudgetMicrounits)
		status.BudgetRatio = &ratio
		status.BudgetPercent = ratio * 100
	}
	return status
}

// fleetInfo returns the fleet-wide collector roll-up plus its trends.
func (s *sampler) fleetInfo() FleetInfo {
	if s == nil {
		return FleetInfo{}
	}
	s.mu.Lock()
	l := s.last
	s.mu.Unlock()
	return FleetInfo{
		Enabled:            l.enabled,
		Failing:            l.failing,
		Pending:            l.pending,
		MeanDurationMs:     l.meanDurMs,
		FailingSeries:      s.failing.Values(),
		MeanDurationSeries: s.meanDurMs.Values(),
	}
}

// cardinalityTrend returns the total active-series count and its trend. Both
// are zero when self-observability is off (no tracker is wired).
func (s *sampler) cardinalityTrend() CardinalityTrend {
	if s == nil {
		return CardinalityTrend{}
	}
	s.mu.Lock()
	total := s.last.seriesTotal
	s.mu.Unlock()
	return CardinalityTrend{TotalSeries: total, Series: s.seriesTotal.Values()}
}

// headroomTrend returns one throttle bucket's headroom history, or nil for a
// bucket that has never been sampled.
func (s *sampler) headroomTrend(tenantID, workload string) []float64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	ring := s.headroom[headroomKey{tenantID: tenantID, workload: workload}]
	s.mu.Unlock()
	return ring.Values()
}

// deltaU64 returns b's advance over a, clamped at 0. The totals are monotonic,
// so this only matters if one ever is not — and a negative rate on the chart
// would be a worse lie than a flat 0.
func deltaU64(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// deltaU32 is deltaU64 for MemStats.NumGC.
func deltaU32(cur, prev uint32) uint32 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// lastFloat returns the newest value in a rate ring, or 0 when it is empty.
func lastFloat(r *ringbuf.Ring[float64]) float64 {
	v := r.Values()
	if len(v) == 0 {
		return 0
	}
	return v[len(v)-1]
}

// humanBytes renders a byte count in the compact form the status cards use
// (e.g. "12M"). It matches the sibling exporters' formatting.
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatUint(b, 10) + "B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatUint(b/div, 10) + string("KMGTP"[exp])
}
