package telemetry

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"sync/atomic"
)

// TrafficClass separates routine collection from exceptional traffic whose
// volume should not be projected as steady-state ingest.
type TrafficClass string

const (
	TrafficClassSteadyState       TrafficClass = "steady_state"
	TrafficClassColdStartBackfill TrafficClass = "cold_start_backfill"
	TrafficClassManualReplay      TrafficClass = "manual_replay"
)

// Attribution is the complete bounded key for logical source and emitted-point
// volume. It deliberately contains no record, metric, or entity attributes.
type Attribution struct {
	TenantID     string
	Collector    string
	Transport    Transport
	TrafficClass TrafficClass
}

// VolumeRow is one cumulative logical-volume total for an Attribution.
type VolumeRow struct {
	Attribution
	SourceRecords uint64
	MetricPoints  uint64
	LogPoints     uint64
}

// VolumeTracker accumulates logical source and emitted-point volume. Its zero
// value is ready for concurrent use.
type VolumeTracker struct {
	mu   sync.Mutex
	rows map[Attribution]*volumeCounterRow
}

type volumeCounterRow struct {
	sourceRecords atomic.Uint64
	metricPoints  atomic.Uint64
	logPoints     atomic.Uint64
}

// RecordSourceRecords adds exact fetched source records independently of
// emitted-point counting.
func (t *VolumeTracker) RecordSourceRecords(attribution Attribution, n uint64) {
	if n == 0 {
		return
	}
	t.counterRow(attribution).sourceRecords.Add(n)
}

func (t *VolumeTracker) counterRow(attribution Attribution) *volumeCounterRow {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rows == nil {
		t.rows = make(map[Attribution]*volumeCounterRow)
	}
	row := t.rows[attribution]
	if row == nil {
		row = &volumeCounterRow{}
		t.rows[attribution] = row
	}
	return row
}

// Snapshot returns an immutable copy of the cumulative rows sorted by tenant,
// collector, transport, then traffic class. Reading does not reset totals.
func (t *VolumeTracker) Snapshot() []VolumeRow {
	t.mu.Lock()
	counters := make([]attributedVolumeCounters, 0, len(t.rows))
	for attribution, row := range t.rows {
		counters = append(counters, attributedVolumeCounters{
			attribution: attribution,
			row:         row,
		})
	}
	t.mu.Unlock()

	rows := make([]VolumeRow, 0, len(counters))
	for _, counter := range counters {
		row := VolumeRow{
			Attribution:   counter.attribution,
			SourceRecords: counter.row.sourceRecords.Load(),
			MetricPoints:  counter.row.metricPoints.Load(),
			LogPoints:     counter.row.logPoints.Load(),
		}
		if row.SourceRecords != 0 || row.MetricPoints != 0 || row.LogPoints != 0 {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, compareVolumeRows)
	return rows
}

type attributedVolumeCounters struct {
	attribution Attribution
	row         *volumeCounterRow
}

func compareVolumeRows(a, b VolumeRow) int {
	if n := cmp.Compare(a.TenantID, b.TenantID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Collector, b.Collector); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Transport, b.Transport); n != 0 {
		return n
	}
	return cmp.Compare(a.TrafficClass, b.TrafficClass)
}

type volumeEmitter struct {
	Emitter
	row *volumeCounterRow
}

func newVolumeEmitter(
	delegate Emitter,
	tracker *VolumeTracker,
	attribution Attribution,
) Emitter {
	return &volumeEmitter{
		Emitter: delegate,
		row:     tracker.counterRow(attribution),
	}
}

func (e *volumeEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	e.Emitter.Counter(name, unit, desc, add, attrs)
	e.row.metricPoints.Add(1)
}

func (e *volumeEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	e.Emitter.Gauge(name, unit, desc, value, attrs)
	e.row.metricPoints.Add(1)
}

func (e *volumeEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	e.Emitter.GaugeSnapshot(name, unit, desc, points)
	e.row.metricPoints.Add(uint64(len(points)))
}

func (e *volumeEmitter) gaugeSnapshotFor(
	tenant, name, unit, desc string,
	points []GaugePoint,
) {
	snapshotFor(e.Emitter, tenant, name, unit, desc, points)
	e.row.metricPoints.Add(uint64(len(points)))
}

func (e *volumeEmitter) UpDownCounter(
	name, unit, desc string,
	value float64,
	attrs Attrs,
) {
	e.Emitter.UpDownCounter(name, unit, desc, value, attrs)
	e.row.metricPoints.Add(1)
}

func (e *volumeEmitter) Histogram(
	name, unit, desc string,
	value float64,
	bounds []float64,
	attrs Attrs,
) {
	e.Emitter.Histogram(name, unit, desc, value, bounds, attrs)
	e.row.metricPoints.Add(1)
}

func (e *volumeEmitter) HistogramCtx(
	ctx context.Context,
	name, unit, desc string,
	value float64,
	bounds []float64,
	attrs Attrs,
) {
	e.Emitter.HistogramCtx(ctx, name, unit, desc, value, bounds, attrs)
	e.row.metricPoints.Add(1)
}

func (e *volumeEmitter) LogEvent(ev Event) {
	e.Emitter.LogEvent(ev)
	e.row.logPoints.Add(1)
}
