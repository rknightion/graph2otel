package telemetry

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type volumeMetricCall struct {
	ctx    context.Context
	name   string
	unit   string
	desc   string
	value  float64
	bounds []float64
	attrs  Attrs
}

type volumeRecordingEmitter struct {
	counter        volumeMetricCall
	gauge          volumeMetricCall
	upDownCounter  volumeMetricCall
	histogram      volumeMetricCall
	histogramCtx   volumeMetricCall
	snapshotName   string
	snapshotUnit   string
	snapshotDesc   string
	snapshotPoints []GaugePoint
	snapshotTenant string
	logEvent       Event
}

func (e *volumeRecordingEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	e.counter = volumeMetricCall{name: name, unit: unit, desc: desc, value: add, attrs: attrs}
}

func (e *volumeRecordingEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	e.gauge = volumeMetricCall{name: name, unit: unit, desc: desc, value: value, attrs: attrs}
}

func (e *volumeRecordingEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	e.snapshotName = name
	e.snapshotUnit = unit
	e.snapshotDesc = desc
	e.snapshotPoints = points
}

func (e *volumeRecordingEmitter) gaugeSnapshotFor(
	tenant, name, unit, desc string,
	points []GaugePoint,
) {
	e.snapshotTenant = tenant
	e.GaugeSnapshot(name, unit, desc, points)
}

func (e *volumeRecordingEmitter) UpDownCounter(
	name, unit, desc string,
	value float64,
	attrs Attrs,
) {
	e.upDownCounter = volumeMetricCall{
		name: name, unit: unit, desc: desc, value: value, attrs: attrs,
	}
}

func (e *volumeRecordingEmitter) Histogram(
	name, unit, desc string,
	value float64,
	bounds []float64,
	attrs Attrs,
) {
	e.histogram = volumeMetricCall{
		name: name, unit: unit, desc: desc, value: value, bounds: bounds, attrs: attrs,
	}
}

func (e *volumeRecordingEmitter) HistogramCtx(
	ctx context.Context,
	name, unit, desc string,
	value float64,
	bounds []float64,
	attrs Attrs,
) {
	e.histogramCtx = volumeMetricCall{
		ctx: ctx, name: name, unit: unit, desc: desc, value: value, bounds: bounds, attrs: attrs,
	}
}

func (e *volumeRecordingEmitter) LogEvent(ev Event) {
	e.logEvent = ev
}

func TestVolumeEmitterForwardsEveryMethodAndCountsFinalPoints(t *testing.T) {
	tracker := &VolumeTracker{}
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "entra.signins.interactive",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassSteadyState,
	}
	delegate := &volumeRecordingEmitter{}
	emitter := newVolumeEmitter(delegate, tracker, attribution)
	attrs := Attrs{"raw_entity_id": "secret-entity"}
	points := []GaugePoint{
		{Value: 10, Attrs: attrs},
		{Value: 20, Attrs: Attrs{"raw_user": "secret-user"}},
	}
	bounds := []float64{1, 2, 3}
	ctx := context.WithValue(context.Background(), volumeContextKey{}, "trace")
	event := Event{
		Name:      "secret-event-name",
		Body:      "secret-event-body",
		Severity:  SeverityWarn,
		Timestamp: time.Unix(1700000000, 0),
		Attrs:     attrs,
	}

	emitter.Counter("secret.counter", "1", "counter description", 1, attrs)
	emitter.Gauge("secret.gauge", "1", "gauge description", 2, attrs)
	emitter.UpDownCounter("secret.updown", "1", "updown description", -3, attrs)
	emitter.Histogram("secret.histogram", "s", "histogram description", 4, bounds, attrs)
	emitter.HistogramCtx(ctx, "secret.histogram_ctx", "s", "ctx description", 5, bounds, attrs)
	emitter.GaugeSnapshot("secret.snapshot", "1", "snapshot description", points)
	emitter.LogEvent(event)

	if got, want := delegate.counter, (volumeMetricCall{
		name: "secret.counter", unit: "1", desc: "counter description", value: 1, attrs: attrs,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("Counter forwarded %+v, want %+v", got, want)
	}
	if got, want := delegate.gauge, (volumeMetricCall{
		name: "secret.gauge", unit: "1", desc: "gauge description", value: 2, attrs: attrs,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("Gauge forwarded %+v, want %+v", got, want)
	}
	if got, want := delegate.upDownCounter, (volumeMetricCall{
		name: "secret.updown", unit: "1", desc: "updown description", value: -3, attrs: attrs,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("UpDownCounter forwarded %+v, want %+v", got, want)
	}
	if got, want := delegate.histogram, (volumeMetricCall{
		name: "secret.histogram", unit: "s", desc: "histogram description",
		value: 4, bounds: bounds, attrs: attrs,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("Histogram forwarded %+v, want %+v", got, want)
	}
	if got, want := delegate.histogramCtx, (volumeMetricCall{
		ctx: ctx, name: "secret.histogram_ctx", unit: "s", desc: "ctx description",
		value: 5, bounds: bounds, attrs: attrs,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("HistogramCtx forwarded %+v, want %+v", got, want)
	}
	if delegate.snapshotName != "secret.snapshot" ||
		delegate.snapshotUnit != "1" ||
		delegate.snapshotDesc != "snapshot description" ||
		!reflect.DeepEqual(delegate.snapshotPoints, points) {
		t.Errorf("GaugeSnapshot was not forwarded unchanged: %+v", delegate)
	}
	if !reflect.DeepEqual(delegate.logEvent, event) {
		t.Errorf("LogEvent forwarded %+v, want %+v", delegate.logEvent, event)
	}

	got := tracker.Snapshot()
	want := []VolumeRow{{
		Attribution:  attribution,
		MetricPoints: 7,
		LogPoints:    1,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}
	for _, raw := range []string{
		"secret.counter", "secret.snapshot", "raw_entity_id",
		"secret-entity", "secret-event-name", "secret-event-body",
	} {
		if strings.Contains(fmt.Sprintf("%#v", got), raw) {
			t.Errorf("volume snapshot retained raw data label %q: %#v", raw, got)
		}
	}

	emitter.GaugeSnapshot("empty.snapshot", "1", "empty", nil)
	if afterEmpty := tracker.Snapshot(); !reflect.DeepEqual(afterEmpty, want) {
		t.Errorf("empty GaugeSnapshot changed volume: got %+v, want %+v", afterEmpty, want)
	}
}

type volumeContextKey struct{}

func TestVolumeEmitterPreservesTenantScopedGaugeSnapshot(t *testing.T) {
	tracker := &VolumeTracker{}
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "intune.devices",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassColdStartBackfill,
	}
	delegate := &volumeRecordingEmitter{}
	emitter := newVolumeEmitter(delegate, tracker, attribution)
	scoped, ok := emitter.(tenantSnapshotter)
	if !ok {
		t.Fatalf("newVolumeEmitter() = %T, want tenantSnapshotter", emitter)
	}
	points := []GaugePoint{{Value: 1}, {Value: 2}, {Value: 3}}

	scoped.gaugeSnapshotFor("snapshot-tenant", "metric", "1", "desc", points)

	if delegate.snapshotTenant != "snapshot-tenant" {
		t.Errorf("tenant scope = %q, want snapshot-tenant", delegate.snapshotTenant)
	}
	if !reflect.DeepEqual(delegate.snapshotPoints, points) {
		t.Errorf("points = %+v, want %+v", delegate.snapshotPoints, points)
	}
	if got := tracker.Snapshot(); !reflect.DeepEqual(got, []VolumeRow{{
		Attribution:  attribution,
		MetricPoints: 3,
	}}) {
		t.Errorf("Snapshot() = %+v, want 3 metric points", got)
	}
}

func TestVolumeEmitterPreservesEventLagEmission(t *testing.T) {
	tracker := &VolumeTracker{}
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "entra.signins.interactive",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassSteadyState,
	}
	delegate := &volumeRecordingEmitter{}
	counted := newVolumeEmitter(delegate, tracker, attribution)
	now := time.Unix(1700000010, 0)
	emitter := WithEventLag(
		counted,
		attribution.Collector,
		attribution.TenantID,
		attribution.Transport,
		func() time.Time { return now },
	)
	event := Event{
		Name:      "entra.signin",
		Timestamp: now.Add(-5 * time.Second),
	}

	emitter.LogEvent(event)

	if delegate.histogram.name != metricEventLag || delegate.histogram.value != 5 {
		t.Errorf("event lag histogram = %+v, want %s value 5", delegate.histogram, metricEventLag)
	}
	if !reflect.DeepEqual(delegate.logEvent, event) {
		t.Errorf("event = %+v, want %+v", delegate.logEvent, event)
	}
	if got := tracker.Snapshot(); !reflect.DeepEqual(got, []VolumeRow{{
		Attribution:  attribution,
		MetricPoints: 1,
		LogPoints:    1,
	}}) {
		t.Errorf("Snapshot() = %+v, want event-lag metric plus log", got)
	}
}

func TestVolumeTrackerAccumulatesSourceRecordsAndReturnsSortedImmutableSnapshots(t *testing.T) {
	var tracker VolumeTracker
	rows := []Attribution{
		{
			TenantID:     "tenant-b",
			Collector:    "collector-a",
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		{
			TenantID:     "tenant-a",
			Collector:    "collector-z",
			Transport:    TransportBlob,
			TrafficClass: TrafficClassColdStartBackfill,
		},
		{
			TenantID:     "tenant-a",
			Collector:    "collector-a",
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		{
			TenantID:     "tenant-a",
			Collector:    "collector-a",
			Transport:    TransportBlob,
			TrafficClass: TrafficClassManualReplay,
		},
	}
	for i := len(rows) - 1; i >= 0; i-- {
		tracker.RecordSourceRecords(rows[i], uint64(i+1))
	}
	tracker.RecordSourceRecords(rows[2], 10)
	tracker.RecordSourceRecords(rows[0], 0)

	first := tracker.Snapshot()
	want := []VolumeRow{
		{
			Attribution:   rows[3],
			SourceRecords: 4,
		},
		{
			Attribution:   rows[2],
			SourceRecords: 13,
		},
		{
			Attribution:   rows[1],
			SourceRecords: 2,
		},
		{
			Attribution:   rows[0],
			SourceRecords: 1,
		},
	}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Snapshot() = %+v, want sorted %+v", first, want)
	}

	first[0].TenantID = "mutated"
	first[0].SourceRecords = 999
	if second := tracker.Snapshot(); !reflect.DeepEqual(second, want) {
		t.Errorf("mutating returned snapshot changed tracker: got %+v, want %+v", second, want)
	}
}

type volumeDiscardEmitter struct{}

func (volumeDiscardEmitter) Counter(string, string, string, float64, Attrs) {}
func (volumeDiscardEmitter) Gauge(string, string, string, float64, Attrs)   {}
func (volumeDiscardEmitter) GaugeSnapshot(string, string, string, []GaugePoint) {
}
func (volumeDiscardEmitter) UpDownCounter(string, string, string, float64, Attrs) {}
func (volumeDiscardEmitter) Histogram(string, string, string, float64, []float64, Attrs) {
}
func (volumeDiscardEmitter) HistogramCtx(
	context.Context,
	string, string, string,
	float64,
	[]float64,
	Attrs,
) {
}
func (volumeDiscardEmitter) LogEvent(Event) {}

func TestVolumeTrackerIsConcurrencySafe(t *testing.T) {
	const (
		workers    = 32
		iterations = 200
	)
	var tracker VolumeTracker
	attributions := []Attribution{
		{
			TenantID:     "tenant-a",
			Collector:    "collector-a",
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		{
			TenantID:     "tenant-b",
			Collector:    "collector-b",
			Transport:    TransportBlob,
			TrafficClass: TrafficClassManualReplay,
		},
	}
	emitters := []Emitter{
		newVolumeEmitter(volumeDiscardEmitter{}, &tracker, attributions[0]),
		newVolumeEmitter(volumeDiscardEmitter{}, &tracker, attributions[1]),
	}

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		index := worker % len(attributions)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				tracker.RecordSourceRecords(attributions[index], 2)
				emitters[index].Counter("metric", "1", "desc", 1, nil)
				emitters[index].LogEvent(Event{Name: "event"})
				_ = tracker.Snapshot()
			}
		}()
	}
	wg.Wait()

	const workersPerAttribution = workers / 2
	wantPerRow := VolumeRow{
		SourceRecords: uint64(workersPerAttribution * iterations * 2),
		MetricPoints:  uint64(workersPerAttribution * iterations),
		LogPoints:     uint64(workersPerAttribution * iterations),
	}
	got := tracker.Snapshot()
	if len(got) != len(attributions) {
		t.Fatalf("len(Snapshot()) = %d, want %d: %+v", len(got), len(attributions), got)
	}
	for i := range got {
		wantPerRow.Attribution = attributions[i]
		if got[i] != wantPerRow {
			t.Errorf("row[%d] = %+v, want %+v", i, got[i], wantPerRow)
		}
	}
}

func TestVolumeEmitterExistingAttributionDoesNotTakeMapLock(t *testing.T) {
	var tracker VolumeTracker
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "defender.device_process",
		Transport:    TransportBlob,
		TrafficClass: TrafficClassSteadyState,
	}
	emitter := newVolumeEmitter(volumeDiscardEmitter{}, &tracker, attribution)
	emitter.Counter("warmup", "1", "desc", 1, nil)

	tracker.mu.Lock()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		emitter.Counter("hot.metric", "1", "desc", 1, nil)
		emitter.LogEvent(Event{Name: "hot.log"})
		close(done)
	}()
	<-started

	select {
	case <-done:
		tracker.mu.Unlock()
	case <-time.After(time.Second):
		tracker.mu.Unlock()
		<-done
		t.Fatal("existing attribution update blocked on the global map lock")
	}

	if got := tracker.Snapshot(); !reflect.DeepEqual(got, []VolumeRow{{
		Attribution:  attribution,
		MetricPoints: 2,
		LogPoints:    1,
	}}) {
		t.Errorf("Snapshot() = %+v, want warmup plus lock-independent updates", got)
	}
}
