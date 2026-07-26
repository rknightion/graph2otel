package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

type capacityMetricCall struct {
	name  string
	unit  string
	desc  string
	value float64
	attrs Attrs
}

type capacityRecordingEmitter struct {
	mu       sync.Mutex
	counters []capacityMetricCall
	gauges   []capacityMetricCall
	logs     []Event
}

func (e *capacityRecordingEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counters = append(e.counters, capacityMetricCall{
		name: name, unit: unit, desc: desc, value: add, attrs: cloneCapacityAttrs(attrs),
	})
}

func (e *capacityRecordingEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gauges = append(e.gauges, capacityMetricCall{
		name: name, unit: unit, desc: desc, value: value, attrs: cloneCapacityAttrs(attrs),
	})
}

func (*capacityRecordingEmitter) GaugeSnapshot(string, string, string, []GaugePoint) {}
func (*capacityRecordingEmitter) UpDownCounter(string, string, string, float64, Attrs) {
}
func (*capacityRecordingEmitter) Histogram(string, string, string, float64, []float64, Attrs) {
}
func (*capacityRecordingEmitter) HistogramCtx(
	context.Context,
	string,
	string,
	string,
	float64,
	[]float64,
	Attrs,
) {
}

func (e *capacityRecordingEmitter) LogEvent(event Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	event.Attrs = cloneCapacityAttrs(event.Attrs)
	e.logs = append(e.logs, event)
}

func cloneCapacityAttrs(attrs Attrs) Attrs {
	if attrs == nil {
		return nil
	}
	cloned := make(Attrs, len(attrs))
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}

func (e *capacityRecordingEmitter) counterTotal(name string, wantAttrs Attrs) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var total float64
	for _, call := range e.counters {
		if call.name == name && capacityAttrsEqual(call.attrs, wantAttrs) {
			total += call.value
		}
	}
	return total
}

func (e *capacityRecordingEmitter) gaugeCall(name string, wantAttrs Attrs) (capacityMetricCall, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for index := len(e.gauges) - 1; index >= 0; index-- {
		call := e.gauges[index]
		if call.name == name && capacityAttrsEqual(call.attrs, wantAttrs) {
			return call, true
		}
	}
	return capacityMetricCall{}, false
}

func capacityAttrsEqual(got, want Attrs) bool {
	if len(got) != len(want) {
		return false
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			return false
		}
	}
	return true
}

func TestProviderCollectorEmitterCountsOnlyPostLimiterPoints(t *testing.T) {
	recorder := &capacityRecordingEmitter{}
	provider := &Provider{
		selfObsEmitter: recorder,
		limiter:        NewLimiter(Limits{PerMetric: 1}),
		volume:         &VolumeTracker{},
	}
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "intune.devices",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassSteadyState,
	}

	emitter := provider.CollectorEmitter(attribution)
	emitter.GaugeSnapshot(
		"intune.device.score",
		semconv.UnitSeconds,
		"non-additive test gauge",
		[]GaugePoint{
			{Value: 2, Attrs: Attrs{"state": "kept"}},
			{Value: 1, Attrs: Attrs{"state": "dropped"}},
		},
	)
	emitter.LogEvent(Event{
		Name:      "intune.device",
		Timestamp: time.Unix(1_700_000_000, 0),
	})

	rows := provider.Volume()
	if len(rows) != 1 {
		t.Fatalf("volume rows = %+v, want one attribution", rows)
	}
	if rows[0].MetricPoints != 1 || rows[0].LogPoints != 1 {
		t.Fatalf("post-limiter points = %+v, want one metric and one log", rows[0])
	}
	if rows[0].Attribution != attribution {
		t.Fatalf("attribution = %+v, want %+v", rows[0].Attribution, attribution)
	}
	if got := recorder.logs[0].Attrs; got[semconv.AttrTenantID] != "tenant-a" ||
		got[semconv.AttrIngestTransport] != "graph" {
		t.Fatalf("collector log attrs = %v, want tenant and transport stamps", got)
	}
}

func TestProviderReportCapacityEmitsExactDeltasAndSteadyCostOnce(t *testing.T) {
	recorder := &capacityRecordingEmitter{}
	volume := &VolumeTracker{}
	attribution := Attribution{
		TenantID:     "tenant-a",
		Collector:    "entra.signins",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassSteadyState,
	}
	counted := newVolumeEmitter(recorder, volume, attribution)
	counted.Gauge("entra.signins.count", semconv.UnitRecords, "", 1, nil)
	counted.LogEvent(Event{Name: "entra.signin", Timestamp: time.Unix(1_700_000_000, 0)})
	volume.RecordSourceRecords(attribution, 3)

	transport := newOTLPTransportTracker()
	transport.metrics.payloadBytes.Add(40)
	transport.metrics.retryAttempts.Add(2)
	transport.logs.payloadBytes.Add(60)
	transport.logs.retryAttempts.Add(1)

	now := time.Unix(1_700_000_060, 0)
	provider := &Provider{
		selfObsEmitter: recorder,
		card:           nil,
		limiter:        NewLimiter(Limits{}),
		volume:         volume,
		transport:      transport,
		capacityReport: capacityReportState{startedAt: now.Add(-time.Minute)},
		capacityNow:    func() time.Time { return now },
		cost: CostOptions{
			Enabled:      true,
			Currency:     "GBP",
			PriceVersion: "ops-2026-07",
			Period:       time.Minute,
			Rates: CostRates{
				SourceRecordMicrounits:           10,
				MetricPointMicrounits:            2,
				LogRecordMicrounits:              3,
				TransmittedPayloadByteMicrounits: 1,
			},
		},
	}

	provider.ReportSelfObs()
	now = now.Add(time.Minute)
	provider.ReportSelfObs()

	common := Attrs{
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrCollector:       "entra.signins",
		semconv.AttrIngestTransport: "graph",
		semconv.AttrTrafficClass:    "steady_state",
	}
	metricAttrs := cloneCapacityAttrs(common)
	metricAttrs["signal"] = "metric"
	logAttrs := cloneCapacityAttrs(common)
	logAttrs["signal"] = "log"
	if got := recorder.counterTotal(MetricIngestEmittedPoints, metricAttrs); got != 1 {
		t.Errorf("metric emitted points = %v, want 1", got)
	}
	if got := recorder.counterTotal(MetricIngestEmittedPoints, logAttrs); got != 1 {
		t.Errorf("log emitted points = %v, want 1", got)
	}
	for signal, want := range map[string]struct {
		bytes   float64
		retries float64
	}{
		"metrics": {bytes: 40, retries: 2},
		"logs":    {bytes: 60, retries: 1},
	} {
		attrs := Attrs{"signal": signal}
		if got := recorder.counterTotal(MetricOTLPTransmittedPayloadBytes, attrs); got != want.bytes {
			t.Errorf("%s payload bytes = %v, want %v", signal, got, want.bytes)
		}
		if got := recorder.counterTotal(MetricOTLPRetryAttempts, attrs); got != want.retries {
			t.Errorf("%s retries = %v, want %v", signal, got, want.retries)
		}
	}

	costAttrs := Attrs{
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrCollector:       "entra.signins",
		semconv.AttrIngestTransport: "graph",
		"currency":                  "GBP",
		"price_version":             "ops-2026-07",
		"attribution":               CostAttributionEstimated,
	}
	cost, ok := recorder.gaugeCall(MetricIngestCostProjected, costAttrs)
	if !ok {
		t.Fatal("projected cost gauge missing")
	}
	if cost.value != 68 {
		t.Fatalf("running projected cost = %v, want 68 microunits after two observed minutes", cost.value)
	}
	if cost.unit != "{microunit}" {
		t.Fatalf("projected cost unit = %q, want {microunit}", cost.unit)
	}
}
