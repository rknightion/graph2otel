package telemetry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestProviderProcessSelfObsScopeRegistryCoversEveryReportMetric is #284's
// provider-level drift gate, extended by #289 for bounded tenant attribution.
//
// ReportSelfObs deliberately bypasses every per-tenant emitter. That bypass
// must be an explicit scope decision, not an accident: process values omit
// tenant_id, while bounded collector-capacity rows add it themselves.
func TestProviderProcessSelfObsScopeRegistryCoversEveryReportMetric(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	emitter := newOtelEmitter(mp.Meter("scope-gate"), nil, nil)
	card := NewCardinalityTrackerForLimit(1)
	limiter := NewLimiter(Limits{PerMetric: 1, Global: 10})
	delivery := newDeliveryTracker()
	delivery.recordMetricExport(errors.New("Authorization: Bearer must-not-escape"))
	delivery.recordMetricFailure(DeliveryFailureForceFlushFailed)
	delivery.recordMetricFailure(DeliveryFailureShutdownFailed)
	delivery.recordLogExport(nil)

	// Seed both report halves. Three distinct synchronous series force the
	// limiter's folded path, so series.clipped cannot disappear from coverage.
	limited := limiter.Wrap(emitter)
	for _, path := range []string{"a", "b", "c"} {
		limited.Counter("entra.test.counter", "{request}", "", 1, Attrs{"path": path})
	}
	card.Observe("entra.test.counter", Attrs{
		semconv.AttrTenantID: "tenant-a",
		"path":               "a",
	})

	p := &Provider{
		selfObsEmitter: emitter,
		card:           card,
		limiter:        limiter,
		delivery:       delivery,
	}
	seedCapacityReportForTest(p)
	p.ReportSelfObs()

	got := map[string][]attribute.Set{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect provider self-observability: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if len(metric.Name) >= len(selfObsPrefix) &&
				metric.Name[:len(selfObsPrefix)] == selfObsPrefix {
				switch data := metric.Data.(type) {
				case metricdata.Sum[float64]:
					for _, point := range data.DataPoints {
						got[metric.Name] = append(got[metric.Name], point.Attributes)
					}
				case metricdata.Gauge[float64]:
					for _, point := range data.DataPoints {
						got[metric.Name] = append(got[metric.Name], point.Attributes)
					}
				}
			}
		}
	}
	for name, points := range got {
		scope, ok := providerSelfObsScopes[name]
		if !ok {
			t.Errorf("%s is emitted by Provider.ReportSelfObs without an explicit scope", name)
			continue
		}
		for _, attrs := range points {
			_, hasTenant := attrs.Value(attribute.Key(semconv.AttrTenantID))
			switch scope {
			case selfObsScopeProcess:
				if hasTenant {
					t.Errorf("%s is process-scoped but carries tenant_id: %v", name, attrs)
				}
			case selfObsScopeTenantAttribution:
				if !hasTenant {
					t.Errorf("%s is tenant-attributed but omits tenant_id: %v", name, attrs)
				}
			default:
				t.Errorf("%s has unknown provider self-observation scope %d", name, scope)
			}
		}
	}
	for name := range providerSelfObsScopes {
		if len(got[name]) == 0 {
			t.Errorf("providerSelfObsScopes contains stale metric %s that ReportSelfObs did not emit", name)
		}
	}

	for _, name := range []string{
		"graph2otel.otlp.delivery.export_attempts",
		"graph2otel.otlp.delivery.export_successes",
		"graph2otel.otlp.delivery.export_failures",
		"graph2otel.otlp.delivery.force_flush_failures",
		"graph2otel.otlp.delivery.shutdown_failures",
		"graph2otel.otlp.delivery.degraded",
	} {
		if len(got[name]) == 0 {
			t.Errorf("Provider.ReportSelfObs did not emit delivery metric %s", name)
		}
	}
}

func seedCapacityReportForTest(p *Provider) {
	now := time.Unix(1_700_000_060, 0)
	attribution := Attribution{
		TenantID:     "tenant-capacity",
		Collector:    "entra.capacity",
		Transport:    TransportGraph,
		TrafficClass: TrafficClassSteadyState,
	}
	p.volume = &VolumeTracker{}
	p.volume.RecordSourceRecords(attribution, 1)
	row := p.volume.counterRow(attribution)
	row.metricPoints.Store(1)
	row.logPoints.Store(1)
	p.transport = newOTLPTransportTracker()
	p.transport.metrics.payloadBytes.Store(10)
	p.transport.metrics.retryAttempts.Store(1)
	p.transport.logs.payloadBytes.Store(20)
	p.transport.logs.retryAttempts.Store(1)
	p.cost = CostOptions{
		Enabled:      true,
		Currency:     "GBP",
		PriceVersion: "test",
		Period:       time.Minute,
		Rates: CostRates{
			SourceRecordMicrounits:           1,
			MetricPointMicrounits:            1,
			LogRecordMicrounits:              1,
			TransmittedPayloadByteMicrounits: 1,
		},
	}
	p.capacityReport.startedAt = now.Add(-time.Minute)
	p.capacityNow = func() time.Time { return now }
}

func TestProviderReportDeliverySelfObsIsBoundedAndDoesNotDoubleCount(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	emitter := newOtelEmitter(mp.Meter("delivery-selfobs"), nil, nil)
	delivery := newDeliveryTracker()
	delivery.recordMetricExport(errors.New("Authorization: Bearer must-not-escape"))
	delivery.recordMetricFailure(DeliveryFailureForceFlushFailed)
	delivery.recordMetricFailure(DeliveryFailureShutdownFailed)
	delivery.recordLogExport(nil)

	p := &Provider{
		selfObsEmitter: emitter,
		card:           NewCardinalityTrackerForLimit(1),
		limiter:        NewLimiter(Limits{}),
		delivery:       delivery,
	}
	p.ReportSelfObs()
	p.ReportSelfObs()

	type key struct {
		name   string
		signal string
	}
	want := map[key]float64{
		{"graph2otel.otlp.delivery.export_attempts", "metrics"}:      1,
		{"graph2otel.otlp.delivery.export_attempts", "logs"}:         1,
		{"graph2otel.otlp.delivery.export_successes", "metrics"}:     0,
		{"graph2otel.otlp.delivery.export_successes", "logs"}:        1,
		{"graph2otel.otlp.delivery.export_failures", "metrics"}:      1,
		{"graph2otel.otlp.delivery.export_failures", "logs"}:         0,
		{"graph2otel.otlp.delivery.force_flush_failures", "metrics"}: 1,
		{"graph2otel.otlp.delivery.force_flush_failures", "logs"}:    0,
		{"graph2otel.otlp.delivery.shutdown_failures", "metrics"}:    1,
		{"graph2otel.otlp.delivery.shutdown_failures", "logs"}:       0,
		{"graph2otel.otlp.delivery.degraded", "metrics"}:             1,
		{"graph2otel.otlp.delivery.degraded", "logs"}:                0,
	}
	got := map[key]float64{}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect provider delivery self-observability: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if !strings.HasPrefix(metric.Name, "graph2otel.otlp.delivery.") {
				continue
			}
			switch data := metric.Data.(type) {
			case metricdata.Sum[float64]:
				if metric.Unit != "{operation}" || !data.IsMonotonic {
					t.Errorf("%s unit/monotonic = %q/%v, want {operation}/true",
						metric.Name, metric.Unit, data.IsMonotonic)
				}
				for _, point := range data.DataPoints {
					attrs := point.Attributes.ToSlice()
					if len(attrs) != 1 || string(attrs[0].Key) != "signal" {
						t.Errorf("%s attributes = %v, want only signal", metric.Name, attrs)
						continue
					}
					got[key{metric.Name, attrs[0].Value.AsString()}] = point.Value
				}
			case metricdata.Gauge[float64]:
				if metric.Unit != "1" {
					t.Errorf("%s unit = %q, want 1", metric.Name, metric.Unit)
				}
				for _, point := range data.DataPoints {
					attrs := point.Attributes.ToSlice()
					if len(attrs) != 1 || string(attrs[0].Key) != "signal" {
						t.Errorf("%s attributes = %v, want only signal", metric.Name, attrs)
						continue
					}
					got[key{metric.Name, attrs[0].Value.AsString()}] = point.Value
				}
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("delivery metric rows = %d, want %d: got=%v", len(got), len(want), got)
	}
	for k, wantValue := range want {
		if gotValue, ok := got[k]; !ok || gotValue != wantValue {
			t.Errorf("%s{%s} = %v present=%v, want %v", k.name, k.signal, gotValue, ok, wantValue)
		}
	}
}
