package telemetry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestProviderProcessSelfObsScopeRegistryCoversEveryReportMetric is #284's
// provider-level drift gate.
//
// ReportSelfObs deliberately bypasses every per-tenant emitter: its
// cardinality values describe the one process-wide provider, not a tenant.
// That bypass must be an explicit scope decision, not an accident. Adding a
// new metric to the provider report therefore fails here until its process
// scope is recorded. A tenant-specific metric does not belong in this report;
// it must be emitted through a tenant-decorated path instead.
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
	p.ReportSelfObs()

	got := map[string]bool{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect provider self-observability: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if len(metric.Name) >= len(selfObsPrefix) &&
				metric.Name[:len(selfObsPrefix)] == selfObsPrefix {
				got[metric.Name] = true
			}
		}
	}
	for name := range got {
		if scope, ok := providerSelfObsScopes[name]; !ok || scope != selfObsScopeProcess {
			t.Errorf("%s is emitted by Provider.ReportSelfObs without tenant_id but has no "+
				"explicit process scope; classify it in providerSelfObsScopes or move it "+
				"behind a tenant-decorated emitter", name)
		}
	}
	for name := range providerSelfObsScopes {
		if !got[name] {
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
		if !got[name] {
			t.Errorf("Provider.ReportSelfObs did not emit delivery metric %s", name)
		}
	}
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
