package telemetry

import (
	"context"
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
}
