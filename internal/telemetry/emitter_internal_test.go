package telemetry

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestObservableGaugeRegisteredOncePerMetricName is the half of #236 that no
// external test can see.
//
// The obvious fix — key e.observables by (name, tenant) — would register a
// second Float64ObservableGauge for the same instrument name, one per tenant.
// That is its own bug: the SDK resolves duplicate registrations to one
// aggregator, so the callbacks stack up invisibly and every collection pays for
// all of them. The partition therefore has to live INSIDE observableGauge: one
// instrument, one callback, several point sets.
func TestObservableGaugeRegisteredOncePerMetricName(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	e := newOtelEmitter(mp.Meter("test"), nil, nil)
	const name = "intune.test.instrument"
	for _, tenant := range []string{"t1", "t2", "t3"} {
		e.gaugeSnapshotFor(tenant, name, "1", "d", []GaugePoint{
			{Value: 1, Attrs: Attrs{"tenant_id": tenant}},
		})
	}

	e.mu.Lock()
	instruments := len(e.observables)
	og := e.observables[name]
	e.mu.Unlock()
	if instruments != 1 {
		t.Fatalf("registered %d observable instruments for one metric name, want 1", instruments)
	}

	og.mu.Lock()
	partitions := len(og.points)
	og.mu.Unlock()
	if partitions != 3 {
		t.Errorf("the one instrument holds %d tenant partitions, want 3 — the split must be inside "+
			"observableGauge, not in the instrument key", partitions)
	}
}
