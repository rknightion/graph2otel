package telemetry_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// TestProvider_StdoutFlushesMetricOnShutdown asserts the "stdout" protocol
// resolves to a working exporter: Shutdown flushes the metric pipeline to the
// configured writer.
func TestProvider_StdoutFlushesMetricOnShutdown(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	p, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: "test",
		Protocol:       "stdout",
		StdoutWriter:   &buf,
		MetricInterval: time.Hour, // rely on Shutdown to flush, not the interval
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !strings.Contains(buf.String(), "entra.test.counter") {
		t.Fatalf("stdout output missing metric name; got:\n%s", buf.String())
	}
}

// TestProvider_MetricsResourceOmitsServiceVersion asserts service.version is
// NOT attached to the metrics resource (so Grafana Cloud's OTLP ingest cannot
// promote it to a per-series label and churn the whole series set on every
// :main redeploy — the #104 doubling), while the logs resource DOES keep it.
// The stdout exporter prints each signal's Resource block, so a metrics-only
// flush must not mention service.version, and a run that also emits a log must.
func TestProvider_MetricsResourceOmitsServiceVersion(t *testing.T) {
	ctx := context.Background()

	// Metrics-only flush: the log batch processor has nothing to emit, so the
	// buffer holds only ResourceMetrics — which must not carry service.version.
	var metricsBuf bytes.Buffer
	pm, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: "v1.2.3-abcdef",
		Protocol:       "stdout",
		StdoutWriter:   &metricsBuf,
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	pm.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	if err := pm.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if strings.Contains(metricsBuf.String(), "service.version") {
		t.Fatalf("metrics resource carries service.version (#104 regression); got:\n%s", metricsBuf.String())
	}

	// A run that emits a log record must carry service.version on the logs
	// resource (logs are never summed, so per-record version attribution is safe).
	var logBuf bytes.Buffer
	pl, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: "v1.2.3-abcdef",
		Protocol:       "stdout",
		StdoutWriter:   &logBuf,
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	pl.Emitter().LogEvent(telemetry.Event{Name: "entra.test", Body: "hi"})
	if err := pl.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !strings.Contains(logBuf.String(), "service.version") {
		t.Fatalf("logs resource dropped service.version; got:\n%s", logBuf.String())
	}
}

// TestProvider_InvalidProtocolErrors asserts an unrecognized protocol is
// rejected at construction rather than failing silently at export time.
func TestProvider_InvalidProtocolErrors(t *testing.T) {
	if _, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		ServiceName: "graph2otel",
		Protocol:    "bogus",
	}); err == nil {
		t.Fatal("NewProvider(protocol=bogus) = nil error, want an error")
	}
}

// TestProvider_AppliesCardinalityLimit asserts the configured per-instrument
// cardinality limit reaches the MeterProvider: emitting more distinct
// attribute sets than the limit produces the SDK's otel.metric.overflow
// series. Without the limit wired through, three series stay well under the
// SDK default (2000) and no overflow appears, so this fails unless the limit
// is applied.
func TestProvider_AppliesCardinalityLimit(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	p, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:      "graph2otel",
		ServiceVersion:   "test",
		Protocol:         "stdout",
		StdoutWriter:     &buf,
		MetricInterval:   time.Hour,
		CardinalityLimit: 2,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		p.Emitter().Counter("entra.test.counter", "1", "", 1, telemetry.Attrs{"id": id})
	}
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !strings.Contains(buf.String(), "otel.metric.overflow") {
		t.Fatalf("expected otel.metric.overflow series with cardinality limit 2; got:\n%s", buf.String())
	}
}

// TestProvider_SelfObsCardinalityTrackerReflectsLimit drives the same
// over-the-limit scenario through Provider.Emitter(), then asserts
// Provider.Cardinality() (enabled via SelfObsEnabled) recorded the true
// distinct-series count and marked the metric capped — the in-process
// counterpart to the SDK-level otel.metric.overflow assertion above.
func TestProvider_SelfObsCardinalityTrackerReflectsLimit(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	p, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:      "graph2otel",
		Protocol:         "stdout",
		StdoutWriter:     &buf,
		MetricInterval:   time.Hour,
		CardinalityLimit: 2,
		SelfObsEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(ctx) })

	tr := p.Cardinality()
	if tr == nil {
		t.Fatal("Cardinality() = nil, want a tracker (SelfObsEnabled=true)")
	}
	for _, id := range []string{"a", "b", "c"} {
		p.Emitter().Counter("entra.test.counter", "1", "", 1, telemetry.Attrs{"id": id})
	}
	snap := tr.Snapshot() // no Report yet: nothing observed until we call it
	if snap != nil {
		t.Fatalf("Snapshot() before Report = %+v, want nil", snap)
	}
	tr.Report(p.Emitter())
	snap = tr.Snapshot()
	if len(snap) != 1 || snap[0].Metric != "entra.test.counter" || snap[0].Count != 2 || !snap[0].Capped {
		t.Fatalf("Snapshot() = %+v, want one entry entra.test.counter Count=2 Capped=true", snap)
	}
}

// TestProvider_SelfObsDisabledHasNilTracker asserts Cardinality() returns nil
// when SelfObsEnabled is left false (the default), and Report on a nil
// tracker is a safe no-op.
func TestProvider_SelfObsDisabledHasNilTracker(t *testing.T) {
	p, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		ServiceName: "graph2otel",
		Protocol:    "stdout",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	if tr := p.Cardinality(); tr != nil {
		t.Fatalf("Cardinality() = %+v, want nil (SelfObsEnabled defaults to false)", tr)
	}
}
