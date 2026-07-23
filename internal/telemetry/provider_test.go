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

// TestProvider_ClipsToANamedBucketNotTheSDKOverflow asserts the whole #235
// substitution end-to-end through the real provider: the configured limit is
// enforced by graph2otel's limiter, and the SDK's own cap is gone.
//
// Both halves matter. If Options.Limits were not wired through, four series
// would sail past unclipped. If the SDK's cap were left in place underneath, it
// would keep truncating at its own default into otel.metric.overflow — a series
// that names nothing, chosen by arrival order, at a threshold nothing in the
// config mentions.
func TestProvider_ClipsToANamedBucketNotTheSDKOverflow(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	p, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		ServiceVersion: "test",
		Protocol:       "stdout",
		StdoutWriter:   &buf,
		MetricInterval: time.Hour,
		Limits:         telemetry.Limits{PerMetric: 2},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	for _, id := range []string{"a", "b", "c", "d"} {
		p.Emitter().Counter("entra.test.counter", "{request}", "", 1, telemetry.Attrs{"path": id})
	}
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "otel.metric.overflow") {
		t.Errorf("the SDK's otel.metric.overflow appeared — its cap must be disabled in "+
			"favor of the limiter, or it silently truncates underneath at its own "+
			"threshold:\n%s", out)
	}
	if !strings.Contains(out, `"Value":"other"`) {
		t.Errorf("no `other` bucket in the export — the tail of an additive counter must fold "+
			"into a named series a reader can interpret:\n%s", out)
	}
}

// TestProvider_SelfObsTracksTheSeriesThatSurviveTheLimiter is the in-process
// counterpart to the export assertion above.
//
// The tracker sits INSIDE the limiter — it counts what actually reaches the SDK,
// not what collectors offered — so an over-limit metric shows the clipped count,
// which is the number that costs money. What was clipped is reported separately
// by graph2otel.series.clipped; conflating the two would make the tracker's
// number describe neither the bill nor the loss.
func TestProvider_SelfObsTracksTheSeriesThatSurviveTheLimiter(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	p, err := telemetry.NewProvider(ctx, telemetry.Options{
		ServiceName:    "graph2otel",
		Protocol:       "stdout",
		StdoutWriter:   &buf,
		MetricInterval: time.Hour,
		Limits:         telemetry.Limits{PerMetric: 2},
		SelfObsEnabled: true,
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
		p.Emitter().Counter("entra.test.counter", "{request}", "", 1, telemetry.Attrs{"path": id})
	}
	snap := tr.Snapshot() // no Report yet: nothing observed until we call it
	if snap != nil {
		t.Fatalf("Snapshot() before Report = %+v, want nil", snap)
	}
	tr.Report(p.Emitter())
	snap = tr.Snapshot()
	// Two admitted plus the `other` bucket the third folded into.
	if len(snap) != 1 || snap[0].Metric != "entra.test.counter" || snap[0].Count != 3 {
		t.Fatalf("Snapshot() = %+v, want one entry entra.test.counter Count=3 "+
			"(two admitted plus the `other` bucket)", snap)
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
