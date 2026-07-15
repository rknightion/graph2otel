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
