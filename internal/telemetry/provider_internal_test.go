package telemetry

import (
	"context"
	"encoding/base64"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

// TestOTLPHTTPURL pins the OTLP/HTTP per-signal URL construction. The OTEL Go
// otlphttp exporter's WithEndpointURL uses the URL path AS-IS (it does not
// append /v1/<signal>), so a Grafana Cloud base endpoint like ".../otlp" must
// have the signal path appended or the gateway returns 404.
func TestOTLPHTTPURL(t *testing.T) {
	cases := []struct {
		base, signal, want string
	}{
		{"https://otlp-gateway-prod-us-central-0.grafana.net/otlp", "metrics", "https://otlp-gateway-prod-us-central-0.grafana.net/otlp/v1/metrics"},
		{"https://otlp-gateway-prod-us-central-0.grafana.net/otlp/", "logs", "https://otlp-gateway-prod-us-central-0.grafana.net/otlp/v1/logs"},
		{"https://x/otlp/v1/metrics", "metrics", "https://x/otlp/v1/metrics"}, // already signal-specific: no double-append
		{"http://collector:4318", "metrics", "http://collector:4318/v1/metrics"},
	}
	for _, c := range cases {
		if got := otlpHTTPURL(c.base, c.signal); got != c.want {
			t.Errorf("otlpHTTPURL(%q, %q) = %q, want %q", c.base, c.signal, got, c.want)
		}
	}
}

// TestNewMetricExporterResolvesEachProtocol asserts every supported
// Options.Protocol value builds a metric exporter without error. Exporter
// construction is lazy (no dial/connect happens here), so this stays a pure,
// fast, network-free construction check — the exporters are never used to
// export in this test.
func TestNewMetricExporterResolvesEachProtocol(t *testing.T) {
	for _, proto := range []string{"", "http", "grpc", "stdout"} {
		exp, err := newMetricExporter(context.Background(), Options{
			Protocol: proto,
			Endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp",
		})
		if err != nil {
			t.Fatalf("newMetricExporter(protocol=%q): %v", proto, err)
		}
		if exp == nil {
			t.Fatalf("newMetricExporter(protocol=%q) returned a nil exporter", proto)
		}
	}
}

// TestNewLogExporterResolvesEachProtocol is the log-exporter mirror of
// TestNewMetricExporterResolvesEachProtocol.
func TestNewLogExporterResolvesEachProtocol(t *testing.T) {
	for _, proto := range []string{"", "http", "grpc", "stdout"} {
		exp, err := newLogExporter(context.Background(), Options{
			Protocol: proto,
			Endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp",
		})
		if err != nil {
			t.Fatalf("newLogExporter(protocol=%q): %v", proto, err)
		}
		if exp == nil {
			t.Fatalf("newLogExporter(protocol=%q) returned a nil exporter", proto)
		}
	}
}

// TestNewExportersRejectUnknownProtocol asserts an unrecognized protocol is
// rejected at construction for both signal exporters.
func TestNewExportersRejectUnknownProtocol(t *testing.T) {
	if _, err := newMetricExporter(context.Background(), Options{Protocol: "bogus"}); err == nil {
		t.Error("newMetricExporter(protocol=bogus) = nil error, want an error")
	}
	if _, err := newLogExporter(context.Background(), Options{Protocol: "bogus"}); err == nil {
		t.Error("newLogExporter(protocol=bogus) = nil error, want an error")
	}
}

// TestGrafanaCloudAuthHeader pins the Basic-auth header format Grafana
// Cloud's OTLP gateway expects, and that it is omitted entirely when either
// half of the credential is missing (a self-managed collector).
func TestGrafanaCloudAuthHeader(t *testing.T) {
	got := grafanaCloudAuthHeader("123456", "glc_token")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("123456:glc_token"))
	if got != want {
		t.Errorf("grafanaCloudAuthHeader = %q, want %q", got, want)
	}
	if got := grafanaCloudAuthHeader("", "glc_token"); got != "" {
		t.Errorf("grafanaCloudAuthHeader with empty instanceID = %q, want \"\"", got)
	}
	if got := grafanaCloudAuthHeader("123456", ""); got != "" {
		t.Errorf("grafanaCloudAuthHeader with empty token = %q, want \"\"", got)
	}
}

func TestGrafanaCloudHeaders(t *testing.T) {
	h := grafanaCloudHeaders(Options{InstanceID: "123456", Token: "glc_token"})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("123456:glc_token"))
	if h["Authorization"] != want {
		t.Errorf("headers = %+v, missing expected Authorization", h)
	}
	if got := grafanaCloudHeaders(Options{}); got != nil {
		t.Errorf("grafanaCloudHeaders with no credentials = %+v, want nil", got)
	}
}

// TestCumulativeTemporalitySelectorAlwaysCumulative pins the OTLP metric
// temporality. Grafana Cloud / Mimir OTLP ingestion accepts CUMULATIVE only
// (delta is rejected with HTTP 400 and there is no server-side delta->cumulative
// conversion), so the selector must return cumulative for EVERY instrument kind.
func TestCumulativeTemporalitySelectorAlwaysCumulative(t *testing.T) {
	kinds := []sdkmetric.InstrumentKind{
		sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindGauge,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter,
		sdkmetric.InstrumentKindObservableGauge,
	}
	for _, k := range kinds {
		if got := cumulativeTemporalitySelector(k); got != metricdata.CumulativeTemporality {
			t.Errorf("cumulativeTemporalitySelector(%v) = %v, want CumulativeTemporality", k, got)
		}
	}
}

// TestMeterProviderEnablesHistogramExemplars asserts a Float64Histogram
// recorded under a SAMPLED span context attaches exactly one exemplar:
// histograms keep the SDK's default reservoir so HistogramCtx-recorded
// signals (e.g. under a real Kiota transport span) link to sampled traces.
func TestMeterProviderEnablesHistogramExemplars(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(append(
		metricProviderOptions(resource.Empty(), 10000),
		sdkmetric.WithReader(reader),
	)...)
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	hist, err := mp.Meter("test").Float64Histogram(
		"t.exemplar.histogram",
		metric.WithExplicitBucketBoundaries(0, 5, 10, 25, 50, 100),
	)
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x01},
		SpanID:     trace.SpanID{0x01},
		TraceFlags: trace.FlagsSampled,
	}))
	hist.Record(ctx, 42.0, metric.WithAttributes(attribute.String("k", "v")))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	exemplars := 0
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if h, ok := m.Data.(metricdata.Histogram[float64]); ok {
				for _, dp := range h.DataPoints {
					exemplars += len(dp.Exemplars)
				}
			}
		}
	}
	if exemplars != 1 {
		t.Errorf("got %d exemplar(s) on histogram; want 1", exemplars)
	}
}

// TestMeterProviderDropsExemplarsForSyncInstruments asserts that synchronous
// Counter, UpDownCounter, and Gauge instruments produce ZERO exemplars even
// under a SAMPLED span context. These are always recorded with
// context.Background() by the Emitter, so their per-series reservoirs can
// never capture an exemplar — the no-op reservoir eliminates that dead-weight
// heap allocation. Aggregation must stay unaffected.
func TestMeterProviderDropsExemplarsForSyncInstruments(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(append(
		metricProviderOptions(resource.Empty(), 10000),
		sdkmetric.WithReader(reader),
	)...)
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	m := mp.Meter("test")
	ctr, err := m.Int64Counter("t.noop.counter")
	if err != nil {
		t.Fatalf("Int64Counter: %v", err)
	}
	udctr, err := m.Int64UpDownCounter("t.noop.updowncounter")
	if err != nil {
		t.Fatalf("Int64UpDownCounter: %v", err)
	}
	gauge, err := m.Float64Gauge("t.noop.gauge")
	if err != nil {
		t.Fatalf("Float64Gauge: %v", err)
	}

	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x01},
		SpanID:     trace.SpanID{0x01},
		TraceFlags: trace.FlagsSampled,
	}))
	attrs := metric.WithAttributes(attribute.String("k", "v"))
	ctr.Add(ctx, 1, attrs)
	udctr.Add(ctx, 1, attrs)
	gauge.Record(ctx, 3.14, attrs)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	type result struct {
		exemplars int
		value     float64
	}
	results := map[string]result{}
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			switch d := met.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					r := results[met.Name]
					r.exemplars += len(dp.Exemplars)
					r.value += float64(dp.Value)
					results[met.Name] = r
				}
			case metricdata.Gauge[float64]:
				for _, dp := range d.DataPoints {
					r := results[met.Name]
					r.exemplars += len(dp.Exemplars)
					r.value = dp.Value
					results[met.Name] = r
				}
			}
		}
	}

	checks := []struct {
		name      string
		wantValue float64
	}{
		{"t.noop.counter", 1},
		{"t.noop.updowncounter", 1},
		{"t.noop.gauge", 3.14},
	}
	for _, c := range checks {
		r, ok := results[c.name]
		if !ok {
			t.Errorf("metric %q not found in collected output", c.name)
			continue
		}
		if r.exemplars != 0 {
			t.Errorf("metric %q: got %d exemplar(s); want 0", c.name, r.exemplars)
		}
		if r.value != c.wantValue {
			t.Errorf("metric %q: value = %v, want %v", c.name, r.value, c.wantValue)
		}
	}
}
