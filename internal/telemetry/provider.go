package telemetry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// noopReservoir is an exemplar.Reservoir that never stores anything. It is
// used to suppress per-series reservoir allocations for synchronous Counter,
// UpDownCounter, and Gauge instruments: those are always recorded with
// context.Background() by the Emitter, so their default FixedSizeReservoir
// (sized to GOMAXPROCS) would be allocated per unique time series and never
// populated — pure dead-weight heap.
type noopReservoir struct{}

func (noopReservoir) Offer(_ context.Context, _ time.Time, _ exemplar.Value, _ []attribute.KeyValue) {
}
func (noopReservoir) Collect(_ *[]exemplar.Exemplar) {}

// noopReservoirSingleton is the single instance reused across all series.
// Because noopReservoir holds no state, sharing it is safe.
var noopReservoirSingleton noopReservoir

// noopReservoirProvider returns the no-op singleton for any attribute set, so
// there is zero per-series allocation.
func noopReservoirProvider(_ attribute.Set) exemplar.Reservoir {
	return noopReservoirSingleton
}

// noopExemplarSelector returns noopReservoirProvider for any aggregation. It
// is used as the ExemplarReservoirProviderSelector on the per-kind views that
// suppress exemplars for synchronous non-histogram instruments.
func noopExemplarSelector(_ sdkmetric.Aggregation) exemplar.ReservoirProvider {
	return noopReservoirProvider
}

// scopeName is the instrumentation scope for all emitted telemetry.
const scopeName = "github.com/rknightion/graph2otel"

// Options configures the OTLP/stdout telemetry pipeline.
type Options struct {
	ServiceName    string
	ServiceVersion string

	Protocol string // "grpc" | "http" | "stdout" (empty defaults to "http")
	Endpoint string // full URL for http (incl. e.g. Grafana Cloud's ".../otlp"); host:port for grpc

	// InstanceID and Token are the Grafana Cloud OTLP gateway credentials
	// (config.GrafanaCloudConfig): when both are non-empty, NewProvider adds a
	// Basic-auth Authorization header built from them to every OTLP exporter.
	// Leave both empty for a self-managed OTLP collector that needs no such
	// header.
	InstanceID string
	Token      string

	MetricInterval time.Duration // PeriodicReader interval (default 60s)

	// CardinalityLimit is the hard per-instrument limit on the number of distinct
	// attribute sets collected per cycle; sets beyond it collapse into the SDK's
	// otel.metric.overflow series. 0 or negative means unlimited (the SDK's own
	// default of 2000 still applies). Pair with a self-obs CardinalityTracker
	// (see NewProvider) built with the same value so graph2otel.series.active
	// pins exactly when a metric reaches the limit.
	CardinalityLimit int

	// SelfObsEnabled turns on the graph2otel.series.active cardinality tracker
	// (nil Cardinality() otherwise).
	SelfObsEnabled bool

	// StdoutWriter overrides the destination in "stdout" protocol (default os.Stdout).
	StdoutWriter io.Writer
}

// Provider owns the OTEL MeterProvider and LoggerProvider and exposes a single
// Emitter for collectors. Shutdown flushes and releases both.
type Provider struct {
	mp      *sdkmetric.MeterProvider
	lp      *sdklog.LoggerProvider
	emitter Emitter
	card    *CardinalityTracker // nil unless self-observability is enabled
}

// metricProviderOptions returns the MeterProvider options shared by the
// production pipeline and tests — everything except the reader, which
// differs (a PeriodicReader in production, a ManualReader in tests).
// Centralizing them here lets the cardinality-limit and exemplar-filter
// behavior be asserted against an in-memory reader without duplicating the
// wiring.
//
// Exemplar strategy: the trace-based exemplar filter is always on, so a
// Float64Histogram recorded via HistogramCtx under a real (e.g. Kiota
// transport) span context attaches an exemplar. Three per-instrument-kind
// Views override the reservoir provider for synchronous Counter,
// UpDownCounter, and Gauge to a no-op singleton, because those instruments
// are always recorded with context.Background() by the Emitter, so their
// default FixedSizeReservoir (sized to GOMAXPROCS) would be allocated per
// unique time series and can never be populated — pure dead-weight heap at
// high cardinality. Observable (async, i.e. GaugeSnapshot) instruments are
// already dropped by the SDK under the trace-based filter, so no view is
// needed for them.
func metricProviderOptions(res *resource.Resource, cardinalityLimit int) []sdkmetric.Option {
	noopMask := sdkmetric.Stream{ExemplarReservoirProviderSelector: noopExemplarSelector}
	return []sdkmetric.Option{
		sdkmetric.WithResource(res),
		// Hard per-instrument cardinality limit (0/neg = SDK default of 2000).
		sdkmetric.WithCardinalityLimit(cardinalityLimit),
		sdkmetric.WithExemplarFilter(exemplar.TraceBasedFilter),
		sdkmetric.WithView(
			sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindCounter}, noopMask),
			sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindUpDownCounter}, noopMask),
			sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindGauge}, noopMask),
		),
	}
}

// NewProvider builds the telemetry pipeline for the given options.
func NewProvider(ctx context.Context, opts Options) (*Provider, error) {
	res, err := buildResource(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}
	metricExp, err := newMetricExporter(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	logExp, err := newLogExporter(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("log exporter: %w", err)
	}

	interval := opts.MetricInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	mpOpts := append(
		metricProviderOptions(res, opts.CardinalityLimit),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(interval))),
	)
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
	)

	var card *CardinalityTracker
	if opts.SelfObsEnabled {
		card = NewCardinalityTrackerWithCap(opts.CardinalityLimit)
	}

	emitter := newOtelEmitter(mp.Meter(scopeName), lp.Logger(scopeName), card)

	return &Provider{
		mp:      mp,
		lp:      lp,
		emitter: emitter,
		card:    card,
	}, nil
}

// Emitter returns the Emitter collectors should use.
func (p *Provider) Emitter() Emitter { return p.emitter }

// Cardinality returns the self-observability cardinality tracker, or nil when
// self-observability is disabled. The caller drives Report on the export
// interval and may call Report safely even when this is nil.
func (p *Provider) Cardinality() *CardinalityTracker { return p.card }

// Shutdown flushes and stops the metric and log pipelines.
func (p *Provider) Shutdown(ctx context.Context) error {
	return errors.Join(p.mp.Shutdown(ctx), p.lp.Shutdown(ctx))
}

func buildResource(ctx context.Context, opts Options) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{attribute.String("service.name", opts.ServiceName)}
	if opts.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", opts.ServiceVersion))
	}
	// The schemaless WithAttributes block carries the service.* identity; the
	// core detectors add host/os/process attributes so multiple instances (or
	// tenants) are distinguishable in Grafana. All detectors share one semconv
	// schema URL, so merging them with the schemaless block cannot raise a
	// schema-URL conflict. A narrow process subset is used deliberately —
	// WithProcess() would also emit process.command_args and process.owner,
	// which can leak deploy paths and usernames to the backend.
	res, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithHost(),
		resource.WithProcessPID(),
		resource.WithProcessExecutableName(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
	)
	// A partial resource (a detector that couldn't read its source — e.g.
	// os.Hostname() failing) must NOT abort startup: the exporter's core job is
	// unaffected, so continue with whatever attributes were resolved. Any other
	// error (which, given the shared schema URL, should not occur) is fatal.
	if err != nil && errors.Is(err, resource.ErrPartialResource) {
		return res, nil
	}
	return res, err
}

// otlpHTTPURL appends the OTLP/HTTP per-signal path (/v1/metrics, /v1/logs) to
// a base endpoint. The OTEL Go otlphttp exporter's WithEndpointURL uses the
// URL path as-is, so a base gateway endpoint (e.g. Grafana Cloud's ".../otlp")
// must have the signal path appended or the gateway returns 404. A base that
// already ends with the signal path is returned unchanged (no double-append).
func otlpHTTPURL(base, signal string) string {
	base = strings.TrimRight(base, "/")
	suffix := "/v1/" + signal
	if strings.HasSuffix(base, suffix) {
		return base
	}
	return base + suffix
}

// grafanaCloudAuthHeader builds the HTTP Basic-auth header value Grafana
// Cloud's OTLP gateway expects: "Basic base64(instanceID:token)". It returns
// "" when either instanceID or token is empty, since a self-managed OTLP
// collector needs no such header.
func grafanaCloudAuthHeader(instanceID, token string) string {
	if instanceID == "" || token == "" {
		return ""
	}
	creds := base64.StdEncoding.EncodeToString([]byte(instanceID + ":" + token))
	return "Basic " + creds
}

// grafanaCloudHeaders returns the header map to attach to every OTLP
// exporter: just the Grafana Cloud Authorization header when opts carries
// InstanceID+Token, or nil otherwise (a self-managed collector).
func grafanaCloudHeaders(opts Options) map[string]string {
	auth := grafanaCloudAuthHeader(opts.InstanceID, opts.Token)
	if auth == "" {
		return nil
	}
	return map[string]string{"Authorization": auth}
}

// cumulativeTemporalitySelector forces cumulative temporality for every
// instrument kind. Grafana Cloud / Mimir OTLP ingestion accepts cumulative only
// (delta is rejected with HTTP 400 and there is no server-side delta->cumulative
// conversion), so we pin it explicitly rather than relying on the SDK default.
func cumulativeTemporalitySelector(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func newMetricExporter(ctx context.Context, opts Options) (sdkmetric.Exporter, error) {
	switch opts.Protocol {
	case "stdout":
		w := opts.StdoutWriter
		if w == nil {
			w = os.Stdout
		}
		return stdoutmetric.New(stdoutmetric.WithWriter(w))
	case "", "http":
		o := []otlpmetrichttp.Option{otlpmetrichttp.WithTemporalitySelector(cumulativeTemporalitySelector)}
		if opts.Endpoint != "" {
			o = append(o, otlpmetrichttp.WithEndpointURL(otlpHTTPURL(opts.Endpoint, "metrics")))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlpmetrichttp.WithHeaders(h))
		}
		return otlpmetrichttp.New(ctx, o...)
	case "grpc":
		o := []otlpmetricgrpc.Option{otlpmetricgrpc.WithTemporalitySelector(cumulativeTemporalitySelector)}
		if opts.Endpoint != "" {
			o = append(o, otlpmetricgrpc.WithEndpoint(opts.Endpoint))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlpmetricgrpc.WithHeaders(h))
		}
		return otlpmetricgrpc.New(ctx, o...)
	default:
		return nil, fmt.Errorf("unknown otlp protocol %q (want grpc, http, or stdout)", opts.Protocol)
	}
}

func newLogExporter(ctx context.Context, opts Options) (sdklog.Exporter, error) {
	switch opts.Protocol {
	case "stdout":
		w := opts.StdoutWriter
		if w == nil {
			w = os.Stdout
		}
		return stdoutlog.New(stdoutlog.WithWriter(w))
	case "", "http":
		o := []otlploghttp.Option{}
		if opts.Endpoint != "" {
			o = append(o, otlploghttp.WithEndpointURL(otlpHTTPURL(opts.Endpoint, "logs")))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlploghttp.WithHeaders(h))
		}
		return otlploghttp.New(ctx, o...)
	case "grpc":
		o := []otlploggrpc.Option{}
		if opts.Endpoint != "" {
			o = append(o, otlploggrpc.WithEndpoint(opts.Endpoint))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlploggrpc.WithHeaders(h))
		}
		return otlploggrpc.New(ctx, o...)
	default:
		return nil, fmt.Errorf("unknown otlp protocol %q (want grpc, http, or stdout)", opts.Protocol)
	}
}
