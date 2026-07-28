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

// nativeHistogramInstruments are the histogram instruments exported as base-2
// exponential (Prometheus native) histograms rather than explicit-bucket ones
// (#186). A View overrides each named instrument's aggregation, so the deriver
// records them with no explicit bounds and the SDK produces an exponential
// histogram; Grafana Cloud stores it as a native histogram. These are the
// blob-derived MGAL latency/size distributions (#128). Add a name here to make
// its histogram native. Kept a literal list rather than a wildcard so existing
// explicit-bucket histograms (the graph2otel.*.http.client.request.duration
// self-obs) are unaffected.
var nativeHistogramInstruments = []string{
	"entra.graph_activity.request.duration",
	"entra.graph_activity.response.size",
}

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

	// Limits is the cardinality policy graph2otel enforces itself
	// (internal/telemetry's Limiter): a per-metric cap that keeps the most
	// significant series and folds the rest into a named `other` bucket, and a
	// global cap arbitrated across metrics by max-min fairness.
	//
	// The OTEL SDK's own per-instrument cap is DISABLED unconditionally in favor
	// of it (#235). The SDK's is arrival-ordered — the survivors are whichever
	// showed up first, and the rest vanish into an opaque otel.metric.overflow
	// that names nothing — so leaving it underneath would only reimpose an
	// arbitrary lower ceiling on top of a strictly better mechanism, at a
	// threshold nothing in the config mentions.
	Limits Limits

	// SelfObsEnabled turns on the graph2otel.series.active cardinality tracker
	// (nil Cardinality() otherwise).
	SelfObsEnabled bool

	// Cost configures optional operator-priced, observational cost projection.
	// It never feeds the scheduler, limiter, client, or exporter control paths.
	Cost CostOptions

	// StdoutWriter overrides the destination in "stdout" protocol (default os.Stdout).
	StdoutWriter io.Writer
}

// Provider owns the OTEL MeterProvider and the per-domain LoggerProviders, and
// exposes a single Emitter for collectors. Shutdown flushes and releases all of
// them.
type Provider struct {
	mp *sdkmetric.MeterProvider
	// lps is one LoggerProvider per telemetry.EventDomains() value (#402).
	// There is deliberately no single "the" LoggerProvider: a record's
	// graph2otel.event_domain rides its RESOURCE, the SDK stamps a resource
	// from the provider that created the logger, and sdklog.Record has no
	// resource setter — so varying the attribute per record means varying the
	// provider per record. See eventdomain.go.
	lps map[string]*sdklog.LoggerProvider
	// sharedLogExp is the one exporter every domain provider writes through.
	// Provider.Shutdown closes it explicitly, because the per-provider
	// shutdowns deliberately do not — see sharedLogExporter.
	sharedLogExp *sharedLogExporter
	// transport is the process-wide post-compression payload/retry tracker.
	// It is separate from delivery: delivery observes one SDK exporter callback
	// after all internal retries, while transport observes the attempts within it.
	transport *otlpTransportTracker
	// delivery is the one process-wide tracker shared by both exporter wrappers.
	// Its fixed metrics/logs fields keep the two delivery paths independent.
	delivery *deliveryTracker
	// emitter is held as the concrete *otelEmitter, not the Emitter interface,
	// so Throughput can read its emit counters without a type assertion.
	emitter *otelEmitter
	// limited is emitter wrapped by the cardinality limiter; it is what
	// Emitter() hands out, so nothing can reach the SDK unbounded.
	limited Emitter
	// selfObsEmitter is the un-limited path used only by ReportSelfObs. Each
	// metric emitted there is explicitly classified as process-scoped or
	// tenant-attributed by the provider scope drift gate.
	selfObsEmitter Emitter
	// volume accumulates exact bounded source and post-limiter emitted-point
	// totals for passive admin introspection and the self-observation report.
	volume *VolumeTracker
	// capacityReport owns cumulative snapshot differencing. capacityNow is an
	// injected clock used only by focused package tests.
	capacityReport capacityReportState
	capacityNow    func() time.Time
	cost           CostOptions
	limiter        *Limiter
	card           *CardinalityTracker // nil unless self-observability is enabled
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
func metricProviderOptions(res *resource.Resource) []sdkmetric.Option {
	noopMask := sdkmetric.Stream{ExemplarReservoirProviderSelector: noopExemplarSelector}
	views := []sdkmetric.View{
		sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindCounter}, noopMask),
		sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindUpDownCounter}, noopMask),
		sdkmetric.NewView(sdkmetric.Instrument{Name: "*", Kind: sdkmetric.InstrumentKindGauge}, noopMask),
	}
	for _, name := range nativeHistogramInstruments {
		views = append(views, sdkmetric.NewView(
			sdkmetric.Instrument{Name: name},
			sdkmetric.Stream{
				// Recorded via context.Background() through the blob seam, so an
				// exemplar reservoir would be dead weight — reuse the no-op.
				ExemplarReservoirProviderSelector: noopExemplarSelector,
				Aggregation:                       sdkmetric.AggregationBase2ExponentialHistogram{MaxSize: 160, MaxScale: 20},
			},
		))
	}
	return []sdkmetric.Option{
		sdkmetric.WithResource(res),
		// The SDK's per-instrument cardinality limit is disabled (0 = no limit,
		// per its own docs) because graph2otel's Limiter supersedes it — see
		// Options.Limits. Leaving the SDK default of 2000 in place would silently
		// truncate at a threshold no config mentions, arrival-ordered, into a
		// series named otel.metric.overflow that nothing can interpret.
		sdkmetric.WithCardinalityLimit(0),
		sdkmetric.WithExemplarFilter(exemplar.TraceBasedFilter),
		sdkmetric.WithView(views...),
	}
}

// NewProvider builds the telemetry pipeline for the given options.
func NewProvider(ctx context.Context, opts Options) (*Provider, error) {
	// Two resources by design: metrics OMIT service.version (see buildResource
	// — avoids the redeploy series-doubling in #104), logs KEEP it. Everything
	// else (service.name, host/os/process detectors) is identical.
	metricRes, err := buildResource(ctx, opts, false)
	if err != nil {
		return nil, fmt.Errorf("build metrics resource: %w", err)
	}
	logRes, err := buildResource(ctx, opts, true)
	if err != nil {
		return nil, fmt.Errorf("build logs resource: %w", err)
	}
	transport := newOTLPTransportTracker()
	metricExp, err := newMetricExporterWithTransport(ctx, opts, transport)
	if err != nil {
		return nil, fmt.Errorf("metric exporter: %w", err)
	}
	logExp, err := newLogExporterWithTransport(ctx, opts, transport)
	if err != nil {
		return nil, fmt.Errorf("log exporter: %w", err)
	}
	return newProvider(opts, metricRes, logRes, metricExp, logExp, transport), nil
}

// newProviderWithExporters is the narrow injected construction seam used by
// package tests to exercise the real SDK reader and batch processor around
// controlled exporters. SDK types remain absent from public Options.
func newProviderWithExporters(
	ctx context.Context,
	opts Options,
	metricExp sdkmetric.Exporter,
	logExp sdklog.Exporter,
) (*Provider, error) {
	metricRes, err := buildResource(ctx, opts, false)
	if err != nil {
		return nil, fmt.Errorf("build metrics resource: %w", err)
	}
	logRes, err := buildResource(ctx, opts, true)
	if err != nil {
		return nil, fmt.Errorf("build logs resource: %w", err)
	}
	return newProvider(
		opts,
		metricRes,
		logRes,
		metricExp,
		logExp,
		newOTLPTransportTracker(),
	), nil
}

func newProvider(
	opts Options,
	metricRes *resource.Resource,
	logRes *resource.Resource,
	metricExp sdkmetric.Exporter,
	logExp sdklog.Exporter,
	transport *otlpTransportTracker,
) *Provider {
	metricExp = wrapOTLPMetricTransportExporter(metricExp, transport)
	logExp = wrapOTLPLogTransportExporter(logExp, transport)
	delivery := newDeliveryTracker()
	metricExp = wrapMetricExporter(metricExp, delivery)
	logExp = wrapLogExporter(logExp, delivery)
	interval := opts.MetricInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	mpOpts := append(
		metricProviderOptions(metricRes),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(interval))),
	)
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	lps, loggers, sharedLogExp := newDomainLoggerProviders(logRes, logExp)

	var card *CardinalityTracker
	if opts.SelfObsEnabled {
		card = NewCardinalityTrackerForLimit(opts.Limits.PerMetric)
	}

	emitter := newOtelEmitter(mp.Meter(scopeName), loggers[EventDomainOther], card)
	emitter.loggers = loggers
	limiter := NewLimiter(opts.Limits)
	volume := &VolumeTracker{}
	now := time.Now()

	return &Provider{
		mp:             mp,
		lps:            lps,
		sharedLogExp:   sharedLogExp,
		transport:      transport,
		delivery:       delivery,
		emitter:        emitter,
		selfObsEmitter: emitter,
		volume:         volume,
		capacityReport: capacityReportState{startedAt: now},
		capacityNow:    time.Now,
		cost:           opts.Cost,
		card:           card,
		limiter:        limiter,
		// The limiter wraps the base emitter INNERMOST, so WithTenant (#143) and
		// WithTransport (#141) decorate outside it and their stamps are already
		// applied by the time a point is ranked. tenant_id is part of series
		// identity, so a limiter running before that stamp would rank and fold
		// two tenants' series against each other as if they were one set.
		limited: limiter.Wrap(emitter),
	}
}

// Emitter returns the Emitter collectors should use.
func (p *Provider) Emitter() Emitter { return p.limited }

// CollectorEmitter returns a per-run emitter whose bounded attribution counts
// only points which survive the central limiter. Tenant and transport stamps
// sit outside the limiter so they participate in series identity before
// ranking, while the volume counter sits inside it and sees only forwarded
// points.
func (p *Provider) CollectorEmitter(attribution Attribution) Emitter {
	if p == nil {
		return nil
	}
	base := p.selfObsEmitter
	if base == nil || p.limiter == nil || p.volume == nil {
		return p.limited
	}
	counted := newVolumeEmitter(base, p.volume, attribution)
	return WithTenant(
		WithTransport(p.limiter.Wrap(counted), attribution.Transport),
		attribution.TenantID,
	)
}

// RecordSourceRecords adds one completed collector run's exact fetched count
// to the passive cumulative volume snapshot.
func (p *Provider) RecordSourceRecords(attribution Attribution, count uint64) {
	if p == nil || p.volume == nil {
		return
	}
	p.volume.RecordSourceRecords(attribution, count)
}

// Volume returns a deterministic immutable cumulative attribution snapshot.
func (p *Provider) Volume() []VolumeRow {
	if p == nil || p.volume == nil {
		return nil
	}
	return p.volume.Snapshot()
}

// Limiter returns the cardinality limiter this provider's Emitter enforces.
func (p *Provider) Limiter() *Limiter { return p.limiter }

// Delivery returns an immutable snapshot of the process-wide metric and log
// exporter callback state.
func (p *Provider) Delivery() DeliverySnapshot {
	if p.delivery == nil {
		return DeliverySnapshot{
			Metrics: DeliverySignal{State: DeliveryStateStarting},
			Logs:    DeliverySignal{State: DeliveryStateStarting},
		}
	}
	return p.delivery.snapshot()
}

// Transport returns an immutable cumulative snapshot of the process-wide OTLP
// payload bytes and exporter retry attempts observed since startup.
func (p *Provider) Transport() OTLPTransportSnapshot {
	if p.transport == nil {
		return OTLPTransportSnapshot{}
	}
	return p.transport.snapshot()
}

// ReportSelfObs emits one export interval's cardinality self-observability: the
// per-metric active-series counts, then what the limiter clipped and the global
// total. Order matters — the tracker's Report snapshots and resets, and the
// limiter consumes that same snapshot for its global arbitration rather than
// counting every series a second time.
//
// It reports through the UNDECORATED emitter on purpose. These series are the
// evidence that clipping is happening; routing them through the limiter would
// make the report subject to the thing it reports on. They are also genuinely
// PROCESS-global: one MeterProvider, limiter and tracker are shared by every
// tenant. Duplicating the same values once per tenant would make them easy to
// over-count. providerSelfObsScopes plus its mutation-proven test makes every
// metric on this bypass an explicit scope decision.
func (p *Provider) ReportSelfObs() {
	p.card.Report(p.selfObsEmitter)
	p.limiter.Report(p.selfObsEmitter, p.card.Snapshot())
	if p.delivery != nil {
		p.delivery.report(p.selfObsEmitter)
	}
	p.reportCapacity()
}

// Throughput returns the cumulative count of metric data points and log
// records the Emitter has shipped since process start. It is in-process
// introspection for the admin status page (#227), never exported as OTLP, and
// never reset by a read — callers difference consecutive reads for a rate.
func (p *Provider) Throughput() Throughput { return p.emitter.Throughput() }

// Cardinality returns the self-observability cardinality tracker, or nil when
// self-observability is disabled. The caller drives Report on the export
// interval and may call Report safely even when this is nil.
func (p *Provider) Cardinality() *CardinalityTracker { return p.card }

// Shutdown flushes and stops the metric and log pipelines.
//
// EVERY domain provider is shut down, not just the busiest: each owns its own
// BatchProcessor and therefore its own queue, so skipping one silently discards
// whatever it had buffered at exit. Errors are joined rather than
// short-circuited for the same reason — one provider failing to flush must not
// stop the others from trying.
func (p *Provider) Shutdown(ctx context.Context) error {
	errs := make([]error, 0, len(p.lps)+1)
	errs = append(errs, p.mp.Shutdown(ctx))
	for _, d := range EventDomains() {
		if lp, ok := p.lps[d]; ok {
			errs = append(errs, lp.Shutdown(ctx))
		}
	}
	// Last, and only now: the shared exporter. Closing it any earlier would
	// discard whatever the not-yet-drained providers still hold.
	if p.sharedLogExp != nil {
		errs = append(errs, p.sharedLogExp.closeShared(ctx))
	}
	return errors.Join(errs...)
}

// buildResource builds the OTEL resource. includeServiceVersion controls
// whether service.version is attached: it is TRUE for the logs resource and
// FALSE for the metrics resource. The split exists because Grafana Cloud's OTLP
// ingest promotes resource attributes to per-series labels — so putting
// service.version (which, on the :main edge image, is the per-commit git SHA)
// on the metrics resource churns a fresh series set on every redeploy. The old
// series linger for the query lookback window (an OTLP push carries no
// staleness signal, unlike a scrape target going down), so any panel that sums
// across a bounded dimension doubles for ~5–10 min after each restart (#104).
// Version stays fully discoverable via graph2otel.build_info (and target_info);
// logs are never summed, so the logs resource keeps service.version for
// per-record version attribution.
func buildResource(ctx context.Context, opts Options, includeServiceVersion bool) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{attribute.String("service.name", opts.ServiceName)}
	if includeServiceVersion && opts.ServiceVersion != "" {
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
	return newMetricExporterWithTransport(ctx, opts, nil)
}

func newMetricExporterWithTransport(
	ctx context.Context,
	opts Options,
	transport *otlpTransportTracker,
) (sdkmetric.Exporter, error) {
	switch opts.Protocol {
	case "stdout":
		w := opts.StdoutWriter
		if w == nil {
			w = os.Stdout
		}
		return stdoutmetric.New(stdoutmetric.WithWriter(w))
	case "", "http":
		o := []otlpmetrichttp.Option{otlpmetrichttp.WithTemporalitySelector(cumulativeTemporalitySelector)}
		if transport != nil {
			o = append(o, otlpmetrichttp.WithRequestObserver(otlpHTTPRequestObserver{}))
		}
		if opts.Endpoint != "" {
			o = append(o, otlpmetrichttp.WithEndpointURL(otlpHTTPURL(opts.Endpoint, "metrics")))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlpmetrichttp.WithHeaders(h))
		}
		return otlpmetrichttp.New(ctx, o...)
	case "grpc":
		o := []otlpmetricgrpc.Option{otlpmetricgrpc.WithTemporalitySelector(cumulativeTemporalitySelector)}
		if transport != nil {
			o = append(o, otlpmetricgrpc.WithDialOption(otlpGRPCDialOptions(otlpSignalMetrics)...))
		}
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
	return newLogExporterWithTransport(ctx, opts, nil)
}

func newLogExporterWithTransport(
	ctx context.Context,
	opts Options,
	transport *otlpTransportTracker,
) (sdklog.Exporter, error) {
	switch opts.Protocol {
	case "stdout":
		w := opts.StdoutWriter
		if w == nil {
			w = os.Stdout
		}
		return stdoutlog.New(stdoutlog.WithWriter(w))
	case "", "http":
		o := []otlploghttp.Option{}
		if transport != nil {
			o = append(o, otlploghttp.WithRequestObserver(otlpHTTPRequestObserver{}))
		}
		if opts.Endpoint != "" {
			o = append(o, otlploghttp.WithEndpointURL(otlpHTTPURL(opts.Endpoint, "logs")))
		}
		if h := grafanaCloudHeaders(opts); len(h) > 0 {
			o = append(o, otlploghttp.WithHeaders(h))
		}
		return otlploghttp.New(ctx, o...)
	case "grpc":
		o := []otlploggrpc.Option{}
		if transport != nil {
			o = append(o, otlploggrpc.WithDialOption(otlpGRPCDialOptions(otlpSignalLogs)...))
		}
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
