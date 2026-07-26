package telemetry

import (
	"context"
	"sync/atomic"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
)

type otlpSignal uint8

const (
	otlpSignalMetrics otlpSignal = iota
	otlpSignalLogs
)

// OTLPTransportSignal is the cumulative process transport activity for one
// OTLP signal. PayloadBytes counts encoded payload bytes after compression and
// before protocol/network framing. RetryAttempts counts second-and-later
// exporter retry-loop invocations within one SDK export callback.
type OTLPTransportSignal struct {
	PayloadBytes  uint64
	RetryAttempts uint64
}

// OTLPTransportSnapshot is an immutable process-wide transport snapshot.
type OTLPTransportSnapshot struct {
	Metrics OTLPTransportSignal
	Logs    OTLPTransportSignal
}

type otlpTransportCounters struct {
	payloadBytes  atomic.Uint64
	retryAttempts atomic.Uint64
}

type otlpTransportTracker struct {
	metrics otlpTransportCounters
	logs    otlpTransportCounters
}

func newOTLPTransportTracker() *otlpTransportTracker {
	return &otlpTransportTracker{}
}

func (t *otlpTransportTracker) newExportState(signal otlpSignal) *otlpExportTransportState {
	return &otlpExportTransportState{
		counters: t.counters(signal),
	}
}

func (t *otlpTransportTracker) counters(signal otlpSignal) *otlpTransportCounters {
	if signal == otlpSignalLogs {
		return &t.logs
	}
	return &t.metrics
}

func (t *otlpTransportTracker) snapshot() OTLPTransportSnapshot {
	return OTLPTransportSnapshot{
		Metrics: snapshotOTLPTransportCounters(&t.metrics),
		Logs:    snapshotOTLPTransportCounters(&t.logs),
	}
}

func snapshotOTLPTransportCounters(c *otlpTransportCounters) OTLPTransportSignal {
	return OTLPTransportSignal{
		PayloadBytes:  c.payloadBytes.Load(),
		RetryAttempts: c.retryAttempts.Load(),
	}
}

type otlpExportTransportState struct {
	counters *otlpTransportCounters
	attempts atomic.Uint64
}

func (s *otlpExportTransportState) recordAttempt() {
	if s == nil || s.counters == nil {
		return
	}
	if s.attempts.Add(1) > 1 {
		s.counters.retryAttempts.Add(1)
	}
}

func (s *otlpExportTransportState) recordPayload(n int) {
	if s == nil || s.counters == nil || n <= 0 {
		return
	}
	s.counters.payloadBytes.Add(uint64(n))
}

type otlpTransportStateContextKey struct{}

func withOTLPTransportState(ctx context.Context, state *otlpExportTransportState) context.Context {
	return context.WithValue(ctx, otlpTransportStateContextKey{}, state)
}

func otlpTransportStateFromContext(ctx context.Context) (*otlpExportTransportState, bool) {
	state, ok := ctx.Value(otlpTransportStateContextKey{}).(*otlpExportTransportState)
	return state, ok && state != nil
}

// otlpHTTPRequestObserver is the adapter shared by the two narrowly patched
// OTLP/HTTP exporters. It carries no tracker pointer: each SDK Export wrapper
// puts the correct per-export, per-signal state on the context before the
// exporter's retry loop derives its attempt contexts.
type otlpHTTPRequestObserver struct{}

func (otlpHTTPRequestObserver) Attempt(ctx context.Context) {
	if state, ok := otlpTransportStateFromContext(ctx); ok {
		state.recordAttempt()
	}
}

func (otlpHTTPRequestObserver) PayloadBytes(ctx context.Context, n int) {
	if state, ok := otlpTransportStateFromContext(ctx); ok {
		state.recordPayload(n)
	}
}

const (
	otlpMetricsExportMethod = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	otlpLogsExportMethod    = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
)

func otlpExportMethod(signal otlpSignal) string {
	if signal == otlpSignalLogs {
		return otlpLogsExportMethod
	}
	return otlpMetricsExportMethod
}

func otlpGRPCDialOptions(signal otlpSignal) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(otlpGRPCExportAttemptInterceptor(signal)),
		grpc.WithStatsHandler(otlpGRPCPayloadStatsHandler{signal: signal}),
	}
}

func otlpGRPCExportAttemptInterceptor(signal otlpSignal) grpc.UnaryClientInterceptor {
	method := otlpExportMethod(signal)
	return func(
		ctx context.Context,
		fullMethod string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if fullMethod == method {
			if state, ok := otlpTransportStateFromContext(ctx); ok {
				state.recordAttempt()
			}
		}
		return invoker(ctx, fullMethod, req, reply, cc, opts...)
	}
}

type otlpGRPCMethodContextKey struct{}

type otlpGRPCPayloadStatsHandler struct {
	signal otlpSignal
}

func (h otlpGRPCPayloadStatsHandler) TagRPC(
	ctx context.Context,
	info *stats.RPCTagInfo,
) context.Context {
	return context.WithValue(
		ctx,
		otlpGRPCMethodContextKey{},
		info != nil && info.FullMethodName == otlpExportMethod(h.signal),
	)
}

func (otlpGRPCPayloadStatsHandler) HandleRPC(ctx context.Context, event stats.RPCStats) {
	matches, _ := ctx.Value(otlpGRPCMethodContextKey{}).(bool)
	if !matches {
		return
	}
	payload, ok := event.(*stats.OutPayload)
	if !ok || !payload.Client {
		return
	}
	if state, ok := otlpTransportStateFromContext(ctx); ok {
		state.recordPayload(payload.CompressedLength)
	}
}

func (otlpGRPCPayloadStatsHandler) TagConn(
	ctx context.Context,
	_ *stats.ConnTagInfo,
) context.Context {
	return ctx
}

func (otlpGRPCPayloadStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

type otlpMetricTransportExporter struct {
	exporter sdkmetric.Exporter
	tracker  *otlpTransportTracker
}

func wrapOTLPMetricTransportExporter(
	exporter sdkmetric.Exporter,
	tracker *otlpTransportTracker,
) sdkmetric.Exporter {
	return &otlpMetricTransportExporter{exporter: exporter, tracker: tracker}
}

func (e *otlpMetricTransportExporter) Temporality(
	kind sdkmetric.InstrumentKind,
) metricdata.Temporality {
	return e.exporter.Temporality(kind)
}

func (e *otlpMetricTransportExporter) Aggregation(
	kind sdkmetric.InstrumentKind,
) sdkmetric.Aggregation {
	return e.exporter.Aggregation(kind)
}

func (e *otlpMetricTransportExporter) Export(
	ctx context.Context,
	data *metricdata.ResourceMetrics,
) error {
	state := e.tracker.newExportState(otlpSignalMetrics)
	return e.exporter.Export(withOTLPTransportState(ctx, state), data)
}

func (e *otlpMetricTransportExporter) ForceFlush(ctx context.Context) error {
	return e.exporter.ForceFlush(ctx)
}

func (e *otlpMetricTransportExporter) Shutdown(ctx context.Context) error {
	return e.exporter.Shutdown(ctx)
}

type otlpLogTransportExporter struct {
	exporter sdklog.Exporter
	tracker  *otlpTransportTracker
}

func wrapOTLPLogTransportExporter(
	exporter sdklog.Exporter,
	tracker *otlpTransportTracker,
) sdklog.Exporter {
	return &otlpLogTransportExporter{exporter: exporter, tracker: tracker}
}

func (e *otlpLogTransportExporter) Export(ctx context.Context, records []sdklog.Record) error {
	state := e.tracker.newExportState(otlpSignalLogs)
	return e.exporter.Export(withOTLPTransportState(ctx, state), records)
}

func (e *otlpLogTransportExporter) ForceFlush(ctx context.Context) error {
	return e.exporter.ForceFlush(ctx)
}

func (e *otlpLogTransportExporter) Shutdown(ctx context.Context) error {
	return e.exporter.Shutdown(ctx)
}
