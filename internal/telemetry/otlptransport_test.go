package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// A missing or wrong attempt ordinal breaks the retry contract: only the
// second and later exporter retry-loop invocations are retries, while every
// payload send contributes its post-compression bytes.
func TestOTLPTransportTrackerCountsPayloadAndRetriesBySignal(t *testing.T) {
	tracker := newOTLPTransportTracker()

	metrics := tracker.newExportState(otlpSignalMetrics)
	metrics.recordAttempt()
	metrics.recordPayload(11)
	metrics.recordAttempt()
	metrics.recordPayload(7)
	metrics.recordAttempt()
	metrics.recordPayload(5)

	logs := tracker.newExportState(otlpSignalLogs)
	logs.recordAttempt()
	logs.recordPayload(13)

	got := tracker.snapshot()
	want := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 23, RetryAttempts: 2},
		Logs:    OTLPTransportSignal{PayloadBytes: 13},
	}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

// A serialization, size, or cancellation failure can return from Export
// before the transport is called. It must not be manufactured into an initial
// attempt, retry, or intended-size byte count.
func TestOTLPTransportTrackerPreTransportFailureStaysZero(t *testing.T) {
	tracker := newOTLPTransportTracker()
	_ = tracker.newExportState(otlpSignalMetrics)

	if got := tracker.snapshot(); got != (OTLPTransportSnapshot{}) {
		t.Fatalf("snapshot = %+v, want zero transport activity", got)
	}
}

// The exporter-specific HTTP/gRPC hooks receive only context. Losing the
// private state while deriving retry or timeout contexts would silently make
// production totals zero.
func TestOTLPTransportStateSurvivesDerivedContext(t *testing.T) {
	tracker := newOTLPTransportTracker()
	state := tracker.newExportState(otlpSignalLogs)
	ctx, cancel := context.WithCancel(withOTLPTransportState(context.Background(), state))
	defer cancel()

	got, ok := otlpTransportStateFromContext(ctx)
	if !ok || got != state {
		t.Fatalf("state from derived context = (%p, %t), want (%p, true)", got, ok, state)
	}
}

// Tracker methods are called from SDK readers, the log batch processor, HTTP
// body reads, and grpc stats callbacks. A plain non-atomic accumulator races
// and loses totals.
func TestOTLPTransportTrackerConcurrentConservation(t *testing.T) {
	tracker := newOTLPTransportTracker()
	const exports = 200

	var wg sync.WaitGroup
	wg.Add(exports * 2)
	for range exports {
		go func() {
			defer wg.Done()
			state := tracker.newExportState(otlpSignalMetrics)
			state.recordAttempt()
			state.recordPayload(3)
			state.recordAttempt()
			state.recordPayload(5)
		}()
		go func() {
			defer wg.Done()
			state := tracker.newExportState(otlpSignalLogs)
			state.recordAttempt()
			state.recordPayload(7)
		}()
	}
	wg.Wait()

	got := tracker.snapshot()
	want := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{
			PayloadBytes:  exports * (3 + 5),
			RetryAttempts: exports,
		},
		Logs: OTLPTransportSignal{
			PayloadBytes: exports * 7,
		},
	}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

// Missing either wrapper would make real exporter hooks unable to correlate an
// HTTP request or gRPC RPC with its SDK Export callback. It also proves the
// new transport snapshot does not alter #268's one-callback delivery meaning.
func TestProviderTransportWrapsInjectedExportersWithoutChangingDelivery(t *testing.T) {
	metricExporter := transportAwareMetricExporter{
		onExport: func(ctx context.Context) {
			state, ok := otlpTransportStateFromContext(ctx)
			if !ok {
				t.Fatal("metric exporter context has no transport state")
			}
			state.recordAttempt()
			state.recordPayload(17)
			state.recordAttempt()
			state.recordPayload(19)
		},
	}
	logExporter := transportAwareLogExporter{
		onExport: func(ctx context.Context) {
			state, ok := otlpTransportStateFromContext(ctx)
			if !ok {
				t.Fatal("log exporter context has no transport state")
			}
			state.recordAttempt()
			state.recordPayload(23)
		},
	}

	p, err := newProviderWithExporters(context.Background(), Options{
		ServiceName:    "graph2otel",
		MetricInterval: time.Hour,
	}, &metricExporter, &logExporter)
	if err != nil {
		t.Fatalf("newProviderWithExporters: %v", err)
	}
	p.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	p.Emitter().LogEvent(Event{Name: "entra.test", Body: "test"})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	wantTransport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 36, RetryAttempts: 1},
		Logs:    OTLPTransportSignal{PayloadBytes: 23},
	}
	if got := p.Transport(); got != wantTransport {
		t.Errorf("Transport() = %+v, want %+v", got, wantTransport)
	}
	gotDelivery := p.Delivery()
	if gotDelivery.Metrics.ExportAttempts != 1 || gotDelivery.Logs.ExportAttempts != 1 {
		t.Errorf("Delivery() callback attempts = metrics %d logs %d, want one each",
			gotDelivery.Metrics.ExportAttempts, gotDelivery.Logs.ExportAttempts)
	}
}

// A helper tested in isolation is insufficient: NewProvider must create the
// tracker before constructing both gRPC exporters and pass the same tracker to
// their dial hooks and outer context wrappers.
func TestProviderGRPCTransportHooksBothSignals(t *testing.T) {
	metricService := &retryingMetricService{}
	metricService.attempts.Store(1) // make the first provider request succeed.
	logService := &retryingLogService{}
	logService.attempts.Store(1)
	server := grpc.NewServer()
	colmetricpb.RegisterMetricsServiceServer(server, metricService)
	collogpb.RegisterLogsServiceServer(server, logService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	go func() {
		_ = server.Serve(listener)
	}()

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+listener.Addr().String())
	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
	p, err := NewProvider(context.Background(), Options{
		ServiceName:    "graph2otel",
		Protocol:       "grpc",
		Endpoint:       listener.Addr().String(),
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	p.Emitter().LogEvent(Event{Name: "entra.test", Body: "test"})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := p.Transport()
	if got.Metrics.PayloadBytes == 0 || got.Logs.PayloadBytes == 0 {
		t.Fatalf("Transport() = %+v, want non-zero payload bytes for both signals", got)
	}
	if got.Metrics.RetryAttempts != 0 || got.Logs.RetryAttempts != 0 {
		t.Fatalf("Transport() = %+v, want no retries for successful exports", got)
	}
}

// NewProvider must install the fork's narrow observer option on both HTTP
// exporters. Replacing the HTTP client here would silently discard the
// exporter's TLS, mTLS, proxy, timeout, and environment configuration.
func TestProviderHTTPTransportHooksBothSignals(t *testing.T) {
	var metricsBytes atomic.Uint64
	var logsBytes atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll(%s): %v", r.URL.Path, err)
			return
		}
		switch r.URL.Path {
		case "/v1/metrics":
			metricsBytes.Add(uint64(len(body)))
		case "/v1/logs":
			logsBytes.Add(uint64(len(body)))
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
	p, err := NewProvider(context.Background(), Options{
		ServiceName:    "graph2otel",
		Protocol:       "http",
		Endpoint:       server.URL,
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	p.Emitter().LogEvent(Event{Name: "entra.test", Body: "test"})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := p.Transport()
	if got.Metrics.PayloadBytes != metricsBytes.Load() || got.Metrics.PayloadBytes == 0 {
		t.Errorf("metric payload bytes = %d, want server-observed %d", got.Metrics.PayloadBytes, metricsBytes.Load())
	}
	if got.Logs.PayloadBytes != logsBytes.Load() || got.Logs.PayloadBytes == 0 {
		t.Errorf("log payload bytes = %d, want server-observed %d", got.Logs.PayloadBytes, logsBytes.Load())
	}
	if got.Metrics.RetryAttempts != 0 || got.Logs.RetryAttempts != 0 {
		t.Errorf("Transport() = %+v, want no retries for successful exports", got)
	}
}

// Removing either gRPC dial hook breaks a different half of the contract: the
// interceptor observes exporter retry-loop RPCs, while OutPayload reports the
// post-compression payload accepted by grpc-go for every actual send.
func TestGRPCMetricTransportCountsCompressedPayloadAndExporterRetry(t *testing.T) {
	serverStats := &grpcPayloadStats{}
	service := &retryingMetricService{}
	server := grpc.NewServer(grpc.StatsHandler(serverStats))
	colmetricpb.RegisterMetricsServiceServer(server, service)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	go func() {
		_ = server.Serve(listener)
	}()

	tracker := newOTLPTransportTracker()
	rawExporter, err := otlpmetricgrpc.New(
		context.Background(),
		otlpmetricgrpc.WithEndpoint(listener.Addr().String()),
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithCompressor("gzip"),
		otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Millisecond,
			MaxElapsedTime:  time.Second,
		}),
		otlpmetricgrpc.WithDialOption(otlpGRPCDialOptions(otlpSignalMetrics)...),
	)
	if err != nil {
		t.Fatalf("otlpmetricgrpc.New: %v", err)
	}
	exporter := wrapOTLPMetricTransportExporter(rawExporter, tracker)
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	if err := exporter.Export(context.Background(), &metricdata.ResourceMetrics{}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := service.attempts.Load(); got != 2 {
		t.Fatalf("server attempts = %d, want 2", got)
	}
	wantBytes := uint64(serverStats.compressedBytes.Load())
	if wantBytes == 0 {
		t.Fatal("server observed zero compressed payload bytes")
	}
	want := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{
			PayloadBytes:  wantBytes,
			RetryAttempts: 1,
		},
	}
	if got := tracker.snapshot(); got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

// The log exporter is a separately versioned module with its own retry client.
// Filtering only the MetricsService method would leave log transport totals at
// zero while the metric integration stayed green.
func TestGRPCLogTransportCountsCompressedPayloadAndExporterRetry(t *testing.T) {
	serverStats := &grpcPayloadStats{}
	service := &retryingLogService{}
	server := grpc.NewServer(grpc.StatsHandler(serverStats))
	collogpb.RegisterLogsServiceServer(server, service)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	go func() {
		_ = server.Serve(listener)
	}()

	tracker := newOTLPTransportTracker()
	rawExporter, err := otlploggrpc.New(
		context.Background(),
		otlploggrpc.WithEndpoint(listener.Addr().String()),
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithCompressor("gzip"),
		otlploggrpc.WithRetry(otlploggrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Millisecond,
			MaxElapsedTime:  time.Second,
		}),
		otlploggrpc.WithDialOption(otlpGRPCDialOptions(otlpSignalLogs)...),
	)
	if err != nil {
		t.Fatalf("otlploggrpc.New: %v", err)
	}
	exporter := wrapOTLPLogTransportExporter(rawExporter, tracker)
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	if err := exporter.Export(context.Background(), []sdklog.Record{{}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := service.attempts.Load(); got != 2 {
		t.Fatalf("server attempts = %d, want 2", got)
	}
	wantBytes := uint64(serverStats.compressedBytes.Load())
	if wantBytes == 0 {
		t.Fatal("server observed zero compressed payload bytes")
	}
	want := OTLPTransportSnapshot{
		Logs: OTLPTransportSignal{
			PayloadBytes:  wantBytes,
			RetryAttempts: 1,
		},
	}
	if got := tracker.snapshot(); got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

type transportAwareMetricExporter struct {
	onExport func(context.Context)
}

func (*transportAwareMetricExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (*transportAwareMetricExporter) Aggregation(sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.AggregationDefault{}
}

func (e *transportAwareMetricExporter) Export(ctx context.Context, _ *metricdata.ResourceMetrics) error {
	e.onExport(ctx)
	return nil
}

func (*transportAwareMetricExporter) ForceFlush(context.Context) error { return nil }
func (*transportAwareMetricExporter) Shutdown(context.Context) error   { return nil }

type transportAwareLogExporter struct {
	onExport func(context.Context)
}

func (e *transportAwareLogExporter) Export(ctx context.Context, _ []sdklog.Record) error {
	e.onExport(ctx)
	return nil
}

func (*transportAwareLogExporter) ForceFlush(context.Context) error { return nil }
func (*transportAwareLogExporter) Shutdown(context.Context) error   { return nil }

type retryingMetricService struct {
	colmetricpb.UnimplementedMetricsServiceServer
	attempts atomic.Int64
}

func (s *retryingMetricService) Export(
	context.Context,
	*colmetricpb.ExportMetricsServiceRequest,
) (*colmetricpb.ExportMetricsServiceResponse, error) {
	if s.attempts.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "retry once")
	}
	return &colmetricpb.ExportMetricsServiceResponse{}, nil
}

type retryingLogService struct {
	collogpb.UnimplementedLogsServiceServer
	attempts atomic.Int64
}

func (s *retryingLogService) Export(
	context.Context,
	*collogpb.ExportLogsServiceRequest,
) (*collogpb.ExportLogsServiceResponse, error) {
	if s.attempts.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "retry once")
	}
	return &collogpb.ExportLogsServiceResponse{}, nil
}

type grpcPayloadStats struct {
	compressedBytes atomic.Int64
}

func (*grpcPayloadStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (s *grpcPayloadStats) HandleRPC(_ context.Context, event stats.RPCStats) {
	if payload, ok := event.(*stats.InPayload); ok {
		s.compressedBytes.Add(int64(payload.CompressedLength))
	}
}

func (*grpcPayloadStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (*grpcPayloadStats) HandleConn(context.Context, stats.ConnStats) {}
