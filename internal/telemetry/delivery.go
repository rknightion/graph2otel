package telemetry

import (
	"context"
	"sync"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// DeliveryState is the current local state of one SDK exporter callback path.
type DeliveryState string

const (
	DeliveryStateStarting DeliveryState = "starting"
	DeliveryStateHealthy  DeliveryState = "healthy"
	DeliveryStateDegraded DeliveryState = "degraded"
)

// DeliveryFailureCode is the bounded category of the most recent exporter
// callback failure. Raw exporter errors remain in the existing OTel error
// handler and are never retained in delivery state.
type DeliveryFailureCode string

const (
	DeliveryFailureExportFailed     DeliveryFailureCode = "export_failed"
	DeliveryFailureForceFlushFailed DeliveryFailureCode = "force_flush_failed"
	DeliveryFailureShutdownFailed   DeliveryFailureCode = "shutdown_failed"
)

// DeliverySignal is an immutable value snapshot for one telemetry signal.
// Timestamps are absent until observed and otherwise canonical UTC RFC3339Nano.
type DeliverySignal struct {
	State DeliveryState

	ExportAttempts     uint64
	ExportSuccesses    uint64
	ExportFailures     uint64
	ForceFlushFailures uint64
	ShutdownFailures   uint64

	LastSuccessAt   string
	LastFailureAt   string
	LastFailureCode DeliveryFailureCode
}

// DeliverySnapshot is the process-wide exporter callback state. Metrics and
// logs are fixed fields so ordering and the closed signal set are deterministic.
type DeliverySnapshot struct {
	Metrics DeliverySignal
	Logs    DeliverySignal
}

type deliveryTracker struct {
	mu sync.Mutex

	metrics DeliverySignal
	logs    DeliverySignal

	reportedMetrics DeliverySignal
	reportedLogs    DeliverySignal
}

func newDeliveryTracker() *deliveryTracker {
	return &deliveryTracker{
		metrics: DeliverySignal{State: DeliveryStateStarting},
		logs:    DeliverySignal{State: DeliveryStateStarting},
	}
}

func (t *deliveryTracker) snapshot() DeliverySnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return DeliverySnapshot{
		Metrics: t.metrics,
		Logs:    t.logs,
	}
}

func (t *deliveryTracker) report(emitter Emitter) {
	t.mu.Lock()
	current := DeliverySnapshot{
		Metrics: t.metrics,
		Logs:    t.logs,
	}
	deltas := DeliverySnapshot{
		Metrics: deliveryCounterDelta(t.metrics, t.reportedMetrics),
		Logs:    deliveryCounterDelta(t.logs, t.reportedLogs),
	}
	t.reportedMetrics = t.metrics
	t.reportedLogs = t.logs
	t.mu.Unlock()

	reportDeliverySignal(emitter, "metrics", deltas.Metrics)
	reportDeliverySignal(emitter, "logs", deltas.Logs)
	emitter.GaugeSnapshot(
		deliveryDegradedMetric,
		"1",
		"Whether the most recent exporter callback failure remains unrecovered by a successful export.",
		[]GaugePoint{
			{Value: deliveryDegradedValue(current.Metrics), Attrs: Attrs{"signal": "metrics"}},
			{Value: deliveryDegradedValue(current.Logs), Attrs: Attrs{"signal": "logs"}},
		},
	)
}

func deliveryCounterDelta(current, reported DeliverySignal) DeliverySignal {
	return DeliverySignal{
		ExportAttempts:     current.ExportAttempts - reported.ExportAttempts,
		ExportSuccesses:    current.ExportSuccesses - reported.ExportSuccesses,
		ExportFailures:     current.ExportFailures - reported.ExportFailures,
		ForceFlushFailures: current.ForceFlushFailures - reported.ForceFlushFailures,
		ShutdownFailures:   current.ShutdownFailures - reported.ShutdownFailures,
	}
}

func reportDeliverySignal(emitter Emitter, signal string, delta DeliverySignal) {
	attrs := Attrs{"signal": signal}
	emitter.Counter(
		deliveryExportAttemptsMetric,
		"{operation}",
		"Exporter callback attempts since process start.",
		float64(delta.ExportAttempts),
		attrs,
	)
	emitter.Counter(
		deliveryExportSuccessesMetric,
		"{operation}",
		"Exporter callbacks accepted since process start.",
		float64(delta.ExportSuccesses),
		attrs,
	)
	emitter.Counter(
		deliveryExportFailuresMetric,
		"{operation}",
		"Exporter callbacks that returned an error since process start.",
		float64(delta.ExportFailures),
		attrs,
	)
	emitter.Counter(
		deliveryForceFlushFailuresMetric,
		"{operation}",
		"Exporter force-flush callbacks that returned an error since process start.",
		float64(delta.ForceFlushFailures),
		attrs,
	)
	emitter.Counter(
		deliveryShutdownFailuresMetric,
		"{operation}",
		"Exporter shutdown callbacks that returned an error since process start.",
		float64(delta.ShutdownFailures),
		attrs,
	)
}

func deliveryDegradedValue(signal DeliverySignal) float64 {
	if signal.State == DeliveryStateDegraded {
		return 1
	}
	return 0
}

const (
	deliveryExportAttemptsMetric     = "graph2otel.otlp.delivery.export_attempts"
	deliveryExportSuccessesMetric    = "graph2otel.otlp.delivery.export_successes"
	deliveryExportFailuresMetric     = "graph2otel.otlp.delivery.export_failures"
	deliveryForceFlushFailuresMetric = "graph2otel.otlp.delivery.force_flush_failures"
	deliveryShutdownFailuresMetric   = "graph2otel.otlp.delivery.shutdown_failures"
	deliveryDegradedMetric           = "graph2otel.otlp.delivery.degraded"
)

func (t *deliveryTracker) recordMetricExport(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	recordDeliveryExport(&t.metrics, err)
}

func (t *deliveryTracker) recordLogExport(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	recordDeliveryExport(&t.logs, err)
}

func (t *deliveryTracker) recordMetricFailure(code DeliveryFailureCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	recordDeliveryFailure(&t.metrics, code)
}

func (t *deliveryTracker) recordLogFailure(code DeliveryFailureCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	recordDeliveryFailure(&t.logs, code)
}

func recordDeliveryExport(signal *DeliverySignal, err error) {
	signal.ExportAttempts++
	if err == nil {
		signal.ExportSuccesses++
		signal.State = DeliveryStateHealthy
		signal.LastSuccessAt = deliveryTimestamp()
		signal.LastFailureCode = ""
		return
	}

	signal.ExportFailures++
	signal.State = DeliveryStateDegraded
	signal.LastFailureAt = deliveryTimestamp()
	signal.LastFailureCode = DeliveryFailureExportFailed
}

func recordDeliveryFailure(signal *DeliverySignal, code DeliveryFailureCode) {
	switch code {
	case DeliveryFailureForceFlushFailed:
		signal.ForceFlushFailures++
	case DeliveryFailureShutdownFailed:
		signal.ShutdownFailures++
	default:
		return
	}
	signal.State = DeliveryStateDegraded
	signal.LastFailureAt = deliveryTimestamp()
	signal.LastFailureCode = code
}

func deliveryTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

type metricDeliveryExporter struct {
	exporter sdkmetric.Exporter
	tracker  *deliveryTracker
}

func wrapMetricExporter(exporter sdkmetric.Exporter, tracker *deliveryTracker) sdkmetric.Exporter {
	return &metricDeliveryExporter{exporter: exporter, tracker: tracker}
}

func (e *metricDeliveryExporter) Temporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	return e.exporter.Temporality(kind)
}

func (e *metricDeliveryExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return e.exporter.Aggregation(kind)
}

func (e *metricDeliveryExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	err := e.exporter.Export(ctx, data)
	e.tracker.recordMetricExport(err)
	return err
}

func (e *metricDeliveryExporter) ForceFlush(ctx context.Context) error {
	err := e.exporter.ForceFlush(ctx)
	if err != nil {
		e.tracker.recordMetricFailure(DeliveryFailureForceFlushFailed)
	}
	return err
}

func (e *metricDeliveryExporter) Shutdown(ctx context.Context) error {
	err := e.exporter.Shutdown(ctx)
	if err != nil {
		e.tracker.recordMetricFailure(DeliveryFailureShutdownFailed)
	}
	return err
}

type logDeliveryExporter struct {
	exporter sdklog.Exporter
	tracker  *deliveryTracker
}

func wrapLogExporter(exporter sdklog.Exporter, tracker *deliveryTracker) sdklog.Exporter {
	return &logDeliveryExporter{exporter: exporter, tracker: tracker}
}

func (e *logDeliveryExporter) Export(ctx context.Context, records []sdklog.Record) error {
	err := e.exporter.Export(ctx, records)
	e.tracker.recordLogExport(err)
	return err
}

func (e *logDeliveryExporter) ForceFlush(ctx context.Context) error {
	err := e.exporter.ForceFlush(ctx)
	if err != nil {
		e.tracker.recordLogFailure(DeliveryFailureForceFlushFailed)
	}
	return err
}

func (e *logDeliveryExporter) Shutdown(ctx context.Context) error {
	err := e.exporter.Shutdown(ctx)
	if err != nil {
		e.tracker.recordLogFailure(DeliveryFailureShutdownFailed)
	}
	return err
}
