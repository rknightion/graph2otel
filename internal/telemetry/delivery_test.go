package telemetry

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestDeliveryTrackerWrappedExporters(t *testing.T) {
	secretErr := &deliveryTestError{"export rejected: Authorization: Bearer secret-value"}
	flushErr := &deliveryTestError{"flush rejected"}
	shutdownErr := &deliveryTestError{"shutdown rejected"}
	logFlushErr := &deliveryTestError{"log flush rejected"}
	logShutdownErr := &deliveryTestError{"log shutdown rejected"}

	tracker := newDeliveryTracker()
	metricDelegate := &fakeMetricExporter{
		exportErrors:     []error{secretErr, nil},
		forceFlushErrors: []error{flushErr, nil},
		shutdownErrors:   []error{shutdownErr, nil},
	}
	logDelegate := &fakeLogExporter{
		forceFlushErrors: []error{logFlushErr, nil},
		shutdownErrors:   []error{logShutdownErr, nil},
	}

	metricExporter := wrapMetricExporter(metricDelegate, tracker)
	logExporter := wrapLogExporter(logDelegate, tracker)

	initial := tracker.snapshot()
	assertDeliverySignal(t, "initial metrics", initial.Metrics, DeliverySignal{
		State: DeliveryStateStarting,
	})
	assertDeliverySignal(t, "initial logs", initial.Logs, DeliverySignal{
		State: DeliveryStateStarting,
	})

	metricDelegate.onExport = func() {
		got := tracker.snapshot().Metrics
		if got.ExportAttempts != 0 {
			t.Errorf("tracker updated before metric delegate returned: %+v", got)
		}
	}
	assertOriginalError(t, "metric Export", metricExporter.Export(
		context.Background(),
		&metricdata.ResourceMetrics{},
	), secretErr)
	metricDelegate.onExport = nil

	afterMetricFailure := tracker.snapshot()
	assertDeliverySignal(t, "metrics after failed export", afterMetricFailure.Metrics, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:           DeliveryStateDegraded,
			ExportAttempts:  1,
			ExportFailures:  1,
			LastFailureCode: DeliveryFailureExportFailed,
		},
		LastFailureAtMust: true,
	})
	assertDeliverySignal(t, "logs isolated from metric failure", afterMetricFailure.Logs, DeliverySignal{
		State: DeliveryStateStarting,
	})
	if got := fmt.Sprint(afterMetricFailure); strings.Contains(got, "secret-value") || strings.Contains(got, "Bearer") {
		t.Fatalf("delivery snapshot retained exporter error secret: %s", got)
	}

	logDelegate.onExport = func() {
		got := tracker.snapshot().Logs
		if got.ExportAttempts != 0 {
			t.Errorf("tracker updated before log delegate returned: %+v", got)
		}
	}
	if got := logExporter.Export(context.Background(), nil); got != nil {
		t.Fatalf("log Export error = %v, want nil", got)
	}
	logDelegate.onExport = nil
	afterLogSuccess := tracker.snapshot()
	assertDeliverySignal(t, "metrics isolated from log success", afterLogSuccess.Metrics, afterMetricFailure.Metrics)
	assertDeliverySignal(t, "logs after successful export", afterLogSuccess.Logs, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:           DeliveryStateHealthy,
			ExportAttempts:  1,
			ExportSuccesses: 1,
		},
		LastSuccessAtMust: true,
	})

	assertOriginalError(t, "metric ForceFlush", metricExporter.ForceFlush(context.Background()), flushErr)
	afterFlushFailure := tracker.snapshot()
	assertDeliverySignal(t, "metrics after failed force flush", afterFlushFailure.Metrics, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateDegraded,
			ExportAttempts:     1,
			ExportFailures:     1,
			ForceFlushFailures: 1,
			LastFailureCode:    DeliveryFailureForceFlushFailed,
		},
		LastFailureAtMust:      true,
		LastFailureAtNotBefore: afterMetricFailure.Metrics.LastFailureAt,
	})

	if got := metricExporter.ForceFlush(context.Background()); got != nil {
		t.Fatalf("successful metric ForceFlush error = %v, want nil", got)
	}
	assertDeliverySignal(t, "successful force flush cannot clear degradation", tracker.snapshot().Metrics, afterFlushFailure.Metrics)

	assertOriginalError(t, "metric Shutdown", metricExporter.Shutdown(context.Background()), shutdownErr)
	afterShutdownFailure := tracker.snapshot()
	assertDeliverySignal(t, "metrics after failed shutdown", afterShutdownFailure.Metrics, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateDegraded,
			ExportAttempts:     1,
			ExportFailures:     1,
			ForceFlushFailures: 1,
			ShutdownFailures:   1,
			LastFailureCode:    DeliveryFailureShutdownFailed,
		},
		LastFailureAtMust:      true,
		LastFailureAtNotBefore: afterFlushFailure.Metrics.LastFailureAt,
	})

	if got := metricExporter.Shutdown(context.Background()); got != nil {
		t.Fatalf("successful metric Shutdown error = %v, want nil", got)
	}
	assertDeliverySignal(t, "successful shutdown cannot clear degradation", tracker.snapshot().Metrics, afterShutdownFailure.Metrics)

	if got := metricExporter.Export(context.Background(), &metricdata.ResourceMetrics{}); got != nil {
		t.Fatalf("recovering metric Export error = %v, want nil", got)
	}
	recovered := tracker.snapshot()
	assertDeliverySignal(t, "metrics after export recovery", recovered.Metrics, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateHealthy,
			ExportAttempts:     2,
			ExportSuccesses:    1,
			ExportFailures:     1,
			ForceFlushFailures: 1,
			ShutdownFailures:   1,
			LastFailureAt:      afterShutdownFailure.Metrics.LastFailureAt,
			LastFailureCode:    "",
		},
		LastSuccessAtMust:      true,
		LastSuccessAtNotBefore: afterShutdownFailure.Metrics.LastFailureAt,
	})

	metricsBeforeLogLifecycle := recovered.Metrics
	assertOriginalError(t, "log ForceFlush", logExporter.ForceFlush(context.Background()), logFlushErr)
	afterLogFlushFailure := tracker.snapshot()
	assertDeliverySignal(t, "logs after failed force flush", afterLogFlushFailure.Logs, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateDegraded,
			ExportAttempts:     1,
			ExportSuccesses:    1,
			ForceFlushFailures: 1,
			LastSuccessAt:      afterLogSuccess.Logs.LastSuccessAt,
			LastFailureCode:    DeliveryFailureForceFlushFailed,
		},
		LastFailureAtMust: true,
	})
	assertDeliverySignal(t, "metrics isolated from log force flush", afterLogFlushFailure.Metrics, metricsBeforeLogLifecycle)
	if got := logExporter.ForceFlush(context.Background()); got != nil {
		t.Fatalf("successful log ForceFlush error = %v, want nil", got)
	}
	assertDeliverySignal(t, "successful log force flush cannot clear degradation", tracker.snapshot().Logs, afterLogFlushFailure.Logs)

	assertOriginalError(t, "log Shutdown", logExporter.Shutdown(context.Background()), logShutdownErr)
	afterLogShutdownFailure := tracker.snapshot()
	assertDeliverySignal(t, "logs after failed shutdown", afterLogShutdownFailure.Logs, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateDegraded,
			ExportAttempts:     1,
			ExportSuccesses:    1,
			ForceFlushFailures: 1,
			ShutdownFailures:   1,
			LastSuccessAt:      afterLogSuccess.Logs.LastSuccessAt,
			LastFailureCode:    DeliveryFailureShutdownFailed,
		},
		LastFailureAtMust:      true,
		LastFailureAtNotBefore: afterLogFlushFailure.Logs.LastFailureAt,
	})
	if got := logExporter.Shutdown(context.Background()); got != nil {
		t.Fatalf("successful log Shutdown error = %v, want nil", got)
	}
	assertDeliverySignal(t, "successful log shutdown cannot clear degradation", tracker.snapshot().Logs, afterLogShutdownFailure.Logs)

	if got := logExporter.Export(context.Background(), nil); got != nil {
		t.Fatalf("recovering log Export error = %v, want nil", got)
	}
	logRecovered := tracker.snapshot()
	assertDeliverySignal(t, "logs after export recovery", logRecovered.Logs, expectedDeliverySignal{
		DeliverySignal: DeliverySignal{
			State:              DeliveryStateHealthy,
			ExportAttempts:     2,
			ExportSuccesses:    2,
			ForceFlushFailures: 1,
			ShutdownFailures:   1,
			LastFailureAt:      afterLogShutdownFailure.Logs.LastFailureAt,
			LastFailureCode:    "",
		},
		LastSuccessAtMust:      true,
		LastSuccessAtNotBefore: afterLogShutdownFailure.Logs.LastFailureAt,
	})
	recovered = logRecovered

	for name, signal := range map[string]DeliverySignal{
		"metrics": recovered.Metrics,
		"logs":    recovered.Logs,
	} {
		if signal.ExportAttempts != signal.ExportSuccesses+signal.ExportFailures {
			t.Errorf("%s conservation: attempts=%d successes=%d failures=%d",
				name, signal.ExportAttempts, signal.ExportSuccesses, signal.ExportFailures)
		}
	}

	if got, want := metricDelegate.exportCalls.Load(), int64(2); got != want {
		t.Errorf("metric delegate Export calls = %d, want %d", got, want)
	}
	if got, want := metricDelegate.forceFlushCalls.Load(), int64(2); got != want {
		t.Errorf("metric delegate ForceFlush calls = %d, want %d", got, want)
	}
	if got, want := metricDelegate.shutdownCalls.Load(), int64(2); got != want {
		t.Errorf("metric delegate Shutdown calls = %d, want %d", got, want)
	}
	if got, want := logDelegate.exportCalls.Load(), int64(2); got != want {
		t.Errorf("log delegate Export calls = %d, want %d", got, want)
	}
	if got, want := logDelegate.forceFlushCalls.Load(), int64(2); got != want {
		t.Errorf("log delegate ForceFlush calls = %d, want %d", got, want)
	}
	if got, want := logDelegate.shutdownCalls.Load(), int64(2); got != want {
		t.Errorf("log delegate Shutdown calls = %d, want %d", got, want)
	}
}

func TestDeliveryMetricExporterDelegatesSelectorsExactlyOnce(t *testing.T) {
	tracker := newDeliveryTracker()
	delegate := &fakeMetricExporter{
		temporality: metricdata.DeltaTemporality,
		aggregation: sdkmetric.AggregationDrop{},
	}
	exporter := wrapMetricExporter(delegate, tracker)

	if got := exporter.Temporality(sdkmetric.InstrumentKindCounter); got != metricdata.DeltaTemporality {
		t.Errorf("Temporality = %v, want delta", got)
	}
	if _, ok := exporter.Aggregation(sdkmetric.InstrumentKindCounter).(sdkmetric.AggregationDrop); !ok {
		t.Errorf("Aggregation = %T, want AggregationDrop", exporter.Aggregation(sdkmetric.InstrumentKindCounter))
	}
	if got := delegate.temporalityCalls.Load(); got != 1 {
		t.Errorf("delegate Temporality calls = %d, want 1", got)
	}
	if got := delegate.aggregationCalls.Load(); got != 1 {
		t.Errorf("delegate Aggregation calls = %d, want 1", got)
	}
}

func TestDeliveryTrackerConcurrentIsolationAndConservation(t *testing.T) {
	tracker := newDeliveryTracker()
	metricDelegate := &fakeMetricExporter{exportErr: errors.New("metric failure")}
	logDelegate := &fakeLogExporter{}
	metricExporter := wrapMetricExporter(metricDelegate, tracker)
	logExporter := wrapLogExporter(logDelegate, tracker)

	const calls = 200
	var wg sync.WaitGroup
	wg.Add(calls * 2)
	for range calls {
		go func() {
			defer wg.Done()
			_ = metricExporter.Export(context.Background(), &metricdata.ResourceMetrics{})
		}()
		go func() {
			defer wg.Done()
			_ = logExporter.Export(context.Background(), nil)
		}()
	}
	wg.Wait()

	got := tracker.snapshot()
	if got.Metrics.ExportAttempts != calls || got.Metrics.ExportFailures != calls || got.Metrics.ExportSuccesses != 0 {
		t.Errorf("metric snapshot = %+v, want %d failed exports", got.Metrics, calls)
	}
	if got.Logs.ExportAttempts != calls || got.Logs.ExportSuccesses != calls || got.Logs.ExportFailures != 0 {
		t.Errorf("log snapshot = %+v, want %d successful exports", got.Logs, calls)
	}
	for name, signal := range map[string]DeliverySignal{"metrics": got.Metrics, "logs": got.Logs} {
		if signal.ExportAttempts != signal.ExportSuccesses+signal.ExportFailures {
			t.Errorf("%s conservation: %+v", name, signal)
		}
	}
}

func TestProvider_DeliveryUsesInjectedExporters(t *testing.T) {
	metricDelegate := &fakeMetricExporter{}
	logDelegate := &fakeLogExporter{}
	p, err := newProviderWithExporters(context.Background(), Options{
		ServiceName:    "graph2otel",
		MetricInterval: time.Hour,
	}, metricDelegate, logDelegate)
	if err != nil {
		t.Fatalf("newProviderWithExporters: %v", err)
	}

	p.Emitter().Counter("entra.test.counter", "1", "", 1, nil)
	p.Emitter().LogEvent(Event{Name: "entra.test", Body: "test"})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := p.Delivery()
	if got.Metrics.State != DeliveryStateHealthy || got.Metrics.ExportSuccesses != 1 {
		t.Errorf("metric delivery = %+v, want one accepted export", got.Metrics)
	}
	if got.Logs.State != DeliveryStateHealthy || got.Logs.ExportSuccesses != 1 {
		t.Errorf("log delivery = %+v, want one accepted export", got.Logs)
	}
	if metricDelegate.exportCalls.Load() != 1 || logDelegate.exportCalls.Load() != 1 {
		t.Errorf("delegate exports: metrics=%d logs=%d, want one each",
			metricDelegate.exportCalls.Load(), logDelegate.exportCalls.Load())
	}
}

type expectedDeliverySignal struct {
	DeliverySignal
	LastSuccessAtMust      bool
	LastFailureAtMust      bool
	LastSuccessAtNotBefore string
	LastFailureAtNotBefore string
}

func assertDeliverySignal(t *testing.T, name string, got DeliverySignal, want any) {
	t.Helper()

	expected := expectedDeliverySignal{}
	switch value := want.(type) {
	case DeliverySignal:
		expected.DeliverySignal = value
	case expectedDeliverySignal:
		expected = value
	default:
		t.Fatalf("%s: unsupported expectation type %T", name, want)
	}

	if got.State != expected.State ||
		got.ExportAttempts != expected.ExportAttempts ||
		got.ExportSuccesses != expected.ExportSuccesses ||
		got.ExportFailures != expected.ExportFailures ||
		got.ForceFlushFailures != expected.ForceFlushFailures ||
		got.ShutdownFailures != expected.ShutdownFailures ||
		got.LastFailureCode != expected.LastFailureCode {
		t.Errorf("%s = %+v, want counters/state/code %+v", name, got, expected.DeliverySignal)
	}

	assertTimestamp(t, name+" last_success_at", got.LastSuccessAt, expected.LastSuccessAt, expected.LastSuccessAtMust)
	assertTimestamp(t, name+" last_failure_at", got.LastFailureAt, expected.LastFailureAt, expected.LastFailureAtMust)
	assertTimestampNotBefore(t, name+" last_success_at", got.LastSuccessAt, expected.LastSuccessAtNotBefore)
	assertTimestampNotBefore(t, name+" last_failure_at", got.LastFailureAt, expected.LastFailureAtNotBefore)
}

func assertTimestamp(t *testing.T, name, got, exact string, required bool) {
	t.Helper()
	if exact != "" {
		if got != exact {
			t.Errorf("%s = %q, want %q", name, got, exact)
		}
		return
	}
	if !required {
		if got != "" {
			t.Errorf("%s = %q, want absent", name, got)
		}
		return
	}
	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Errorf("%s = %q, want RFC3339Nano: %v", name, got, err)
		return
	}
	if parsed.Location() != time.UTC || got != parsed.UTC().Format(time.RFC3339Nano) {
		t.Errorf("%s = %q, want canonical UTC RFC3339Nano", name, got)
	}
}

func assertTimestampNotBefore(t *testing.T, name, got, notBefore string) {
	t.Helper()
	if notBefore == "" {
		return
	}
	gotTime, gotErr := time.Parse(time.RFC3339Nano, got)
	notBeforeTime, notBeforeErr := time.Parse(time.RFC3339Nano, notBefore)
	if gotErr != nil || notBeforeErr != nil {
		t.Errorf("%s comparison has invalid timestamp got=%q (%v) notBefore=%q (%v)",
			name, got, gotErr, notBefore, notBeforeErr)
		return
	}
	if gotTime.Before(notBeforeTime) {
		t.Errorf("%s = %q, want >= %q", name, got, notBefore)
	}
}

type deliveryTestError struct {
	text string
}

func (e *deliveryTestError) Error() string { return e.text }

func assertOriginalError(t *testing.T, name string, got error, want *deliveryTestError) {
	t.Helper()
	if reflect.TypeOf(got) != reflect.TypeOf(want) ||
		reflect.ValueOf(got).Pointer() != reflect.ValueOf(want).Pointer() {
		t.Fatalf("%s error = %v (%T), want original error identity %v", name, got, got, want)
	}
}

type fakeMetricExporter struct {
	mu sync.Mutex

	exportErr        error
	exportErrors     []error
	forceFlushErrors []error
	shutdownErrors   []error
	temporality      metricdata.Temporality
	aggregation      sdkmetric.Aggregation
	onExport         func()

	exportCalls      atomic.Int64
	forceFlushCalls  atomic.Int64
	shutdownCalls    atomic.Int64
	temporalityCalls atomic.Int64
	aggregationCalls atomic.Int64
}

func (f *fakeMetricExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	f.temporalityCalls.Add(1)
	return f.temporality
}

func (f *fakeMetricExporter) Aggregation(sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	f.aggregationCalls.Add(1)
	if f.aggregation == nil {
		return sdkmetric.AggregationDefault{}
	}
	return f.aggregation
}

func (f *fakeMetricExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	f.exportCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onExport != nil {
		f.onExport()
	}
	if len(f.exportErrors) > 0 {
		err := f.exportErrors[0]
		f.exportErrors = f.exportErrors[1:]
		return err
	}
	return f.exportErr
}

func (f *fakeMetricExporter) ForceFlush(context.Context) error {
	f.forceFlushCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forceFlushErrors) == 0 {
		return nil
	}
	err := f.forceFlushErrors[0]
	f.forceFlushErrors = f.forceFlushErrors[1:]
	return err
}

func (f *fakeMetricExporter) Shutdown(context.Context) error {
	f.shutdownCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.shutdownErrors) == 0 {
		return nil
	}
	err := f.shutdownErrors[0]
	f.shutdownErrors = f.shutdownErrors[1:]
	return err
}

type fakeLogExporter struct {
	mu sync.Mutex

	exportErr        error
	exportErrors     []error
	forceFlushErrors []error
	shutdownErrors   []error
	onExport         func()

	exportCalls     atomic.Int64
	forceFlushCalls atomic.Int64
	shutdownCalls   atomic.Int64
}

func (f *fakeLogExporter) Export(context.Context, []sdklog.Record) error {
	f.exportCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onExport != nil {
		f.onExport()
	}
	if len(f.exportErrors) > 0 {
		err := f.exportErrors[0]
		f.exportErrors = f.exportErrors[1:]
		return err
	}
	return f.exportErr
}

func (f *fakeLogExporter) ForceFlush(context.Context) error {
	f.forceFlushCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forceFlushErrors) == 0 {
		return nil
	}
	err := f.forceFlushErrors[0]
	f.forceFlushErrors = f.forceFlushErrors[1:]
	return err
}

func (f *fakeLogExporter) Shutdown(context.Context) error {
	f.shutdownCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.shutdownErrors) == 0 {
		return nil
	}
	err := f.shutdownErrors[0]
	f.shutdownErrors = f.shutdownErrors[1:]
	return err
}
