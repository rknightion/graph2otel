package telemetry_test

import (
	"flag"
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "update testdata/signals.json")

// TestSignalGolden captures the production Provider.ReportSelfObs surface
// through one dedicated recorder. The separate seed recorder is deliberately
// excluded from GoldenAt: entra.capture.counter exists only to exercise the
// limiter's clipped branch and is not a production self-observability signal.
func TestSignalGolden(t *testing.T) {
	selfObs := telemetrytest.New()
	seed := telemetrytest.New()
	card := telemetry.NewCardinalityTrackerForLimit(1)
	limiter := telemetry.NewLimiter(telemetry.Limits{PerMetric: 1, Global: 10})
	limited := limiter.Wrap(seed.Emitter())

	for _, path := range []string{"a", "b", "c"} {
		limited.Counter(
			"entra.capture.counter",
			"{request}",
			"Test-only seed that forces the limiter's production clipped branch.",
			1,
			telemetry.Attrs{"path": path},
		)
	}
	card.Observe("entra.capture.counter", telemetry.Attrs{
		semconv.AttrTenantID: "tenant-capture",
		"path":               "a",
	})

	provider := telemetry.NewSelfObsProviderForTest(
		selfObs.Emitter(),
		card,
		limiter,
		telemetry.DeliverySnapshot{
			Metrics: telemetry.DeliverySignal{
				State:              telemetry.DeliveryStateDegraded,
				ExportAttempts:     1,
				ExportFailures:     1,
				ForceFlushFailures: 1,
				ShutdownFailures:   1,
				LastFailureCode:    telemetry.DeliveryFailureShutdownFailed,
			},
			Logs: telemetry.DeliverySignal{
				State:           telemetry.DeliveryStateHealthy,
				ExportAttempts:  1,
				ExportSuccesses: 1,
			},
		},
	)
	provider.ReportSelfObs()
	gotMetricNames := map[string]bool{}
	for _, name := range selfObs.MetricNames() {
		gotMetricNames[name] = true
	}
	for _, name := range []string{
		"graph2otel.otlp.delivery.export_attempts",
		"graph2otel.otlp.delivery.export_successes",
		"graph2otel.otlp.delivery.export_failures",
		"graph2otel.otlp.delivery.force_flush_failures",
		"graph2otel.otlp.delivery.shutdown_failures",
		"graph2otel.otlp.delivery.degraded",
	} {
		if !gotMetricNames[name] {
			t.Errorf("signal capture missing Provider.ReportSelfObs delivery metric %s", name)
		}
	}
	telemetry.WithEventLag(
		telemetry.WithTenant(metricOnlyEmitter{Emitter: selfObs.Emitter()}, "tenant-capture"),
		"entra.capture",
		"tenant-capture",
		telemetry.TransportGraph,
		func() time.Time { return time.Unix(100, 0) },
	).LogEvent(telemetry.Event{
		Name:      "entra.capture",
		Timestamp: time.Unix(99, 0),
	})

	// Capture the over-horizon drop counter (#401) so it reaches the signal
	// catalog and therefore the coverage gate. Nothing else emits it: it only
	// fires on a record the backend would reject, which no collector test
	// produces, so without this the one metric that reports silent data loss
	// would itself be invisible to the dashboard gate.
	telemetry.WithEventHorizon(
		telemetry.WithTenant(metricOnlyEmitter{Emitter: selfObs.Emitter()}, "tenant-capture"),
		telemetry.EventHorizon,
		"entra.capture",
		"tenant-capture",
		telemetry.TransportGraph,
		func() time.Time { return time.Unix(100, 0).Add(telemetry.EventHorizon + time.Hour) },
	).LogEvent(telemetry.Event{
		Name:      "entra.capture",
		Timestamp: time.Unix(100, 0),
	})

	if err := signalcapture.GoldenAt(
		filepath.Join("testdata", "signals.json"),
		*updateSignalGolden,
		selfObs,
	); err != nil {
		t.Fatal(err)
	}
}

// metricOnlyEmitter lets this package's golden exercise the production
// event-lag metric without registering its test seed as a production log name.
type metricOnlyEmitter struct{ telemetry.Emitter }

func (metricOnlyEmitter) LogEvent(telemetry.Event) {}
