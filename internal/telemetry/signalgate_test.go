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

	provider := telemetry.NewSelfObsProviderForTest(selfObs.Emitter(), card, limiter)
	provider.ReportSelfObs()
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
