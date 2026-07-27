package telemetry_test

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// horizonAt builds a horizon-guarded emitter whose clock is pinned to now.
func horizonAt(
	t *testing.T, now time.Time, horizon time.Duration,
) (*telemetrytest.Recorder, telemetry.Emitter) {
	t.Helper()
	rec := telemetrytest.New()
	e := telemetry.WithEventHorizon(
		rec.Emitter(), horizon, "intune.compliance_alert", "tenant-a",
		telemetry.Transport("blob"), func() time.Time { return now },
	)
	return rec, e
}

func TestARecordJustInsideTheHorizonIsSent(t *testing.T) {
	// The off-by-one that matters most. A guard that is one tick too tight
	// silently truncates good data, and the truncation looks exactly like the
	// source having gone quiet.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Body:      "inside",
		Timestamp: now.Add(-telemetry.EventHorizon),
	})

	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("a record exactly at the horizon was dropped: got %d log records, want 1", got)
	}
	if points := rec.MetricPoints("graph2otel.event.over_horizon"); len(points) != 0 {
		t.Fatalf("a record at the horizon was counted as over it: %+v", points)
	}
}

func TestARecordOlderThanTheHorizonIsNeverSent(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Body:      "too old",
		Timestamp: now.Add(-telemetry.EventHorizon - time.Second),
	})

	if got := len(rec.LogRecords()); got != 0 {
		t.Fatalf("an over-horizon record was sent and would be rejected: got %d log records, want 0", got)
	}
}

func TestTheProductionRejectionCaseIsCaught(t *testing.T) {
	// The exact record shape observed being rejected on 2026-07-27: an event time
	// about one hour past seven days. A guard at exactly 7d would let this pass
	// and lose it; 165h catches it.
	now := time.Date(2026, 7, 27, 19, 21, 56, 0, time.UTC)
	observed := time.Date(2026, 7, 20, 18, 15, 15, 0, time.UTC)
	if age := now.Sub(observed); age <= 7*24*time.Hour {
		t.Fatalf("fixture no longer reproduces the case: age %v is inside 7 days", age)
	}
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{Name: "intune.compliance_alert", Timestamp: observed})

	if got := len(rec.LogRecords()); got != 0 {
		t.Fatalf("the production rejection case was still emitted: got %d, want 0", got)
	}
}

func TestADropIsCountedAndAttributed(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Timestamp: now.Add(-30 * 24 * time.Hour),
	})

	points := rec.MetricPoints("graph2otel.event.over_horizon")
	if len(points) != 1 {
		t.Fatalf("over-horizon drop was not counted: got %d points, want 1", len(points))
	}
	if points[0].Value != 1 {
		t.Errorf("drop count = %v, want 1", points[0].Value)
	}
	for key, want := range map[string]string{
		semconv.AttrCollector:       "intune.compliance_alert",
		semconv.AttrTenantID:        "tenant-a",
		semconv.AttrIngestTransport: "blob",
	} {
		if got := points[0].Attrs[key]; got != want {
			t.Errorf("attr %s = %v, want %q — a drop nobody can attribute is barely better than a silent one",
				key, got, want)
		}
	}
}

func TestAStampedTransportWinsOverTheCollectorDefault(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Timestamp: now.Add(-30 * 24 * time.Hour),
		Attrs:     telemetry.Attrs{semconv.AttrIngestTransport: "report_export"},
	})

	points := rec.MetricPoints("graph2otel.event.over_horizon")
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if got := points[0].Attrs[semconv.AttrIngestTransport]; got != "report_export" {
		t.Errorf("ingest_transport = %v, want report_export (the outermost stamp wins)", got)
	}
}

func TestAnUndatedRecordIsNotThisGuardsBusiness(t *testing.T) {
	// A record with no event time has nothing to judge. Dropping it here would
	// duplicate a decision already made where the event time is parsed, and
	// counting it as over-horizon would be a false attribution.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{Name: "intune.compliance_alert", Body: "undated"})

	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("an undated record was swallowed by the horizon guard: got %d, want 1", got)
	}
	if points := rec.MetricPoints("graph2otel.event.over_horizon"); len(points) != 0 {
		t.Fatalf("an undated record was counted as over-horizon: %+v", points)
	}
}

func TestAFutureDatedRecordIsSent(t *testing.T) {
	// Clock skew on the source side produces a negative age. That is a different
	// problem and not one this guard should convert into data loss.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Timestamp: now.Add(time.Hour),
	})

	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("a future-dated record was dropped: got %d, want 1", got)
	}
}

func TestAZeroHorizonDisablesTheGuard(t *testing.T) {
	// The escape hatch for a self-hosted Loki or non-Loki sink with a wider accept
	// window. It must be a real no-op, not a smaller number.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, 0)

	e.LogEvent(telemetry.Event{
		Name:      "intune.compliance_alert",
		Timestamp: now.Add(-365 * 24 * time.Hour),
	})

	if got := len(rec.LogRecords()); got != 1 {
		t.Fatalf("a zero horizon still dropped a record: got %d, want 1", got)
	}
}

func TestTheGuardNeverRestampsARecord(t *testing.T) {
	// Making an over-age record deliverable by stamping it "now" would claim the
	// event happened days after it did. Misdated is wrong; wrong is worse than
	// absent. This pins that the in-window record's timestamp is passed through
	// untouched.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)
	original := now.Add(-100 * time.Hour)

	e.LogEvent(telemetry.Event{Name: "intune.compliance_alert", Timestamp: original})

	records := rec.LogRecords()
	if len(records) != 1 {
		t.Fatalf("got %d log records, want 1", len(records))
	}
	if !records[0].Timestamp.Equal(original) {
		t.Errorf("timestamp = %v, want %v — the guard must never restamp", records[0].Timestamp, original)
	}
}

func TestMetricsAndOtherSignalsPassThroughUnaffected(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	rec, e := horizonAt(t, now, telemetry.EventHorizon)

	e.Counter("graph2otel.test.counter", semconv.UnitRecords, "desc", 3, nil)
	e.Gauge("graph2otel.test.gauge", semconv.UnitRecords, "desc", 7, nil)

	if points := rec.MetricPoints("graph2otel.test.counter"); len(points) != 1 {
		t.Errorf("counter did not pass through: got %d points", len(points))
	}
	if points := rec.MetricPoints("graph2otel.test.gauge"); len(points) != 1 {
		t.Errorf("gauge did not pass through: got %d points", len(points))
	}
}

func TestTheHorizonLeavesRoomBelowTheMeasuredAcceptWindow(t *testing.T) {
	// The margin is the whole reason this is 165h and not 168h. A production
	// rejection was observed only ~1h past the limit, so a guard set at exactly
	// the window would still lose records to skew and flush latency.
	const acceptWindow = 7 * 24 * time.Hour
	if telemetry.EventHorizon >= acceptWindow {
		t.Fatalf("horizon %v is not inside the measured %v accept window",
			telemetry.EventHorizon, acceptWindow)
	}
	if margin := acceptWindow - telemetry.EventHorizon; margin < 2*time.Hour {
		t.Fatalf("margin %v is too thin to absorb clock skew and flush latency", margin)
	}
}
