package telemetry_test

import (
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestWithTransportStampsIngestTransport is the core of #141: a record emitted
// through a transport-decorated emitter carries the provenance attribute naming
// the transport that produced it.
func TestWithTransportStampsIngestTransport(t *testing.T) {
	for _, tc := range []struct {
		transport telemetry.Transport
		want      string
	}{
		{telemetry.TransportGraph, "graph"},
		{telemetry.TransportBlob, "blob"},
		{telemetry.TransportO365Activity, "o365_activity"},
		{telemetry.TransportAuditQuery, "audit_query"},
		{telemetry.TransportReportExport, "report_export"},
		{telemetry.TransportMDCA, "mdca"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			rec := telemetrytest.New()
			e := telemetry.WithTransport(rec.Emitter(), tc.transport)

			e.LogEvent(telemetry.Event{Name: "entra.signin", Body: "b"})

			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d log records, want 1", len(logs))
			}
			if got := logs[0].Attrs[semconv.AttrIngestTransport]; got != tc.want {
				t.Errorf("%s = %q, want %q", semconv.AttrIngestTransport, got, tc.want)
			}
		})
	}
}

// TestWithTransportDoesNotMutateCallerAttrs pins the property that makes the
// shared-mapper design safe. mapSignIn is deliberately ONE mapper serving both
// the Graph and blob transports (#141); if the decorator stamped into the map
// the mapper handed it, a caller reusing or concurrently reading that map would
// see another transport's value. The decorator must copy.
func TestWithTransportDoesNotMutateCallerAttrs(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithTransport(rec.Emitter(), telemetry.TransportBlob)

	attrs := telemetry.Attrs{"id": "abc"}
	e.LogEvent(telemetry.Event{Name: "entra.signin", Attrs: attrs})

	if _, ok := attrs[semconv.AttrIngestTransport]; ok {
		t.Fatalf("decorator mutated the caller's Attrs map: %v", attrs)
	}
	if len(attrs) != 1 {
		t.Fatalf("caller's Attrs map changed size: %v", attrs)
	}
}

// TestWithTransportIsConcurrencySafe guards the copy above under -race. Two
// transports sharing one mapper's output is exactly the blob-vs-poll sign-in
// case, and it is the shape a naive in-place stamp would corrupt.
func TestWithTransportIsConcurrencySafe(t *testing.T) {
	rec := telemetrytest.New()
	graph := telemetry.WithTransport(rec.Emitter(), telemetry.TransportGraph)
	blob := telemetry.WithTransport(rec.Emitter(), telemetry.TransportBlob)

	shared := telemetry.Attrs{"id": "abc"}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); graph.LogEvent(telemetry.Event{Name: "e", Attrs: shared}) }()
		go func() { defer wg.Done(); blob.LogEvent(telemetry.Event{Name: "e", Attrs: shared}) }()
	}
	wg.Wait()

	var graphN, blobN int
	for _, l := range rec.LogRecords() {
		switch l.Attrs[semconv.AttrIngestTransport] {
		case "graph":
			graphN++
		case "blob":
			blobN++
		}
	}
	if graphN != 50 || blobN != 50 {
		t.Errorf("got graph=%d blob=%d, want 50/50 — stamps crossed between transports", graphN, blobN)
	}
}

// TestWithTransportOverwritesNothingElse pins that the decorator adds exactly
// one key and leaves every other attribute untouched — the AC that a blob and a
// Graph record for the same event stay identical in every other respect, so
// they remain dedupe-able on `id`.
func TestWithTransportPreservesEveryOtherAttribute(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithTransport(rec.Emitter(), telemetry.TransportBlob)

	e.LogEvent(telemetry.Event{
		Name:  "entra.signin",
		Body:  "body",
		Attrs: telemetry.Attrs{"id": "abc", "user_principal_name": "a@b.c", "source": "passthrough"},
	})

	got := rec.LogRecords()[0].Attrs
	for k, want := range map[string]string{
		"id":                  "abc",
		"user_principal_name": "a@b.c",
		// `source` has three live meanings already (#141); the provenance
		// attribute must not be one of them, and must not clobber a collector's.
		"source": "passthrough",
	} {
		if got[k] != want {
			t.Errorf("attr %q = %q, want %q", k, got[k], want)
		}
	}
	if rec.LogRecords()[0].EventName != "entra.signin" {
		t.Errorf("EventName = %q, want entra.signin", rec.LogRecords()[0].EventName)
	}
}

// TestWithTransportOutermostStampWins pins the precedence the two-layer wiring
// depends on. The Scheduler hands every collector a TransportGraph-wrapped
// emitter (the truthful default for the 15 SnapshotCollectors that poll Graph
// and emit inline). An ingest engine wraps that emitter AGAIN at its own
// LogEvent site, so the engine's wrapper is outermost. If the inner Scheduler
// wrapper overwrote, every blob/o365/job record would be mislabeled "graph" —
// silently, and in exactly the direction that makes the attribute useless.
func TestWithTransportOutermostStampWins(t *testing.T) {
	rec := telemetrytest.New()
	// inner = what the Scheduler hands a collector; outer = what the engine wraps it in.
	inner := telemetry.WithTransport(rec.Emitter(), telemetry.TransportGraph)
	outer := telemetry.WithTransport(inner, telemetry.TransportBlob)

	outer.LogEvent(telemetry.Event{Name: "entra.signin"})

	if got := rec.LogRecords()[0].Attrs[semconv.AttrIngestTransport]; got != "blob" {
		t.Errorf("%s = %q, want \"blob\" — the inner Scheduler stamp clobbered the engine's",
			semconv.AttrIngestTransport, got)
	}
}

// TestWithTransportLeavesMetricsUnstamped pins a deliberate scope boundary.
// Provenance is LOG-ONLY: adding a label to a metric changes that metric's
// series identity, which would silently break every existing dashboard and
// alert built on it (#82's normalized names). Logs take attributes as Loki
// structured metadata (#90), so adding one there is non-breaking.
func TestWithTransportLeavesMetricsUnstamped(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithTransport(rec.Emitter(), telemetry.TransportBlob)

	e.Gauge("entra.signin.count", "1", "d", 1, telemetry.Attrs{"status": "ok"})

	pts := rec.MetricPoints("entra.signin.count")
	if len(pts) != 1 {
		t.Fatalf("got %d metric points, want 1", len(pts))
	}
	if _, ok := pts[0].Attrs[semconv.AttrIngestTransport]; ok {
		t.Errorf("metric carries %s; provenance is log-only (would change series identity): %v",
			semconv.AttrIngestTransport, pts[0].Attrs)
	}
}
