package o365pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// newActivityCollectorForTest wires a real client + real engine at the fake API,
// wrapped in the ActivityCollector adapter under test.
func newActivityCollectorForTest(t *testing.T, f *fakeAPI, cts ...o365activityclient.ContentType) *ActivityCollector {
	t.Helper()
	return NewActivityCollector(
		"m365.test", 10*time.Minute, 5*time.Minute,
		f.client(t), newStore(t), testConfig(cts...),
	)
}

// TestActivityCollectorReportsItsSchedule pins the three scalar accessors the
// scheduler reads. They are trivial, and that is the point: they are the reason
// the adapter exists at all — o365pipeline.Collector exposes Collect(ctx, from,
// to, e) error, while collector.WindowCollector wants CollectWindow plus
// Name/DefaultInterval/Lag.
func TestActivityCollectorReportsItsSchedule(t *testing.T) {
	f := newFakeAPI(t)
	c := newActivityCollectorForTest(t, f)

	if got := c.Name(); got != "m365.test" {
		t.Errorf("Name() = %q, want m365.test", got)
	}
	if got := c.DefaultInterval(); got != 10*time.Minute {
		t.Errorf("DefaultInterval() = %s, want 10m", got)
	}
	if got := c.Lag(); got != 5*time.Minute {
		t.Errorf("Lag() = %s, want 5m", got)
	}
}

// TestActivityCollectorCollectWindowDrainsTheFeed proves the adapter actually
// delegates to the engine rather than merely satisfying the interface: a full
// subscribe -> list -> fetch -> map -> emit cycle must run through it.
func TestActivityCollectorCollectWindowDrainsTheFeed(t *testing.T) {
	base := testBase()
	f := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base,
		records:     []map[string]any{rec("rec-a", base), rec("rec-b", base)},
	})
	c := newActivityCollectorForTest(t, f, o365activityclient.ContentExchange)
	recorder := telemetrytest.New()

	to := base.Add(time.Hour)
	if _, err := c.CollectWindow(context.Background(), base.Add(-time.Hour), to, recorder.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	if got, want := bodies(recorder.LogRecords()), []string{"rec-a", "rec-b"}; len(got) != len(want) {
		t.Fatalf("emitted %v, want %v — the adapter did not drive the engine", got, want)
	}
}

// TestActivityCollectorReturnsToAsHighWaterMark pins the documented return: the
// engine keeps its OWN durable watermark in the checkpoint store, so the value
// handed back to the scheduler is cosmetic. Returning `to` says that out loud —
// a zero return would be equivalent, since the scheduler substitutes `to` for a
// zero hwm.
func TestActivityCollectorReturnsToAsHighWaterMark(t *testing.T) {
	base := testBase()
	f := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base,
		records:     []map[string]any{rec("rec-a", base)},
	})
	c := newActivityCollectorForTest(t, f, o365activityclient.ContentExchange)

	to := base.Add(time.Hour)
	hwm, err := c.CollectWindow(context.Background(), base.Add(-time.Hour), to, telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if !hwm.Equal(to) {
		t.Errorf("CollectWindow hwm = %s, want %s (`to`)", hwm.Format(time.RFC3339), to.Format(time.RFC3339))
	}
}

// TestActivityCollectorReturnsZeroHighWaterMarkOnError pins the failure path's
// return, which the adapter move must preserve rather than improve.
//
// Deliberately NOT claiming this prevents data loss. It does not: the scheduler
// discards the hwm whenever err is non-nil (scheduler.go:308-314 returns before
// touching the checkpoint), so `to` would be equally safe. What this pins is that
// the value handed back is not a false claim about a window that was never
// drained — see the CollectWindow doc.
func TestActivityCollectorReturnsZeroHighWaterMarkOnError(t *testing.T) {
	base := testBase()
	f := newFakeAPI(t, blobSpec{
		contentType: o365activityclient.ContentExchange,
		contentID:   "blob-1",
		created:     base,
		records:     []map[string]any{rec("rec-a", base)},
		errCode:     o365activityclient.CodeInternalError,
		errStatus:   400,
	})
	c := newActivityCollectorForTest(t, f, o365activityclient.ContentExchange)

	hwm, err := c.CollectWindow(context.Background(), base.Add(-time.Hour), base.Add(time.Hour), telemetrytest.New().Emitter())
	if err == nil {
		t.Fatal("CollectWindow returned nil error on a failing blob fetch")
	}
	if !hwm.IsZero() {
		t.Errorf("CollectWindow hwm = %s on error, want zero — a non-zero hwm advances the scheduler over an undrained window",
			hwm.Format(time.RFC3339))
	}
}
