package main

import (
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collectors"
)

// derivesMetrics is the interface blobpipeline.BlobCollector satisfies. Every
// collector subpackage wraps *BlobCollector in a package-local named type, so a
// type assertion to the concrete type would fail — embedding promotes the
// method, so assert on the method instead.
type derivesMetrics interface{ DerivesMetrics() bool }

// TestBlobIntervalMatchesWhetherTheCollectorDerivesMetrics is the #425 gate.
//
// Before this, eleven blob collectors each declared a private `5 * time.Minute`
// — one decision copy-pasted eleven times, with its rationale stated in exactly
// one of them. Every ListBlobs is a billed transaction and the freshness floor
// is Azure-side, so log-only collectors take the slower shared default.
//
// The two that also derive metrics cannot: their tick is an input to #128's
// metric-recency gate. A record appended just after a tick is not read until
// the next, so its age at the gate is up to `tick + Azure write latency`. At
// 15m that lands level with the 20m window and the tail of every batch stops
// counting toward metrics — silently, since the logs stay complete.
//
// The gate keys on DerivesMetrics() rather than on a hand-written list of
// names, so adding Derive to a log-only collector fails here instead of quietly
// gating its new metrics away. That is the whole point: the invariant is about
// the REASON, and a name list would go stale the moment a twelfth collector
// lands.
//
// It lives in package main because that is the only place every collector
// subpackage is imported, so their init()-time RegisterBlob calls have all run
// — the same reason blobPathNames in source_test.go walks the path from here.
func TestBlobIntervalMatchesWhetherTheCollectorDerivesMetrics(t *testing.T) {
	factories := collectors.BlobAll()
	if len(factories) == 0 {
		t.Fatal("BlobAll() is empty — registration did not run, so this gate proves nothing")
	}

	var logOnly, metric int
	for _, bf := range factories {
		c := bf(collectors.BlobDeps{TenantID: "t"})
		dm, ok := c.(derivesMetrics)
		if !ok {
			t.Errorf("blob collector %q does not expose DerivesMetrics() — it is not built on "+
				"blobpipeline.BlobCollector, so this gate cannot see its cadence", c.Name())
			continue
		}

		want := blobpipeline.DefaultInterval
		if dm.DerivesMetrics() {
			want = blobpipeline.MetricDerivingInterval
			metric++
		} else {
			logOnly++
		}
		if got := c.DefaultInterval(); got != want {
			t.Errorf("blob collector %q derives_metrics=%v: DefaultInterval() = %v, want %v",
				c.Name(), dm.DerivesMetrics(), got, want)
		}
	}

	// Both sides must be exercised, or a future change that made every collector
	// log-only would leave the metric-deriving half of this contract unasserted
	// while the test still passed.
	if metric == 0 {
		t.Error("no metric-deriving blob collector found — the pinned-cadence half of this gate is unasserted")
	}
	if logOnly == 0 {
		t.Error("no log-only blob collector found — the shared-default half of this gate is unasserted")
	}
}

// TestBlobIngestIntervalOverridesTheLogOnlyDefault pins the #425 config knob:
// blob_ingest.interval retunes every LOG-ONLY blob collector for a tenant, and
// leaves the metric-deriving ones alone. An operator turning the cadence down
// to save on listing must not silently break the two metric streams — that is
// the reason those two are exempt, and it is only a real guarantee if a test
// says so.
func TestBlobIngestIntervalOverridesTheLogOnlyDefault(t *testing.T) {
	const configured = 42 * time.Minute

	for _, bf := range collectors.BlobAll() {
		c := bf(collectors.BlobDeps{TenantID: "t", Interval: configured})
		dm, ok := c.(derivesMetrics)
		if !ok {
			continue // already reported by the gate above
		}
		want := configured
		if dm.DerivesMetrics() {
			want = blobpipeline.MetricDerivingInterval
		}
		if got := c.DefaultInterval(); got != want {
			t.Errorf("blob collector %q derives_metrics=%v with blob_ingest.interval=%v: "+
				"DefaultInterval() = %v, want %v", c.Name(), dm.DerivesMetrics(), configured, got, want)
		}
	}
}
