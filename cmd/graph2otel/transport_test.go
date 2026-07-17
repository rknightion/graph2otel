package main

import (
	"os"
	"strings"
	"testing"
)

// TestSchedulerGetsTheGraphTransportBaseline guards the single composition-root
// line that names the transport for twelve collectors (#141).
//
// The four ingest engines and the three exportjob collectors stamp themselves,
// and each of those has a behavioral test in its own package. The twelve
// remaining direct emitters — the SnapshotCollector log twins, entra/risk being
// the reference shape — poll Graph and emit inline with no engine, so their only
// stamp is the one the Scheduler's emitter carries. Nothing else in the tree
// would notice if that wrap were dropped: the records would simply ship with no
// provenance at all, silently, on a quarter of the collectors.
//
// This asserts on source text rather than behavior because setupTenant needs a
// live credential to reach a Scheduler, so there is no cheap way to observe the
// wiring at runtime. It is a weaker gate than the engine tests and is meant to
// be: it proves the line is present, not that it works — the decorator's own
// tests in internal/telemetry prove that part.
func TestSchedulerGetsTheGraphTransportBaseline(t *testing.T) {
	src, err := os.ReadFile("tenants.go")
	if err != nil {
		t.Fatalf("reading tenants.go: %v", err)
	}
	const want = "telemetry.WithTransport(emitter, telemetry.TransportGraph)"
	if !strings.Contains(string(src), want) {
		t.Errorf("the Scheduler is not handed a transport-stamped emitter: expected %s.\n"+
			"Without it the twelve engine-less SnapshotCollectors emit with no ingest_transport, "+
			"and an operator filtering by transport silently misses them (#141).", want)
	}
}
