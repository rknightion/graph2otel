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

// TestSchedulerGetsTheTenantBaseline guards the composition-root line that makes
// every domain signal tenant-attributable (#143).
//
// Same weakness and same justification as the transport test above: setupTenant
// needs a live credential to reach a Scheduler, so this proves the line is
// present, not that it works — internal/telemetry's tenant tests prove the
// behavior, including the parse-the-interface gate that stops a new Emitter
// method shipping unstamped.
//
// What makes it worth having anyway: this is the ONLY place a tenant reaches
// domain telemetry. Drop this wrap and nothing else in the tree fails — every
// collector still emits, every test still passes, and two tenants' metrics
// quietly become one series again. That is the failure this line exists to
// prevent, so it is exactly the line worth pinning.
func TestSchedulerGetsTheTenantBaseline(t *testing.T) {
	src, err := os.ReadFile("tenants.go")
	if err != nil {
		t.Fatalf("reading tenants.go: %v", err)
	}
	const want = "telemetry.WithTenant("
	if !strings.Contains(string(src), want) {
		t.Errorf("the Scheduler is not handed a tenant-stamped emitter: expected %s.\n"+
			"Without it, domain metrics carry no tenant_id — and because there is one MeterProvider\n"+
			"and one resource for the process, two tenants' identical series collide and interleave.\n"+
			"A multi-tenant deploy then reports a meaningless number, not a coarse one (#143).", want)
	}
}
