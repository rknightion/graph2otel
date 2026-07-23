package main

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
)

// These gates live in package main for the same reason the collectordoc gates
// do (#139): the registry is populated only by the blank imports in
// collectors_import.go, which is package main's own file. Any other home would
// need its own copy of that import list, and a collector added to production
// but missed off the copy would be invisible to the very gate meant to see it.

// knownConflictPairs is every pair of collectors that ship the SAME records
// over different transports, measured live on camden 2026-07-16 (#144): the
// polled collector's own checkpoint seen_ids intersected against the ids in its
// blob container gave 18/18 and 1375/1375 — total overlap, not partial.
//
// The list is here, in a TEST, and deliberately NOT in production code. A
// central list in production is what went blind in #139/#100; production reads
// the declaration off each collector, and this table's only job is to fail when
// a declaration that was measured to be necessary goes missing.
var knownConflictPairs = [][2]string{
	{"entra.signins.non_interactive.blob", "entra.signins.non_interactive"},
	{"entra.signins.service_principal.blob", "entra.signins.service_principal"},
	{"m365.activity", "m365.unified_audit"},
}

// registeredCollectors constructs every registered collector, from every
// registration path, exactly as registrySnapshot does for the doc gates.
func registeredCollectors(t *testing.T) []collector.Collector {
	t.Helper()
	snapshot, window, blob, o365, mdca, exo, hunt := registrySnapshot()
	var out []collector.Collector
	for _, group := range [][]any{snapshot, window, blob, o365, mdca, exo, hunt} {
		for _, c := range group {
			cc, ok := c.(collector.Collector)
			if !ok {
				t.Fatalf("%T does not implement collector.Collector", c)
			}
			out = append(out, cc)
		}
	}
	return out
}

func collectorsByName(t *testing.T) map[string]collector.Collector {
	t.Helper()
	byName := map[string]collector.Collector{}
	for _, c := range registeredCollectors(t) {
		byName[c.Name()] = c
	}
	return byName
}

// TestEveryKnownConflictPairFires is the acceptance test: each measured pair,
// registered together, must refuse to start.
func TestEveryKnownConflictPairFires(t *testing.T) {
	byName := collectorsByName(t)
	for _, pair := range knownConflictPairs {
		declarer, peer := pair[0], pair[1]
		a, ok := byName[declarer]
		if !ok {
			t.Fatalf("collector %q is not registered — the conflict pair table is stale", declarer)
		}
		b, ok := byName[peer]
		if !ok {
			t.Fatalf("collector %q is not registered — the conflict pair table is stale", peer)
		}
		if err := collectors.CheckConflicts([]collector.Collector{a, b}); err == nil {
			t.Errorf("CheckConflicts(%q, %q) = nil, want an error — these were measured shipping every record twice (#144); %q must declare ConflictsWith(%q)",
				declarer, peer, declarer, peer)
		}
	}
}

// TestInteractiveAndNonInteractiveSignInsDoNotConflict is THE false-positive
// guard, and the reason conflicts are declared rather than derived (#144).
//
// Both collectors emit event name "entra.signin", both poll /auditLogs/signIns,
// and they are the single most common sign-in configuration there is. They are
// disjoint slices of one endpoint — different signInEventTypes, no shared id —
// so running both is correct and must start. Any check that reasons from the
// event name, the endpoint, or the name prefix fails here.
func TestInteractiveAndNonInteractiveSignInsDoNotConflict(t *testing.T) {
	byName := collectorsByName(t)
	interactive, ok := byName["entra.signins.interactive"]
	if !ok {
		t.Fatal("entra.signins.interactive is not registered")
	}
	nonInteractive, ok := byName["entra.signins.non_interactive"]
	if !ok {
		t.Fatal("entra.signins.non_interactive is not registered")
	}
	if err := collectors.CheckConflicts([]collector.Collector{interactive, nonInteractive}); err != nil {
		t.Errorf("CheckConflicts fired for entra.signins.interactive + entra.signins.non_interactive: %v\n"+
			"They emit the same event name over the same endpoint but carry DISJOINT records — this is a legitimate, common config and must start. A conflict derived from the event name produces exactly this false positive.", err)
	}
}

// TestMicrosoftServicePrincipalSignInsDeclareNoConflict pins the other side of
// the same judgment. entra.signins.microsoft_service_principal sits in the same
// spec table as the two blob twins that DO conflict, so a copy-pasted
// declaration is the likely mistake — but its records are Microsoft's own
// first-party service-to-service auth, live-sampled at ZERO id overlap with the
// polled service-principal stream, and it has no Graph endpoint at all. It is a
// disjoint dataset. It must never suppress the polled stream.
func TestMicrosoftServicePrincipalSignInsDeclareNoConflict(t *testing.T) {
	byName := collectorsByName(t)
	msp, ok := byName["entra.signins.microsoft_service_principal"]
	if !ok {
		t.Fatal("entra.signins.microsoft_service_principal is not registered")
	}
	if d, isDeclarer := msp.(collectors.ConflictsWith); isDeclarer && len(d.ConflictsWith()) > 0 {
		t.Errorf("entra.signins.microsoft_service_principal declares ConflictsWith(%v) — it has no polled twin; 160/160 sampled records were Microsoft-tenant-owned and ZERO sign-in ids overlapped the polled stream (#135)", d.ConflictsWith())
	}
}

// TestConflictCheckSeesEveryRegistrationPath is the #139/#100 gate.
//
// The three conflicting pairs straddle three different construction paths —
// blob (BlobAll) against window (WindowAll) for the two sign-in pairs, and o365
// (O365All) against window for m365 — so a check fed from fewer paths than the
// binary registers reports fewer conflicts than exist, and passes because it is
// BLIND rather than because it is satisfied. That is not hypothetical: it is
// exactly what happened to collectordoc.Rows when O365All() landed.
//
// Feeding the union of every path and asserting every measured pair is reported
// is what makes that failure visible: drop a path from registrySnapshot (or add
// a fifth and forget it) and this fails by name.
func TestConflictCheckSeesEveryRegistrationPath(t *testing.T) {
	err := collectors.CheckConflicts(registeredCollectors(t))
	if err == nil {
		t.Fatal("CheckConflicts over the whole registry returned nil — every measured conflict pair is registered, so it must report all of them")
	}
	for _, pair := range knownConflictPairs {
		if !strings.Contains(err.Error(), pair[0]) || !strings.Contains(err.Error(), pair[1]) {
			t.Errorf("the whole-registry conflict error does not name the %q/%q pair — the check cannot see one of the registration paths (#139):\n%v",
				pair[0], pair[1], err)
		}
	}
}

// TestCheckRegistryConflicts_FiresOverTheAssembledRegistry exercises what the
// composition root actually calls, over what it actually builds.
//
// The two collectors here reach the registry through DIFFERENT construction
// paths — the blob twin via collectors.BlobAll() -> Registry.Register, the
// polled twin via collectors.WindowAll() -> Registry.RegisterWindow — so this
// pins the property the whole design rests on: every path converges on one
// collector.Registry, and walking that registry sees all of them without
// knowing how many there are.
func TestCheckRegistryConflicts_FiresOverTheAssembledRegistry(t *testing.T) {
	byName := collectorsByName(t)

	blobTwin, ok := byName["entra.signins.non_interactive.blob"].(collector.SnapshotCollector)
	if !ok {
		t.Fatal("entra.signins.non_interactive.blob is not a SnapshotCollector")
	}
	polledTwin, ok := byName["entra.signins.non_interactive"].(collector.WindowCollector)
	if !ok {
		t.Fatal("entra.signins.non_interactive is not a WindowCollector")
	}

	reg := collector.NewRegistry()
	reg.Register(blobTwin, time.Minute)
	reg.RegisterWindow(polledTwin, time.Minute, time.Hour, time.Hour)

	if err := checkRegistryConflicts(reg); err == nil {
		t.Error("checkRegistryConflicts returned nil for a registry holding both transports of the same sign-in records — the process must refuse to start (#144)")
	}
}

// TestCheckRegistryConflicts_SilentOnTheSupportedConfig is the other half: blob
// ingest on, the polled beta twin off. That is the documented way to run this,
// and it must start.
func TestCheckRegistryConflicts_SilentOnTheSupportedConfig(t *testing.T) {
	byName := collectorsByName(t)
	blobTwin, ok := byName["entra.signins.non_interactive.blob"].(collector.SnapshotCollector)
	if !ok {
		t.Fatal("entra.signins.non_interactive.blob is not a SnapshotCollector")
	}
	interactive, ok := byName["entra.signins.interactive"].(collector.WindowCollector)
	if !ok {
		t.Fatal("entra.signins.interactive is not a WindowCollector")
	}

	reg := collector.NewRegistry()
	reg.Register(blobTwin, time.Minute)
	reg.RegisterWindow(interactive, time.Minute, time.Hour, time.Hour)

	if err := checkRegistryConflicts(reg); err != nil {
		t.Errorf("checkRegistryConflicts fired on blob non-interactive + polled interactive, which carry disjoint records: %v", err)
	}
}

// TestConflictDeclarationsNameRegisteredCollectors catches the silent typo. A
// declaration naming "entra.signins.non_interctive" is never registered, so it
// never fires, so the collector looks guarded and is not. Nothing else in the
// build would notice: the peer is a string, not a symbol.
func TestConflictDeclarationsNameRegisteredCollectors(t *testing.T) {
	byName := collectorsByName(t)
	for _, c := range registeredCollectors(t) {
		d, ok := c.(collectors.ConflictsWith)
		if !ok {
			continue
		}
		// An empty declaration is legitimate and deliberately not an error: the
		// three sign-in blob categories share one impl type, so the one with no
		// polled twin implements the interface and returns nil. That is the
		// correct shape — the fact is per-spec, not per-type.
		for _, peer := range d.ConflictsWith() {
			if _, exists := byName[peer]; !exists {
				t.Errorf("%q declares a conflict with %q, which is not a registered collector — a peer is a string, not a symbol, so this typo would never fire and the collector only LOOKS guarded", c.Name(), peer)
			}
			if peer == c.Name() {
				t.Errorf("%q declares a conflict with itself — it is registered by definition, so this would refuse every boot if the check did not guard it", c.Name())
			}
		}
	}
}
