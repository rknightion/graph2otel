package main

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
)

// blobPathNames / windowPathNames enumerate the collector names reachable
// through each registration path, constructed with dummy deps (Name() touches
// no live dependency).
func blobPathNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, bf := range collectors.BlobAll() {
		names[bf(collectors.BlobDeps{TenantID: "t"}).Name()] = true
	}
	return names
}

func windowPathNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, wf := range collectors.WindowAll() {
		rw := wf(collectors.WindowDeps{TenantID: "t"})
		if rw.Collector != nil {
			names[rw.Collector.Name()] = true
		}
	}
	return names
}

// TestGroupDBlobTwinsShareTheirPolledName pins the structural precondition the
// source toggle rests on (#135 group D): entra.directory_audits and
// entra.provisioning each register through BOTH the window (polled) path AND the
// blob path under the SAME name. If a rename split them, the source selection
// would silently stop being mutually exclusive.
func TestGroupDBlobTwinsShareTheirPolledName(t *testing.T) {
	blob, window := blobPathNames(t), windowPathNames(t)
	for _, name := range []string{"entra.directory_audits", "entra.provisioning"} {
		if !window[name] {
			t.Errorf("%s is not registered on the window (graph) path", name)
		}
		if !blob[name] {
			t.Errorf("%s is not registered on the blob path (its blob twin is missing or misnamed)", name)
		}
	}
	// The sign-in blob twins are a DIFFERENT pattern — distinct .blob names, not
	// same-name source toggles. Guard that we did not accidentally converge them.
	if window["entra.signins.service_principal.blob"] {
		t.Error("entra.signins.service_principal.blob leaked onto the window path")
	}
}

// TestSourceSelectionIsMutuallyExclusive proves the two predicates that drive
// the composition root give exactly one active transport per source-switchable
// collector, and never leave one running nowhere.
func TestSourceSelectionIsMutuallyExclusive(t *testing.T) {
	const twin = "entra.directory_audits"
	polled := map[string]bool{twin: true}

	cases := []struct {
		source         string
		blobConfigured bool
		wantGraph      bool // polled/window registration active
		wantBlob       bool // blob twin registers (only if blobConfigured)
	}{
		{"graph", true, true, false},  // default: poll, blob twin stands down
		{"graph", false, true, false}, // no blob ingest: poll
		{"blob", true, false, true},   // switched: blob twin runs, polling off
		{"blob", false, true, false},  // blob requested but unavailable: fall back to polling, do not vanish
	}
	for _, c := range cases {
		gotGraph := graphPollingActive(c.source, c.blobConfigured)
		// The blob path only runs at all when blob ingest is configured.
		gotBlob := c.blobConfigured && blobTwinSelected(twin, polled, c.source)
		if gotGraph != c.wantGraph || gotBlob != c.wantBlob {
			t.Errorf("source=%s blobConfigured=%v: got graph=%v blob=%v, want graph=%v blob=%v",
				c.source, c.blobConfigured, gotGraph, gotBlob, c.wantGraph, c.wantBlob)
		}
		// The load-bearing invariant: never both, and (with a source to run on)
		// never neither.
		if gotGraph && gotBlob {
			t.Errorf("source=%s: BOTH transports active — the same event would be ingested twice", c.source)
		}
		if !gotGraph && !gotBlob {
			t.Errorf("source=%s blobConfigured=%v: NEITHER transport active — the collector runs nowhere", c.source, c.blobConfigured)
		}
	}

	// A pure-blob collector (no polled twin) always registers, source ignored.
	if !blobTwinSelected("entra.signins.service_principal.blob", polled, "graph") {
		t.Error("a pure-blob collector must register regardless of source")
	}
}
