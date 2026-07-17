package telemetry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// stampingEngines maps each ingest-engine package to the transport it must
// stamp. Adding an engine means adding it here — that is the point.
var stampingEngines = map[string]telemetry.Transport{
	"logpipeline":  telemetry.TransportGraph,
	"blobpipeline": telemetry.TransportBlob,
	"jobpipeline":  telemetry.TransportAuditQuery,
	"o365pipeline": telemetry.TransportO365Activity,
}

// TestEveryEngineStampsItsOwnTransport closes this design's one silent-mislabel
// path.
//
// The composition root wraps the Scheduler's emitter as TransportGraph, which is
// the truthful default for the SnapshotCollectors that poll Graph and emit
// inline. The cost of that default is that a NON-Graph engine which forgets to
// re-wrap does not fail loudly — it inherits "graph" and ships a confident lie,
// which is worse than shipping no provenance at all.
//
// This is not hypothetical, and it is not a new class of bug on this project.
// CLAUDE.md records the #139/#100 incident in these terms: "a fourth
// registration path landed and the coverage test stayed green over a missing
// collector" — a design enumerated the paths it knew about, a path outside the
// enumeration existed, and the gate could not see it. A hand-maintained list of
// engines would repeat exactly that. So this test does not trust the list: it
// reads the tree and fails if the tree contains an engine the list does not.
func TestEveryEngineStampsItsOwnTransport(t *testing.T) {
	for pkg, want := range stampingEngines {
		src := packageSource(t, filepath.Join("..", pkg))
		call := "telemetry.WithTransport(e, telemetry." + transportConstName(t, want) + ")"
		if !strings.Contains(src, call) {
			t.Errorf("engine %q does not stamp its transport: expected a %s call.\n"+
				"Without it the Scheduler's graph baseline is the only stamp its records get, "+
				"which mislabels every one of them.", pkg, call)
		}
	}
}

// TestNoUnregisteredIngestEngineExists is the half that makes the list above
// trustworthy: a fifth *pipeline package cannot land unnoticed. It fails until
// the new engine is registered in stampingEngines, at which point the test above
// starts demanding that it actually stamps.
func TestNoUnregisteredIngestEngineExists(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatalf("reading internal/: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), "pipeline") {
			continue
		}
		if _, ok := stampingEngines[e.Name()]; !ok {
			t.Errorf("internal/%s looks like an ingest engine but names no transport (#141).\n"+
				"Add it to stampingEngines and stamp it, or its records inherit the Scheduler's "+
				"\"graph\" baseline and claim to be Graph polls.", e.Name())
		}
	}
}

// TestExportJobStillHasNoEmitSeam pins the fact that forced report_export to be
// stamped by its three collectors rather than by an engine (#141).
//
// internal/exportjob creates, polls, and downloads a job, then hands rows back —
// it never calls LogEvent, so there is no engine seam to stamp from. If that
// changes, this test fails, and the three collectors' self-stamping
// (appinstallreport, defenderreport, certinventoryreport) should move here
// instead of being duplicated three ways.
func TestExportJobStillHasNoEmitSeam(t *testing.T) {
	if src := packageSource(t, filepath.Join("..", "exportjob")); strings.Contains(src, ".LogEvent(") {
		t.Error("internal/exportjob now emits log records. report_export is currently stamped by " +
			"its three collectors precisely because this package had no emit seam — revisit that, " +
			"and stamp here instead.")
	}
}

// packageSource concatenates a package's non-test Go source.
func packageSource(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		b.Write(data)
	}
	return b.String()
}

// transportConstName maps a transport value back to its Go constant name, so the
// expected call this test greps for names the constant a developer would type
// rather than the wire value.
func transportConstName(t *testing.T, tr telemetry.Transport) string {
	t.Helper()
	names := map[telemetry.Transport]string{
		telemetry.TransportGraph:        "TransportGraph",
		telemetry.TransportBlob:         "TransportBlob",
		telemetry.TransportO365Activity: "TransportO365Activity",
		telemetry.TransportAuditQuery:   "TransportAuditQuery",
		telemetry.TransportReportExport: "TransportReportExport",
	}
	n, ok := names[tr]
	if !ok {
		t.Fatalf("no constant name known for transport %q — add it here", tr)
	}
	return n
}
