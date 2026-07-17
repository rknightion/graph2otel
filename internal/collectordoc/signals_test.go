package collectordoc

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collectors/entra/organization"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// TestPackageDirResolvesARealCollectorPackage is the load-bearing case the
// #140 comment thread found the hard way: a collector's registry NAME is not
// a string transform of its package path (entra.signin_activity lives in
// entra/signinactivity, no underscore). packageDir must go through
// reflection, never munge the name.
func TestPackageDirResolvesARealCollectorPackage(t *testing.T) {
	dir, err := packageDir(organization.New(nil, nil))
	if err != nil {
		t.Fatalf("packageDir: %v", err)
	}
	want := filepath.Join("internal", "collectors", "entra", "organization")
	if dir != want {
		t.Errorf("packageDir = %q, want %q", dir, want)
	}
}

// TestPackageDirRejectsATypeOutsideCollectors guards the error path: a type
// whose package is not under internal/collectors/ (here, one of this
// package's own test fakes) has no signals.json to resolve, and that must be
// reported rather than silently producing a blank cell.
func TestPackageDirRejectsATypeOutsideCollectors(t *testing.T) {
	if _, err := packageDir(fakeSnapshot{name: "x"}); err == nil {
		t.Fatal("packageDir accepted a type whose package (internal/collectordoc itself) is not under internal/collectors/")
	}
}

// TestLoadSignalsRoundTripsTheCommittedGolden proves loadSignals reads the
// same golden signalcapture.Golden writes — the substrate the generated doc
// depends on being trustworthy.
func TestLoadSignalsRoundTripsTheCommittedGolden(t *testing.T) {
	root := filepath.Join("..", "..")
	sig, err := loadSignals(root, filepath.Join("internal", "collectors", "entra", "organization"))
	if err != nil {
		t.Fatalf("loadSignals: %v", err)
	}
	found := false
	for _, m := range sig.Metrics {
		if m.Name == "entra.directory.sync.last_sync_age_seconds" {
			found = true
		}
	}
	if !found {
		t.Errorf("loaded signals = %+v, want entra.directory.sync.last_sync_age_seconds among the metrics", sig.Metrics)
	}
}

// TestPackageDirResolvesTheBareBlobCollectorException covers the one
// collector reflection genuinely cannot resolve on its own:
// entra/graphactivity's factory returns a bare *blobpipeline.BlobCollector
// rather than a domain-specific wrapper, so reflect.TypeOf(c).PkgPath() on
// the constructed value resolves to internal/blobpipeline itself — the
// package that DEFINES the type, not the one that BUILT it. This is the same
// two-shapes distinction blobConfig already documents; packageDir needs its
// own named exception for it, keyed by collector name.
func TestPackageDirResolvesTheBareBlobCollectorException(t *testing.T) {
	c := &blobpipeline.BlobCollector{
		NameField: "entra.graph_activity",
		Interval:  5 * time.Minute,
		Config: blobpipeline.ContainerConfig{
			Container: "insights-logs-microsoftgraphactivitylogs",
			Map:       func(map[string]any) (telemetry.Event, bool) { return telemetry.Event{}, false },
		},
	}
	dir, err := packageDir(c)
	if err != nil {
		t.Fatalf("packageDir: %v", err)
	}
	want := filepath.Join("internal", "collectors", "entra", "graphactivity")
	if dir != want {
		t.Errorf("packageDir = %q, want %q", dir, want)
	}
}

// TestPackageDirRejectsAnUnmappedBareBlobCollector: a bare *BlobCollector for
// a name NOT in directBlobPackages must hard-error rather than silently
// resolving to internal/blobpipeline (which has no signals.json of its own).
func TestPackageDirRejectsAnUnmappedBareBlobCollector(t *testing.T) {
	c := &blobpipeline.BlobCollector{NameField: "entra.some_new_blob_collector"}
	if _, err := packageDir(c); err == nil {
		t.Fatal("packageDir accepted a bare *blobpipeline.BlobCollector with no directBlobPackages entry")
	}
}

// TestLoadSignalsMissingGoldenIsAHardError: a package with no
// testdata/signals.json must fail loudly, never render as a blank "—" cell —
// a silently empty signal column is exactly the kind of confidently-wrong doc
// #140 exists to prevent.
func TestLoadSignalsMissingGoldenIsAHardError(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := loadSignals(root, filepath.Join("internal", "collectors", "entra", "does_not_exist")); err == nil {
		t.Fatal("loadSignals accepted a missing golden")
	}
}
