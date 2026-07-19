package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectordoc"
	"github.com/rknightion/graph2otel/internal/collectors"
)

// updateCollectorDoc regenerates the committed docs/collectors.md golden file
// instead of asserting it, mirroring internal/config's -update flag. Run:
// go test ./cmd/graph2otel -run TestCollectorReferenceDocInSync -update
var updateCollectorDoc = flag.Bool("update", false, "rewrite generated golden files (docs/collectors.md)")

// These gates live in package main, and that placement is the point (#139).
//
// The registry is populated only by the blank imports in collectors_import.go,
// which is package main's own file. Any other home for this test would need its
// own copy of that import list — and a collector added to production but missed
// off the copy would be invisible to the very gate meant to catch it, which is
// precisely the drift being fixed. Here the gate sees exactly what the binary
// sees, for free.
//
// Every collector is constructed with ZERO Deps: no Graph client, no storage
// source, no credentials, no network. That is the same thing the compile-time
// interface checks at the bottom of each collector file do, and it is why this
// is a plain `go test` and not a tool that needs a tenant.

// registrySnapshot constructs every registered collector exactly as the tenant
// loop does, minus the dependencies.
//
// EVERY registration path must be walked here. A path this function forgets is
// invisible to all three gates below, which then pass because they cannot see
// the collector rather than because it is documented — a green gate over an
// undocumented collector, which is worse than no gate at all. That is not
// hypothetical: O365All() (#100) was added as a fourth path and the annotation
// gate went green over a collector missing from the reference entirely. If a
// fifth path lands, it is added here too.
func registrySnapshot() (snapshot, window, blob, o365, mdca []any) {
	for _, f := range collectors.All() {
		snapshot = append(snapshot, f(collectors.Deps{}))
	}
	for _, f := range collectors.WindowAll() {
		rw := f(collectors.WindowDeps{})
		if rw.Collector == nil {
			continue
		}
		window = append(window, rw.Collector)
	}
	for _, f := range collectors.BlobAll() {
		blob = append(blob, f(collectors.BlobDeps{}))
	}
	for _, f := range collectors.O365All() {
		rw := f(collectors.O365Deps{})
		if rw.Collector == nil {
			continue
		}
		o365 = append(o365, rw.Collector)
	}
	for _, f := range collectors.MDCAAll() {
		rw := f(collectors.MDCADeps{})
		if rw.Collector == nil {
			continue
		}
		mdca = append(mdca, rw.Collector)
	}
	return snapshot, window, blob, o365, mdca
}

func registeredNames(t *testing.T) []string {
	t.Helper()
	snapshot, window, blob, o365, mdca := registrySnapshot()
	var names []string
	for _, group := range [][]any{snapshot, window, blob, o365, mdca} {
		for _, c := range group {
			n, ok := c.(interface{ Name() string })
			if !ok {
				t.Fatalf("%T has no Name()", c)
			}
			names = append(names, n.Name())
		}
	}
	return names
}

// TestCollectorAnnotationsCoverEveryCollector is THE drift gate: registering a
// collector without writing its reference prose fails a plain `go test`, by
// name. It is the analog of TestExampleConfigCoversEveryKey — a missing entry
// means the doc is stale, an extra one means a stale rename (or a row for
// something that was never a single collector, as `purview.labels` was).
func TestCollectorAnnotationsCoverEveryCollector(t *testing.T) {
	if err := collectordoc.CheckAnnotations(registeredNames(t)); err != nil {
		t.Error(err)
	}
}

// TestEveryCollectorNameIsUnique guards the assumption the annotation map makes:
// annotations are keyed by name, so two collectors sharing one would silently
// share a row — and one of them would document the other.
//
// The ONE deliberate exception is a source-switchable collector (#135 group D):
// entra.directory_audits / entra.provisioning register under the SAME name on
// both the polled (window) path and the blob path, because they are one
// collector with two transports selected by `source: graph|blob`. They are
// mutually exclusive at runtime (exactly one registers per tenant), and they
// share one annotation/config/self-obs identity BY DESIGN, so that cross-path
// sharing is not a collision. What is still a bug is two collectors sharing a
// name within the SAME category — so uniqueness is checked per category.
func TestEveryCollectorNameIsUnique(t *testing.T) {
	snapshot, window, blob, o365, mdca := registrySnapshot()
	nameOf := func(c any) string {
		n, ok := c.(interface{ Name() string })
		if !ok {
			t.Fatalf("%T has no Name()", c)
		}
		return n.Name()
	}

	// Polled paths (snapshot/window/o365) share one namespace: a name there must
	// be unique — two polled collectors sharing one would be indistinguishable.
	polled := map[string]bool{}
	for _, group := range [][]any{snapshot, window, o365, mdca} {
		for _, c := range group {
			n := nameOf(c)
			if polled[n] {
				t.Errorf("collector name %q is registered twice on the polled paths — names are the annotation key, the config key, and the self-obs attribute, so they must be unique", n)
			}
			polled[n] = true
		}
	}

	// Blob names must be unique among blob collectors. A name also present on a
	// polled path is the allowed source-switchable twin, not a duplicate.
	blobSeen := map[string]bool{}
	for _, c := range blob {
		n := nameOf(c)
		if blobSeen[n] {
			t.Errorf("blob collector name %q is registered twice on the blob path", n)
		}
		blobSeen[n] = true
	}
}

// TestCollectorReferenceDocInSync is the golden gate: docs/collectors.md's
// generated block must equal what the registry renders right now. It catches
// what the annotation gate cannot — a changed interval, a new scope, a
// collector that became Experimental — since those need no new annotation.
// Regenerate with `scripts/regen-generated.sh collectordoc`.
func TestCollectorReferenceDocInSync(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "collectors.md")

	snapshot, window, blob, o365, mdca := registrySnapshot()
	root := filepath.Join("..", "..")
	rows, err := collectordoc.Rows(snapshot, window, blob, o365, mdca, root)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	block, err := collectordoc.Render(rows)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	current, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read docs/collectors.md: %v", err)
	}
	want, err := collectordoc.Splice(string(current), block)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}

	if *updateCollectorDoc {
		if err := os.WriteFile(docPath, []byte(want), 0o644); err != nil { //nolint:gosec // G306: generated docs file is intentionally world-readable
			t.Fatalf("write docs/collectors.md: %v", err)
		}
		t.Logf("regenerated %s", docPath)
		return
	}
	if want != string(current) {
		t.Errorf("docs/collectors.md is out of date with the collector registry — regenerate with " +
			"`scripts/regen-generated.sh collectordoc` (or `go test ./cmd/graph2otel -run TestCollectorReferenceDocInSync -update`) and commit the result")
	}
}

// TestRowsHardErrorsWhenACollectorPackageHasNoGolden proves the signal column
// fails loudly rather than rendering blank: every registered collector here
// is real, so packageDir resolves every one of them fine, but pointing Rows
// at a root with no testdata/signals.json anywhere under it must still fail —
// a missing golden is a build error, never a silently empty cell.
func TestRowsHardErrorsWhenACollectorPackageHasNoGolden(t *testing.T) {
	snapshot, window, blob, o365, mdca := registrySnapshot()
	if _, err := collectordoc.Rows(snapshot, window, blob, o365, mdca, t.TempDir()); err == nil {
		t.Fatal("Rows accepted a root with no signals.json golden for any collector")
	}
}
