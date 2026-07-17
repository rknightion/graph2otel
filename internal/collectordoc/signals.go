// Package collectordoc: signals.go resolves a constructed collector back to
// its testdata/signals.json golden and renders it as the doc's signal column.
//
// # Why reflection, not the registry name
//
// A collector's registry name is NOT a string transform of its package
// directory: entra.signin_activity is keyed with an underscore but lives in
// entra/signinactivity (no underscore, no dot), and annotations.go is full of
// similar mismatches. Munging the name would silently mis-resolve a golden —
// exactly the guessing #140's own postmortem rejected for the doc's prose.
// reflect.TypeOf(c).PkgPath() reads the ACTUAL package a collector's
// concrete type is declared in, which is truth by construction the same way
// the golden itself is.
//
// # Why package granularity is safe now
//
// The goldens this reads are captured per PACKAGE
// (internal/signalcapture.Golden), while a doc row is per COLLECTOR. That was
// a real blocker (#140) until purview/labels — the one package hosting two
// collectors with different emissions — was split into
// purview/sensitivitylabels and purview/retentionlabels. package == collector
// now holds tree-wide except entra/signins (7 collectors, one package), which
// is harmless because all seven emit the identical entra.signin signal — so
// resolving by package never attributes one collector's emissions to
// another's row.
package collectordoc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// modulePath is this repo's module, used to turn a package's import path
// (github.com/rknightion/graph2otel/internal/collectors/entra/organization)
// into a path relative to the repo root that filepath.Join can use directly.
const modulePath = "github.com/rknightion/graph2otel/"

// collectorsRoot is the subtree every collector package lives under. A
// resolved package outside it has no signals.json to find — the reflection
// found some other type entirely, most likely a test fake.
const collectorsRoot = "internal/collectors/"

// directBlobPackages resolves the one collector whose constructed value's
// concrete type carries NO origin info for reflection to walk at all:
// entra/graphactivity's factory returns a bare *blobpipeline.BlobCollector
// rather than wrapping it in a domain-specific type (contrast entra/signins,
// which wraps the SAME type in an unexported struct to add
// RequiredCapability — see blobConfig's comment in collectordoc.go for this
// exact pair of shapes). reflect.TypeOf(c).PkgPath() on a bare
// *blobpipeline.BlobCollector resolves to internal/blobpipeline itself — the
// package that DEFINES the type, not the one whose factory BUILT it — so
// there is no golden to find there.
//
// This is a NAMED exception keyed by the collector's own registry name, not a
// name→folder transform: it exists for exactly the collector blobConfig
// already special-cases, for the identical reason. A second entry should
// prompt the same question blobConfig's comment raises — usually the fix is
// to wrap the collector, as entra/signins does, not to grow this map.
var directBlobPackages = map[string]string{
	"entra.graph_activity": "internal/collectors/entra/graphactivity",
}

// packageDir resolves the source directory (relative to the repo root, e.g.
// "internal/collectors/entra/organization") that declares c's concrete type.
//
// c is a collector constructed with zero Deps, exactly as Rows receives it —
// a pointer in every real case, so the pointer is dereferenced first; reflect
// reports a pointer type's own (empty) PkgPath, not its element's.
func packageDir(c any) (string, error) {
	if b, ok := c.(*blobpipeline.BlobCollector); ok && b != nil {
		if dir, ok := directBlobPackages[b.NameField]; ok {
			return dir, nil
		}
		return "", fmt.Errorf("collectordoc: collector %q is a bare *blobpipeline.BlobCollector with no entry in "+
			"collectordoc.directBlobPackages — its type carries no package info reflection can recover, so add one",
			b.NameField)
	}

	t := reflect.TypeOf(c)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.PkgPath() == "" {
		return "", fmt.Errorf("collectordoc: %T has no resolvable package path", c)
	}
	pkgPath := t.PkgPath()
	rel, ok := strings.CutPrefix(pkgPath, modulePath)
	if !ok {
		return "", fmt.Errorf("collectordoc: package %q is outside this module — cannot resolve its signals.json", pkgPath)
	}
	if !strings.HasPrefix(rel, collectorsRoot) {
		return "", fmt.Errorf("collectordoc: package %q is not under %s — cannot resolve its signals.json", pkgPath, collectorsRoot)
	}
	return rel, nil
}

// loadSignals reads a package's committed golden. A missing or unparseable
// golden is a hard error, mirroring blobConfig's convention elsewhere in this
// package: a blank signal cell would be a silently wrong doc, which is the
// failure mode this whole package exists to remove.
func loadSignals(root, pkgDir string) (signalcapture.Signals, error) {
	path := filepath.Join(root, pkgDir, "testdata", "signals.json")
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is built from a reflected package dir + a fixed filename, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return signalcapture.Signals{}, fmt.Errorf(
				"collectordoc: no %s — regenerate with `scripts/regen-generated.sh signals` "+
					"(or `go test ./%s -update`)", path, pkgDir)
		}
		return signalcapture.Signals{}, fmt.Errorf("collectordoc: reading %s: %w", path, err)
	}
	var sig signalcapture.Signals
	if err := json.Unmarshal(body, &sig); err != nil {
		return signalcapture.Signals{}, fmt.Errorf("collectordoc: parsing %s: %w", path, err)
	}
	return sig, nil
}

// metricCell renders one metric as `name` or `name{k1,k2}`. Keys are rendered
// in the order the golden already sorted them (signalcapture.Union sorts
// before marshaling), so no re-sort happens here.
func metricCell(m signalcapture.MetricSignal) string {
	if len(m.AttrKeys) == 0 {
		return code(m.Name)
	}
	return code(m.Name + "{" + strings.Join(m.AttrKeys, ",") + "}")
}

// renderMetrics is the signal cell for a snapshot-shaped row: every metric,
// flat and fully-qualified — no dotted-suffix compression. The
// entra.organization drift (annotations.go hand-wrote a `.` infix — the doc
// said entra.organization.directory.sync.last_sync_age_seconds — that the
// real metric never had) is exactly what shorthand hid, and generating from
// the golden makes that class of bug structurally impossible.
//
// A snapshot collector that ALSO logs a twin per entity (entra.risk,
// intune.devices, purview.sensitivity_labels) gets that noted after its
// metrics: the log's own attribute keys are noise at 15-22 deep (#140), so
// only the bare event name(s) appear.
func renderMetrics(sig signalcapture.Signals) string {
	parts := make([]string, 0, len(sig.Metrics))
	for _, m := range sig.Metrics {
		parts = append(parts, metricCell(m))
	}
	cell := strings.Join(parts, ", ")

	if len(sig.Logs) == 0 {
		return cell
	}
	events := make([]string, 0, len(sig.Logs))
	for _, l := range sig.Logs {
		events = append(events, code(l.EventName))
	}
	twin := "plus a log twin per " + strings.Join(events, ", ")
	if cell == "" {
		return twin
	}
	return cell + ", " + twin
}

// renderLogs is the signal cell for a window/blob-shaped row: bare event
// names, comma-separated, no attribute keys — matching entra.signin's
// existing hand-written form. Attribute keys are deliberately omitted here
// (unlike metrics): a log-shaped collector's attribute set is per-entity by
// design (#112) and runs 15-22 keys deep, which is noise in a reference table
// rather than useful signal.
func renderLogs(sig signalcapture.Signals) string {
	parts := make([]string, 0, len(sig.Logs))
	for _, l := range sig.Logs {
		parts = append(parts, code(l.EventName))
	}
	return strings.Join(parts, ", ")
}

// signalCell renders a row's generated signal column, dispatching on Kind:
// snapshot rows are metric-shaped (with an optional log-twin note), window
// and blob rows are log-shaped.
func signalCell(r Row) string {
	switch r.Kind {
	case KindSnapshot:
		return renderMetrics(r.Signals)
	case KindWindow, KindBlob:
		return renderLogs(r.Signals)
	}
	return ""
}
