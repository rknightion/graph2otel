package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// TestEveryCollectorPackageEnforcesCardinality is the half that makes the #112
// gate trustworthy: it fails when a collector package does not install it.
//
// The gate itself lives in each package's TestMain (see internal/signalcapture),
// which is what lets it judge every emission from every test — including tests
// written later by someone who has never heard of #112. But a per-package
// opt-in is only as good as the enumeration that checks it, and this project
// has been bitten by exactly that: CLAUDE.md records the #139/#100 incident as
// "a fourth registration path landed and the coverage test stayed green over a
// missing collector". A hand-kept list of packages would repeat it.
//
// So this walks the tree rather than trusting a list. A new collector package
// fails here until it installs the gate, and cannot ship silently unguarded.
func TestEveryCollectorPackageEnforcesCardinality(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "collectors")

	var missing []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == root {
			return err
		}
		// Only packages that have tests can enforce anything; a package with no
		// test files has nothing to judge and is caught by other gates.
		tests, _ := filepath.Glob(filepath.Join(path, "*_test.go"))
		if len(tests) == 0 {
			return nil
		}
		for _, f := range tests {
			b, readErr := os.ReadFile(f)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(b), "signalcapture.Main(m)") {
				return nil
			}
		}
		rel, _ := filepath.Rel(root, path)
		missing = append(missing, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	for _, pkg := range missing {
		t.Errorf("collector package %q does not enforce the #112 cardinality gate.\n"+
			"Add a signalgate_test.go containing:\n\n"+
			"\tfunc TestMain(m *testing.M) { signalcapture.Main(m) }\n\n"+
			"Without it, nothing stops this package putting a UPN or a device id on a "+
			"metric label — the bug class behind #83/#110/#111/#114.", pkg)
	}
}

// goldenMetrics reads every collector package's testdata/signals.json and
// returns each metric it declares, tagged with the package it came from.
//
// The goldens are the only tree-wide inventory of what graph2otel emits that is
// built FROM emissions rather than from source inspection, which is what makes
// them worth walking: a check over them cannot describe a metric that does not
// exist, and cannot miss one a package really emits. Both properties matter for
// #235, whose limiter has to have an answer for every metric on the wire.
func goldenMetrics(t *testing.T) map[string][]signalcapture.MetricSignal {
	t.Helper()
	root := filepath.Join("..", "..", "internal", "collectors")
	out := map[string][]signalcapture.MetricSignal{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "signals.json" {
			return err
		}
		b, readErr := os.ReadFile(path) //nolint:gosec // walking a fixed in-repo tree
		if readErr != nil {
			return readErr
		}
		var s signalcapture.Signals
		if jerr := json.Unmarshal(b, &s); jerr != nil {
			return fmt.Errorf("%s: %w", path, jerr)
		}
		rel, _ := filepath.Rel(root, filepath.Dir(filepath.Dir(path)))
		out[rel] = s.Metrics
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatal("no signal goldens found — this gate would pass vacuously")
	}
	return out
}

// TestEveryEmittedUnitIsClassifiedForAdditivity is #235's build gate.
//
// The limiter has to decide, for every metric it clips, whether the tail may be
// summed into an `other` bucket or must be dropped and counted. semconv's table
// answers that from the unit. A unit the table does not recognize gets the
// fail-safe answer (non-additive), which is correct but silent — the metric
// quietly loses its tail forever and nothing says so.
//
// So an unrecognized unit fails here instead, at the moment it is introduced.
// Annotation units ("{device}") need no entry: they follow the convention that
// they name a countable thing, and only the deny-list of quality words is
// enumerated. This fires for a real UCUM unit nobody has classified.
func TestEveryEmittedUnitIsClassifiedForAdditivity(t *testing.T) {
	for pkg, metrics := range goldenMetrics(t) {
		for _, m := range metrics {
			if semconv.UnitClassified(m.Unit) {
				continue
			}
			t.Errorf("metric %q (%s) has unit %q, which semconv's additivity table does not "+
				"classify.\n"+
				"#235's limiter cannot decide whether this metric's clipped tail may be summed "+
				"into an `other` bucket or must be dropped, so it fails safe and drops it — "+
				"silently, forever.\n"+
				"Add %q to additiveUnits or nonAdditiveUnits in internal/semconv/additive.go. "+
				"Ask: is a SUM of this quantity a number anyone would want? Bytes yes, "+
				"percentages and durations no.", m.Name, pkg, m.Unit, m.Unit)
		}
	}
}

// TestNoMetricNameIsEmittedWithTwoShapes closes the hole the per-package capture
// structurally cannot see.
//
// The emitter creates each OTEL instrument on first use and caches it BY NAME,
// so if two packages emit one metric name with different units or aggregation
// kinds, the first one to run wins and the second's unit never reaches the wire
// — silently, and differently depending on collector scheduling. Within a single
// package that collapse happens before the Recorder sees anything, which is why
// signalcapture.Union cannot detect it. Across packages the goldens are separate
// files, so the disagreement survives to here and is visible.
//
// It also protects the gate above from itself: a metric classified as additive
// in one package and non-additive in another would make the limiter's behavior
// depend on which collector emitted first.
func TestNoMetricNameIsEmittedWithTwoShapes(t *testing.T) {
	type shape struct{ unit, kind, pkg string }
	seen := map[string]shape{}

	// Sorted for a deterministic "first" in the error message; map order would
	// otherwise name a different package as the incumbent on every run.
	byPkg := goldenMetrics(t)
	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		for _, m := range byPkg[pkg] {
			prev, ok := seen[m.Name]
			if !ok {
				seen[m.Name] = shape{unit: m.Unit, kind: m.Kind, pkg: pkg}
				continue
			}
			if prev.unit != m.Unit || prev.kind != m.Kind {
				t.Errorf("metric %q is emitted with two different shapes:\n"+
					"  %s: unit %q, kind %q\n"+
					"  %s: unit %q, kind %q\n"+
					"The emitter caches the instrument by NAME on first use, so only one of "+
					"these ever reaches the wire and which one depends on collector scheduling. "+
					"Either make them agree or give them different metric names.",
					m.Name, prev.pkg, prev.unit, prev.kind, pkg, m.Unit, m.Kind)
			}
		}
	}
}
