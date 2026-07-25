package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// TestEverySelfObservabilityEmitterPackageHasSignalGate closes #288's
// non-collector discovery loop. GoldenPaths deliberately starts from gates,
// so source inspection is used only to find packages that should have opted
// in; emitted signal shape still comes exclusively from runtime captures.
func TestEverySelfObservabilityEmitterPackageHasSignalGate(t *testing.T) {
	root := filepath.Join("..", "..")
	missing, err := missingSelfObsSignalGates(root)
	if err != nil {
		t.Fatalf("discovering self-observability emitters: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("production packages emit graph2otel.* metrics without a signal gate: %s\n"+
			"Add signalgate_test.go and a dedicated testdata/signals.json fixture; "+
			"otherwise the generated catalog can stay green while missing the package.",
			strings.Join(missing, ", "))
	}
}

func TestEverySourceNamedSelfObservabilityMetricIsCaptured(t *testing.T) {
	root := filepath.Join("..", "..")
	missing, err := uncapturedSelfObsMetrics(root)
	if err != nil {
		t.Fatalf("checking source-named self-observability metrics: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("production graph2otel.* metrics are absent from every signal golden: %s\n"+
			"Exercise each metric in its package's dedicated signal fixture and regenerate; "+
			"source discovery establishes completeness, while the golden remains the shape authority.",
			strings.Join(missing, ", "))
	}
}

func TestSelfObservabilityEmitterDiscoveryRejectsAnUngatedPackage(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "internal", "newtransport")
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatal(err)
	}
	source := `package newtransport
const metricPrefix = "graph2otel.new."
const metricRequests = metricPrefix + "requests"
func emit(e interface{ Counter(string, string, string, float64, map[string]string) }) {
	e.Counter(metricRequests, "1", "requests", 1, nil)
}
`
	if err := os.WriteFile(filepath.Join(pkg, "transport.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	missing, err := missingSelfObsSignalGates(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "internal/newtransport" {
		t.Fatalf("missing gates = %v, want [internal/newtransport]", missing)
	}
}

func TestSourceNamedSelfObservabilityMetricDiscoveryRejectsAnUncapturedMetric(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "internal", "newtransport")
	if err := os.MkdirAll(filepath.Join(pkg, "testdata"), 0o750); err != nil {
		t.Fatal(err)
	}
	source := `package newtransport
const metricRequests = "graph2otel.new.requests"
func emit(e interface{ Counter(string, string, string, float64, map[string]string) }) {
	e.Counter(metricRequests, "1", "requests", 1, nil)
}
`
	for path, body := range map[string]string{
		filepath.Join(pkg, "transport.go"):             source,
		filepath.Join(pkg, "signalgate_test.go"):       "package newtransport\n",
		filepath.Join(pkg, "testdata", "signals.json"): "{}\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing, err := uncapturedSelfObsMetrics(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "internal/newtransport:graph2otel.new.requests"
	if len(missing) != 1 || missing[0] != want {
		t.Fatalf("uncaptured metrics = %v, want [%s]", missing, want)
	}
}

func TestSourceNamedSelfObservabilityMetricMustBeCapturedByEveryEmitterPackage(t *testing.T) {
	root := t.TempDir()
	const metric = "graph2otel.shared.requests"
	for _, name := range []string{"first", "second"} {
		pkg := filepath.Join(root, "internal", name)
		if err := os.MkdirAll(filepath.Join(pkg, "testdata"), 0o750); err != nil {
			t.Fatal(err)
		}
		source := "package " + name + "\n" +
			"const metricRequests = \"" + metric + "\"\n" +
			"func emit(e interface{ Counter(string, string, string, float64, map[string]string) }) {\n" +
			"\te.Counter(metricRequests, \"1\", \"requests\", 1, nil)\n}\n"
		golden := "{}\n"
		if name == "first" {
			golden = `{"Metrics":[{"Name":"graph2otel.shared.requests","Unit":"1","Kind":"sum","Description":"requests","AttrKeys":null}],"Logs":null}` + "\n"
		}
		for path, body := range map[string]string{
			filepath.Join(pkg, "transport.go"):             source,
			filepath.Join(pkg, "signalgate_test.go"):       "package " + name + "\n",
			filepath.Join(pkg, "testdata", "signals.json"): golden,
		} {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	missing, err := uncapturedSelfObsMetrics(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "internal/second:" + metric
	if len(missing) != 1 || missing[0] != want {
		t.Fatalf("uncaptured package-metric pairs = %v, want [%s]", missing, want)
	}
}

func missingSelfObsSignalGates(root string) ([]string, error) {
	packages, err := selfObsEmitterPackages(filepath.Join(root, "internal"))
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, pkg := range packages {
		if _, err := os.Stat(filepath.Join(pkg, "signalgate_test.go")); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		rel, _ := filepath.Rel(root, pkg)
		missing = append(missing, filepath.ToSlash(rel))
	}
	sort.Strings(missing)
	return missing, nil
}

func uncapturedSelfObsMetrics(root string) ([]string, error) {
	source, err := selfObsEmitterMetrics(filepath.Join(root, "internal"))
	if err != nil {
		return nil, err
	}
	paths, err := signalcapture.GoldenPaths(root)
	if err != nil {
		return nil, err
	}
	captured := map[string]map[string]bool{}
	for _, path := range paths {
		body, readErr := os.ReadFile(path) //nolint:gosec // fixed in-repo/test tree
		if readErr != nil {
			return nil, readErr
		}
		var signals signalcapture.Signals
		if err := json.Unmarshal(body, &signals); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		pkg := filepath.Dir(filepath.Dir(path))
		captured[pkg] = map[string]bool{}
		for _, metric := range signals.Metrics {
			captured[pkg][metric.Name] = true
		}
	}
	var missing []string
	for name, packages := range source {
		for _, pkg := range packages {
			if !captured[pkg][name] {
				rel, _ := filepath.Rel(root, pkg)
				missing = append(missing, filepath.ToSlash(rel)+":"+name)
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func selfObsEmitterPackages(internalRoot string) ([]string, error) {
	metrics, err := selfObsEmitterMetrics(internalRoot)
	if err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	for _, packages := range metrics {
		for _, dir := range packages {
			dirs[dir] = true
		}
	}
	var out []string
	for dir := range dirs {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out, nil
}

func selfObsEmitterMetrics(internalRoot string) (map[string][]string, error) {
	filesByDir := map[string][]string{}
	err := filepath.WalkDir(internalRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		filesByDir[filepath.Dir(path)] = append(filesByDir[filepath.Dir(path)], path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	metrics := map[string][]string{}
	for dir, files := range filesByDir {
		names, parseErr := packageSelfObsMetrics(files)
		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", dir, parseErr)
		}
		for _, name := range names {
			metrics[name] = append(metrics[name], dir)
		}
	}
	return metrics, nil
}

func packageSelfObsMetrics(files []string) ([]string, error) {
	var parsed []*ast.File
	constExprs := map[string]ast.Expr{}
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, file)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				values := spec.(*ast.ValueSpec)
				for i, name := range values.Names {
					if i < len(values.Values) {
						constExprs[name.Name] = values.Values[i]
					}
				}
			}
		}
	}

	var resolve func(ast.Expr) (string, bool)
	var resolveExpr func(ast.Expr, map[string]bool) (string, bool)
	resolveExpr = func(expr ast.Expr, visiting map[string]bool) (string, bool) {
		switch value := expr.(type) {
		case *ast.BasicLit:
			if value.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(value.Value)
			return s, err == nil
		case *ast.Ident:
			if visiting[value.Name] {
				return "", false
			}
			constExpr, ok := constExprs[value.Name]
			if !ok {
				return "", false
			}
			visiting[value.Name] = true
			s, ok := resolveExpr(constExpr, visiting)
			delete(visiting, value.Name)
			return s, ok
		case *ast.BinaryExpr:
			if value.Op != token.ADD {
				return "", false
			}
			left, lok := resolveExpr(value.X, visiting)
			right, rok := resolveExpr(value.Y, visiting)
			return left + right, lok && rok
		default:
			return "", false
		}
	}
	resolve = func(expr ast.Expr) (string, bool) {
		return resolveExpr(expr, map[string]bool{})
	}

	names := map[string]bool{}
	for identifier, expr := range constExprs {
		if !strings.Contains(strings.ToLower(identifier), "metric") {
			continue
		}
		if name, ok := resolve(expr); ok &&
			strings.HasPrefix(name, "graph2otel.") &&
			!strings.HasSuffix(name, ".") {
			names[name] = true
		}
	}

	emitterMethods := map[string]bool{
		"Counter": true, "Gauge": true, "GaugeSnapshot": true,
		"Histogram": true, "HistogramCtx": true,
	}
	for _, file := range parsed {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !emitterMethods[selector.Sel.Name] {
				return true
			}
			name, ok := resolve(call.Args[0])
			if ok && strings.HasPrefix(name, "graph2otel.") {
				names[name] = true
			}
			return true
		})
	}
	var out []string
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// goldenMetrics reads every signal-gated package's testdata/signals.json and
// returns each metric it declares, tagged with the package it came from.
//
// The goldens are the only tree-wide inventory of what graph2otel emits that is
// built FROM emissions rather than from source inspection, which is what makes
// them worth walking: a check over them cannot describe a metric that does not
// exist, and cannot miss one a package really emits. Both properties matter for
// #235, whose limiter has to have an answer for every metric on the wire.
func goldenMetrics(t *testing.T) map[string][]signalcapture.MetricSignal {
	t.Helper()
	root := filepath.Join("..", "..")
	out := map[string][]signalcapture.MetricSignal{}

	paths, err := signalcapture.GoldenPaths(root)
	if err != nil {
		t.Fatalf("discovering signal goldens: %v", err)
	}
	for _, path := range paths {
		b, readErr := os.ReadFile(path) //nolint:gosec // walking a fixed in-repo tree
		if readErr != nil {
			t.Fatalf("reading %s: %v", path, readErr)
		}
		var s signalcapture.Signals
		if jerr := json.Unmarshal(b, &s); jerr != nil {
			t.Fatalf("parsing %s: %v", path, jerr)
		}
		rel, _ := filepath.Rel(root, filepath.Dir(filepath.Dir(path)))
		out[rel] = s.Metrics
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
	type shape struct{ unit, kind, description, pkg string }
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
				seen[m.Name] = shape{
					unit: m.Unit, kind: m.Kind, description: m.Description, pkg: pkg,
				}
				continue
			}
			if prev.unit != m.Unit || prev.kind != m.Kind || prev.description != m.Description {
				t.Errorf("metric %q is emitted with two different shapes:\n"+
					"  %s: unit %q, kind %q, description %q\n"+
					"  %s: unit %q, kind %q, description %q\n"+
					"The emitter caches the instrument by NAME on first use, so only one of "+
					"these shapes ever reaches the wire and which one depends on collector scheduling. "+
					"Either make them agree or give them different metric names.",
					m.Name,
					prev.pkg, prev.unit, prev.kind, prev.description,
					pkg, m.Unit, m.Kind, m.Description)
			}
		}
	}
}
