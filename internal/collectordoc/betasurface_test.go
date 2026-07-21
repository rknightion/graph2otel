package collectordoc

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The Microsoft Graph beta drift canary (tools/graphdrift, #220) watches the
// beta surface named in spec/graph-beta-surface.json. A canary that cannot see
// a consumer reports coverage it does not have — the same failure mode as the
// fourth collector-registration path that slipped past the coverage test in
// #139/#100 — so the manifest is gated against the source from both sides here.
//
// betaServiceRoot is the string a collector must build a URL from to be a beta
// consumer. Matching on the literal rather than on a `betaBaseURL` identifier is
// deliberate: internal/collectors/intune/remediationrunstates names its beta
// root `defaultBaseURL`, and an identifier-based scan misses it.
const betaServiceRoot = "https://graph.microsoft.com/beta"

// betaScanRoots are the repo-relative trees searched for beta consumers.
var betaScanRoots = []string{"internal", "cmd"}

type betaManifest struct {
	MetadataURL string `json:"metadata_url"`
	Note        string `json:"note"`
	Packages    []struct {
		Package    string   `json:"package"`
		Collectors []string `json:"collectors"`
		Operations []struct {
			Path      string `json:"path"`
			ResolveAs string `json:"resolve_as"`
			Unmodeled bool   `json:"unmodeled"`
			Type      string `json:"type"`
			Note      string `json:"note"`
		} `json:"operations"`
	} `json:"packages"`
}

type betaSnapshot struct {
	Operations []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"operations"`
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func loadBetaManifest(t *testing.T) betaManifest {
	t.Helper()
	raw, err := os.ReadFile(repoPath("spec", "graph-beta-surface.json"))
	if err != nil {
		t.Fatalf("read beta-surface manifest: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var man betaManifest
	if err := dec.Decode(&man); err != nil {
		t.Fatalf("decode beta-surface manifest: %v (tools/graphdrift and this test decode the same file strictly; a field only one of them knows about is a silent hole)", err)
	}
	return man
}

// betaConsumingPackages returns every repo-relative package directory whose
// non-test Go source contains a string literal built on the beta service root.
// It reads string literals off the AST rather than grepping, so a comment
// mentioning the beta root (internal/logpipeline documents BaseURLOverride with
// one) is not mistaken for a consumer.
func betaConsumingPackages(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()
	for _, root := range betaScanRoots {
		err := filepath.WalkDir(repoPath(root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			found := false
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr == nil && strings.Contains(v, betaServiceRoot) {
					found = true
				}
				return true
			})
			if found {
				pkg := filepath.ToSlash(filepath.Dir(strings.TrimPrefix(filepath.ToSlash(path), "../../")))
				out[pkg] = append(out[pkg], filepath.Base(path))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s for beta consumers: %v", root, err)
		}
	}
	return out
}

func TestBetaSurfaceManifestCoversEveryBetaConsumer(t *testing.T) {
	man := loadBetaManifest(t)
	declared := map[string]bool{}
	for _, p := range man.Packages {
		declared[p.Package] = true
	}
	consuming := betaConsumingPackages(t)

	if len(consuming) == 0 {
		t.Fatal("found no beta consumers at all — the scan is broken, not the repo")
	}

	var missing []string
	for pkg, files := range consuming {
		if !declared[pkg] {
			missing = append(missing, pkg+" ("+strings.Join(files, ", ")+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these packages build %s URLs but are not in spec/graph-beta-surface.json, so the drift canary is blind to them:\n  %s\nAdd them, then regenerate the snapshot: go run -C tools/graphdrift . -update",
			betaServiceRoot, strings.Join(missing, "\n  "))
	}

	var stale []string
	for pkg := range declared {
		if _, ok := consuming[pkg]; !ok {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("spec/graph-beta-surface.json lists packages that no longer build %s URLs:\n  %s\nDrop them, then regenerate the snapshot: go run -C tools/graphdrift . -update",
			betaServiceRoot, strings.Join(stale, "\n  "))
	}
}

// TestBetaSurfaceSnapshotMatchesManifest is the offline half of the canary: the
// daily workflow catches upstream drift, this catches a snapshot that was never
// regenerated after the manifest changed. Both files are committed, so it needs
// no network and runs in `make check`.
func TestBetaSurfaceSnapshotMatchesManifest(t *testing.T) {
	man := loadBetaManifest(t)

	raw, err := os.ReadFile(repoPath("spec", "graph-beta-snapshot.json"))
	if err != nil {
		t.Fatalf("read beta-surface snapshot: %v", err)
	}
	var snap betaSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("decode beta-surface snapshot: %v", err)
	}

	inSnapshot := map[string]bool{}
	for _, op := range snap.Operations {
		if op.Type == "" {
			t.Errorf("snapshot operation %s resolves to no type; regenerate it and check the reported error", op.Path)
		}
		inSnapshot[op.Path] = true
	}

	inManifest := map[string]bool{}
	for _, p := range man.Packages {
		for _, op := range p.Operations {
			inManifest[op.Path] = true
			if !inSnapshot[op.Path] {
				t.Errorf("%s: %s is in the manifest but not the snapshot — run: go run -C tools/graphdrift . -update", p.Package, op.Path)
			}
		}
	}
	for path := range inSnapshot {
		if !inManifest[path] {
			t.Errorf("%s is in the snapshot but no longer in the manifest — run: go run -C tools/graphdrift . -update", path)
		}
	}
}

// TestBetaDriftDocNamesEveryWatchedCollector keeps docs/api-drift.md's coverage
// table honest. #220's acceptance bar is that the docs state which endpoints the
// canary covers; a hand-written table that silently falls behind the manifest
// states the opposite of the truth.
func TestBetaDriftDocNamesEveryWatchedCollector(t *testing.T) {
	man := loadBetaManifest(t)
	doc, err := os.ReadFile(repoPath("docs", "api-drift.md"))
	if err != nil {
		t.Fatalf("read docs/api-drift.md: %v", err)
	}
	text := string(doc)
	for _, p := range man.Packages {
		for _, c := range p.Collectors {
			if !strings.Contains(text, "`"+c+"`") {
				t.Errorf("docs/api-drift.md does not name the watched collector %s in its coverage table", c)
			}
		}
	}
}

func TestBetaSurfaceManifestIsWellFormed(t *testing.T) {
	man := loadBetaManifest(t)
	if man.MetadataURL != betaServiceRoot+"/$metadata" {
		t.Errorf("metadata_url = %q, want %s/$metadata", man.MetadataURL, betaServiceRoot)
	}
	if len(man.Packages) == 0 {
		t.Fatal("manifest declares no packages")
	}
	for _, p := range man.Packages {
		if len(p.Collectors) == 0 {
			t.Errorf("%s: names no collectors", p.Package)
		}
		if len(p.Operations) == 0 {
			t.Errorf("%s: declares no operations", p.Package)
		}
		for _, op := range p.Operations {
			if !strings.HasPrefix(op.Path, "/") {
				t.Errorf("%s: path %q must start with /", p.Package, op.Path)
			}
			if strings.Contains(op.Path, betaServiceRoot) {
				t.Errorf("%s: path %q must be written without the service root", p.Package, op.Path)
			}
			if op.Unmodeled && (op.Type == "" || op.Note == "") {
				t.Errorf("%s: unmodeled path %q needs both the type it decodes and a note recording the evidence", p.Package, op.Path)
			}
			if !op.Unmodeled && op.Type != "" {
				t.Errorf("%s: path %q is modeled, so its type is resolved from the EDM, not declared", p.Package, op.Path)
			}
		}
	}
}
