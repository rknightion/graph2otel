package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
