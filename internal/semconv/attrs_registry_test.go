package semconv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowedSharedValue lists the unordered pairs of Attr* constant names that are
// DELIBERATELY allowed to share the same string value. There is exactly one such
// pair: AttrWorkload/AttrService, which m365/activity feeds from a single source
// value on purpose (see attrs_m365.go). Every other value-collision is a bug —
// two Go symbols naming one attribute key, which defeats the point of the
// registry and hides drift. The pair is stored order-independently.
var allowedSharedValue = map[[2]string]bool{
	pair("AttrWorkload", "AttrService"): true,
}

func pair(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

// loadAttrConsts parses this package's own source files (drift-proof: it reads
// the tree rather than trusting a hand-maintained list, so a constant added in
// any attrs_*.go is picked up automatically — the #139/#100 lesson) and returns
// every package-level const whose name starts with "Attr", mapped to its string
// value.
func loadAttrConsts(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				cname := vs.Names[0].Name
				if !strings.HasPrefix(cname, "Attr") {
					continue
				}
				bl, ok := vs.Values[0].(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(bl.Value)
				if err != nil {
					t.Fatalf("unquote %s value %q: %v", cname, bl.Value, err)
				}
				if prev, dup := out[cname]; dup {
					t.Fatalf("constant %s declared twice (%q and %q)", cname, prev, val)
				}
				out[cname] = val
			}
		}
	}
	return out
}

// TestNoDuplicateAttrValues is Gate A: no two DISTINCT Attr* constants may share
// the same string value, except the explicitly allowlisted AttrWorkload/AttrService
// pair. A duplicate value means two symbols name one attribute key, which is the
// drift the registry exists to prevent.
func TestNoDuplicateAttrValues(t *testing.T) {
	consts := loadAttrConsts(t)
	if len(consts) == 0 {
		t.Fatal("no Attr* constants found — the parser walk is broken")
	}

	byValue := map[string][]string{}
	for name, val := range consts {
		byValue[val] = append(byValue[val], name)
	}

	for val, names := range byValue {
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		// A shared value is allowed only when the whole group is exactly one
		// allowlisted pair.
		if len(names) == 2 && allowedSharedValue[pair(names[0], names[1])] {
			continue
		}
		t.Errorf("attribute value %q is shared by multiple constants %v — each key must have exactly one constant (allowlist only %v)", val, names, allowlistNames())
	}
}

func allowlistNames() [][2]string {
	out := make([][2]string, 0, len(allowedSharedValue))
	for p := range allowedSharedValue {
		out = append(out, p)
	}
	return out
}
