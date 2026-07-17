package semconv_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// attrSetters are the telemetry helpers whose SECOND positional argument is an
// attribute key. A bare string literal in that position must instead be a
// semconv.Attr* constant (#161).
var attrSetters = map[string]bool{
	"SetStr": true, "SetBool": true, "SetNum": true,
	"SetList": true, "SetStrs": true, "SetDurationSeconds": true,
}

// TestNoBareAttributeKeyLiterals is the #161 drift gate: it walks every
// non-test .go file under internal/collectors and fails if an attribute key is
// written as a bare string literal instead of a semconv.Attr* constant. It
// covers the three emit shapes this codebase uses:
//
//   - telemetry.SetX(attrs, "key", …) calls,
//   - telemetry.Attrs{"key": …} composite literals (metric labels + log attrs),
//   - attrs["key"] index expressions (the map is named `attrs` everywhere).
//
// Truth by construction paired with #140's signalcapture golden: that golden
// stops an emitted key's VALUE from drifting silently; this gate stops a new
// bare-literal key from being introduced at all, so the registry cannot be
// bypassed. Any legitimate new key adds one semconv constant — the cost the
// issue asked for.
func TestNoBareAttributeKeyLiterals(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "collectors")
	fset := token.NewFileSet()
	var violations []string

	record := func(lit *ast.BasicLit, form string) {
		if lit.Kind == token.STRING {
			violations = append(violations, fmt.Sprintf("%s: %s key %s — use a semconv.Attr* constant (#161)",
				fset.Position(lit.Pos()), form, lit.Value))
		}
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || !attrSetters[sel.Sel.Name] {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "telemetry" {
					return true
				}
				if len(node.Args) >= 2 {
					if lit, ok := node.Args[1].(*ast.BasicLit); ok {
						record(lit, "telemetry."+sel.Sel.Name)
					}
				}
			case *ast.CompositeLit:
				sel, ok := node.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Attrs" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "telemetry" {
					return true
				}
				for _, elt := range node.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if lit, ok := kv.Key.(*ast.BasicLit); ok {
							record(lit, "telemetry.Attrs")
						}
					}
				}
			case *ast.IndexExpr:
				if id, ok := node.X.(*ast.Ident); !ok || id.Name != "attrs" {
					return true
				}
				if lit, ok := node.Index.(*ast.BasicLit); ok {
					record(lit, "attrs[...]")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(violations) > 0 {
		t.Errorf("bare attribute-key string literals found — every attribute key must be a semconv.Attr* constant (#161):\n%s",
			strings.Join(violations, "\n"))
	}
}
