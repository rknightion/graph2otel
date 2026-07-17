package collectordoc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// claudeMDMaxLines is the tripwire from the #146 post-mortem: CLAUDE.md grew
// 160 -> 701 lines of correction-chain narrative in 48 hours and nothing
// forced the "split it to docs/" decision. CLAUDE.md holds current-truth rules
// only; deep lore belongs in docs/ reference files (graph-api-gotchas.md,
// blob-ingest.md, o365-management-api.md, signals.md), each pointed at from
// CLAUDE.md's reference table. Raising this limit is a maintainer decision,
// not a fix for a failing build.
const claudeMDMaxLines = 350

func TestClaudeMDStaysCurrentTruthSized(t *testing.T) {
	path := filepath.Join("..", "..", "CLAUDE.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CLAUDE.md: %v", err)
	}
	lines := bytes.Count(data, []byte("\n"))
	if lines > claudeMDMaxLines {
		t.Fatalf("CLAUDE.md is %d lines (limit %d). Move detail into a docs/ reference file and leave a pointer — see #146.", lines, claudeMDMaxLines)
	}
}
