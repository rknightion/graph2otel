package collectordoc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// agentsMDMaxLines is the tripwire from the #146 post-mortem: the project
// instruction file grew 160 -> 701 lines of correction-chain narrative in 48
// hours and nothing forced the "split it to docs/" decision. It holds
// current-truth rules only; deep lore belongs in docs/ reference files
// (graph-api-gotchas.md, blob-ingest.md, o365-management-api.md, signals.md),
// each pointed at from its reference table. Raising this limit is a maintainer
// decision, not a fix for a failing build.
//
// The watched file is AGENTS.md, not CLAUDE.md: since the 2026-08-14 tracker
// migration AGENTS.md carries the instructions and CLAUDE.md is a five-line
// `@AGENTS.md` import, so pointing the tripwire at CLAUDE.md would measure the
// import stub and pass forever.
const agentsMDMaxLines = 350

// backlogBlockStart and backlogBlockEnd delimit the instruction block that
// `backlog init` writes and rewrites — it is tool-managed, not hand-written
// guidance, and it changes size on an upstream version bump. Counting it would
// make this tripwire fire for a reason it does not watch, so it is excluded and
// the budget stays what it has always been: the project's own prose.
var (
	backlogBlockStart = []byte("<!-- BACKLOG.MD GUIDELINES START -->")
	backlogBlockEnd   = []byte("<!-- BACKLOG.MD GUIDELINES END -->")
)

func TestAgentsMDStaysCurrentTruthSized(t *testing.T) {
	path := filepath.Join("..", "..", "AGENTS.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}

	authored := data
	if start := bytes.Index(data, backlogBlockStart); start >= 0 {
		end := bytes.Index(data, backlogBlockEnd)
		if end < start {
			t.Fatalf("AGENTS.md has a %q with no matching %q — the tool-managed block is malformed", backlogBlockStart, backlogBlockEnd)
		}
		authored = append(append([]byte{}, data[:start]...), data[end+len(backlogBlockEnd):]...)
	}

	lines := bytes.Count(authored, []byte("\n"))
	if lines > agentsMDMaxLines {
		t.Fatalf("AGENTS.md is %d hand-written lines (limit %d, tool-managed block excluded). Move detail into a docs/ reference file and leave a pointer — see #146.", lines, agentsMDMaxLines)
	}
}
