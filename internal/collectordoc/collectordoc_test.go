package collectordoc

import (
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// fakeSnapshot is a minimal collector implementing only the mandatory
// Collector methods — no Experimental, no CapabilityRequirer, no
// PermissionRequirer — so RowFor's optional type assertions are exercised in
// their absent form.
type fakeSnapshot struct {
	name string
	iv   time.Duration
}

func (f fakeSnapshot) Name() string                   { return f.name }
func (f fakeSnapshot) DefaultInterval() time.Duration { return f.iv }

// fakeFull implements every optional interface.
type fakeFull struct{ fakeSnapshot }

func (fakeFull) Experimental() bool                     { return true }
func (fakeFull) RequiredCapability() license.Capability { return license.CapEntraP2 }
func (fakeFull) RequiredPermissions() []string          { return []string{"B.Read.All", "A.Read.All"} }

// fakeWindow adds Lag, which is what makes RowFor classify the window columns.
type fakeWindow struct {
	fakeSnapshot
	lag time.Duration
}

func (f fakeWindow) Lag() time.Duration { return f.lag }

// embeddedBlob mirrors the real entra/signins shape: a wrapper struct that
// embeds *blobpipeline.BlobCollector rather than being one. RowFor must reach
// the container config through the embedding, not just through a direct type
// assertion — the three sign-in blob collectors are all this shape.
type embeddedBlob struct{ *blobpipeline.BlobCollector }

func newBlob(name, container, cursorKey string) *blobpipeline.BlobCollector {
	return &blobpipeline.BlobCollector{
		NameField: name,
		Interval:  5 * time.Minute,
		Config: blobpipeline.ContainerConfig{
			Container: container,
			CursorKey: cursorKey,
			Map:       func(map[string]any) (telemetry.Event, bool) { return telemetry.Event{}, false },
		},
	}
}

func TestRowForReadsRegistryFacts(t *testing.T) {
	ann := Annotation{Collects: "things", Source: "`/things`"}
	row, err := RowFor(fakeFull{fakeSnapshot{name: "entra.things", iv: 30 * time.Minute}}, KindSnapshot, ann)
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if row.Name != "entra.things" {
		t.Errorf("Name = %q", row.Name)
	}
	if row.Domain != "Entra ID" {
		t.Errorf("Domain = %q, want the domain derived from the name prefix", row.Domain)
	}
	if row.Interval != 30*time.Minute {
		t.Errorf("Interval = %v", row.Interval)
	}
	if !row.Experimental {
		t.Error("Experimental not read from the collector")
	}
	if row.Capability != license.CapEntraP2 {
		t.Errorf("Capability = %q", row.Capability)
	}
	// Permissions must be rendered in the order the collector declares them,
	// not sorted: the declaration order is the collector author's grouping.
	if strings.Join(row.Permissions, ",") != "B.Read.All,A.Read.All" {
		t.Errorf("Permissions = %v, want declaration order preserved", row.Permissions)
	}
}

func TestRowForAbsentOptionalInterfaces(t *testing.T) {
	row, err := RowFor(fakeSnapshot{name: "intune.plain", iv: time.Hour}, KindSnapshot, Annotation{})
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if row.Experimental || row.Capability != "" || len(row.Permissions) != 0 {
		t.Errorf("a collector implementing no optional interface should carry no gating, got %+v", row)
	}
	if row.Domain != "Intune" {
		t.Errorf("Domain = %q", row.Domain)
	}
}

func TestRowForUnknownDomainIsAnError(t *testing.T) {
	// A new top-level namespace must force a deliberate generator update rather
	// than silently rendering into a section that does not exist.
	if _, err := RowFor(fakeSnapshot{name: "azure.things", iv: time.Minute}, KindSnapshot, Annotation{}); err == nil {
		t.Fatal("RowFor accepted an unknown domain prefix; want an error")
	}
}

func TestRowForWindowReadsLag(t *testing.T) {
	row, err := RowFor(fakeWindow{fakeSnapshot{name: "entra.events", iv: 5 * time.Minute}, 15 * time.Minute}, KindWindow, Annotation{})
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if row.Lag != 15*time.Minute {
		t.Errorf("Lag = %v, want it read from the WindowCollector", row.Lag)
	}
}

func TestRowForBlobReadsContainerDirectly(t *testing.T) {
	row, err := RowFor(newBlob("entra.direct", "insights-logs-cat", ""), KindBlob, Annotation{})
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if row.Container != "insights-logs-cat" {
		t.Errorf("Container = %q", row.Container)
	}
	// An unset CursorKey defaults to the container — the doc must show the
	// EFFECTIVE key, since that is what a collision would collide on.
	if row.CursorKey != "insights-logs-cat" {
		t.Errorf("CursorKey = %q, want it defaulted to the container", row.CursorKey)
	}
}

func TestRowForBlobReadsContainerThroughEmbedding(t *testing.T) {
	row, err := RowFor(&embeddedBlob{newBlob("entra.wrapped", "insights-logs-wrapped", "custom-key")}, KindBlob, Annotation{})
	if err != nil {
		t.Fatalf("RowFor: %v", err)
	}
	if row.Container != "insights-logs-wrapped" {
		t.Errorf("Container = %q, want it reached through the embedded BlobCollector", row.Container)
	}
	if row.CursorKey != "custom-key" {
		t.Errorf("CursorKey = %q, want the explicit override", row.CursorKey)
	}
}

func TestRowForBlobWithNoContainerIsAnError(t *testing.T) {
	// If the reflection path ever stops finding the embedded BlobCollector, the
	// generator must fail loudly rather than emit a blank container cell.
	if _, err := RowFor(fakeSnapshot{name: "entra.notablob", iv: time.Minute}, KindBlob, Annotation{}); err == nil {
		t.Fatal("RowFor accepted a blob collector with no reachable container; want an error")
	}
}

func TestGatingCellRendersRegistryFactsAndHandNote(t *testing.T) {
	cases := []struct {
		name string
		row  Row
		want string
	}{
		{"ungated", Row{}, "—"},
		{"capability", Row{Capability: license.CapEntraP1}, "`needs-license/entra_p1`"},
		{"beta", Row{Experimental: true}, "`beta`"},
		{"both", Row{Capability: license.CapEntraP1, Experimental: true}, "`needs-license/entra_p1`, `beta`"},
		{"note only", Row{Ann: Annotation{Gating: "half of it needs P2"}}, "half of it needs P2"},
		{"fact plus note", Row{Capability: license.CapEntraP1, Ann: Annotation{Gating: "staleness slice only"}},
			"`needs-license/entra_p1` (staleness slice only)"},
	}
	for _, tc := range cases {
		if got := gatingCell(tc.row); got != tc.want {
			t.Errorf("%s: gatingCell = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestDurRendersOperatorNotation pins the interval/lag cells to the notation an
// operator writes in the `collectors:` config block. The naive
// trim-the-zero-suffix approach silently eats a trailing digit — 30m0s renders
// as "3" — which is a wrong doc rather than a failure, so every real interval in
// the registry is a case here.
func TestDurRendersOperatorNotation(t *testing.T) {
	cases := map[time.Duration]string{
		0:                          "—",
		5 * time.Minute:            "5m",
		10 * time.Minute:           "10m", // the case the trim bug turned into "1"
		12 * time.Minute:           "12m",
		15 * time.Minute:           "15m",
		20 * time.Minute:           "20m",
		30 * time.Minute:           "30m", // the case the trim bug turned into "3"
		time.Hour:                  "1h",
		6 * time.Hour:              "6h",
		24 * time.Hour:             "24h",
		90 * time.Second:           "90s",
		time.Hour + 30*time.Minute: "90m", // no whole-hour form, so the minute form wins
	}
	for d, want := range cases {
		if got := dur(d); got != want {
			t.Errorf("dur(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestRenderEscapesPipesInProse(t *testing.T) {
	rows := []Row{{
		Name: "entra.x", Domain: "Entra ID", Kind: KindSnapshot, Interval: time.Minute,
		Ann: Annotation{Collects: "a | b", Source: "`/x`"},
	}}
	out, err := Render(rows)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "a | b") {
		t.Error("an unescaped pipe in a prose cell would break the markdown table")
	}
	if !strings.Contains(out, `a \| b`) {
		t.Error("expected the pipe to be escaped, not dropped")
	}
}

func TestRenderGroupsBySectionInFixedOrder(t *testing.T) {
	rows := []Row{
		{Name: "purview.a", Domain: "Purview", Kind: KindSnapshot, Interval: time.Hour},
		{Name: "entra.b", Domain: "Entra ID", Kind: KindBlob, Interval: time.Minute, Container: "c", CursorKey: "c"},
		{Name: "entra.a", Domain: "Entra ID", Kind: KindSnapshot, Interval: time.Minute},
	}
	out, err := Render(rows)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	iEntraSnap := strings.Index(out, "## Entra ID — metrics")
	iEntraBlob := strings.Index(out, "## Entra ID — logs (blob collectors)")
	iPurview := strings.Index(out, "## Purview — metrics")
	if iEntraSnap < 0 || iEntraBlob < 0 || iPurview < 0 {
		t.Fatalf("missing a section heading:\n%s", out)
	}
	if iEntraSnap >= iEntraBlob || iEntraBlob >= iPurview {
		t.Error("sections are not in the fixed declared order")
	}
	// An empty section must not render an empty table.
	if strings.Contains(out, "## Intune") {
		t.Error("a section with no rows should be omitted entirely")
	}
}

func TestRenderBlobSectionUsesBlobColumns(t *testing.T) {
	rows := []Row{{
		Name: "entra.graph_activity", Domain: "Entra ID", Kind: KindBlob, Interval: 5 * time.Minute,
		Container: "insights-logs-microsoftgraphactivitylogs", CursorKey: "insights-logs-microsoftgraphactivitylogs",
		Ann: Annotation{Collects: "graph calls", Category: "MicrosoftGraphActivityLogs"},
	}}
	out, err := Render(rows)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"Container", "Cursor key", "Storage Blob Data Reader", "MicrosoftGraphActivityLogs"} {
		if !strings.Contains(out, want) {
			t.Errorf("blob section missing %q:\n%s", want, out)
		}
	}
	// Blob collectors declare no Graph scope and emit no metrics — the
	// Graph-shaped columns must not appear in their table.
	if strings.Contains(out, "Graph endpoint") {
		t.Error("blob rows must not be forced into Graph-shaped columns")
	}
}

func TestSpliceReplacesOnlyTheGeneratedBlock(t *testing.T) {
	doc := "intro prose\n\n" + beginMarker + "\nOLD\n" + endMarker + "\n\ntrailing prose\n"
	got, err := Splice(doc, "NEW")
	if err != nil {
		t.Fatalf("Splice: %v", err)
	}
	if !strings.Contains(got, "intro prose") || !strings.Contains(got, "trailing prose") {
		t.Error("Splice clobbered hand-written prose outside the markers")
	}
	if strings.Contains(got, "OLD") || !strings.Contains(got, "NEW") {
		t.Error("Splice did not replace the generated block")
	}
}

func TestSpliceWithoutMarkersIsAnError(t *testing.T) {
	if _, err := Splice("no markers here", "NEW"); err == nil {
		t.Fatal("Splice accepted a doc with no generated-block markers")
	}
}

func TestDiffNames(t *testing.T) {
	missing, extra := DiffNames([]string{"a", "b"}, map[string]Annotation{"a": {}, "c": {}})
	if strings.Join(missing, ",") != "b" {
		t.Errorf("missing = %v, want [b]", missing)
	}
	if strings.Join(extra, ",") != "c" {
		t.Errorf("extra = %v, want [c]", extra)
	}
}
