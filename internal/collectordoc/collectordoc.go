// Package collectordoc generates docs/collectors.md's reference tables from the
// live collector registry, so a collector cannot ship undocumented (#139).
//
// # Why this exists
//
// The reference was hand-maintained and drifted one-directionally: 57 collectors
// were registered and 49 documented, because adding a collector never forced a
// doc edit. Nothing in `make check` noticed. Worse, hand-diffing the table
// against the code gives the wrong answer in BOTH directions — a grep catches
// metric names as if they were collectors and misses collectors whose names come
// from spec structs. Only walking the registry gives truth.
//
// # The split: registry facts are generated, prose is hand-written, neither is
// written twice
//
// Each row is a MERGE of three sources, and every fact has exactly one home:
//
//   - Facts the registry knows — name, kind, poll interval, safety lag,
//     Experimental, the license.CapabilityRequirer capability, the declared Graph
//     permissions, and (for blob collectors) the container and effective cursor
//     key — are read off the CONSTRUCTED collector here. They are never written
//     by hand, so they cannot be wrong.
//   - Facts the registry does not know — what the collector is FOR, which Graph
//     endpoints it polls, and any partial license gating that lives inside
//     Collect() rather than in a declared interface — are hand-written prose in
//     annotations.go, keyed by collector name.
//   - The metric and log-event names a collector emits are GENERATED from its
//     package's testdata/signals.json golden (#140, internal/signalcapture) —
//     see signals.go. They used to be hand-written prose here, and that prose
//     drifted uncaught: annotations.go once said entra.organization emitted
//     `entra.organization.directory.sync.last_sync_age_seconds`, a name the
//     collector never had. A golden produced FROM the real emissions cannot
//     describe a signal that does not exist.
//
// See the doc gate in cmd/graph2otel/collectordoc_test.go, which fails when a
// registered collector has no annotation, and Rows below, which fails when a
// registered collector's package has no signals.json golden.
//
// The rendered tables live between markers in docs/collectors.md; everything
// outside them (the intro, the per-section notes, the cardinality rule) is
// hand-written and Splice never touches it.
package collectordoc

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/signalcapture"
)

// Markers delimit the generated block inside docs/collectors.md. Splice
// rewrites what is between them and nothing else.
const (
	beginMarker = "<!-- BEGIN GENERATED COLLECTOR REFERENCE (scripts/regen-generated.sh collectordoc) -->"
	endMarker   = "<!-- END GENERATED COLLECTOR REFERENCE -->"
)

// Kind is a collector's registration path, which is also what decides its
// column set: the three paths know different things about themselves.
type Kind int

const (
	// KindSnapshot is collectors.Register / collectors.All — metric-shaped
	// inventory polls against Graph.
	KindSnapshot Kind = iota
	// KindWindow is collectors.RegisterWindow / collectors.WindowAll —
	// log-shaped event-stream polls against Graph, with a watermark and a lag.
	KindWindow
	// KindBlob is collectors.RegisterBlob / collectors.BlobAll — read-only Azure
	// Storage ingest. These poll no Graph endpoint and declare no Graph scope, so
	// they get their own columns rather than blanks in Graph-shaped ones.
	KindBlob
)

// Annotation is the hand-written half of a row: everything about a collector
// that the registry cannot know. Every registered collector needs one, and an
// annotation with no registered collector is equally an error — see DiffNames.
type Annotation struct {
	// Collects is the one-line "what is this for", in the doc's voice.
	Collects string
	// Source is the Graph endpoint(s) polled, backticked. Blob collectors leave
	// it empty: their container comes from the registry, and Category names the
	// diagnostic-settings category it is derived from.
	Source string
	// Category is the Azure Monitor diagnostic-settings category feeding a blob
	// collector's container (e.g. "MicrosoftGraphActivityLogs"). Its casing is
	// not recoverable from the container name, which is lowercased. Blob only.
	Category string
	// Gating carries license/beta nuance the registry cannot express: a
	// collector that PARTIALLY degrades gates inside Collect() on Deps.Caps
	// rather than declaring license.CapabilityRequirer, so no interface reports
	// it. Rendered alongside the generated gating facts, never instead of them.
	Gating string
}

// Row is one collector's fully resolved reference entry: registry facts plus
// its Annotation.
type Row struct {
	Name         string
	Domain       string
	Kind         Kind
	Interval     time.Duration
	Lag          time.Duration // window collectors only
	Experimental bool
	Capability   license.Capability
	Permissions  []string
	Container    string // blob only
	CursorKey    string // blob only; the EFFECTIVE key, with the container default resolved
	Ann          Annotation
	// Signals is what the collector's package actually emits, per its
	// testdata/signals.json golden (#140). Populated by Rows, never by RowFor:
	// RowFor is tested with bare Row{} literals that carry no golden on disk,
	// so resolving it there would force every white-box test to fake one.
	Signals signalcapture.Signals
}

// domains maps a collector name's first dotted segment to its doc domain. A
// name outside this set is an error rather than a default, so a new top-level
// namespace forces a deliberate decision about where it belongs.
var domains = map[string]string{
	"entra":   "Entra ID",
	"intune":  "Intune",
	"m365":    "M365",
	"purview": "Purview",
}

// collectorFacts is the mandatory interface every collector satisfies
// (collector.Collector). It is restated here so this package does not depend on
// internal/collector just to read two methods.
type collectorFacts interface {
	Name() string
	DefaultInterval() time.Duration
}

// RowFor reads every registry-knowable fact off a constructed collector and
// merges in its hand-written annotation.
//
// c is constructed from its factory with zero Deps — no Graph client, no
// storage source, no credentials. That is exactly what the compile-time checks
// at the bottom of each collector file already do, and it is why this generator
// runs in a plain `go test` with no tenant.
func RowFor(c any, kind Kind, ann Annotation) (Row, error) {
	facts, ok := c.(collectorFacts)
	if !ok {
		return Row{}, fmt.Errorf("collectordoc: %T implements neither Name() nor DefaultInterval()", c)
	}
	name := facts.Name()

	prefix, _, found := strings.Cut(name, ".")
	if !found {
		return Row{}, fmt.Errorf("collectordoc: collector %q has no dotted domain prefix", name)
	}
	domain, known := domains[prefix]
	if !known {
		return Row{}, fmt.Errorf("collectordoc: collector %q has unknown domain prefix %q — add it to collectordoc.domains and give it a section", name, prefix)
	}

	row := Row{
		Name:     name,
		Domain:   domain,
		Kind:     kind,
		Interval: facts.DefaultInterval(),
		Ann:      ann,
	}

	// Optional interfaces, asserted exactly as the composition root asserts
	// them, so the doc reports the gating the tenant loop will actually apply.
	if e, ok := c.(interface{ Experimental() bool }); ok {
		row.Experimental = e.Experimental()
	}
	if r, ok := c.(license.CapabilityRequirer); ok {
		row.Capability = r.RequiredCapability()
	}
	if p, ok := c.(preflight.PermissionRequirer); ok {
		row.Permissions = p.RequiredPermissions()
	}
	if w, ok := c.(interface{ Lag() time.Duration }); ok {
		row.Lag = w.Lag()
	}

	if kind == KindBlob {
		cfg, ok := blobConfig(c)
		if !ok {
			return Row{}, fmt.Errorf("collectordoc: blob collector %q exposes no blobpipeline.BlobCollector — the container cannot be read from the registry", name)
		}
		row.Container = cfg.Container
		row.CursorKey = cfg.CursorKey
		if row.CursorKey == "" {
			// Mirror blobpipeline's own default. The doc must show the EFFECTIVE
			// key, because that is what two collectors would collide on (#135).
			row.CursorKey = cfg.Container
		}
	}
	return row, nil
}

// blobConfig reaches a blob collector's ContainerConfig.
//
// Two shapes exist and both are load-bearing: entra/graphactivity's factory
// returns a *blobpipeline.BlobCollector directly, while entra/signins wraps one
// in an unexported struct that embeds it (to add RequiredCapability). The
// container is a FIELD, not a method, so embedding does not promote it into any
// interface — hence the reflection fallback over the wrapper's exported fields.
//
// A miss is reported to the caller rather than swallowed: a blank container cell
// would be a silently wrong doc, which is the failure mode this whole package
// exists to remove.
func blobConfig(c any) (blobpipeline.ContainerConfig, bool) {
	if b, ok := c.(*blobpipeline.BlobCollector); ok && b != nil {
		return b.Config, true
	}
	v := reflect.ValueOf(c)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return blobpipeline.ContainerConfig{}, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return blobpipeline.ContainerConfig{}, false
	}
	for i := range v.NumField() {
		if !v.Type().Field(i).IsExported() {
			continue
		}
		if b, ok := v.Field(i).Interface().(*blobpipeline.BlobCollector); ok && b != nil {
			return b.Config, true
		}
	}
	return blobpipeline.ContainerConfig{}, false
}

// DiffNames compares the registered collector names against the annotation
// keys. missing means a collector shipped with no prose (the drift this package
// exists to catch); extra means an annotation outlived its collector, or names a
// collector that never existed — `purview.labels` was exactly that, a doc row
// for something that is really two collectors.
func DiffNames(registered []string, anns map[string]Annotation) (missing, extra []string) {
	have := map[string]bool{}
	for _, n := range registered {
		have[n] = true
		if _, ok := anns[n]; !ok {
			missing = append(missing, n)
		}
	}
	for n := range anns {
		if !have[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// CheckAnnotations reports whether every registered collector has prose and
// every annotation still has a collector. It is the drift gate's core: a new
// collector fails here, by name, with the file to edit.
func CheckAnnotations(registered []string) error {
	missing, extra := DiffNames(registered, annotations)
	var problems []string
	if len(missing) > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d registered collector(s) have no annotation in internal/collectordoc/annotations.go — "+
				"add one (what it collects, its endpoint(s), what it emits) so the reference documents it:\n  %s",
			len(missing), strings.Join(missing, "\n  ")))
	}
	if len(extra) > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d annotation(s) in internal/collectordoc/annotations.go match no registered collector — "+
				"a stale rename, or a row for something that was never one collector:\n  %s",
			len(extra), strings.Join(extra, "\n  ")))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n\n"))
	}
	return nil
}

// Rows builds the full row set from a registry snapshot: the constructed
// collectors from collectors.All(), WindowAll(), BlobAll() and O365All()
// respectively, each already built from its factory with zero Deps.
//
// They arrive as []any so this package never imports internal/collectors — it
// reads every fact through the same optional interfaces the composition root
// asserts on, which is what keeps the doc honest about what will actually run.
//
// EVERY registration path must be passed here. A path this function does not
// walk is invisible to the reference AND to all three drift gates — which then
// pass because they are blind, not because they are satisfied. That is exactly
// what happened when O365All() landed (#100) without being added here: the
// annotation gate went green over a collector it could not see. If a fifth
// construction path is ever added, this signature changes with it.
//
// O365 collectors are KindWindow because that is what they are: they register
// via RegisterWindow and their cursor is a time watermark. Their source being a
// second first-party API rather than Graph is not a cursor distinction, and the
// kind split here is about the cursor. (Contrast blob collectors, which get
// their own kind because a byte-offset-per-blob cursor genuinely cannot express
// a [from, to] window.)
//
// root is the repo root (e.g. filepath.Join("..", "..") from a test two
// directories under it), used to resolve each collector's package back to its
// testdata/signals.json golden (#140, see signals.go). A collector whose
// package has no golden hard-errors here — the same convention blobConfig
// uses for a missing container: a blank signal cell would be a silently wrong
// doc, which is what this whole package exists to prevent.
func Rows(snapshot, window, blob, o365 []any, root string) ([]Row, error) {
	var rows []Row
	for _, group := range []struct {
		kind Kind
		cs   []any
	}{{KindSnapshot, snapshot}, {KindWindow, window}, {KindBlob, blob}, {KindWindow, o365}} {
		for _, c := range group.cs {
			facts, ok := c.(collectorFacts)
			if !ok {
				return nil, fmt.Errorf("collectordoc: %T is not a collector", c)
			}
			row, err := RowFor(c, group.kind, annotations[facts.Name()])
			if err != nil {
				return nil, err
			}
			pkgDir, err := packageDir(c)
			if err != nil {
				return nil, err
			}
			sig, err := loadSignals(root, pkgDir)
			if err != nil {
				return nil, err
			}
			row.Signals = sig
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// section is one rendered table: a (domain, kind) pair with its heading.
type section struct {
	domain string
	kind   Kind
	title  string
}

// sections fixes the order the tables render in. A (domain, kind) pair absent
// from this list is an error in Render — the same "force a decision" rule the
// domains map applies.
var sections = []section{
	{"Entra ID", KindSnapshot, "Entra ID — metrics (snapshot collectors)"},
	{"Entra ID", KindWindow, "Entra ID — logs (window collectors)"},
	{"Entra ID", KindBlob, "Entra ID — logs (blob collectors)"},
	{"Intune", KindSnapshot, "Intune — metrics (snapshot collectors)"},
	{"Intune", KindWindow, "Intune — logs (window collectors)"},
	{"Intune", KindBlob, "Intune — logs (blob collectors)"},
	{"M365", KindWindow, "M365 — logs (window collectors)"},
	{"M365", KindSnapshot, "M365 — metrics (snapshot collectors)"},
	{"Purview", KindSnapshot, "Purview — metrics (snapshot collectors)"},
	{"Purview", KindWindow, "Purview — logs (window collectors)"},
}

// headers is the column set per kind. Blob collectors get their own: they poll
// no Graph endpoint, declare no Graph scope, and emit no metrics (#128), so
// Graph-shaped columns would be three blanks and a lie.
var headers = map[Kind][]string{
	KindSnapshot: {"Collector", "Collects", "Graph endpoint(s)", "Required scope(s)", "License / beta", "Interval", "Metric namespace"},
	KindWindow:   {"Collector", "Collects", "Graph endpoint(s)", "Required scope(s)", "License / beta", "Interval", "Lag", "Log event"},
	KindBlob:     {"Collector", "Collects", "Container (diagnostic category)", "Cursor key", "Required role", "License / beta", "Interval", "Log event"},
}

// Render turns rows into the generated block: one markdown table per non-empty
// section, in the fixed section order, with collectors in registration order
// within each.
func Render(rows []Row) (string, error) {
	byKey := map[string][]Row{}
	for _, r := range rows {
		byKey[sectionKey(r.Domain, r.Kind)] = append(byKey[sectionKey(r.Domain, r.Kind)], r)
	}

	var b strings.Builder
	placed := 0
	for _, s := range sections {
		got := byKey[sectionKey(s.domain, s.kind)]
		if len(got) == 0 {
			continue
		}
		placed += len(got)
		fmt.Fprintf(&b, "## %s\n\n", s.title)
		cols := headers[s.kind]
		fmt.Fprintf(&b, "| %s |\n", strings.Join(cols, " | "))
		fmt.Fprintf(&b, "|%s\n", strings.Repeat(" --- |", len(cols)))
		for _, r := range got {
			cells, err := cellsFor(r)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "| %s |\n", strings.Join(cells, " | "))
		}
		b.WriteString("\n")
	}
	if placed != len(rows) {
		return "", fmt.Errorf("collectordoc: %d of %d collectors fell outside every declared section — add the missing (domain, kind) pair to collectordoc.sections", len(rows)-placed, len(rows))
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func sectionKey(domain string, kind Kind) string { return fmt.Sprintf("%s/%d", domain, kind) }

// cellsFor renders one row against its kind's column set.
func cellsFor(r Row) ([]string, error) {
	switch r.Kind {
	case KindSnapshot:
		return []string{
			code(r.Name), esc(r.Ann.Collects), esc(or(r.Ann.Source, "—")),
			scopes(r.Permissions), gatingCell(r), dur(r.Interval), esc(or(signalCell(r), "—")),
		}, nil
	case KindWindow:
		return []string{
			code(r.Name), esc(r.Ann.Collects), esc(or(r.Ann.Source, "—")),
			scopes(r.Permissions), gatingCell(r), dur(r.Interval), dur(r.Lag), esc(or(signalCell(r), "—")),
		}, nil
	case KindBlob:
		return []string{
			code(r.Name), esc(r.Ann.Collects), containerCell(r), code(r.CursorKey),
			"`Storage Blob Data Reader`", gatingCell(r), dur(r.Interval), esc(or(signalCell(r), "—")),
		}, nil
	}
	return nil, fmt.Errorf("collectordoc: collector %q has unknown kind %d", r.Name, r.Kind)
}

// containerCell pairs the registry-read container with the hand-written
// diagnostic-settings category it comes from — the category's casing is lost in
// the container name, which Azure Monitor lowercases.
func containerCell(r Row) string {
	if r.Ann.Category == "" {
		return code(r.Container)
	}
	return code(r.Container) + " (" + esc(r.Ann.Category) + ")"
}

// gatingCell renders the License / beta column: the registry's declared facts
// first, then any hand-written nuance in parentheses.
//
// A collector with NO declared capability may still be gated — the ones that
// partially degrade check Deps.Caps inside Collect() instead of declaring
// license.CapabilityRequirer, and no interface reports that. Those carry the
// whole story in Annotation.Gating, which is why a note alone is a valid cell.
func gatingCell(r Row) string {
	var facts []string
	if r.Capability != "" {
		facts = append(facts, code("needs-license/"+string(r.Capability)))
	}
	if r.Experimental {
		facts = append(facts, "`beta`")
	}
	note := esc(r.Ann.Gating)
	switch {
	case len(facts) == 0 && note == "":
		return "—"
	case len(facts) == 0:
		return note
	case note == "":
		return strings.Join(facts, ", ")
	default:
		return strings.Join(facts, ", ") + " (" + note + ")"
	}
}

// scopes renders the declared Graph permissions in DECLARATION order — the
// collector author's grouping (primary scope first) carries meaning that
// sorting would destroy.
func scopes(perms []string) string {
	if len(perms) == 0 {
		return "—"
	}
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = code(p)
	}
	return strings.Join(out, ", ")
}

// dur renders a duration the way an operator writes it in the `collectors:`
// config block: 15m, 1h, 24h — not Go's 15m0s / 1h0m0s.
//
// Computed from the unit rather than trimmed off d.String(): "30m0s" ends with
// "0m0s", so trimming zero suffixes eats the trailing digit and renders 30m as
// "3". That produces a wrong doc rather than an error, which is exactly the
// class of failure this package exists to prevent.
func dur(d time.Duration) string {
	switch {
	case d == 0:
		return "—"
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return d.String()
}

func code(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + s + "`"
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// esc escapes pipes so a prose cell containing one ("debug | info") cannot
// break the markdown table out from under the row.
func esc(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "|", `\|`)
}

// Splice replaces the generated block inside doc with block, leaving every
// hand-written byte outside the markers untouched. A doc with no markers is an
// error rather than an append: silently bolting a table onto the end of a
// hand-written page is worse than failing.
func Splice(doc, block string) (string, error) {
	start := strings.Index(doc, beginMarker)
	end := strings.Index(doc, endMarker)
	if start < 0 || end < 0 || end < start {
		return "", fmt.Errorf("collectordoc: generated-block markers not found (expected %q ... %q)", beginMarker, endMarker)
	}
	return doc[:start] + beginMarker + "\n\n" + block + "\n\n" + doc[end:], nil
}
