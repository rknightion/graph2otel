package annotations

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// callRecorder records which Emitter methods reached the wrapped emitter, so a
// forwarding gap is visible rather than inferred.
type callRecorder struct {
	calls []string
	logs  []telemetry.Event
	snaps map[string][]telemetry.GaugePoint
}

func newCallRecorder() *callRecorder {
	return &callRecorder{snaps: map[string][]telemetry.GaugePoint{}}
}

func (c *callRecorder) Counter(name, _, _ string, _ float64, _ telemetry.Attrs) {
	c.calls = append(c.calls, "Counter:"+name)
}

func (c *callRecorder) Gauge(name, _, _ string, _ float64, _ telemetry.Attrs) {
	c.calls = append(c.calls, "Gauge:"+name)
}

func (c *callRecorder) GaugeSnapshot(name, _, _ string, points []telemetry.GaugePoint) {
	c.calls = append(c.calls, "GaugeSnapshot:"+name)
	c.snaps[name] = points
}

func (c *callRecorder) UpDownCounter(name, _, _ string, _ float64, _ telemetry.Attrs) {
	c.calls = append(c.calls, "UpDownCounter:"+name)
}

func (c *callRecorder) Histogram(name, _, _ string, _ float64, _ []float64, _ telemetry.Attrs) {
	c.calls = append(c.calls, "Histogram:"+name)
}

func (c *callRecorder) HistogramCtx(_ context.Context, name, _, _ string, _ float64, _ []float64, _ telemetry.Attrs) {
	c.calls = append(c.calls, "HistogramCtx:"+name)
}

func (c *callRecorder) LogEvent(ev telemetry.Event) {
	c.calls = append(c.calls, "LogEvent:"+ev.Name)
	c.logs = append(c.logs, ev)
}

// TestTeeForwardsEveryMethod is the "it cannot drop telemetry" gate. The tee
// exists to observe; if any method failed to forward, a collector's metric or
// log would vanish the moment annotations were switched on.
func TestTeeForwardsEveryMethod(t *testing.T) {
	base := newCallRecorder()
	rec, _ := newTestRecorder(t, testConfig(), t.TempDir())
	e := Tee(base, rec, rec.BeginRun(testTenant, "c"))

	e.Counter("m.counter", "1", "d", 1, nil)
	e.Gauge("m.gauge", "1", "d", 1, nil)
	e.GaugeSnapshot("m.snapshot", "1", "d", nil)
	e.UpDownCounter("m.updown", "1", "d", 1, nil)
	e.Histogram("m.hist", "s", "d", 1, []float64{1}, nil)
	e.HistogramCtx(t.Context(), "m.histctx", "s", "d", 1, []float64{1}, nil)
	e.LogEvent(telemetry.Event{Name: "entra.signin"})

	want := []string{
		"Counter:m.counter", "Gauge:m.gauge", "GaugeSnapshot:m.snapshot",
		"UpDownCounter:m.updown", "Histogram:m.hist", "HistogramCtx:m.histctx",
		"LogEvent:entra.signin",
	}
	if !slices.Equal(base.calls, want) {
		t.Errorf("forwarded calls = %v, want %v", base.calls, want)
	}
}

// TestEveryEmitterMethodIsOverriddenExplicitly parses the Emitter interface and
// the teeEmitter's method set and fails if one is missing.
//
// This is the same guard telemetry's tenantEmitter carries, for the same reason:
// an un-overridden method is PROMOTED from the embedded Emitter and compiles
// perfectly, so an eighth Emitter method would land here silently — forwarding
// correctly but invisible to the rule set, which is the failure that looks like
// "annotations mysteriously stopped covering that signal".
func TestEveryEmitterMethodIsOverriddenExplicitly(t *testing.T) {
	iface := reflect.TypeOf((*telemetry.Emitter)(nil)).Elem()
	want := make([]string, 0, iface.NumMethod())
	for i := range iface.NumMethod() {
		want = append(want, iface.Method(i).Name)
	}
	sort.Strings(want)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("tee.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse tee.go: %v", err)
	}
	got := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if !ok || ident.Name != "teeEmitter" {
			continue
		}
		got[fn.Name.Name] = true
	}

	var missing []string
	for _, name := range want {
		if !got[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("teeEmitter does not explicitly override %s.\n"+
			"An un-overridden method is promoted from the embedded Emitter, compiles, "+
			"and forwards — but the rule set never sees those records.",
			strings.Join(missing, ", "))
	}
}

// TestTeeForwardsBeforeObserving pins the ordering: the record reaches the
// telemetry pipeline first, so nothing the rule set does can delay or alter it.
func TestTeeForwardsBeforeObserving(t *testing.T) {
	base := newCallRecorder()
	rec, sink := newTestRecorder(t, testConfig(), t.TempDir())
	e := Tee(base, rec, rec.BeginRun(testTenant, "c"))

	ev := directoryAudit("audit-order", "Update conditional access policy")
	e.LogEvent(ev)

	if len(base.logs) != 1 {
		t.Fatalf("the wrapped emitter received %d records, want 1", len(base.logs))
	}
	if len(sink.all()) != 1 {
		t.Fatalf("the rule set produced %d annotations, want 1", len(sink.all()))
	}
	// The forwarded record must be byte-identical: nothing here may stamp,
	// rename or strip an attribute.
	if !reflect.DeepEqual(base.logs[0], ev) {
		t.Errorf("the forwarded record was mutated:\ngot  %+v\nwant %+v", base.logs[0], ev)
	}
}

// TestTeeWithoutARecorderIsAPassthrough covers the unconfigured path.
func TestTeeWithoutARecorderIsAPassthrough(t *testing.T) {
	base := newCallRecorder()
	if got := Tee(base, nil, runID{}); got != telemetry.Emitter(base) {
		t.Error("Tee with no recorder must return the base emitter unchanged")
	}
	if got := Tee(nil, nil, runID{}); got != nil {
		t.Error("Tee with no base emitter must return nil")
	}
}
