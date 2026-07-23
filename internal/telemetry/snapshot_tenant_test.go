package telemetry_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const (
	tenantA = "aaaaaaaa-0000-0000-0000-000000000001"
	tenantB = "bbbbbbbb-0000-0000-0000-000000000002"
)

// tenantsOf returns the tenant_id of every point recorded for a metric, so a
// test can assert which tenants survived a collection.
func tenantsOf(rec *telemetrytest.Recorder, metric string) map[string]int {
	out := map[string]int{}
	for _, p := range rec.MetricPoints(metric) {
		out[p.Attrs[semconv.AttrTenantID]]++
	}
	return out
}

// TestGaugeSnapshotKeepsEveryTenantsSeries is #236.
//
// There is exactly ONE otelEmitter for the process — cmd/graph2otel/tenants.go
// takes provider.Emitter() once and WithTenant decorates that same instance per
// tenant — and GaugeSnapshot used to key its observable state by metric name
// alone, replacing the point set wholesale. So the second tenant to poll erased
// the first tenant's series for that metric, silently, on all 321 GaugeSnapshot
// call sites. The label #143 added was correct on the points that survived; most
// points did not survive.
func TestGaugeSnapshotKeepsEveryTenantsSeries(t *testing.T) {
	rec := telemetrytest.New()
	base := rec.Emitter()
	a := telemetry.WithTenant(base, tenantA)
	b := telemetry.WithTenant(base, tenantB)

	const metric = "intune.test.devices"
	a.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "compliant"}},
		{Value: 2, Attrs: telemetry.Attrs{"state": "noncompliant"}},
	})
	b.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 3, Attrs: telemetry.Attrs{"state": "compliant"}},
	})

	got := tenantsOf(rec, metric)
	if got[tenantA] != 2 {
		t.Errorf("tenant A has %d series after tenant B snapshotted, want 2 — B's snapshot erased A's (%v)",
			got[tenantA], got)
	}
	if got[tenantB] != 1 {
		t.Errorf("tenant B has %d series, want 1 (%v)", got[tenantB], got)
	}
}

// TestGaugeSnapshotSurvivesTheProductionDecoratorChain builds the emitter the
// composition root actually builds — limiter innermost (provider.go), then
// WithTransport, then WithTenant outermost (cmd/graph2otel/tenants.go:314) — and
// asserts the tenant partition still reaches the base emitter through all of it.
//
// The per-decorator unit tests cannot catch a decorator that swallows the scope
// while wrapped by another, and a swallowed scope restores the exact #236 bug in
// production while every narrower test stays green.
func TestGaugeSnapshotSurvivesTheProductionDecoratorChain(t *testing.T) {
	rec := telemetrytest.New()
	limited := telemetry.WithCardinalityLimits(rec.Emitter(), telemetry.Limits{PerMetric: 5000, Global: 100000})

	chain := func(tenant string) telemetry.Emitter {
		return telemetry.WithTenant(telemetry.WithTransport(limited, telemetry.TransportGraph), tenant)
	}

	const metric = "entra.test.chain"
	chain(tenantA).GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
	})
	chain(tenantB).GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
	})

	got := tenantsOf(rec, metric)
	if got[tenantA] != 1 || got[tenantB] != 1 {
		t.Errorf("through the production chain: series by tenant = %v, want one each for A and B — "+
			"a decorator dropped the tenant scope", got)
	}
}

// TestGaugeSnapshotClearsOnlyTheSnapshottingTenant is the case that forces the
// tenant to be an ARGUMENT rather than something read back off the points.
//
// An empty snapshot is the documented way to clear a metric, and it carries no
// attributes — so an implementation that recovered the tenant from the points
// would clear the wrong partition (or none), leaving one tenant's series frozen
// at their last values forever while the metric looked healthy.
func TestGaugeSnapshotClearsOnlyTheSnapshottingTenant(t *testing.T) {
	rec := telemetrytest.New()
	base := rec.Emitter()
	a := telemetry.WithTenant(base, tenantA)
	b := telemetry.WithTenant(base, tenantB)

	const metric = "intune.test.clear"
	a.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
		{Value: 1, Attrs: telemetry.Attrs{"state": "stale"}},
	})
	b.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
	})

	a.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", nil)

	got := tenantsOf(rec, metric)
	if got[tenantA] != 0 {
		t.Errorf("tenant A kept %d series after snapshotting an empty set, want 0 (%v)", got[tenantA], got)
	}
	if got[tenantB] != 1 {
		t.Errorf("tenant A's clear removed tenant B's series: %v, want one series for B", got)
	}
}

// TestGaugeSnapshotDropsAbsentSeriesPerTenant keeps #104's behavior inside each
// partition: a series absent from a LATER snapshot still drops out of the
// export. Partitioning must not turn an observable gauge into sticky state —
// that would reintroduce exactly the ghost series the observable gauge exists to
// avoid, one partition at a time.
func TestGaugeSnapshotDropsAbsentSeriesPerTenant(t *testing.T) {
	rec := telemetrytest.New()
	base := rec.Emitter()
	a := telemetry.WithTenant(base, tenantA)
	b := telemetry.WithTenant(base, tenantB)

	const metric = "intune.test.drop"
	a.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "a1"}},
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "a2"}},
	})
	b.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "b1"}},
	})
	a.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"device_id": "a1"}},
	})

	devices := map[string]string{}
	for _, p := range rec.MetricPoints(metric) {
		devices[p.Attrs["device_id"]] = p.Attrs[semconv.AttrTenantID]
	}
	if _, ghost := devices["a2"]; ghost {
		t.Errorf("device a2 survived a later snapshot that omitted it: %v", devices)
	}
	if devices["a1"] != tenantA || devices["b1"] != tenantB {
		t.Errorf("series by device = %v, want a1 under tenant A and b1 under tenant B", devices)
	}
}

// TestGaugeSnapshotEmptyTenantSharesOnePartition pins single-tenant continuity.
//
// WithTenant("") returns the emitter unchanged, so those snapshots arrive
// unscoped and all share the one "" partition — which is the pre-#236 behavior
// exactly. A deploy that has not configured a tenant must see no change at all.
func TestGaugeSnapshotEmptyTenantSharesOnePartition(t *testing.T) {
	rec := telemetrytest.New()
	e := telemetry.WithTenant(rec.Emitter(), "")

	const metric = "intune.test.untenanted"
	e.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
		{Value: 1, Attrs: telemetry.Attrs{"state": "stale"}},
	})
	e.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
		{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
	})

	points := rec.MetricPoints(metric)
	if len(points) != 1 {
		t.Fatalf("got %d series, want 1 — an unscoped snapshot must replace the previous one wholesale: %+v",
			len(points), points)
	}
	if _, stamped := points[0].Attrs[semconv.AttrTenantID]; stamped {
		t.Errorf("empty tenant still stamped tenant_id: %v", points[0].Attrs)
	}
}

// TestGaugeSnapshotIsConcurrencySafeAcrossTenants runs what production runs: one
// Scheduler per tenant snapshotting the same metric names into one shared
// emitter, while the reader collects. Partitioned state is new shared state, and
// this is the -race proof that the partition map is not written outside the lock
// the callback reads it under.
func TestGaugeSnapshotIsConcurrencySafeAcrossTenants(t *testing.T) {
	rec := telemetrytest.New()
	base := rec.Emitter()

	tenants := []string{tenantA, tenantB, "cccccccc-0000-0000-0000-000000000003"}
	const metric = "intune.test.concurrent"

	var wg sync.WaitGroup
	for _, tenant := range tenants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := telemetry.WithTenant(base, tenant)
			for i := range 50 {
				e.GaugeSnapshot(metric, semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
					{Value: float64(i), Attrs: telemetry.Attrs{"state": "ok"}},
				})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			rec.MetricPoints(metric)
		}
	}()
	wg.Wait()

	got := tenantsOf(rec, metric)
	for _, tenant := range tenants {
		if got[tenant] != 1 {
			t.Errorf("tenant %s has %d series after the concurrent run, want 1 (%v)", tenant, got[tenant], got)
		}
	}
}

// TestEveryEmitterDecoratorForwardsTheSnapshotTenant is the gate that makes the
// whole scheme trustworthy, and it is the same shape as
// TestEveryEmitterMethodStampsTheTenant for the same reason.
//
// Every decorator in this package embeds the Emitter interface, so a decorator
// that does not declare gaugeSnapshotFor still satisfies Emitter, still
// compiles, and silently drops the tenant scope on the floor — putting every
// tenant's observable gauges back into one partition. That is #236 restored,
// invisibly, by a decorator whose author never thought about tenants (see
// transportEmitter, which is exactly that decorator).
//
// So rather than trusting a hand-maintained list, this finds every type in the
// package that embeds Emitter and requires it to declare the method.
func TestEveryEmitterDecoratorForwardsTheSnapshotTenant(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the telemetry package directory: %v", err)
	}

	decorators := map[string]bool{}
	forwards := map[string]bool{}
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		parsed++
		for _, d := range file.Decls {
			switch decl := d.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, f := range st.Fields.List {
						id, ok := f.Type.(*ast.Ident)
						if ok && len(f.Names) == 0 && id.Name == "Emitter" {
							decorators[ts.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil || len(decl.Recv.List) != 1 || decl.Name.Name != "gaugeSnapshotFor" {
					continue
				}
				star, ok := decl.Recv.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				if id, ok := star.X.(*ast.Ident); ok {
					forwards[id.Name] = true
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatal("parsed no package files — did the tests move out of the package directory?")
	}
	if len(decorators) == 0 {
		t.Fatal("found no types embedding Emitter — the gate is not looking at anything")
	}

	var missing []string
	for name := range decorators {
		if !forwards[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s embeds Emitter but does not declare gaugeSnapshotFor, so GaugeSnapshot is promoted\n"+
			"from the wrapped emitter and the TENANT SCOPE is dropped — every tenant's observable gauges\n"+
			"collapse back into one partition and overwrite each other (#236).\n"+
			"Add: func (e *%s) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {\n"+
			"\tsnapshotFor(e.Emitter, tenant, name, unit, desc, points)\n}", name, name)
	}
}
