package telemetry_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const testTenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"

// TestWithTenantStampsEveryMetricInstrument is the core of #143.
//
// Unlike #141's transport stamp — deliberately log-only, because a metric label
// changes series identity (#82) — this one is deliberately a METRIC label. That
// series-identity change IS the point: without it, two tenants' domain metrics
// are not merely unsliceable, they are THE SAME SERIES (one MeterProvider, one
// resource, identical labels), so a two-tenant deploy gets a meaningless number
// rather than a coarse one.
//
// Every instrument is covered explicitly. A metric that silently missed the
// stamp would collide across tenants exactly like today, while the gauge next to
// it separated correctly — the worst shape of this bug, because it looks fixed.
func TestWithTenantStampsEveryMetricInstrument(t *testing.T) {
	tests := []struct {
		name   string
		metric string
		emit   func(e telemetry.Emitter)
	}{
		{
			name:   "Counter",
			metric: "entra.test.counter",
			emit: func(e telemetry.Emitter) {
				e.Counter("entra.test.counter", semconv.UnitDimensionless, "d", 1, telemetry.Attrs{"state": "ok"})
			},
		},
		{
			name:   "Gauge",
			metric: "entra.test.gauge",
			emit: func(e telemetry.Emitter) {
				e.Gauge("entra.test.gauge", semconv.UnitDimensionless, "d", 1, telemetry.Attrs{"state": "ok"})
			},
		},
		{
			name:   "GaugeSnapshot",
			metric: "entra.test.snapshot",
			emit: func(e telemetry.Emitter) {
				e.GaugeSnapshot("entra.test.snapshot", semconv.UnitDimensionless, "d", []telemetry.GaugePoint{
					{Value: 1, Attrs: telemetry.Attrs{"state": "ok"}},
				})
			},
		},
		{
			name:   "UpDownCounter",
			metric: "entra.test.updown",
			emit: func(e telemetry.Emitter) {
				e.UpDownCounter("entra.test.updown", semconv.UnitDimensionless, "d", 1, telemetry.Attrs{"state": "ok"})
			},
		},
		{
			name:   "Histogram",
			metric: "entra.test.histogram",
			emit: func(e telemetry.Emitter) {
				e.Histogram("entra.test.histogram", semconv.UnitSeconds, "d", 1, []float64{1, 2}, telemetry.Attrs{"state": "ok"})
			},
		},
		{
			name:   "HistogramCtx",
			metric: "entra.test.histogramctx",
			emit: func(e telemetry.Emitter) {
				e.HistogramCtx(context.Background(), "entra.test.histogramctx", semconv.UnitSeconds, "d", 1,
					[]float64{1, 2}, telemetry.Attrs{"state": "ok"})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := telemetrytest.New()
			tc.emit(telemetry.WithTenant(rec.Emitter(), testTenant))

			points := rec.MetricPoints(tc.metric)
			if len(points) == 0 {
				t.Fatalf("%s: no points recorded for %q", tc.name, tc.metric)
			}
			for _, p := range points {
				if got := p.Attrs[semconv.AttrTenantID]; got != testTenant {
					t.Errorf("%s: tenant_id = %q, want %q (attrs: %v)", tc.name, got, testTenant, p.Attrs)
				}
				if got := p.Attrs["state"]; got != "ok" {
					t.Errorf("%s: stamping dropped the collector's own attrs: state = %q, want \"ok\"", tc.name, got)
				}
			}
		})
	}
}

// TestWithTenantStampsLogRecords covers the half #143 said must be decided
// explicitly rather than riding in by accident.
//
// It is stamped: log attributes are Loki structured metadata (#90), so this is
// additive and cannot break an existing stream selector, and graph2otel is a
// SIEM feed — a sign-in whose tenant is unknowable is a poor security record.
// It is also what makes deleting the hand-rolled tenant_id from
// entra/securityalerts and entra/securityincidents lossless.
func TestWithTenantStampsLogRecords(t *testing.T) {
	rec := telemetrytest.New()
	telemetry.WithTenant(rec.Emitter(), testTenant).LogEvent(telemetry.Event{
		Name:  "entra.test_event",
		Body:  "b",
		Attrs: telemetry.Attrs{"id": "x"},
	})

	recs := rec.LogRecords()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1", len(recs))
	}
	if got := recs[0].Attrs[semconv.AttrTenantID]; got != testTenant {
		t.Errorf("tenant_id = %q, want %q", got, testTenant)
	}
	if got := recs[0].Attrs["id"]; got != "x" {
		t.Errorf("stamping dropped the collector's own attrs: id = %q, want \"x\"", got)
	}
}

// TestWithTenantEmptyTenantIsPassthrough keeps single-tenant continuity.
//
// collector.WithTenant already treats "" as "no tenant configured" (bare
// checkpoint keys, no self-obs tenant label). Matching that here means a
// single-tenant deploy and every collector unit test see byte-identical output
// to today, so this change cannot silently alter series identity for anyone who
// has not configured a tenant.
func TestWithTenantEmptyTenantIsPassthrough(t *testing.T) {
	rec := telemetrytest.New()
	base := rec.Emitter()
	got := telemetry.WithTenant(base, "")
	if got != base {
		t.Fatalf("WithTenant(e, \"\") returned a wrapper; want the original emitter unchanged")
	}

	got.Gauge("entra.test.gauge", semconv.UnitDimensionless, "d", 1, telemetry.Attrs{"state": "ok"})
	points := rec.MetricPoints("entra.test.gauge")
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if _, present := points[0].Attrs[semconv.AttrTenantID]; present {
		t.Errorf("empty tenant still stamped tenant_id: %v", points[0].Attrs)
	}
}

// TestWithTenantDoesNotMutateCallerAttrs pins the lesson #141 paid for.
//
// mapSignIn is ONE mapper shared by the Graph and blob transports, so a single
// Attrs map can be live in two decorated emitters at once. Stamping in place
// would race and cross values between tenants — the worst possible failure for
// an attribute whose entire job is telling tenants apart.
func TestWithTenantDoesNotMutateCallerAttrs(t *testing.T) {
	rec := telemetrytest.New()
	attrs := telemetry.Attrs{"state": "ok"}

	telemetry.WithTenant(rec.Emitter(), testTenant).
		Gauge("entra.test.gauge", semconv.UnitDimensionless, "d", 1, attrs)

	if _, mutated := attrs[semconv.AttrTenantID]; mutated {
		t.Errorf("WithTenant wrote tenant_id into the caller's Attrs map: %v", attrs)
	}

	ev := telemetry.Event{Name: "entra.test_event", Attrs: telemetry.Attrs{"id": "x"}}
	telemetry.WithTenant(rec.Emitter(), testTenant).LogEvent(ev)
	if _, mutated := ev.Attrs[semconv.AttrTenantID]; mutated {
		t.Errorf("WithTenant wrote tenant_id into the caller's Event.Attrs map: %v", ev.Attrs)
	}
}

// TestWithTenantSnapshotDoesNotMutateCallerPoints is the same rule for the one
// instrument that carries its attrs inside a slice of structs, where a shallow
// copy of the slice would still share every point's Attrs map.
func TestWithTenantSnapshotDoesNotMutateCallerPoints(t *testing.T) {
	rec := telemetrytest.New()
	attrs := telemetry.Attrs{"state": "ok"}
	points := []telemetry.GaugePoint{{Value: 1, Attrs: attrs}}

	telemetry.WithTenant(rec.Emitter(), testTenant).
		GaugeSnapshot("entra.test.snapshot", semconv.UnitDimensionless, "d", points)

	if _, mutated := attrs[semconv.AttrTenantID]; mutated {
		t.Errorf("GaugeSnapshot wrote tenant_id into the caller's point Attrs: %v", attrs)
	}
}

// TestWithTenantFirstStampWins keeps the decorator idempotent.
//
// collector/selfobs.go already puts tenant_id on every scrape.* metric via
// selfObsAttrs, and the Scheduler's emitter is wrapped, so those points reach
// the decorator already stamped. They agree by construction (same tenant), but
// making first-stamp-win means an explicit value is never silently rewritten —
// the same precedence rule WithTransport uses.
func TestWithTenantFirstStampWins(t *testing.T) {
	rec := telemetrytest.New()
	telemetry.WithTenant(rec.Emitter(), testTenant).Gauge(
		"graph2otel.test.gauge", semconv.UnitDimensionless, "d", 1,
		telemetry.Attrs{semconv.AttrTenantID: "explicit-tenant"})

	points := rec.MetricPoints("graph2otel.test.gauge")
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if got := points[0].Attrs[semconv.AttrTenantID]; got != "explicit-tenant" {
		t.Errorf("tenant_id = %q, want %q — the decorator clobbered an explicit stamp", got, "explicit-tenant")
	}
}

// TestEveryEmitterMethodStampsTheTenant is the gate that makes the rest
// trustworthy.
//
// tenantEmitter embeds Emitter, so a method it does not override is PROMOTED
// from the wrapped emitter and compiles perfectly while silently emitting
// unstamped. That is the #141 shape of bug — an absent attribute reads as a
// fact ("not that tenant") rather than as "not stamped" — and here it would
// merge two tenants' series back together on exactly the metrics nobody
// remembered to check.
//
// So rather than trusting the explicit list above to stay complete, this parses
// the Emitter interface and asserts tenant.go declares a method for every one of
// its members. Add an 8th method to Emitter and this fails until it is handled.
func TestEveryEmitterMethodStampsTheTenant(t *testing.T) {
	fset := token.NewFileSet()

	iface, err := parser.ParseFile(fset, "types.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing types.go: %v", err)
	}
	var want []string
	ast.Inspect(iface, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Emitter" {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		for _, m := range it.Methods.List {
			for _, name := range m.Names {
				want = append(want, name.Name)
			}
		}
		return false
	})
	if len(want) == 0 {
		t.Fatal("found no methods on the Emitter interface — did types.go move?")
	}

	impl, err := parser.ParseFile(fset, "tenant.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing tenant.go: %v", err)
	}
	got := map[string]bool{}
	for _, d := range impl.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == "tenantEmitter" {
			got[fn.Name.Name] = true
		}
	}

	var missing []string
	for _, m := range want {
		if !got[m] {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("tenantEmitter does not override Emitter.%s — it is promoted from the embedded\n"+
			"Emitter and will emit WITHOUT tenant_id, silently merging that signal across tenants.\n"+
			"Add a %s method to tenant.go that stamps semconv.AttrTenantID and delegates.", m, m)
	}
}
