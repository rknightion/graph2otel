package telemetry

import (
	"context"
	"maps"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// tenantEmitter stamps semconv.AttrTenantID onto every record passing through
// it — metrics AND logs — delegating everything else to the wrapped Emitter.
//
// Every method of Emitter is overridden explicitly. An un-overridden method
// would be PROMOTED from the embedded Emitter, compile perfectly, and emit
// unstamped — merging that one signal across tenants while its neighbors
// separated correctly. TestEveryEmitterMethodStampsTheTenant parses the Emitter
// interface and fails if a method is missing here, so an 8th method cannot land
// unstamped.
type tenantEmitter struct {
	Emitter
	tenant string
}

// WithTenant returns an Emitter that stamps every record it emits with the
// tenant that produced it (semconv.AttrTenantID). An empty tenantID returns e
// unchanged.
//
// # Why this exists (#143)
//
// graph2otel runs one Scheduler per configured tenant, but there is one
// MeterProvider and one OTLP resource for the whole process, and nothing ever
// injected the tenant into a domain record — a collector's labels were exactly
// what it passed. So two tenants' domain metrics were not merely unsliceable,
// they were THE SAME SERIES: same name, same labels, interleaving samples. A
// two-tenant deploy did not get a coarse number, it got a meaningless one, while
// README and CLAUDE.md advertised multi-tenancy. This makes the shipped claim
// true.
//
// # Why it wraps the emitter, not the collectors
//
// The Emitter is the only boundary with nothing behind it: there is exactly one
// LogEvent implementation and every metric path funnels through the facade, so a
// stamp here cannot be escaped. The Scheduler already knows its tenant
// (collector.WithTenant), which makes the composition root the natural seam —
// the same chokepoint WithTransport uses. Threading a tenant through 58
// collectors would be a large diff whose failure mode is one forgotten
// collector silently merging tenants.
//
// # The deliberate asymmetry with WithTransport
//
// Provenance (#141) is log-ONLY, because adding a label to a metric changes its
// series identity and would break existing dashboards (#82). This is the
// opposite: it IS a metric label, and it DOES change series identity for every
// domain metric. That is the point, and it is a breaking change to every
// dashboard and alert query — pre-1.0 is the moment to take it.
//
// Cardinality (#112) is satisfied: tenant_id multiplies series by the number of
// tenants an operator deliberately configured. That is bounded and
// operator-chosen — it does not grow with tenant SIZE, which is what the rule
// forbids — and a single-tenant deploy sees no series-count change at all.
//
// # Empty tenant is a passthrough
//
// collector.WithTenant already treats "" as "no tenant configured" (bare
// checkpoint keys, no self-obs tenant label). Matching that keeps a
// single-tenant deploy, and every collector unit test, byte-identical to before.
//
// The returned Emitter never mutates the caller's Attrs. mapSignIn is
// deliberately ONE mapper shared by two transports, so its output map can be
// live in two decorated emitters at once; stamping in place would race and cross
// values between tenants — the worst possible failure for the attribute whose
// whole job is telling tenants apart.
func WithTenant(e Emitter, tenantID string) Emitter {
	if tenantID == "" {
		return e
	}
	return &tenantEmitter{Emitter: e, tenant: tenantID}
}

// stamp returns a copy of attrs carrying the tenant.
//
// PRECEDENCE: the first stamp wins — an already-stamped record passes through
// unchanged. collector/selfobs.go puts tenant_id on every scrape.* metric via
// selfObsAttrs and the Scheduler's emitter is wrapped, so those points arrive
// here already stamped with the same value. First-wins means an explicit stamp
// is never silently rewritten, matching WithTransport's rule.
func (e *tenantEmitter) stamp(attrs Attrs) Attrs {
	if _, stamped := attrs[semconv.AttrTenantID]; stamped {
		return attrs
	}
	out := make(Attrs, len(attrs)+1)
	maps.Copy(out, attrs)
	out[semconv.AttrTenantID] = e.tenant
	return out
}

func (e *tenantEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	e.Emitter.Counter(name, unit, desc, add, e.stamp(attrs))
}

func (e *tenantEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	e.Emitter.Gauge(name, unit, desc, value, e.stamp(attrs))
}

// GaugeSnapshot stamps every point. The points slice is rebuilt rather than
// written through: each GaugePoint carries its own Attrs map, so mutating in
// place would reach into the caller's maps even if the slice itself were copied.
func (e *tenantEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	stamped := make([]GaugePoint, len(points))
	for i, p := range points {
		stamped[i] = GaugePoint{Value: p.Value, Attrs: e.stamp(p.Attrs)}
	}
	e.Emitter.GaugeSnapshot(name, unit, desc, stamped)
}

func (e *tenantEmitter) UpDownCounter(name, unit, desc string, value float64, attrs Attrs) {
	e.Emitter.UpDownCounter(name, unit, desc, value, e.stamp(attrs))
}

func (e *tenantEmitter) Histogram(name, unit, desc string, value float64, bounds []float64, attrs Attrs) {
	e.Emitter.Histogram(name, unit, desc, value, bounds, e.stamp(attrs))
}

func (e *tenantEmitter) HistogramCtx(ctx context.Context, name, unit, desc string, value float64,
	bounds []float64, attrs Attrs,
) {
	e.Emitter.HistogramCtx(ctx, name, unit, desc, value, bounds, e.stamp(attrs))
}

func (e *tenantEmitter) LogEvent(ev Event) {
	ev.Attrs = e.stamp(ev.Attrs)
	e.Emitter.LogEvent(ev)
}
