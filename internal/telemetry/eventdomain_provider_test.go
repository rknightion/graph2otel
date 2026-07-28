package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// recordingLogExporter captures the resource each exported record carries.
// Resource is read from the RECORD rather than from anything the test wired,
// because that is the only thing that proves the value survived the SDK's own
// stamping — asserting on a resource the test built itself would pass even if
// no record ever reached a per-domain provider.
type recordingLogExporter struct {
	mu       sync.Mutex
	seen     []recordedLog
	closed   bool
	rejected int
}

type recordedLog struct {
	eventName string
	domain    string
	resource  *resource.Resource
}

// Export models a REAL exporter's post-close behavior: once Shutdown has been
// called, an export is refused rather than silently accepted. This is not
// pedantry — an earlier version of this fake accepted exports after close, and
// it passed over a live defect where the first domain provider's shutdown
// closed the exporter shared by all eight, discarding everything the other
// seven still had queued. A fake that cannot fail the way production fails is
// not a test.
func (r *recordingLogExporter) Export(_ context.Context, recs []sdklog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.rejected += len(recs)
		return errors.New("recordingLogExporter: export after shutdown")
	}
	for _, rec := range recs {
		res := rec.Resource()
		var domain string
		for _, kv := range res.Attributes() {
			if string(kv.Key) == ResourceAttrEventDomain {
				domain = kv.Value.AsString()
			}
		}
		r.seen = append(r.seen, recordedLog{eventName: rec.EventName(), domain: domain, resource: res})
	}
	return nil
}

func (r *recordingLogExporter) ForceFlush(context.Context) error { return nil }

func (r *recordingLogExporter) Shutdown(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// rejectedCount is how many records were handed to the exporter after it was
// closed — i.e. how many a real deployment would have lost on exit.
func (r *recordingLogExporter) rejectedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rejected
}

func (r *recordingLogExporter) domainFor(eventName string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seen {
		if s.eventName == eventName {
			return s.domain, true
		}
	}
	return "", false
}

func (r *recordingLogExporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// newDomainTestProvider builds a Provider over a recording log exporter with a
// base logs resource carrying one identifying attribute, so the test can also
// prove the per-domain resources are the base resource PLUS the domain rather
// than a replacement for it.
func newDomainTestProvider(t *testing.T) (*Provider, *recordingLogExporter) {
	t.Helper()
	logRes, err := resource.New(context.Background(), resource.WithAttributes(attribute.String("service.name", "graph2otel")))
	if err != nil {
		t.Fatalf("build logs resource: %v", err)
	}
	metricRes, err := resource.New(context.Background(), resource.WithAttributes(attribute.String("service.name", "graph2otel")))
	if err != nil {
		t.Fatalf("build metrics resource: %v", err)
	}
	rec := &recordingLogExporter{}
	p := newProvider(Options{}, metricRes, logRes, &fakeMetricExporter{}, rec, newOTLPTransportTracker())
	return p, rec
}

// TestLogRecordsCarryTheirEventDomainOnTheResource is the core #402 assertion:
// a record's resource must carry the domain derived from its own event name,
// which is only possible because the emitter routes to a per-domain
// LoggerProvider.
func TestLogRecordsCarryTheirEventDomainOnTheResource(t *testing.T) {
	p, rec := newDomainTestProvider(t)
	e := p.Emitter()

	for _, name := range []string{"entra.signin", "intune.device", "m365.activity", "azure.uncataloged"} {
		e.LogEvent(Event{Name: name, Body: "b", Severity: SeverityInfo})
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if got := rec.count(); got != 4 {
		t.Fatalf("exported %d records, want 4 — a routed record was lost", got)
	}
	want := map[string]string{
		"entra.signin":      "entra",
		"intune.device":     "intune",
		"m365.activity":     "m365",
		"azure.uncataloged": EventDomainOther,
	}
	for name, domain := range want {
		got, ok := rec.domainFor(name)
		if !ok {
			t.Errorf("event %q never reached the exporter", name)
			continue
		}
		if got != domain {
			t.Errorf("event %q carried %s=%q, want %q", name, ResourceAttrEventDomain, got, domain)
		}
	}
}

// TestPerDomainResourceExtendsTheBaseResource guards the obvious way to get the
// mechanism right and the data wrong: building each per-domain resource from
// scratch instead of from the base would silently drop service.name and every
// other identifying attribute, and the test above would still pass.
func TestPerDomainResourceExtendsTheBaseResource(t *testing.T) {
	p, rec := newDomainTestProvider(t)
	p.Emitter().LogEvent(Event{Name: "entra.signin", Body: "b", Severity: SeverityInfo})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("exported %d records, want 1", rec.count())
	}
	res := rec.seen[0].resource
	var sawService bool
	for _, kv := range res.Attributes() {
		if string(kv.Key) == "service.name" && kv.Value.AsString() == "graph2otel" {
			sawService = true
		}
	}
	if !sawService {
		t.Errorf("per-domain resource lost the base attributes: %v", res.Attributes())
	}
}

// TestShutdownFlushesEveryDomainProvider covers the failure mode the single
// provider could not have: with N providers, flushing only the one the last
// record happened to use would silently discard everything buffered in the
// other N-1 on exit. Emitting to several domains and asserting all of them
// arrive AFTER shutdown is what proves the fan-out is flushed rather than
// merely constructed.
func TestShutdownFlushesEveryDomainProvider(t *testing.T) {
	p, rec := newDomainTestProvider(t)
	e := p.Emitter()
	domains := EventDomains()
	for _, d := range domains {
		e.LogEvent(Event{Name: d + ".probe", Body: "b", Severity: SeverityInfo})
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("%d records exported before shutdown — batching is not in play, so this test proves nothing", got)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if got := rec.count(); got != len(domains) {
		t.Errorf("exported %d records after shutdown, want %d — a domain provider was not flushed", got, len(domains))
	}
	if got := rec.rejectedCount(); got != 0 {
		t.Errorf("%d records were exported AFTER the shared exporter closed and would be lost in production", got)
	}
}

// TestMetricsResourceOmitsTheEventDomain pins the deliberate asymmetry. A
// resource attribute participates in metric series identity, so putting the
// domain on the metrics resource would fork every self-observability series by
// domain — paying real active-series cost for a dimension that answers no
// question about a metric (#82). Logs only, on purpose.
func TestMetricsResourceOmitsTheEventDomain(t *testing.T) {
	metricRes, err := buildResource(context.Background(), Options{ServiceName: "graph2otel", ServiceVersion: "v1"}, false)
	if err != nil {
		t.Fatalf("build metrics resource: %v", err)
	}
	for _, kv := range metricRes.Attributes() {
		if string(kv.Key) == ResourceAttrEventDomain {
			t.Fatalf("metrics resource carries %s — it must be logs-only", ResourceAttrEventDomain)
		}
	}
}
