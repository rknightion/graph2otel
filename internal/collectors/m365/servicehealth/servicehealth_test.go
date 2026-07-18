package servicehealth

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies, satisfying collectors.GraphClient
// so the collector runs through collectors.GetAllValues with no live Graph.
type fakeGraph struct{ bodies map[string]string }

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const overviewsURL = defaultBaseURL + overviewsPath

// fixture is a healthOverviews?$expand=issues response shaped after the live
// m7kni wire (2026-07-18, #119): two services (one degraded, one operational),
// the degraded one carrying one UNRESOLVED incident (endDateTime null — the trap)
// and one long-RESOLVED advisory, plus a service with an unmapped status to
// exercise the -1 fallback.
const fixture = `{"value":[
  {
    "id": "Exchange",
    "service": "Exchange Online",
    "status": "serviceDegradation",
    "issues": [
      {
        "id": "EX123", "title": "Mailbox access degraded",
        "classification": "incident", "status": "serviceDegradation",
        "service": "Exchange Online", "feature": "E-Mail and calendar access",
        "featureGroup": "Networking Issues", "origin": "microsoft",
        "impactDescription": "Users may be unable to access mailboxes.",
        "isResolved": false,
        "startDateTime": "2026-07-18T09:00:00Z", "endDateTime": null,
        "lastModifiedDateTime": "2026-07-18T14:00:00Z"
      },
      {
        "id": "EX999", "title": "Old resolved advisory",
        "classification": "advisory", "status": "serviceRestored",
        "service": "Exchange Online", "isResolved": true,
        "startDateTime": "2026-03-12T00:00:00Z", "endDateTime": "2026-03-30T20:00:00Z",
        "lastModifiedDateTime": "2026-04-01T17:06:38Z"
      }
    ]
  },
  {"id": "Teams", "service": "Microsoft Teams", "status": "serviceOperational", "issues": []},
  {"id": "Mystery", "service": "Mystery Service", "status": "someFutureStatus", "issues": []}
]}`

func newFixtureCollector() *Collector {
	return New(&fakeGraph{bodies: map[string]string{overviewsURL: fixture}}, nil)
}

func TestCollectEmitsBoundedServiceAndIssueGauges(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// services.total{status}: one degraded, one operational, one unmapped.
	services := map[string]float64{}
	for _, p := range rec.MetricPoints(metricServicesTotal) {
		services[p.Attrs["status"]] = p.Value
	}
	for status, want := range map[string]float64{"serviceDegradation": 1, "serviceOperational": 1, "someFutureStatus": 1} {
		if services[status] != want {
			t.Errorf("services.total{status=%s} = %v, want %v", status, services[status], want)
		}
	}

	// status{service}: numeric enum. Degradation=4, operational=0, unmapped=-1.
	statuses := map[string]float64{}
	for _, p := range rec.MetricPoints(metricStatus) {
		statuses[p.Attrs["service"]] = p.Value
	}
	for svc, want := range map[string]float64{"Exchange Online": 4, "Microsoft Teams": 0, "Mystery Service": -1} {
		if statuses[svc] != want {
			t.Errorf("status{service=%s} = %v, want %v", svc, statuses[svc], want)
		}
	}

	// issues.total{classification,status}: both issues counted (resolved included).
	issues := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricIssuesTotal) {
		issues[[2]string{p.Attrs["classification"], p.Attrs["status"]}] = p.Value
	}
	if issues[[2]string{"incident", "serviceDegradation"}] != 1 {
		t.Errorf("issues.total{incident,serviceDegradation} = %v, want 1", issues[[2]string{"incident", "serviceDegradation"}])
	}
	if issues[[2]string{"advisory", "serviceRestored"}] != 1 {
		t.Errorf("issues.total{advisory,serviceRestored} = %v, want 1", issues[[2]string{"advisory", "serviceRestored"}])
	}
}

func TestMetricsCarryNoPerIssueAttribute(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	allowed := map[string]map[string]bool{
		metricServicesTotal: {"status": true, "tenant_id": true},
		metricStatus:        {"service": true, "tenant_id": true},
		metricIssuesTotal:   {"classification": true, "status": true, "tenant_id": true},
	}
	for name, ok := range allowed {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if !ok[k] {
					t.Errorf("metric %s has per-issue attribute %q (id/title must never be a metric label): %v", name, k, p.Attrs)
				}
			}
		}
	}
}

func TestOnlyUnresolvedIssuesAreTwinned(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d twins, want 1 (only the unresolved incident, not the resolved advisory)", len(logs))
	}
	l := logs[0]
	if l.EventName != eventIssue {
		t.Errorf("event name = %q, want %q", l.EventName, eventIssue)
	}
	if l.Attrs["id"] != "EX123" {
		t.Errorf("twin id = %q, want EX123 (the unresolved issue)", l.Attrs["id"])
	}
	if l.Attrs["title"] != "Mailbox access degraded" {
		t.Errorf("twin title = %q, want the incident title", l.Attrs["title"])
	}
	if l.Attrs["impact_description"] == "" {
		t.Error("twin must carry impact_description (the operational value)")
	}
	if l.Attrs["is_resolved"] != "false" {
		t.Errorf("is_resolved = %q, want \"false\"", l.Attrs["is_resolved"])
	}
	// endDateTime is null on the unresolved issue — it must be omitted, never a
	// bogus value, and the collector must not have panicked getting here.
	if _, present := l.Attrs["end_date_time"]; present {
		t.Errorf("end_date_time must be omitted for an unresolved issue (null on the wire), got %q", l.Attrs["end_date_time"])
	}
	if l.Attrs["start_date_time"] != "2026-07-18T09:00:00Z" {
		t.Errorf("start_date_time = %q, want the incident start", l.Attrs["start_date_time"])
	}
}

func TestNoIssuesEmitsNoTwins(t *testing.T) {
	// All-healthy tenant: services present, zero issues → zero twins, no panic.
	body := `{"value":[{"id":"Teams","service":"Microsoft Teams","status":"serviceOperational","issues":[]}]}`
	g := &fakeGraph{bodies: map[string]string{overviewsURL: body}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("healthy tenant emitted %d twins, want 0", n)
	}
	if pts := rec.MetricPoints(metricServicesTotal); len(pts) != 1 {
		t.Errorf("services.total points = %d, want 1", len(pts))
	}
}

func TestStatusValueMapping(t *testing.T) {
	cases := map[string]float64{
		"serviceOperational":  0,
		"serviceRestored":     1,
		"investigating":       3,
		"serviceDegradation":  4,
		"serviceInterruption": 5,
		"totallyUnknown":      -1,
	}
	for status, want := range cases {
		if got := statusValue(status); got != want {
			t.Errorf("statusValue(%q) = %v, want %v", status, got, want)
		}
	}
}
