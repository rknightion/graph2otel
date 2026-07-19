package ediscoverycases

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is a canned-response GraphClient: bodies keyed by exact URL, or an
// error keyed by exact URL.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const casesURL = "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases"

// liveCase is the VERBATIM GET /security/cases/ediscoveryCases record from
// m7kni, read as graph2otel-poller 2026-07-19 `[live-measured 2026-07-19, #102]`.
// It is the default "Content Search" case Purview auto-creates, so
// createdDateTime and lastModifiedDateTime are the .NET zero value
// 0001-01-01T00:00:00Z — the trap this fixture pins: those must NOT be emitted
// as a year-0001 timestamp. externalId / closedDateTime / closedBy are null.
const liveCase = `{"value":[{
  "description": "This case contains all content searches from Microsoft Purview compliance portal.",
  "lastModifiedDateTime": "0001-01-01T00:00:00Z",
  "status": "active",
  "closedDateTime": null,
  "externalId": null,
  "id": "ed1518bd-2f9f-4227-af55-9f1061cf9c32",
  "displayName": "Content Search",
  "createdDateTime": "0001-01-01T00:00:00Z",
  "lastModifiedBy": null,
  "closedBy": null
}]}`

func TestCollectAgainstLiveCase(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{casesURL: liveCase}}
	rec := telemetrytest.New()
	if err := NewCases(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(casesMetric)
	if len(pts) != 1 {
		t.Fatalf("metric points = %d, want 1: %+v", len(pts), pts)
	}
	if pts[0].Attrs["status"] != "active" || pts[0].Value != 1 {
		t.Errorf("gauge point = %+v, want {status=active, value=1}", pts[0])
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs))
	}
	lr := logs[0]
	if lr.EventName != caseEventName {
		t.Errorf("event name = %q, want %q", lr.EventName, caseEventName)
	}
	wantAttrs := map[string]string{
		"id":           "ed1518bd-2f9f-4227-af55-9f1061cf9c32",
		"display_name": "Content Search",
		"status":       "active",
		"description":  "This case contains all content searches from Microsoft Purview compliance portal.",
	}
	for k, want := range wantAttrs {
		if lr.Attrs[k] != want {
			t.Errorf("attr %q = %q, want %q", k, lr.Attrs[k], want)
		}
	}
	// The zero-value .NET datetimes and the null fields must be ABSENT — never
	// emitted as a year-0001 timestamp or an empty attribute.
	for _, k := range []string{"created_date_time", "closed_date_time", "external_id"} {
		if v, present := lr.Attrs[k]; present && v != "" {
			t.Errorf("attr %q must be absent (zero/null on the wire), got %q", k, v)
		}
	}
}

func TestBucketsByStatusAndEmitsRealDates(t *testing.T) {
	body := `{"value":[
	  {"id":"a","displayName":"Case A","status":"active"},
	  {"id":"b","displayName":"Case B","status":"closed","createdDateTime":"2026-01-02T03:04:05Z","closedDateTime":"2026-05-06T07:08:09Z","externalId":"EXT-9"},
	  {"id":"c","displayName":"Case C","status":"closed"}
	]}`
	g := &fakeGraph{bodies: map[string]string{casesURL: body}}
	rec := telemetrytest.New()
	if err := NewCases(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(casesMetric) {
		got[p.Attrs["status"]] = p.Value
	}
	if got["active"] != 1 || got["closed"] != 2 {
		t.Errorf("status buckets = %v, want active=1 closed=2", got)
	}

	// Case B carries real created/closed dates + an externalId — all emitted.
	var caseB map[string]string
	for _, lr := range rec.LogRecords() {
		if lr.Attrs["id"] == "b" {
			caseB = lr.Attrs
		}
	}
	if caseB == nil {
		t.Fatal("no log twin for case b")
	}
	wantB := map[string]string{
		"created_date_time": "2026-01-02T03:04:05Z",
		"closed_date_time":  "2026-05-06T07:08:09Z",
		"external_id":       "EXT-9",
	}
	for k, want := range wantB {
		if caseB[k] != want {
			t.Errorf("case b attr %q = %q, want %q", k, caseB[k], want)
		}
	}
}

// TestUnregisteredDataPlaneFailsLoud pins that a 401 (the S&C data-plane
// registration missing, despite eDiscovery.Read.All being granted) fails the
// collector loudly and names the fix, rather than skipping silently — the
// #109/#126 lesson. No signals are emitted on error.
func TestUnregisteredDataPlaneFailsLoud(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		casesURL: errors.New(`status 401: {"error":{"code":"Authentication_MissingOrMalformed","message":"Access token validation failure."}}`),
	}}
	rec := telemetrytest.New()
	err := NewCases(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected an error on 401, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "registration") {
		t.Errorf("401 error must name the S&C data-plane registration fix, got: %v", err)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("emitted %d logs on error, want 0", n)
	}
	if n := len(rec.MetricPoints(casesMetric)); n != 0 {
		t.Errorf("emitted %d metric points on error, want 0", n)
	}
}

func TestExperimentalAndScope(t *testing.T) {
	c := NewCases(&fakeGraph{}, nil)
	if !c.Experimental() {
		t.Error("eDiscovery collector must be Experimental (opt-in: needs the S&C data-plane registration)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "eDiscovery.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [eDiscovery.Read.All]", perms)
	}
}
