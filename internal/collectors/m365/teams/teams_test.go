package teams

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors), satisfying
// collectors.GraphClient so Collect runs with no live Graph call.
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
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"
const listURL = base + teamsListPath

func detailURL(id string) string { return base + "/teams/" + id + "?$select=isArchived,summary" }

// listBody mirrors the live /teams shape (2026-07-19): only id/displayName/
// description/visibility populated. Four teams: public + private (visibility),
// one guest team, plus synthetic ownerless + archived-ownerless fixtures (a live
// ownerless team can't be created — Microsoft blocks removing the last owner).
const listBody = `{"value":[
	{"id":"t-public","displayName":"g2o-test-public","description":"x","visibility":"public"},
	{"id":"t-private","displayName":"g2o-test-private","description":"x","visibility":"private"},
	{"id":"t-guest","displayName":"g2o-test-guest","description":"x","visibility":"private"},
	{"id":"t-orphan","displayName":"orphan","description":"x","visibility":"private"},
	{"id":"t-archived","displayName":"wound-down","description":"x","visibility":"private"}
]}`

func sample() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		listURL: listBody,
		// live-captured summary shape
		detailURL("t-public"):   `{"isArchived":false,"summary":{"ownersCount":1,"membersCount":1,"guestsCount":0}}`,
		detailURL("t-private"):  `{"isArchived":false,"summary":{"ownersCount":1,"membersCount":1,"guestsCount":0}}`,
		detailURL("t-guest"):    `{"isArchived":false,"summary":{"ownersCount":1,"membersCount":1,"guestsCount":1}}`,
		detailURL("t-orphan"):   `{"isArchived":false,"summary":{"ownersCount":0,"membersCount":3,"guestsCount":0}}`,
		detailURL("t-archived"): `{"isArchived":true,"summary":{"ownersCount":0,"membersCount":2,"guestsCount":0}}`,
	}}
}

func gaugeBy(t *testing.T, rec *telemetrytest.Recorder, name, attrKey string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(name) {
		out[p.Attrs[attrKey]] = p.Value
	}
	return out
}

func gaugeScalar(t *testing.T, rec *telemetrytest.Recorder, name string) float64 {
	t.Helper()
	pts := rec.MetricPoints(name)
	if len(pts) != 1 {
		t.Fatalf("%s: got %d points, want 1", name, len(pts))
	}
	return pts[0].Value
}

func TestCollectBucketsVisibilityMembershipOwnerlessGuests(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(sample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// total by visibility: 1 public, 4 private (private+guest+orphan+archived).
	vis := gaugeBy(t, rec, metricTotal, semconv.AttrVisibility)
	if vis["public"] != 1 || vis["private"] != 4 {
		t.Errorf("teams.total by visibility = %v, want public=1 private=4", vis)
	}
	if _, ok := vis["hiddenMembership"]; !ok {
		t.Error("hiddenMembership bucket missing — the grid must emit 0 for stable baselines")
	}

	// membership by role: owners 1+1+1+0+0=3, members 1+1+1+3+2=8, guests 0+0+1+0+0=1.
	mem := gaugeBy(t, rec, metricMembership, semconv.AttrRole)
	if mem["owner"] != 3 || mem["member"] != 8 || mem["guest"] != 1 {
		t.Errorf("membership by role = %v, want owner=3 member=8 guest=1", mem)
	}

	// ownerless: t-orphan only (t-archived has 0 owners but is archived → excluded).
	if got := gaugeScalar(t, rec, metricOwnerless); got != 1 {
		t.Errorf("ownerless.total = %v, want 1 (archived-ownerless excluded)", got)
	}
	// with_guests: only t-guest.
	if got := gaugeScalar(t, rec, metricWithGuests); got != 1 {
		t.Errorf("with_guests.total = %v, want 1", got)
	}
}

func TestCollectEmitsOneLogTwinPerTeam(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(sample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 5 {
		t.Fatalf("emitted %d log twins, want 5 (one per team)", len(logs))
	}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("event name = %q, want %q", l.EventName, eventName)
		}
	}
}

func TestOwnerlessTwinIsWarn_ArchivedIsNot(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(sample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sev := map[string]string{}
	for _, l := range rec.LogRecords() {
		sev[l.Attrs[semconv.AttrDisplayName]] = l.SeverityText
	}
	if sev["orphan"] != "WARN" {
		t.Errorf("ownerless team severity = %q, want WARN (the actionable signal)", sev["orphan"])
	}
	if sev["wound-down"] == "WARN" {
		t.Error("archived ownerless team should NOT be WARN — archived is a desired end-state, not an orphan")
	}
	if sev["g2o-test-public"] != "INFO" {
		t.Errorf("owned team severity = %q, want INFO", sev["g2o-test-public"])
	}
}

// TestCollectForbiddenDegradesGracefully pins that a 403 on the list (scopes not
// granted) is a skip-and-log, not a scrape error.
func TestCollectForbiddenDegradesGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 403: Forbidden"),
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on 403 = %v, want nil (graceful skip)", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("a 403 skip must emit no twins")
	}
}

// TestNameAndPermissions pins the identity + least-privilege scopes.
func TestNameAndPermissions(t *testing.T) {
	c := New(sample(), nil)
	if c.Name() != "m365.teams" {
		t.Errorf("Name = %q", c.Name())
	}
	want := map[string]bool{"Team.ReadBasic.All": true, "TeamSettings.Read.All": true}
	for _, p := range c.RequiredPermissions() {
		if !want[p] {
			t.Errorf("unexpected scope %q", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing scopes: %v", want)
	}
}

// TestNoPerEntityMetricLabels is the #112 guard at the collector level: no team
// id or displayName may appear on any metric series (the signalgate TestMain
// enforces this over the whole package too).
func TestNoPerEntityMetricLabels(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(sample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, name := range []string{metricTotal, metricMembership, metricOwnerless, metricWithGuests} {
		for _, p := range rec.MetricPoints(name) {
			for k, v := range p.Attrs {
				if k == semconv.AttrId || k == semconv.AttrDisplayName {
					t.Errorf("%s carries per-entity label %s=%s — a team id/name must never be a metric label (#112)", name, k, v)
				}
			}
		}
	}
}
