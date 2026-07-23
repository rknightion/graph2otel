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

const betaBase = "https://graph.microsoft.com/beta"

func installedAppsURL(id string) string {
	return betaBase + "/teams/" + id + "/installedApps?$expand=teamsApp"
}
func channelsURL(id string) string { return betaBase + "/teams/" + id + "/channels" }

// m7kni is the real team id the #247 samples were captured from (2026-07-23).
const m7kni = "5bd47737-231d-48e5-b6a0-0c5740d762c1"

// installedAppsBody is two VERBATIM store apps from 247-installedApps.json (RSC
// empty, distributionMethod=store — the only shape observed live on m7kni) plus
// ONE synthetic sideloaded app carrying an RSC grant. A live sideloaded/RSC app
// can't be produced on m7kni (all 63 were store/0-RSC), so the actionable shape
// is exercised synthetically, exactly as the ownerless-team fixture is.
const installedAppsBody = `{"@odata.count":3,"value":[
	{"id":"inst-activity","grantedResourceSpecificApplicationPermissions":[],"consentedPermissionSet":null,
	 "scopeInfo":{"scope":"team","teamId":"` + m7kni + `"},
	 "teamsApp":{"id":"14d6962d-6eeb-4f48-8890-de55454bb136","externalId":null,"displayName":"Activity","distributionMethod":"store"}},
	{"id":"inst-calling","grantedResourceSpecificApplicationPermissions":[],"consentedPermissionSet":null,
	 "scopeInfo":{"scope":"team","teamId":"` + m7kni + `"},
	 "teamsApp":{"id":"20c3440d-c67e-4420-9f80-0e50c39693df","externalId":null,"displayName":"Calling","distributionMethod":"store"}},
	{"id":"inst-side","grantedResourceSpecificApplicationPermissions":["ChannelMessage.Read.Group","TeamMember.Read.Group"],"consentedPermissionSet":null,
	 "scopeInfo":{"scope":"team","teamId":"` + m7kni + `"},
	 "teamsApp":{"id":"synthetic-sideloaded-id","externalId":"ext-123","displayName":"g2o-sideloaded-probe","distributionMethod":"sideloaded"}}
]}`

// channelsBody is the VERBATIM live standard channel plus ONE synthetic private
// channel (private/shared membership was unobservable on m7kni — n=1 standard).
const channelsBody = `{"@odata.count":2,"value":[
	{"id":"19:standard@thread.tacv2","createdDateTime":"2026-07-23T08:23:24.837Z","displayName":"gayyyy","description":"teamtest",
	 "email":"teamtest@m7kni.io","tenantId":"4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
	 "filesFolderWebUrl":"https://m7knio.sharepoint.com/sites/teamtest/Shared Documents/gayyyy",
	 "membershipType":"standard","isArchived":false},
	{"id":"19:private@thread.tacv2","displayName":"secret-chan","email":"","membershipType":"private","isArchived":false}
]}`

// appsChannelsSample is a single-team fixture wiring the beta installedApps +
// channels endpoints, for the #247 signals.
func appsChannelsSample() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		listURL:                 `{"value":[{"id":"` + m7kni + `","displayName":"g2o-teamtest","description":"x","visibility":"public"}]}`,
		detailURL(m7kni):        `{"isArchived":false,"summary":{"ownersCount":1,"membersCount":1,"guestsCount":0}}`,
		installedAppsURL(m7kni): installedAppsBody,
		channelsURL(m7kni):      channelsBody,
	}}
}

func gaugeByTwo(t *testing.T, rec *telemetrytest.Recorder, name, k1, k2 string) map[[2]string]float64 {
	t.Helper()
	out := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(name) {
		out[[2]string{p.Attrs[k1], p.Attrs[k2]}] = p.Value
	}
	return out
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
	want := map[string]bool{
		"Team.ReadBasic.All":            true,
		"TeamSettings.Read.All":         true,
		"TeamsAppInstallation.Read.All": true,
		"Channel.ReadBasic.All":         true,
	}
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

// TestInstalledAppsGaugeBucketsDistributionAndRSC drives the live #247 sample:
// 2 store/no-RSC apps + 1 synthetic sideloaded/RSC app, all bounded labels.
func TestInstalledAppsGaugeBucketsDistributionAndRSC(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(appsChannelsSample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	g := gaugeByTwo(t, rec, metricInstalledApps, semconv.AttrDistributionMethod, semconv.AttrHasRscPermissions)
	if g[[2]string{"store", "false"}] != 2 {
		t.Errorf("store/no-rsc = %v, want 2", g[[2]string{"store", "false"}])
	}
	if g[[2]string{"sideloaded", "true"}] != 1 {
		t.Errorf("sideloaded/rsc = %v, want 1", g[[2]string{"sideloaded", "true"}])
	}
	// Seeded grid: every closed-set combination reports, 0 when empty.
	if _, ok := g[[2]string{"organization", "false"}]; !ok {
		t.Error("organization/false bucket missing — the grid must emit 0 for stable baselines")
	}
}

func TestChannelsGaugeBucketsMembershipAndArchived(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(appsChannelsSample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	g := gaugeByTwo(t, rec, metricChannels, semconv.AttrMembershipType, semconv.AttrIsArchived)
	if g[[2]string{"standard", "false"}] != 1 {
		t.Errorf("standard/live = %v, want 1", g[[2]string{"standard", "false"}])
	}
	if g[[2]string{"private", "false"}] != 1 {
		t.Errorf("private/live = %v, want 1", g[[2]string{"private", "false"}])
	}
	if _, ok := g[[2]string{"shared", "true"}]; !ok {
		t.Error("shared/true bucket missing — the grid must emit 0 for stable baselines")
	}
}

// TestAppTwins pins one twin per installed app, the Warn condition (sideloaded OR
// any RSC grant), and that the RSC grant list is carried as a log attribute.
func TestAppTwins(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(appsChannelsSample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var apps int
	sev := map[string]string{}
	var rscTwin *telemetrytest.LogRecord
	for i := range rec.LogRecords() {
		l := rec.LogRecords()[i]
		if l.EventName != eventNameApp {
			continue
		}
		apps++
		sev[l.Attrs[semconv.AttrAppDisplayName]] = l.SeverityText
		if l.Attrs[semconv.AttrAppDisplayName] == "g2o-sideloaded-probe" {
			r := l
			rscTwin = &r
		}
	}
	if apps != 3 {
		t.Fatalf("app twins = %d, want 3 (one per installed app)", apps)
	}
	if sev["g2o-sideloaded-probe"] != "WARN" {
		t.Errorf("sideloaded+RSC app severity = %q, want WARN", sev["g2o-sideloaded-probe"])
	}
	if sev["Activity"] != "INFO" {
		t.Errorf("store app severity = %q, want INFO", sev["Activity"])
	}
	if rscTwin == nil || rscTwin.Attrs[semconv.AttrHasRscPermissions] != "true" {
		t.Errorf("sideloaded twin has_rsc_permissions = %v, want true", rscTwin)
	}
	if rscTwin != nil && rscTwin.Attrs[semconv.AttrRscPermissions] == "" {
		t.Error("sideloaded twin must carry the RSC grant list (rsc_permissions) — the entra.consent blind spot")
	}
}

func TestChannelTwins(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(appsChannelsSample(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var chans int
	var standard *telemetrytest.LogRecord
	for i := range rec.LogRecords() {
		l := rec.LogRecords()[i]
		if l.EventName != eventNameChannel {
			continue
		}
		chans++
		if l.Attrs[semconv.AttrDisplayName] == "gayyyy" {
			r := l
			standard = &r
		}
	}
	if chans != 2 {
		t.Fatalf("channel twins = %d, want 2", chans)
	}
	if standard == nil {
		t.Fatal("live standard channel twin missing")
	}
	// Per-entity detail carried on the twin, never a metric label.
	if standard.Attrs[semconv.AttrEmailAddress] != "teamtest@m7kni.io" {
		t.Errorf("channel email = %q", standard.Attrs[semconv.AttrEmailAddress])
	}
	if standard.Attrs[semconv.AttrFilesFolderWebUrl] == "" {
		t.Error("channel files_folder_web_url missing on twin")
	}
	if standard.Attrs[semconv.AttrMembershipType] != "standard" {
		t.Errorf("channel membership_type = %q, want standard", standard.Attrs[semconv.AttrMembershipType])
	}
}

// TestForbiddenSubResourceSkipsGauge pins that a 403 on the beta sub-resources
// (scope ungranted) SKIPS that gauge rather than emitting a misleading all-zero
// grid — and never errors the scrape.
func TestForbiddenSubResourceSkipsGauge(t *testing.T) {
	g := appsChannelsSample()
	g.errs = map[string]error{
		installedAppsURL(m7kni): errors.New("graphclient: GET x: status 403: Forbidden"),
		channelsURL(m7kni):      errors.New("graphclient: GET x: status 403: Forbidden"),
	}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on sub-resource 403 = %v, want nil", err)
	}
	if len(rec.MetricPoints(metricInstalledApps)) != 0 {
		t.Error("installed_apps gauge must be skipped when the scope is ungranted (not an all-zero grid)")
	}
	if len(rec.MetricPoints(metricChannels)) != 0 {
		t.Error("channels gauge must be skipped when the scope is ungranted")
	}
	// The base team inventory still emits.
	if len(rec.MetricPoints(metricTotal)) == 0 {
		t.Error("team inventory must still emit when only the sub-resource scopes are missing")
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
	rec2 := telemetrytest.New()
	if err := New(appsChannelsSample(), nil).Collect(context.Background(), rec2.Emitter()); err != nil {
		t.Fatalf("Collect(apps): %v", err)
	}
	checks := []struct {
		rec  *telemetrytest.Recorder
		name string
	}{
		{rec, metricTotal}, {rec, metricMembership}, {rec, metricOwnerless}, {rec, metricWithGuests},
		{rec2, metricInstalledApps}, {rec2, metricChannels},
	}
	for _, c := range checks {
		for _, p := range c.rec.MetricPoints(c.name) {
			for k, v := range p.Attrs {
				if k == semconv.AttrId || k == semconv.AttrDisplayName ||
					k == semconv.AttrAppId || k == semconv.AttrTeamId || k == semconv.AttrRscPermissions {
					t.Errorf("%s carries per-entity label %s=%s — must never be a metric label (#112)", c.name, k, v)
				}
			}
		}
	}
}
