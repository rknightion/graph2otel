package relatedtenants

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors) and records every
// URL asked for, so a test can assert that the disabled path never touches the
// relatedTenants collection at all.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	calls  []string
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return []byte(`{"value": []}`), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base        = "https://graph.microsoft.com/beta"
	settingsURL = base + settingsPath
	relatedURL  = base + relatedTenantsPath
)

func mustReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

func newTestCollector(g collectors.GraphClient) *Collector {
	return &Collector{g: g, baseURL: base, logger: slog.Default()}
}

func collect(t *testing.T, g collectors.GraphClient) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := newTestCollector(g)
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// liveGraph serves the 2026-07-29 m7kni captures. The related-tenant GUIDs are
// substituted with realistic ones (they identify real partner organizations);
// every other byte, including the null metric blocks that make up most of the
// payload, is verbatim.
func liveGraph(t *testing.T) *fakeGraph {
	t.Helper()
	return &fakeGraph{bodies: map[string]string{
		settingsURL: mustReadFile(t, "settings.json"),
		relatedURL:  mustReadFile(t, "relatedtenants.json"),
	}}
}

func recordsNamed(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// pointByAttr finds the single point whose attribute `key` equals `want`.
func pointByAttr(t *testing.T, pts []telemetrytest.MetricPoint, key, want string) telemetrytest.MetricPoint {
	t.Helper()
	var found []telemetrytest.MetricPoint
	for _, p := range pts {
		if v, ok := p.Attrs[key]; ok && v == want {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 point with %s=%v, got %d (points: %+v)", key, want, len(found), pts)
	}
	return found[0]
}

// TestLiveCaptureSplitsMicrosoftInfrastructureFromExternal is the headline
// count. The split is the point: an unsplit total would report 16 external
// tenant relationships when there are 13.
func TestLiveCaptureSplitsMicrosoftInfrastructureFromExternal(t *testing.T) {
	rec := collect(t, liveGraph(t))

	pts := rec.MetricPoints(totalMetric)
	if len(pts) != 2 {
		t.Fatalf("total metric: want 2 points (external + infrastructure), got %d", len(pts))
	}
	if got := pointByAttr(t, pts, semconv.AttrIsMicrosoftInfrastructure, "false").Value; got != 13 {
		t.Errorf("external related tenants = %v, want 13", got)
	}
	if got := pointByAttr(t, pts, semconv.AttrIsMicrosoftInfrastructure, "true").Value; got != 3 {
		t.Errorf("Microsoft-infrastructure related tenants = %v, want 3", got)
	}
}

// TestLiveCaptureMetricCoverage pins the coverage gauge against the live
// reality: exactly one row carries each B2B block, every row carries the
// multi-tenant-application block, and no row carries billing metrics. A
// regression here means the pointer discipline has silently changed which rows
// are counted as measured.
func TestLiveCaptureMetricCoverage(t *testing.T) {
	rec := collect(t, liveGraph(t))
	pts := rec.MetricPoints(withMetricsMetric)

	want := map[string]float64{
		kindB2bRegistration: 1,
		kindB2bSignin:       1,
		kindAppB2bSignin:    1,
		kindMultiTenantApp:  16,
		kindBilling:         0,
	}
	if len(pts) != len(want) {
		t.Fatalf("with_metrics: want %d points, got %d", len(want), len(pts))
	}
	for kind, n := range want {
		if got := pointByAttr(t, pts, semconv.AttrKind, kind).Value; got != n {
			t.Errorf("with_metrics[%s] = %v, want %v", kind, got, n)
		}
	}
}

// TestLiveCaptureEmitsOneTwinPerRow holds the #114 side of the boundary: every
// fetched row gets a record, including the 15 that carry almost no data.
func TestLiveCaptureEmitsOneTwinPerRow(t *testing.T) {
	rec := collect(t, liveGraph(t))
	if got := len(recordsNamed(rec, eventRelatedTenant)); got != 16 {
		t.Errorf("related-tenant twins = %d, want 16 (one per fetched row)", got)
	}
}

// TestTwinsAreStateTwinsNotBackdated pins that no twin is stamped with
// createdDateTime. All 16 live rows share a createdDateTime one second apart
// because it dates the moment discovery was enabled; backdating would date
// every relationship to that instant.
func TestTwinsAreStateTwinsNotBackdated(t *testing.T) {
	rec := collect(t, liveGraph(t))
	for _, r := range recordsNamed(rec, eventRelatedTenant) {
		if !r.Timestamp.IsZero() {
			t.Fatalf("related-tenant twin carries timestamp %v; a state twin must leave it zero so the emitter stamps poll time", r.Timestamp)
		}
	}
}

// decodeLiveRows unmarshals the live fixture into the collector's own row type,
// so the mapper can be exercised directly.
func decodeLiveRows(t *testing.T) []relatedTenant {
	t.Helper()
	var page relatedTenantsPage
	if err := json.Unmarshal([]byte(mustReadFile(t, "relatedtenants.json")), &page); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(page.Value) != 16 {
		t.Fatalf("fixture has %d rows, want 16", len(page.Value))
	}
	return page.Value
}

// TestAbsentMetricBlockEmitsNoKeys asserts on the MAPPER'S OWN RETURNED ATTRS
// rather than on a rendered record. That is deliberate: telemetry.SetStr and
// the recorder both drop or transform empty values, so a mapper that wrote a
// fabricated zero for an absent counter could still render identically to one
// that wrote nothing (the #322/#354 rendered-representation blindness). The
// only place the distinction is visible is the map the mapper returns.
func TestAbsentMetricBlockEmitsNoKeys(t *testing.T) {
	rows := decodeLiveRows(t)

	var bare *relatedTenant
	for i := range rows {
		if rows[i].B2BRegistrationMetrics == nil && rows[i].B2BSignInActivityMetrics == nil {
			bare = &rows[i]
			break
		}
	}
	if bare == nil {
		t.Fatal("fixture no longer contains a row without B2B metrics; this test guards the common case")
	}

	attrs := relatedTenantTwin(*bare).Attrs
	for _, key := range []string{
		semconv.AttrB2bRegistrationInboundUsers,
		semconv.AttrB2bRegistrationOutboundUsers,
		semconv.AttrB2bSigninInboundUsers,
		semconv.AttrB2bSigninOutboundUsers,
		semconv.AttrB2bSigninInboundApplications,
		semconv.AttrB2bSigninOutboundApplications,
	} {
		if v, ok := attrs[key]; ok {
			t.Errorf("absent metric block published %s = %v; an unmeasured counter must emit no key, because 0 reads as 'no B2B users from this partner'", key, v)
		}
	}
}

// TestMultiTenantBlockPublishesNoUserCounters is the shared-leaf-struct trap.
// One metricSnapshot type decodes all four blocks, but
// multiTenantApplicationMetrics carries application counters ONLY — so if those
// user fields ever stop being pointers, every row in the live capture would
// publish two fabricated zero user counts.
func TestMultiTenantBlockPublishesNoUserCounters(t *testing.T) {
	rows := decodeLiveRows(t)

	var only *relatedTenant
	for i := range rows {
		r := rows[i]
		if r.MultiTenantApplicationMetrics != nil && r.B2BSignInActivityMetrics == nil && r.B2BRegistrationMetrics == nil {
			only = &rows[i]
			break
		}
	}
	if only == nil {
		t.Fatal("fixture no longer contains a row with only multiTenantApplicationMetrics")
	}

	s := only.MultiTenantApplicationMetrics.Recent
	if s == nil {
		t.Fatal("fixture row has no recent multi-tenant snapshot")
	}
	if s.InboundMonthlyTotalUsers != nil || s.OutboundMonthlyTotalUsers != nil {
		t.Errorf("multiTenantApplicationMetrics decoded user counters (%v/%v); the wire does not send them",
			s.InboundMonthlyTotalUsers, s.OutboundMonthlyTotalUsers)
	}
	attrs := relatedTenantTwin(*only).Attrs
	if _, ok := attrs[semconv.AttrMultiTenantAppInboundApplications]; !ok {
		t.Error("multi-tenant inbound application count missing; the fixture row carries one")
	}
}

// TestNullBillingMetricsIsNotPresent guards the json.RawMessage trap: a JSON
// null decodes into a non-nil RawMessage holding the four bytes "null", so a
// bare nil check would report all 16 live rows as carrying billing metrics.
func TestNullBillingMetricsIsNotPresent(t *testing.T) {
	if hasBillingMetrics(json.RawMessage("null")) {
		t.Error(`hasBillingMetrics("null") = true; a JSON null is an absent block, not a present one`)
	}
	if hasBillingMetrics(nil) {
		t.Error("hasBillingMetrics(nil) = true, want false")
	}
	if !hasBillingMetrics(json.RawMessage(`{"anything": 1}`)) {
		t.Error("hasBillingMetrics(object) = false; a real object is present")
	}

	rows := decodeLiveRows(t)
	for _, r := range rows {
		if attrs := relatedTenantTwin(r).Attrs; attrs[semconv.AttrHasBillingMetrics] != false {
			t.Fatalf("row %s reports has_billing_metrics = %v; no live row carries one",
				r.ID, attrs[semconv.AttrHasBillingMetrics])
		}
	}
}

// TestUnmeasuredSumsEmitNoPoints: the summed counters must vanish rather than
// read zero when no row supplied the underlying block. A zero would assert
// Microsoft measured no B2B activity, when Microsoft measured nothing.
func TestUnmeasuredSumsEmitNoPoints(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		settingsURL: `{"isRelatedTenantsEnabled": true, "canReceiveInvitations": false}`,
		relatedURL: `{"value": [
			{"id": "11111111-1111-4111-8111-111111111111", "isMicrosoftInfrastructure": false,
			 "createdDateTime": "2026-07-29T00:38:59Z",
			 "b2BRegistrationMetrics": null, "b2BSignInActivityMetrics": null,
			 "appB2BSignInActivityMetrics": null, "multiTenantApplicationMetrics": null,
			 "billingMetrics": null}
		]}`,
	}}
	rec := collect(t, g)

	for _, m := range []string{b2bRegisteredUsersMetric, b2bSigninUsersMetric, multiTenantApplicationsMetric} {
		if pts := rec.MetricPoints(m); len(pts) != 0 {
			t.Errorf("%s emitted %d points on a row with no metric blocks, want 0: %+v", m, len(pts), pts)
		}
	}
	// The count itself IS measured and must still be a real zero/one.
	if got := pointByAttr(t, rec.MetricPoints(totalMetric), semconv.AttrIsMicrosoftInfrastructure, "false").Value; got != 1 {
		t.Errorf("external count = %v, want 1", got)
	}
}

// TestLiveCaptureSumsAcrossRows pins the aggregates against the live payload:
// one row carries B2B registration (1 in / 1 out) and sign-in (1 in / 0 out),
// and all 16 carry multi-tenant applications (15 rows at 1 inbound plus one at
// 100 = 115 inbound, 0 outbound).
func TestLiveCaptureSumsAcrossRows(t *testing.T) {
	rec := collect(t, liveGraph(t))

	reg := rec.MetricPoints(b2bRegisteredUsersMetric)
	if got := pointByAttr(t, reg, semconv.AttrDirection, directionInbound).Value; got != 1 {
		t.Errorf("b2b registered inbound = %v, want 1", got)
	}
	if got := pointByAttr(t, reg, semconv.AttrDirection, directionOutbound).Value; got != 1 {
		t.Errorf("b2b registered outbound = %v, want 1", got)
	}

	apps := rec.MetricPoints(multiTenantApplicationsMetric)
	if got := pointByAttr(t, apps, semconv.AttrDirection, directionInbound).Value; got != 115 {
		t.Errorf("multi-tenant inbound applications = %v, want 115 (15 rows at 1 plus one at 100)", got)
	}
	if got := pointByAttr(t, apps, semconv.AttrDirection, directionOutbound).Value; got != 0 {
		t.Errorf("multi-tenant outbound applications = %v, want a measured 0", got)
	}
}

// TestDisabledDiscoveryNeverFetchesAndNeverReportsZero is the whole reason this
// collector reads settings first. A disabled tenant must show an ABSENT count,
// not a measured zero — and must not issue the relatedTenants request at all.
func TestDisabledDiscoveryNeverFetchesAndNeverReportsZero(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		settingsURL: `{"isRelatedTenantsEnabled": false, "canReceiveInvitations": false}`,
	}}
	rec := collect(t, g)

	for _, url := range g.calls {
		if url == relatedURL {
			t.Error("fetched relatedTenants while discovery is disabled; the settings read exists precisely so this request is never made")
		}
	}
	if pts := rec.MetricPoints(discoveryEnabledMetric); len(pts) != 1 || pts[0].Value != 0 {
		t.Errorf("discovery_enabled = %+v, want a single 0 point", pts)
	}
	for _, m := range []string{totalMetric, withMetricsMetric, b2bRegisteredUsersMetric, b2bSigninUsersMetric, multiTenantApplicationsMetric} {
		if pts := rec.MetricPoints(m); len(pts) != 0 {
			t.Errorf("%s emitted %d points while discovery is disabled, want 0 — a zero would claim discovery ran and found nothing: %+v", m, len(pts), pts)
		}
	}
	if got := len(recordsNamed(rec, eventRelatedTenant)); got != 0 {
		t.Errorf("emitted %d twins while discovery is disabled, want 0", got)
	}
}

// TestEnabledFlagsAreReportedFromTheWire pins both posture flags, including the
// case where they disagree — canReceiveInvitations is a separate control from
// discovery and must not be inferred from it.
func TestEnabledFlagsAreReportedFromTheWire(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		settingsURL: `{"isRelatedTenantsEnabled": true, "canReceiveInvitations": false}`,
		relatedURL:  `{"value": []}`,
	}}
	rec := collect(t, g)

	if pts := rec.MetricPoints(discoveryEnabledMetric); len(pts) != 1 || pts[0].Value != 1 {
		t.Errorf("discovery_enabled = %+v, want a single 1 point", pts)
	}
	if pts := rec.MetricPoints(invitationsEnabledMetric); len(pts) != 1 || pts[0].Value != 0 {
		t.Errorf("can_receive_invitations = %+v, want a single 0 point", pts)
	}
}

// TestEnabledButEmptyCollectionIsAMeasuredZero is the other half of the
// disabled case: discovery on and nothing found is a real, reassuring zero and
// must be emitted as one.
func TestEnabledButEmptyCollectionIsAMeasuredZero(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		settingsURL: `{"isRelatedTenantsEnabled": true, "canReceiveInvitations": true}`,
		relatedURL:  `{"value": []}`,
	}}
	rec := collect(t, g)

	pts := rec.MetricPoints(totalMetric)
	if len(pts) != 2 {
		t.Fatalf("total metric: want 2 points on an empty collection, got %d", len(pts))
	}
	for _, p := range pts {
		if p.Value != 0 {
			t.Errorf("empty collection produced %v, want 0", p.Value)
		}
	}
}

// TestSettingsFailureAbortsBeforeEmitting: a settings fetch that fails must not
// leave a discovery_enabled reading behind, because the false default would
// claim the feature is off.
func TestSettingsFailureAbortsBeforeEmitting(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{settingsURL: errors.New("boom")}}
	rec := telemetrytest.New()
	c := newTestCollector(g)
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("Collect returned nil on a failed settings fetch")
	}
	if pts := rec.MetricPoints(discoveryEnabledMetric); len(pts) != 0 {
		t.Errorf("discovery_enabled emitted %+v after a failed settings fetch; a 0 here would report the feature as disabled", pts)
	}
}

// TestRelatedTenantsFailurePropagates: a failed collection walk must error
// rather than emit a shrunken count.
func TestRelatedTenantsFailurePropagates(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{settingsURL: `{"isRelatedTenantsEnabled": true}`},
		errs:   map[string]error{relatedURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()
	c := newTestCollector(g)
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("Collect returned nil on a failed relatedTenants fetch")
	}
	if pts := rec.MetricPoints(totalMetric); len(pts) != 0 {
		t.Errorf("total emitted %+v after a failed fetch; a partial count reads as tenants disappearing", pts)
	}
}

// TestPagesFollowNextLink proves the walk continues past the first page. The
// live collection fits in one page, so nothing else would exercise this.
func TestPagesFollowNextLink(t *testing.T) {
	second := relatedURL + "?$skiptoken=abc"
	g := &fakeGraph{bodies: map[string]string{
		settingsURL: `{"isRelatedTenantsEnabled": true}`,
		relatedURL: `{"value": [{"id": "11111111-1111-4111-8111-111111111111", "isMicrosoftInfrastructure": false}],
		              "@odata.nextLink": "` + second + `"}`,
		second: `{"value": [{"id": "22222222-2222-4222-8222-222222222222", "isMicrosoftInfrastructure": true}]}`,
	}}
	rec := collect(t, g)

	if got := len(recordsNamed(rec, eventRelatedTenant)); got != 2 {
		t.Errorf("twins across two pages = %d, want 2", got)
	}
}

// TestRelatedTenantIdIsNotTheSharedTenantIdKey: the other party's id must never
// land on `tenant_id`, which telemetry.WithTenant stamps with OUR tenant (#143).
func TestRelatedTenantIdIsNotTheSharedTenantIdKey(t *testing.T) {
	attrs := relatedTenantTwin(relatedTenant{ID: "33333333-3333-4333-8333-333333333333"}).Attrs
	if _, ok := attrs[semconv.AttrTenantID]; ok {
		t.Error("twin wrote the shared tenant_id key; that key means THIS tenant and is stamped at the emitter boundary")
	}
	if got := attrs[semconv.AttrRelatedTenantId]; got != "33333333-3333-4333-8333-333333333333" {
		t.Errorf("related_tenant_id = %v, want the row id", got)
	}
}

// TestFirstObservedPrefersTheEarliestInitialSnapshot: the discovery record's own
// createdDateTime dates the feature being switched on, so the metric blocks'
// `initial` timestamps are the only evidence of when a relationship was first
// measured. The earliest is the honest answer when blocks disagree.
func TestFirstObservedPrefersTheEarliestInitialSnapshot(t *testing.T) {
	early := "2026-07-01T00:00:00Z"
	late := "2026-07-20T00:00:00Z"
	r := relatedTenant{
		ID:                            "44444444-4444-4444-8444-444444444444",
		B2BSignInActivityMetrics:      &metricBlock{Initial: &metricSnapshot{CreatedDateTime: late}},
		MultiTenantApplicationMetrics: &metricBlock{Initial: &metricSnapshot{CreatedDateTime: early}},
	}
	if got := relatedTenantTwin(r).Attrs[semconv.AttrMetricsFirstObservedDateTime]; got != early {
		t.Errorf("metrics_first_observed = %v, want the earliest initial snapshot %v", got, early)
	}

	bare := relatedTenant{ID: "55555555-5555-4555-8555-555555555555"}
	if _, ok := relatedTenantTwin(bare).Attrs[semconv.AttrMetricsFirstObservedDateTime]; ok {
		t.Error("row with no metric blocks published a first-observed timestamp")
	}
}

// TestNoMetricLabelCarriesATenantId is the #112 boundary in the one place it
// could plausibly be crossed here: the related tenant's id is the natural thing
// to label a per-tenant gauge with, and it must never be.
func TestNoMetricLabelCarriesATenantId(t *testing.T) {
	rec := collect(t, liveGraph(t))
	rows := decodeLiveRows(t)
	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ID] = true
	}
	for _, m := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(m) {
			for k, v := range p.Attrs {
				if ids[v] {
					t.Errorf("metric %s label %s carries related tenant id %s; per-entity ids belong on the log twin", m, k, v)
				}
			}
		}
	}
}

// TestPresentBlockWithAbsentLeafEmitsNoKey guards setInt's nil branch, which no
// live row currently exercises: on the 2026-07-29 capture every block that is
// present sends every counter it defines, so block-level nil checks alone would
// keep passing while setInt fabricated zeros.
//
// That gap is exactly the #334 shape — a field declared and simply not sent —
// and it is the failure mode this surface is most exposed to, because Microsoft
// populates these blocks incrementally. Constructed rather than captured on
// purpose; the assertion is on the mapper's returned map, since a zero and an
// absence render identically downstream.
func TestPresentBlockWithAbsentLeafEmitsNoKey(t *testing.T) {
	one := int64(7)
	r := relatedTenant{
		ID: "66666666-6666-4666-8666-666666666666",
		B2BSignInActivityMetrics: &metricBlock{Recent: &metricSnapshot{
			WatermarkDateTime: "2026-07-26T00:00:00Z",
			// Users present, applications NOT sent by this hypothetical row.
			InboundMonthlyTotalUsers: &one,
		}},
	}
	attrs := relatedTenantTwin(r).Attrs

	if got := attrs[semconv.AttrB2bSigninInboundUsers]; got != float64(7) {
		t.Errorf("present counter = %v, want 7", got)
	}
	for _, key := range []string{
		semconv.AttrB2bSigninOutboundUsers,
		semconv.AttrB2bSigninInboundApplications,
		semconv.AttrB2bSigninOutboundApplications,
	} {
		if v, ok := attrs[key]; ok {
			t.Errorf("absent leaf inside a PRESENT block published %s = %v; an unsent counter must emit no key", key, v)
		}
	}
}
