package crosstenantaccess

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// mustRead reads a testdata fixture or fails the test immediately — every
// fixture here is either a VERBATIM live capture (#321, m7kni,
// graph2otel-poller, 2026-07-28) or is explicitly marked synthetic in its own
// comment below.
func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(b)
}

// fakeGraph dispatches by URL suffix to per-path canned bodies/errors/pages,
// so one fake can stand in for the three independent endpoints this
// collector fetches (root singleton, default singleton, partners
// collection).
type fakeGraph struct {
	root        string
	rootErr     error
	dflt        string
	dfltErr     error
	partners    []string // one body per page, followed automatically via nextLink
	partnersErr error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	switch {
	case strings.HasSuffix(url, rootPath):
		if f.rootErr != nil {
			return nil, f.rootErr
		}
		return []byte(f.root), nil
	case strings.HasSuffix(url, defaultPath):
		if f.dfltErr != nil {
			return nil, f.dfltErr
		}
		return []byte(f.dflt), nil
	}
	return nil, errors.New("fakeGraph: unexpected RawGet " + url)
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	if strings.Contains(url, partnersPath) {
		if f.partnersErr != nil {
			return nil, f.partnersErr
		}
		// Page selection: the base partnersPath URL is page 0; a nextLink of
		// "page=N" (synthetic, this fake's own scheme) selects page N.
		page := 0
		if idx := strings.Index(url, "page="); idx >= 0 {
			switch url[idx+len("page="):] {
			case "1":
				page = 1
			}
		}
		if page >= len(f.partners) {
			return nil, errors.New("fakeGraph: partners page out of range")
		}
		return []byte(f.partners[page]), nil
	}
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// singlePagePartners is the VERBATIM live capture: an empty partners
// collection, one page, no nextLink.
const singlePagePartners = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#policies/crossTenantAccessPolicy/partners","value":[]}`

func newFake(t *testing.T) *fakeGraph {
	t.Helper()
	return &fakeGraph{
		root:     mustRead(t, "xtap-root.json"),
		dflt:     mustRead(t, "xtap-default.json"),
		partners: []string{singlePagePartners},
	}
}

// TestCollectEndToEndAgainstLiveCapture drives the VERBATIM live root+default+
// partners capture through the real collector into a recorder, and pins every
// signal it must produce: the access gauge for every configured sub-block, the
// inbound-trust and automatic-consent gauges, the partners count, and both log
// twins' typed fields. A thin per-field golden is a defect (internal/signalcapture's
// package doc) — this test is deliberately the full shape, not one assertion.
func TestCollectEndToEndAgainstLiveCapture(t *testing.T) {
	g := newFake(t)
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// --- entra.cross_tenant_access.access ---
	access := rec.MetricPoints(accessMetric)
	type combo struct{ service, direction, targetKind, accessType string }
	want := []combo{
		{"b2b_collaboration", "outbound", "users_and_groups", "allowed"},
		{"b2b_collaboration", "outbound", "applications", "allowed"},
		{"b2b_collaboration", "inbound", "users_and_groups", "allowed"},
		{"b2b_collaboration", "inbound", "applications", "allowed"},
		{"b2b_direct_connect", "outbound", "users_and_groups", "blocked"},
		{"b2b_direct_connect", "outbound", "applications", "blocked"},
		{"b2b_direct_connect", "inbound", "users_and_groups", "blocked"},
		{"b2b_direct_connect", "inbound", "applications", "blocked"},
		{"tenant_restrictions", "inbound", "users_and_groups", "blocked"},
		{"tenant_restrictions", "inbound", "applications", "blocked"},
	}
	if len(access) != len(want) {
		t.Fatalf("got %d access points, want %d: %+v", len(access), len(want), access)
	}
	for _, w := range want {
		found := false
		for _, p := range access {
			if p.Attrs["service"] == w.service && p.Attrs["direction"] == w.direction &&
				p.Attrs["target_kind"] == w.targetKind && p.Attrs["access_type"] == w.accessType && p.Value == 1 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing access point %+v in %+v", w, access)
		}
	}
	// No devices point: tenantRestrictions.devices is null on the live wire.
	for _, p := range access {
		if p.Attrs["target_kind"] == "devices" {
			t.Errorf("unexpected devices access point %+v — tenantRestrictions.devices is null on the wire", p)
		}
	}

	// --- entra.cross_tenant_access.inbound_trust ---
	trust := rec.MetricPoints(inboundTrustMetric)
	wantTrust := map[string]float64{
		"mfa_accepted":                           1,
		"compliant_device_accepted":              0,
		"hybrid_azure_ad_joined_device_accepted": 0,
	}
	if len(trust) != len(wantTrust) {
		t.Fatalf("got %d inbound_trust points, want %d: %+v", len(trust), len(wantTrust), trust)
	}
	for _, p := range trust {
		want, ok := wantTrust[p.Attrs["setting"]]
		if !ok {
			t.Errorf("unexpected setting %q", p.Attrs["setting"])
			continue
		}
		if p.Value != want {
			t.Errorf("setting %s = %v, want %v", p.Attrs["setting"], p.Value, want)
		}
	}

	// --- entra.cross_tenant_access.automatic_user_consent ---
	consent := rec.MetricPoints(automaticUserConsentMetric)
	wantConsent := map[string]float64{"inbound": 0, "outbound": 0}
	if len(consent) != len(wantConsent) {
		t.Fatalf("got %d automatic_user_consent points, want %d: %+v", len(consent), len(wantConsent), consent)
	}
	for _, p := range consent {
		if p.Value != wantConsent[p.Attrs["direction"]] {
			t.Errorf("direction %s = %v, want %v", p.Attrs["direction"], p.Value, wantConsent[p.Attrs["direction"]])
		}
	}

	// --- entra.cross_tenant_access.partners.total ---
	partners := rec.MetricPoints(partnersTotalMetric)
	if len(partners) != 1 || partners[0].Value != 0 {
		t.Fatalf("partners.total = %+v, want exactly one point valued 0 (empty live collection)", partners)
	}
	if len(partners[0].Attrs) != 0 {
		t.Errorf("partners.total carries attrs %+v, want none (count only, #321)", partners[0].Attrs)
	}

	// --- entra.cross_tenant_access_policy (root twin) ---
	var policyTwin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			r := r
			policyTwin = &r
			break
		}
	}
	if policyTwin == nil {
		t.Fatal("no entra.cross_tenant_access_policy log record emitted")
	}
	if got, want := policyTwin.Attrs["id"], "895e3c89-2715-4624-9715-6a86227312eb"; got != want {
		t.Errorf("policy twin id = %q, want %q", got, want)
	}
	if got, want := policyTwin.Attrs["display_name"], "CrossTenantAccessPolicy for 4b8c18bd-2f9f-4227-af55-9f1061cf9c32"; got != want {
		t.Errorf("policy twin display_name = %q, want %q", got, want)
	}
	// allowedCloudEndpoints is an empty array on the live wire: absent, not a
	// fabricated empty-list attribute.
	if _, ok := policyTwin.Attrs["allowed_cloud_endpoints"]; ok {
		t.Errorf("allowed_cloud_endpoints present = %q, want absent for an empty wire array", policyTwin.Attrs["allowed_cloud_endpoints"])
	}

	// --- entra.cross_tenant_access_default (default twin) ---
	var defaultTwin *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventDefault {
			r := r
			defaultTwin = &r
			break
		}
	}
	if defaultTwin == nil {
		t.Fatal("no entra.cross_tenant_access_default log record emitted")
	}
	wantTwin := map[string]string{
		"id":                         "895e3c89-2715-4624-9715-6a86227312eb",
		"is_service_default":         "false",
		"inbound_trust_mfa_accepted": "true",
		"inbound_trust_compliant_device_accepted":              "false",
		"inbound_trust_hybrid_azure_ad_joined_device_accepted": "false",
		"automatic_consent_inbound_allowed":                    "false",
		"automatic_consent_outbound_allowed":                   "false",
		"b2b_collab_outbound_users_access_type":                "allowed",
		"b2b_collab_outbound_users_target_ids":                 "AllUsers",
		"b2b_collab_outbound_users_target_count":               "1",
		"b2b_direct_outbound_apps_access_type":                 "blocked",
		"tenant_restrictions_users_access_type":                "blocked",
		"tenant_restrictions_apps_access_type":                 "blocked",
	}
	for k, v := range wantTwin {
		if got := defaultTwin.Attrs[k]; got != v {
			t.Errorf("default twin attr %s = %q, want %q", k, got, v)
		}
	}
	// tenantRestrictions.devices is null on the wire: absent, not a
	// fabricated access_type.
	if _, ok := defaultTwin.Attrs["tenant_restrictions_devices_access_type"]; ok {
		t.Errorf("tenant_restrictions_devices_access_type present = %q, want absent (devices is null on the wire)", defaultTwin.Attrs["tenant_restrictions_devices_access_type"])
	}
	if _, ok := defaultTwin.Attrs["b2b_collab_outbound_users_targets_truncated"]; !ok {
		t.Error("b2b_collab_outbound_users_targets_truncated missing — a present target array must always carry its truncated flag")
	}
	if got := defaultTwin.Attrs["b2b_collab_outbound_users_targets_truncated"]; got != "false" {
		t.Errorf("b2b_collab_outbound_users_targets_truncated = %q, want %q (1 target, under the cap)", got, "false")
	}
}

// absentInboundTrustDefault is a SYNTHETIC (hand-built) default configuration
// with NO inboundTrust key at all, standing in for a tenant/API version where
// Graph omits the whole sub-object. It stands in for "the sub-object itself
// is absent", the first of the three ways #321's load-bearing rule must hold.
const absentInboundTrustDefault = `{
  "id": "cfg-1",
  "b2bCollaborationOutbound": {
    "usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers"}]}
  }
}`

func TestCollectAbsentInboundTrustEmitsNoInboundTrustPoints(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: absentInboundTrustDefault, partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(inboundTrustMetric); len(pts) != 0 {
		t.Errorf("got %d inbound_trust points for an absent inboundTrust object, want 0: %+v", len(pts), pts)
	}
}

// partialInboundTrustDefault is SYNTHETIC: inboundTrust is present but
// isMfaAccepted is absent from it while the other two switches are present.
// Stands in for the second of the three absence-vs-false ways: one field
// missing from a present sub-object.
const partialInboundTrustDefault = `{
  "id": "cfg-2",
  "inboundTrust": {
    "isCompliantDeviceAccepted": true,
    "isHybridAzureADJoinedDeviceAccepted": false
  }
}`

func TestCollectPartialInboundTrustEmitsOnlyPresentSwitches(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: partialInboundTrustDefault, partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(inboundTrustMetric)
	if len(pts) != 2 {
		t.Fatalf("got %d inbound_trust points, want exactly 2 (isMfaAccepted absent): %+v", len(pts), pts)
	}
	for _, p := range pts {
		if p.Attrs["setting"] == "mfa_accepted" {
			t.Errorf("mfa_accepted point present for an absent isMfaAccepted field: %+v", p)
		}
	}
	// isCompliantDeviceAccepted: true DOES emit a 1 point (the other half of
	// the absence-vs-false rule: a real false/true value must still surface).
	found := false
	for _, p := range pts {
		if p.Attrs["setting"] == "compliant_device_accepted" {
			found = true
			if p.Value != 1 {
				t.Errorf("compliant_device_accepted = %v, want 1", p.Value)
			}
		}
	}
	if !found {
		t.Error("compliant_device_accepted point missing")
	}
}

// wireFalseDefault is SYNTHETIC, isolating the case a bool COLLECTOR could
// wrongly conflate with "absent": isCompliantDeviceAccepted is explicitly
// false on the wire (present key, false value), which must still emit a 0
// point — the other half of the absence-vs-false rule, without which a
// collector that simply "emits nothing ever" would pass every absence test.
const wireFalseDefault = `{
  "id": "cfg-3",
  "inboundTrust": {"isCompliantDeviceAccepted": false}
}`

func TestCollectWireFalseEmitsZeroPoint(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: wireFalseDefault, partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(inboundTrustMetric)
	if len(pts) != 1 {
		t.Fatalf("got %d inbound_trust points, want exactly 1: %+v", len(pts), pts)
	}
	if pts[0].Attrs["setting"] != "compliant_device_accepted" || pts[0].Value != 0 {
		t.Errorf("point = %+v, want setting=compliant_device_accepted value=0", pts[0])
	}
}

// absentApplicationsDefault is SYNTHETIC: b2bCollaborationInbound is present
// with usersAndGroups but no applications sub-block at all — the third of
// the three absence-vs-false ways, this time for a sub-OBJECT rather than a
// scalar bool.
const absentApplicationsDefault = `{
  "id": "cfg-4",
  "b2bCollaborationInbound": {
    "usersAndGroups": {"accessType": "allowed", "targets": [{"target": "AllUsers"}]}
  }
}`

func TestCollectAbsentApplicationsSubBlockEmitsNoPointForIt(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: absentApplicationsDefault, partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	access := rec.MetricPoints(accessMetric)
	if len(access) != 1 {
		t.Fatalf("got %d access points, want exactly 1 (applications sub-block absent): %+v", len(access), access)
	}
	if access[0].Attrs["target_kind"] != "users_and_groups" {
		t.Errorf("only point should be users_and_groups, got %+v", access[0])
	}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventDefault {
			if _, ok := r.Attrs["b2b_collab_inbound_apps_access_type"]; ok {
				t.Errorf("b2b_collab_inbound_apps_access_type present, want absent for a missing applications sub-block")
			}
		}
	}
}

// nonNullDevicesDefault is SYNTHETIC: exercises the devices sub-block
// actually being present, since the live tenant carries it as null. Proves
// the code path exists and behaves, symmetric with the null-devices
// assertion in the end-to-end test above.
const nonNullDevicesDefault = `{
  "id": "cfg-5",
  "tenantRestrictions": {
    "devices": {"accessType": "blocked"}
  }
}`

func TestCollectNonNullDevicesBlockEmitsOnePoint(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: nonNullDevicesDefault, partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	access := rec.MetricPoints(accessMetric)
	if len(access) != 1 {
		t.Fatalf("got %d access points, want exactly 1 (synthetic non-null devices block): %+v", len(access), access)
	}
	p := access[0]
	if p.Attrs["service"] != "tenant_restrictions" || p.Attrs["target_kind"] != "devices" || p.Attrs["access_type"] != "blocked" || p.Value != 1 {
		t.Errorf("devices point = %+v, want service=tenant_restrictions target_kind=devices access_type=blocked value=1", p)
	}
}

func TestCollectPartnersFailureStillEmitsDefaultConfigurationSignals(t *testing.T) {
	g := newFake(t)
	g.partnersErr = errors.New("throttled")
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the partners fetch error")
	}
	if pts := rec.MetricPoints(accessMetric); len(pts) == 0 {
		t.Error("access points missing after an independent partners failure")
	}
	if pts := rec.MetricPoints(inboundTrustMetric); len(pts) == 0 {
		t.Error("inbound_trust points missing after an independent partners failure")
	}
	if pts := rec.MetricPoints(partnersTotalMetric); len(pts) != 0 {
		t.Errorf("got %d partners.total points after a partners fetch error, want 0", len(pts))
	}
}

func TestCollectDefaultFailureStillEmitsPartnersAndPolicySignals(t *testing.T) {
	g := newFake(t)
	g.dfltErr = errors.New("throttled")
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the default fetch error")
	}
	if pts := rec.MetricPoints(partnersTotalMetric); len(pts) != 1 {
		t.Errorf("got %d partners.total points after an independent default failure, want 1", len(pts))
	}
	foundPolicy := false
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			foundPolicy = true
		}
		if r.EventName == eventDefault {
			t.Error("entra.cross_tenant_access_default emitted despite a default fetch error")
		}
	}
	if !foundPolicy {
		t.Error("entra.cross_tenant_access_policy missing after an independent default failure")
	}
	if pts := rec.MetricPoints(accessMetric); len(pts) != 0 {
		t.Errorf("got %d access points after a default fetch error, want 0", len(pts))
	}
}

func TestCollectRootFailureStillEmitsDefaultAndPartnersSignals(t *testing.T) {
	g := newFake(t)
	g.rootErr = errors.New("throttled")
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the root fetch error")
	}
	if pts := rec.MetricPoints(accessMetric); len(pts) == 0 {
		t.Error("access points missing after an independent root failure")
	}
	if pts := rec.MetricPoints(partnersTotalMetric); len(pts) != 1 {
		t.Errorf("got %d partners.total points after an independent root failure, want 1", len(pts))
	}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			t.Error("entra.cross_tenant_access_policy emitted despite a root fetch error")
		}
	}
}

// twoPagePartnersBody0/1 are SYNTHETIC two-page partner collections (the live
// tenant only ever returns one empty page) used to prove @odata.nextLink
// paging is followed to a correct total, and that no per-partner attribute
// leaks anywhere regardless of page count.
const twoPagePartnersBody0 = `{"value":[{"tenantId":"11111111-1111-1111-1111-111111111111"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners?page=1"}`
const twoPagePartnersBody1 = `{"value":[{"tenantId":"22222222-2222-2222-2222-222222222222"},{"tenantId":"33333333-3333-3333-3333-333333333333"}]}`

func TestCollectPartnersPagingProducesCorrectTotalAndNoPerPartnerAttrs(t *testing.T) {
	g := &fakeGraph{
		root:     mustRead(t, "xtap-root.json"),
		dflt:     mustRead(t, "xtap-default.json"),
		partners: []string{twoPagePartnersBody0, twoPagePartnersBody1},
	}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(partnersTotalMetric)
	if len(pts) != 1 || pts[0].Value != 3 {
		t.Fatalf("partners.total = %+v, want exactly one point valued 3 (1 + 2 across two pages)", pts)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("partners.total carries attrs %+v, want none", pts[0].Attrs)
	}
	// No per-partner tenantId (or anything else) leaked into any metric or log.
	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if strings.Contains(k, "partner") && k != "" {
					t.Errorf("metric %s carries a partner-shaped attribute key %q — partners must be count-only (#321)", name, k)
				}
			}
		}
	}
	for _, r := range rec.LogRecords() {
		if strings.Contains(strings.ToLower(r.EventName), "partner") {
			t.Errorf("unexpected partner log record %+v — no per-partner twin is written (#321)", r)
		}
	}
}

func TestCollectSurfacesDecodeError(t *testing.T) {
	g := &fakeGraph{root: mustRead(t, "xtap-root.json"), dflt: "not json", partners: []string{singlePagePartners}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("expected Collect to surface the default decode error")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.cross_tenant_access" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.All]", perms)
	}
}

func TestDefaultInterval(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
}
