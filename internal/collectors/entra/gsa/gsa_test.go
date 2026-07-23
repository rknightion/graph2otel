package gsa

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors). It
// satisfies collectors.GraphClient without any live Graph call. Headers are
// ignored — the collections send a Prefer max-page-size header via GetAllValues,
// which does not change the URL.
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
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/beta"

const (
	urlTenantStatus       = base + "/networkAccess/tenantStatus"
	urlForwardingProfiles = base + "/networkAccess/forwardingProfiles"
	urlFilteringPolicies  = base + "/networkAccess/filteringPolicies"
	urlConditionalAccess  = base + "/networkAccess/settings/conditionalAccess"
	urlCrossTenantAccess  = base + "/networkAccess/settings/crossTenantAccess"
	urlRemoteNetworks     = base + "/networkAccess/connectivity/remoteNetworks"
)

// The six constants below are VERBATIM live responses captured as
// graph2otel-poller on 2026-07-23 (#239), all HTTP 200 on m7kni.

const liveTenantStatus = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#networkAccess/tenantStatus/$entity",
  "onboardingStatus": "onboarded",
  "onboardingErrorMessage": null
}`

const liveForwardingProfiles = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#networkAccess/forwardingProfiles",
  "value": [
    {
      "id": "5b571580-76eb-4379-b6d1-8bf7bf36db3c",
      "name": "Microsoft 365 traffic forwarding profile",
      "description": "Default traffic forwarding profile for Microsoft 365 traffic acquisition.",
      "state": "disabled",
      "version": "1.0.0",
      "lastModifiedDateTime": "2026-05-18T12:15:02.6858083Z",
      "trafficForwardingType": "m365",
      "priority": 100,
      "isCustomProfile": false,
      "clientFallbackAction": "bypass",
      "localNetworkSettings": null,
      "assignmentRules": null,
      "associations": [],
      "servicePrincipal": {"appId": "83537ec1-d713-4dcb-aa7f-e04f7776f131", "id": "26264ec0-2426-41ba-9bbc-349d6f7b8bfe"}
    },
    {
      "id": "ceb070fa-eeff-453f-8a22-dd6fb11d3a5b",
      "name": "Internet traffic forwarding profile",
      "description": "Default traffic forwarding profile for Internet traffic acquisition.",
      "state": "disabled",
      "version": "1.0.0",
      "lastModifiedDateTime": "2026-06-24T13:27:12.7699895Z",
      "trafficForwardingType": "internet",
      "priority": 300,
      "isCustomProfile": false,
      "clientFallbackAction": "bypass",
      "localNetworkSettings": null,
      "assignmentRules": null,
      "associations": [],
      "servicePrincipal": {"appId": "faeb2281-3a2e-4a3a-9a77-79a61ab499d6", "id": "f98c6810-adce-4f41-86ed-c36272c09f00"}
    },
    {
      "id": "5127bde5-0516-4d97-ba5c-987743c8a8d5",
      "name": "Private access traffic forwarding profile",
      "description": "Default traffic forwarding profile for Private access traffic acquisition.",
      "state": "disabled",
      "version": "1.0.0",
      "lastModifiedDateTime": "2026-05-18T12:15:02.4593406Z",
      "trafficForwardingType": "private",
      "priority": 200,
      "isCustomProfile": false,
      "clientFallbackAction": "bypass",
      "localNetworkSettings": null,
      "assignmentRules": null,
      "associations": [],
      "servicePrincipal": {"appId": "5d39983c-8a00-44ba-be65-c4a835828940", "id": "b1cd3fad-cccf-43db-8725-1268fabead2b"}
    }
  ]
}`

const liveFilteringPolicies = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#filteringPolicies",
  "value": [
    {
      "id": "e109dd92-4669-4358-983d-97b2dcc20461",
      "name": "All websites",
      "description": "All internet access traffic",
      "version": "1.0.0",
      "lastModifiedDateTime": "2025-10-02T16:46:20.2587682Z",
      "createdDateTime": "2025-10-02T16:46:20Z",
      "action": "allow"
    }
  ]
}`

const liveConditionalAccess = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#networkAccess/settings/conditionalAccess/$entity",
  "signalingStatus": "enabled",
  "dataPlaneSignalingOptions": "entraId"
}`

const liveCrossTenantAccess = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#networkAccess/settings/crossTenantAccess/$entity",
  "networkPacketTaggingStatus": "disabled",
  "dataPlaneTaggingOptions": "none"
}`

const liveRemoteNetworks = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#networkAccess/connectivity/remoteNetworks",
  "value": []
}`

// liveGraph returns a fakeGraph stubbed with all six live samples.
func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		urlTenantStatus:       liveTenantStatus,
		urlForwardingProfiles: liveForwardingProfiles,
		urlFilteringPolicies:  liveFilteringPolicies,
		urlConditionalAccess:  liveConditionalAccess,
		urlCrossTenantAccess:  liveCrossTenantAccess,
		urlRemoteNetworks:     liveRemoteNetworks,
	}}
}

func logsByEvent(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestOnboardingStatusGauge pins the numeric enum gauge: onboarded -> 0, no
// label.
func TestOnboardingStatusGauge(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricOnboardingStatus)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), metricOnboardingStatus)
	}
	if pts[0].Value != 0 {
		t.Errorf("%s = %v, want 0 (onboarded)", metricOnboardingStatus, pts[0].Value)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("%s carries labels %v, want none", metricOnboardingStatus, pts[0].Attrs)
	}
}

// TestOnboardingStatusEnumMapping pins the full enum ladder, including the -1
// unmapped collapse for a status Microsoft has never returned.
func TestOnboardingStatusEnumMapping(t *testing.T) {
	cases := map[string]float64{
		"onboarded":             0,
		"onboardingInProgress":  1,
		"offboardingInProgress": 1,
		"onboardingError":       2,
		"offboarded":            2,
		"someBrandNewStatus":    -1,
	}
	for status, want := range cases {
		if got := statusValue(status); got != want {
			t.Errorf("statusValue(%q) = %v, want %v", status, got, want)
		}
	}
}

// TestForwardingProfilesGauge pins the profile-count gauge keyed by
// (traffic_forwarding_type, state): three disabled profiles, one per type.
func TestForwardingProfilesGauge(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricForwardingProfiles) {
		got[[2]string{p.Attrs["traffic_forwarding_type"], p.Attrs["state"]}] = p.Value
	}
	want := map[[2]string]float64{
		{"m365", "disabled"}:     1,
		{"internet", "disabled"}: 1,
		{"private", "disabled"}:  1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d profile series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("profile[%v] = %v, want %v", k, got[k], v)
		}
	}
}

// TestForwardingProfileTwins pins one entra.gsa_forwarding_profile per profile
// carrying the per-entity detail the gauge cannot, at Info severity.
func TestForwardingProfileTwins(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := logsByEvent(rec, eventForwardingProfile)
	if len(logs) != 3 {
		t.Fatalf("got %d %s twins, want 3", len(logs), eventForwardingProfile)
	}
	var m365 *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].Attrs["id"] == "5b571580-76eb-4379-b6d1-8bf7bf36db3c" {
			m365 = &logs[i]
		}
	}
	if m365 == nil {
		t.Fatal("no twin for the m365 forwarding profile")
	}
	if m365.Attrs["name"] != "Microsoft 365 traffic forwarding profile" {
		t.Errorf("name = %q", m365.Attrs["name"])
	}
	if m365.Attrs["traffic_forwarding_type"] != "m365" {
		t.Errorf("traffic_forwarding_type = %q, want m365", m365.Attrs["traffic_forwarding_type"])
	}
	if m365.Attrs["state"] != "disabled" {
		t.Errorf("state = %q, want disabled", m365.Attrs["state"])
	}
	if m365.Attrs["version"] != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", m365.Attrs["version"])
	}
	if m365.Attrs["priority"] != "100" {
		t.Errorf("priority = %q, want 100", m365.Attrs["priority"])
	}
	if m365.Attrs["is_custom_profile"] != "false" {
		t.Errorf("is_custom_profile = %q, want false", m365.Attrs["is_custom_profile"])
	}
	if m365.Attrs["client_fallback_action"] != "bypass" {
		t.Errorf("client_fallback_action = %q, want bypass", m365.Attrs["client_fallback_action"])
	}
	if m365.Attrs["association_count"] != "0" {
		t.Errorf("association_count = %q, want 0", m365.Attrs["association_count"])
	}
	if m365.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO", m365.SeverityText)
	}
}

// TestFilteringPoliciesGauge pins the policy-count gauge keyed by action.
func TestFilteringPoliciesGauge(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricFilteringPolicies) {
		got[p.Attrs["action"]] = p.Value
	}
	if len(got) != 1 || got["allow"] != 1 {
		t.Errorf("%s = %v, want {allow:1}", metricFilteringPolicies, got)
	}
}

// TestFilteringPolicyTwin pins the per-policy twin.
func TestFilteringPolicyTwin(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := logsByEvent(rec, eventFilteringPolicy)
	if len(logs) != 1 {
		t.Fatalf("got %d %s twins, want 1", len(logs), eventFilteringPolicy)
	}
	p := logs[0]
	if p.Attrs["id"] != "e109dd92-4669-4358-983d-97b2dcc20461" {
		t.Errorf("id = %q", p.Attrs["id"])
	}
	if p.Attrs["name"] != "All websites" {
		t.Errorf("name = %q, want All websites", p.Attrs["name"])
	}
	if p.Attrs["action"] != "allow" {
		t.Errorf("action = %q, want allow", p.Attrs["action"])
	}
	if p.Attrs["version"] != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", p.Attrs["version"])
	}
	if p.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO", p.SeverityText)
	}
}

// TestSignalingAndPacketTaggingFlags pins the two 0/1 posture flags: signaling
// enabled (1) and packet tagging disabled (0).
func TestSignalingAndPacketTaggingFlags(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sig := rec.MetricPoints(metricSignalingEnabled)
	if len(sig) != 1 || sig[0].Value != 1 {
		t.Errorf("%s = %v, want single series value 1", metricSignalingEnabled, sig)
	}
	tag := rec.MetricPoints(metricPacketTaggingEnabled)
	if len(tag) != 1 || tag[0].Value != 0 {
		t.Errorf("%s = %v, want single series value 0", metricPacketTaggingEnabled, tag)
	}
}

// TestRemoteNetworksCount pins the count gauge: m7kni has none, so value 0, no
// label, and no per-network twin is emitted.
func TestRemoteNetworksCount(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricRemoteNetworks)
	if len(pts) != 1 || pts[0].Value != 0 {
		t.Errorf("%s = %v, want single series value 0", metricRemoteNetworks, pts)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("%s carries labels %v, want none", metricRemoteNetworks, pts[0].Attrs)
	}
}

// TestCollectIsResilientToOneFailure pins that a failure in one fetch is a
// non-fatal aggregate: the other five still emit.
func TestCollectIsResilientToOneFailure(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{urlTenantStatus: errors.New("throttled")}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the tenant-status failure as an error")
	}
	if pts := rec.MetricPoints(metricOnboardingStatus); len(pts) != 0 {
		t.Errorf("got %d %s series despite tenantStatus failing, want 0", len(pts), metricOnboardingStatus)
	}
	// The other endpoints must still emit despite the tenantStatus failure.
	if pts := rec.MetricPoints(metricForwardingProfiles); len(pts) == 0 {
		t.Error("forwarding-profile gauge absent despite succeeding independently")
	}
	if pts := rec.MetricPoints(metricSignalingEnabled); len(pts) != 1 {
		t.Error("signaling gauge absent despite succeeding independently")
	}
}

func TestNameInterfacesAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.gsa" {
		t.Errorf("Name = %q, want entra.gsa", c.Name())
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (pure-beta collector)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.All]", perms)
	}
}
