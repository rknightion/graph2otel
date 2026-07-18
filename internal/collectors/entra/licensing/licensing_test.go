package licensing

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) and
// records the headers seen on each request.
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]map[string]string // url -> headers
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]map[string]string{}
	}
	f.seenHeaders[url] = headers
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

const base = "https://graph.microsoft.com/v1.0"
const skusURL = base + "/subscribedSkus"

// groupsURL is the hasMembersWithLicenseErrors filter URL the collector
// issues for #122. Built with net/url the same way the collector builds it,
// so a change to either stays in sync.
var groupsURL = base + "/groups?$filter=" + url.QueryEscape("hasMembersWithLicenseErrors eq true") + "&$select=id,displayName"

// noGroupErrors is the fixture for "zero affected groups" - used by every
// test that isn't specifically exercising the groups-with-errors path, so
// the collector's second fetch has something valid to decode.
const noGroupErrors = `{"value": []}`

// liveSubscribedSkus is a VERBATIM GET /subscribedSkus capture from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17,
// #165]`. It is pinned, not hand-written: the previous `twoSkusBody` fixture
// invented ENTERPRISEPACK/POWER_BI_STANDARD SKUs the tenant does not hold and
// round consumed/enabled counts (42/50, 7/100) that no live SKU returns, which
// let a docs-shaped fixture masquerade as a real response.
//
// Five real SKUs are kept to preserve distinct shapes — FLOW_FREE alone has a
// large enabled pool (10000) and consumedUnits=2, where the rest are 1/1. Each
// SKU's servicePlans array is trimmed to a single representative element
// (dropping whole elements only, never editing any value); the collector reads
// only skuPartNumber, consumedUnits, and prepaidUnits.enabled, so servicePlans
// is carried purely to keep the record faithful.
const liveSubscribedSkus = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#subscribedSkus",
  "value": [
    {
      "accountId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "accountName": "m7knio",
      "appliesTo": "User",
      "capabilityStatus": "Enabled",
      "consumedUnits": 1,
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_a929cd4d-8672-47c9-8664-159c1f322ba8",
      "prepaidUnits": {
        "enabled": 1,
        "lockedOut": 0,
        "suspended": 0,
        "warning": 0
      },
      "servicePlans": [
        {
          "appliesTo": "User",
          "provisioningStatus": "Success",
          "servicePlanId": "795aec3a-93a2-45be-92c4-47b9a76340ca",
          "servicePlanName": "CLOUD_PKI",
          "servicePlanType": "SCO"
        }
      ],
      "skuId": "a929cd4d-8672-47c9-8664-159c1f322ba8",
      "skuPartNumber": "Microsoft_Intune_Suite",
      "subscriptionIds": [
        "a7d1c39e-8d40-4eb1-9549-cd4a3f227632"
      ]
    },
    {
      "accountId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "accountName": "m7knio",
      "appliesTo": "User",
      "capabilityStatus": "Enabled",
      "consumedUnits": 1,
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_b05e124f-c7cc-45a0-a6aa-8cf78c946968",
      "prepaidUnits": {
        "enabled": 1,
        "lockedOut": 0,
        "suspended": 0,
        "warning": 0
      },
      "servicePlans": [
        {
          "appliesTo": "User",
          "provisioningStatus": "Success",
          "servicePlanId": "eec0eb4f-6444-4f95-aba0-50c24d67f998",
          "servicePlanName": "AAD_PREMIUM_P2",
          "servicePlanType": "AADPremiumService"
        }
      ],
      "skuId": "b05e124f-c7cc-45a0-a6aa-8cf78c946968",
      "skuPartNumber": "EMSPREMIUM",
      "subscriptionIds": [
        "a7ef3a79-838f-4468-a45d-a45e04453c2a"
      ]
    },
    {
      "accountId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "accountName": "m7knio",
      "appliesTo": "User",
      "capabilityStatus": "Enabled",
      "consumedUnits": 1,
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_b126b073-72db-4a9d-87a4-b17afe41d4ab",
      "prepaidUnits": {
        "enabled": 1,
        "lockedOut": 0,
        "suspended": 0,
        "warning": 0
      },
      "servicePlans": [
        {
          "appliesTo": "User",
          "provisioningStatus": "Success",
          "servicePlanId": "871d91ec-ec1a-452b-a83f-bd76c7d770ef",
          "servicePlanName": "WINDEFATP",
          "servicePlanType": "WindowsDefenderATP"
        }
      ],
      "skuId": "b126b073-72db-4a9d-87a4-b17afe41d4ab",
      "skuPartNumber": "MDATP_XPLAT",
      "subscriptionIds": [
        "bdf52da9-64c7-4d68-aff7-21cd3881adf0"
      ]
    },
    {
      "accountId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "accountName": "m7knio",
      "appliesTo": "User",
      "capabilityStatus": "Enabled",
      "consumedUnits": 2,
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_f30db892-07e9-47e9-837c-80727f46fd3d",
      "prepaidUnits": {
        "enabled": 10000,
        "lockedOut": 0,
        "suspended": 0,
        "warning": 0
      },
      "servicePlans": [
        {
          "appliesTo": "User",
          "provisioningStatus": "Success",
          "servicePlanId": "50e68c76-46c6-4674-81f9-75456511b170",
          "servicePlanName": "FLOW_P2_VIRAL",
          "servicePlanType": "ProcessSimple"
        }
      ],
      "skuId": "f30db892-07e9-47e9-837c-80727f46fd3d",
      "skuPartNumber": "FLOW_FREE",
      "subscriptionIds": [
        "946baf8d-3d31-4221-bfa0-82b71fd1cbe8"
      ]
    },
    {
      "accountId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "accountName": "m7knio",
      "appliesTo": "User",
      "capabilityStatus": "Enabled",
      "consumedUnits": 1,
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_6a0f6da5-0b87-4190-a6ae-9bb5a2b9546a",
      "prepaidUnits": {
        "enabled": 1,
        "lockedOut": 0,
        "suspended": 0,
        "warning": 0
      },
      "servicePlans": [
        {
          "appliesTo": "User",
          "provisioningStatus": "Success",
          "servicePlanId": "9a6eeb79-0b4b-4bf0-9808-39d99a2cd5a3",
          "servicePlanName": "Windows_Autopatch",
          "servicePlanType": "Modern-Workplace-Core-ITaas"
        }
      ],
      "skuId": "6a0f6da5-0b87-4190-a6ae-9bb5a2b9546a",
      "skuPartNumber": "Win10_VDA_E3",
      "subscriptionIds": [
        "7c77fad7-88d6-4d8a-a7f6-d739bbbe9ba7"
      ]
    }
  ]
}`

// twoErroredGroupsBody is the fake /groups?$filter=hasMembersWithLicenseErrors
// eq true response used by tests exercising #122's group-level path: two
// affected groups, one with a display name and one without (to exercise the
// id fallback).
const twoErroredGroupsBody = `{
	"value": [
		{"id": "11111111-1111-1111-1111-111111111111", "displayName": "Finance Team"},
		{"id": "22222222-2222-2222-2222-222222222222", "displayName": ""}
	]
}`

// TestCollectEmitsPerSKUConsumedAndEnabledGauges drives the verbatim live
// capture end-to-end (Collect -> Recorder) and pins the per-SKU consumed and
// enabled gauges against the real subscribedSkus the m7kni tenant returns —
// including FLOW_FREE's distinct 2-consumed / 10000-enabled shape, which a
// docs fixture's round numbers would have hidden. entra.license.enabled must
// stay byte-for-byte unchanged by #122 (see TestCollectEmitsPerSKUConsumedAndEnabledGauges).
func TestCollectEmitsPerSKUConsumedAndEnabledGauges(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: liveSubscribedSkus, groupsURL: noGroupErrors}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	consumed := map[string]float64{}
	for _, p := range rec.MetricPoints(consumedMetricName) {
		consumed[p.Attrs["sku"]] = p.Value
	}
	wantConsumed := map[string]float64{
		"Microsoft_Intune_Suite": 1,
		"EMSPREMIUM":             1,
		"MDATP_XPLAT":            1,
		"FLOW_FREE":              2,
		"Win10_VDA_E3":           1,
	}
	if len(consumed) != len(wantConsumed) {
		t.Fatalf("got %d consumed series, want %d: %v", len(consumed), len(wantConsumed), consumed)
	}
	for sku, v := range wantConsumed {
		if consumed[sku] != v {
			t.Errorf("consumed[%s] = %v, want %v", sku, consumed[sku], v)
		}
	}

	enabled := map[string]float64{}
	for _, p := range rec.MetricPoints(enabledMetricName) {
		enabled[p.Attrs["sku"]] = p.Value
	}
	wantEnabled := map[string]float64{
		"Microsoft_Intune_Suite": 1,
		"EMSPREMIUM":             1,
		"MDATP_XPLAT":            1,
		"FLOW_FREE":              10000,
		"Win10_VDA_E3":           1,
	}
	if len(enabled) != len(wantEnabled) {
		t.Fatalf("got %d enabled series, want %d: %v", len(enabled), len(wantEnabled), enabled)
	}
	for sku, v := range wantEnabled {
		if enabled[sku] != v {
			t.Errorf("enabled[%s] = %v, want %v", sku, enabled[sku], v)
		}
	}
}

func TestCollectFollowsPagination(t *testing.T) {
	page1 := base + "/subscribedSkus?$top=1"
	body1 := `{
		"value": [{"skuId": "sku-1", "skuPartNumber": "ENTERPRISEPACK", "consumedUnits": 1, "prepaidUnits": {"enabled": 2}}],
		"@odata.nextLink": "` + base + `/subscribedSkus?$top=1&$skip=1"
	}`
	page2URL := base + "/subscribedSkus?$top=1&$skip=1"
	body2 := `{"value": [{"skuId": "sku-2", "skuPartNumber": "POWER_BI_STANDARD", "consumedUnits": 3, "prepaidUnits": {"enabled": 4}}]}`

	g := &fakeGraph{bodies: map[string]string{
		skusURL:   `{"value": [], "@odata.nextLink": "` + page1 + `"}`,
		page1:     body1,
		page2URL:  body2,
		groupsURL: noGroupErrors,
	}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(consumedMetricName)
	if len(pts) != 2 {
		t.Fatalf("got %d consumed series across pages, want 2: %+v", len(pts), pts)
	}
}

func TestCollectSurfacesGraphError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{skusURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	c := New(g, nil)
	err := c.Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the subscribedSkus fetch error")
	}
	if len(rec.MetricPoints(consumedMetricName)) != 0 {
		t.Error("expected no consumed series to be emitted on fetch failure")
	}
	if len(rec.MetricPoints(enabledMetricName)) != 0 {
		t.Error("expected no enabled series to be emitted on fetch failure")
	}
}

func TestCollectHandlesEmptyTenant(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: `{"value": []}`, groupsURL: noGroupErrors}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.MetricPoints(consumedMetricName)) != 0 {
		t.Errorf("expected zero consumed series for an empty tenant, got %d", len(rec.MetricPoints(consumedMetricName)))
	}
}

// TestCollectNeverEmitsPerUserOrAssignmentErrorSeries is the cardinality guard
// the authoring guide requires: assignment-error detection would require
// paging every user's licenseAssignmentStates (a per-user, expensive scan with
// no v1.0 tenant-level aggregate) and is deliberately deferred rather than
// implemented as a per-user series. This asserts the collector emits ONLY the
// two bounded per-SKU gauges and nothing else, no matter what the fake backend
// returns.
func TestCollectNeverEmitsPerUserOrAssignmentErrorSeries(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: liveSubscribedSkus, groupsURL: twoErroredGroupsBody}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// The full bounded metric set: per-SKU consumed/enabled/units/capability
	// plus the scalar group-error count. The per-user assignment-error series
	// (#45) is still deliberately absent; the #122 group path is bounded and
	// group-keyed, not per-user.
	names := rec.MetricNames()
	want := map[string]bool{
		consumedMetricName:         true,
		enabledMetricName:          true,
		unitsMetricName:            true,
		capabilityStatusMetricName: true,
		groupsWithErrorsMetricName: true,
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected metric %q emitted; only %v are expected (per-user assignment-errors aggregate is deferred, see collector doc comment)", n, want)
		}
	}
	if len(names) != len(want) {
		t.Errorf("got metrics %v, want exactly %v", names, want)
	}

	// Every emitted point may carry ONLY bounded, tenant-shaped keys — never a
	// per-user or per-group identifier (group id/name live on the log twin).
	allowed := map[string]bool{"sku": true, "state": true, "status": true}
	for _, name := range names {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if !allowed[k] {
					t.Errorf("metric %s carries unexpected attribute %q (per-entity leak?): %v", name, k, p.Attrs)
				}
			}
		}
	}
}

func TestCollectSkipsMalformedSKUButEmitsOthers(t *testing.T) {
	body := `{
		"value": [
			{"skuId": "sku-1", "skuPartNumber": "", "consumedUnits": 1, "prepaidUnits": {"enabled": 2}},
			{"skuId": "sku-2", "skuPartNumber": "POWER_BI_STANDARD", "consumedUnits": 3, "prepaidUnits": {"enabled": 4}}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{skusURL: body, groupsURL: noGroupErrors}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(consumedMetricName)
	if len(pts) != 1 {
		t.Fatalf("got %d consumed series, want 1 (blank skuPartNumber dropped): %+v", len(pts), pts)
	}
	if pts[0].Attrs["sku"] != "POWER_BI_STANDARD" {
		t.Errorf("surviving series sku = %q, want POWER_BI_STANDARD", pts[0].Attrs["sku"])
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.licensing" {
		t.Errorf("Name = %q, want entra.licensing", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := map[string]bool{}
	for _, p := range c.RequiredPermissions() {
		perms[p] = true
	}
	for _, want := range []string{"LicenseAssignment.Read.All", "Group.Read.All"} {
		if !perms[want] {
			t.Errorf("RequiredPermissions missing %q; got %v", want, c.RequiredPermissions())
		}
	}
}

// TestCollectEmitsUnitStatesAndCapabilityStatus pins #122's subscription-health
// signals: all four prepaidUnits states per SKU, and the capabilityStatus info
// gauge (value 1, status lowercased).
func TestCollectEmitsUnitStatesAndCapabilityStatus(t *testing.T) {
	body := `{"value":[
		{"skuId":"s1","skuPartNumber":"ENTERPRISEPACK","consumedUnits":90,"capabilityStatus":"Warning",
		 "prepaidUnits":{"enabled":100,"suspended":5,"warning":3,"lockedOut":1}}
	]}`
	g := &fakeGraph{bodies: map[string]string{skusURL: body, groupsURL: noGroupErrors}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotUnits := map[string]float64{}
	for _, p := range rec.MetricPoints(unitsMetricName) {
		if p.Attrs["sku"] != "ENTERPRISEPACK" {
			t.Errorf("units point wrong sku: %v", p.Attrs)
		}
		gotUnits[p.Attrs["state"]] = p.Value
	}
	wantUnits := map[string]float64{"enabled": 100, "suspended": 5, "warning": 3, "locked_out": 1}
	if len(gotUnits) != len(wantUnits) {
		t.Fatalf("got %d unit states, want 4: %v", len(gotUnits), gotUnits)
	}
	for k, v := range wantUnits {
		if gotUnits[k] != v {
			t.Errorf("units state=%s = %v, want %v", k, gotUnits[k], v)
		}
	}

	caps := rec.MetricPoints(capabilityStatusMetricName)
	if len(caps) != 1 {
		t.Fatalf("got %d capability_status points, want 1", len(caps))
	}
	if caps[0].Value != 1 || caps[0].Attrs["status"] != "warning" || caps[0].Attrs["sku"] != "ENTERPRISEPACK" {
		t.Errorf("capability_status = %v attrs %v, want value 1 status=warning sku=ENTERPRISEPACK", caps[0].Value, caps[0].Attrs)
	}
}

// TestCollectEmitsGroupsWithErrors pins the #122 group-level path: the scalar
// count and one log twin per affected group, and that group id/name never leak
// onto a metric.
func TestCollectEmitsGroupsWithErrors(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: `{"value":[]}`, groupsURL: twoErroredGroupsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(groupsWithErrorsMetricName)
	if len(pts) != 1 || pts[0].Value != 2 {
		t.Fatalf("groups_with_errors = %v, want a single point valued 2", pts)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("groups_with_errors carries attrs %v, want none (scalar)", pts[0].Attrs)
	}

	logs := logsNamed(rec.LogRecords(), eventLicenseGroupError)
	if len(logs) != 2 {
		t.Fatalf("emitted %d %s logs, want 2", len(logs), eventLicenseGroupError)
	}
	var finance *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].Attrs["id"] == "11111111-1111-1111-1111-111111111111" {
			finance = &logs[i]
		}
	}
	if finance == nil || finance.Attrs["display_name"] != "Finance Team" {
		t.Errorf("Finance Team log missing or wrong: %v", logs)
	}
}

// TestZeroGroupsEmitsExplicitZeroNoLogs pins the healthy case: no affected
// groups still emits groups_with_errors.total = 0 (never absent) and no logs.
func TestZeroGroupsEmitsExplicitZeroNoLogs(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{skusURL: `{"value":[]}`, groupsURL: noGroupErrors}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(groupsWithErrorsMetricName)
	if len(pts) != 1 || pts[0].Value != 0 {
		t.Fatalf("groups_with_errors = %v, want a single point valued 0", pts)
	}
	if logs := logsNamed(rec.LogRecords(), eventLicenseGroupError); len(logs) != 0 {
		t.Errorf("emitted %d logs with zero affected groups, want 0", len(logs))
	}
}
