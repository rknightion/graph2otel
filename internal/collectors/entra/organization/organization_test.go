package organization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors).
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
const orgURL = base + "/organization"

// fixedNow is the deterministic "now" every test injects via Collector.now so
// sync-age / tenant-age assertions never flake against wall-clock time.
var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func newCollectorAt(g collectors.GraphClient, now time.Time) *Collector {
	c := New(g, nil)
	c.now = func() time.Time { return now }
	return c
}

// liveOrganization is a VERBATIM GET /organization capture from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17,
// #165]`. It replaces the invented tenant-1/Contoso/contoso.com docs fixture.
//
// The m7kni tenant is CLOUD-ONLY: onPremisesSyncEnabled and
// onPremisesLastSyncDateTime are both null on the wire (the documented default
// for a tenant that never synced from on-premises AD), so this record exercises
// the sync-disabled path — the hybrid-sync branch is covered separately by the
// synthetic hybridSyncedBody below, because no live capture of this tenant can
// produce a sync-active record.
//
// It is pinned, not hand-written. The huge assignedPlans and provisionedPlans
// arrays are trimmed to three representative elements each (dropping whole
// elements only, never editing a value); the collector reads none of them. All
// four verifiedDomains are kept verbatim so the verified_domains.total=4
// assertion is a real count. The businessPhones/city/street/postalCode fields
// were redacted at capture time (they held a personal mobile and home address);
// the corporate technicalNotificationMails rob@m7kni.com is kept and is fine.
const liveOrganization = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#organization",
  "value": [
    {
      "assignedPlans": [
        {
          "assignedDateTime": "2026-07-14T22:04:52Z",
          "capabilityStatus": "Enabled",
          "service": "M365ComplianceDrive",
          "servicePlanId": "af45fb33-8a26-46dc-92db-c70d5a9da509"
        },
        {
          "assignedDateTime": "2026-07-14T17:56:35Z",
          "capabilityStatus": "Enabled",
          "service": "Microsoft-eCDN",
          "servicePlanId": "85704d55-2e73-47ee-93b4-4b8ea14db92b"
        },
        {
          "assignedDateTime": "2026-06-14T07:33:21Z",
          "capabilityStatus": "Suspended",
          "service": "SharePoint",
          "servicePlanId": "c7699d2e-19aa-44de-8edf-1736da088ca1"
        }
      ],
      "businessPhones": [],
      "city": "REDACTED",
      "country": null,
      "countryLetterCode": "GB",
      "createdDateTime": "2025-08-08T18:00:36Z",
      "defaultUsageLocation": null,
      "deletedDateTime": null,
      "directorySizeQuota": {
        "total": 300000,
        "used": 1202
      },
      "displayName": "m7kni",
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "isMultipleDataLocationsForServicesEnabled": null,
      "marketingNotificationEmails": [],
      "onPremisesLastSyncDateTime": null,
      "onPremisesSyncEnabled": null,
      "onPremisesSyncStatus": [],
      "partnerTenantType": null,
      "postalCode": "REDACTED",
      "preferredLanguage": "en",
      "privacyProfile": null,
      "provisionedPlans": [
        {
          "capabilityStatus": "Enabled",
          "provisioningStatus": "Success",
          "service": "SharePoint"
        },
        {
          "capabilityStatus": "Enabled",
          "provisioningStatus": "Success",
          "service": "exchange"
        },
        {
          "capabilityStatus": "Suspended",
          "provisioningStatus": "Success",
          "service": "MicrosoftCommunicationsOnline"
        }
      ],
      "replicationScope": "EU",
      "securityComplianceNotificationMails": [],
      "securityComplianceNotificationPhones": [],
      "state": null,
      "street": "REDACTED",
      "technicalNotificationMails": [
        "rob@m7kni.com"
      ],
      "tenantType": "AAD",
      "verifiedDomains": [
        {
          "capabilities": "Email, OfficeCommunicationsOnline",
          "isDefault": false,
          "isInitial": true,
          "name": "m7knio.onmicrosoft.com",
          "type": "Managed"
        },
        {
          "capabilities": "Email, Intune",
          "isDefault": true,
          "isInitial": false,
          "name": "m7kni.io",
          "type": "Managed"
        },
        {
          "capabilities": "Intune",
          "isDefault": false,
          "isInitial": false,
          "name": "rob-knight.com",
          "type": "Managed"
        },
        {
          "capabilities": "Email, Intune",
          "isDefault": false,
          "isInitial": false,
          "name": "m7kni.com",
          "type": "Managed"
        }
      ]
    }
  ]
}`

// liveCreatedDateTime is the m7kni tenant's real createdDateTime from
// liveOrganization, used by the age_days assertion.
var liveCreatedDateTime = time.Date(2025, 8, 8, 18, 0, 36, 0, time.UTC)

// hybridSyncedBody is a deliberately SYNTHETIC organization record that turns
// on on-premises sync so the age-of-last-sync branch can be exercised. The live
// m7kni tenant is cloud-only (see liveOrganization), so this path has no live
// capture and this synthetic fixture is retained on purpose.
func hybridSyncedBody(lastSync string) string {
	return `{
		"value": [
			{
				"id": "tenant-1",
				"displayName": "Contoso",
				"tenantType": "AAD",
				"createdDateTime": "2020-01-01T00:00:00Z",
				"onPremisesSyncEnabled": true,
				"onPremisesLastSyncDateTime": "` + lastSync + `",
				"verifiedDomains": [
					{"name": "contoso.com", "isDefault": true},
					{"name": "contoso.onmicrosoft.com", "isDefault": false}
				]
			}
		]
	}`
}

func TestCollectEmitsSyncEnabledAndAgeWhenHybridSyncActive(t *testing.T) {
	// 2 hours before fixedNow.
	lastSync := "2026-07-15T10:00:00Z"
	g := &fakeGraph{bodies: map[string]string{orgURL: hybridSyncedBody(lastSync)}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 1 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=1", enabled)
	}

	age := rec.MetricPoints(syncAgeMetricName)
	if len(age) != 1 {
		t.Fatalf("sync age points = %+v, want exactly 1", age)
	}
	wantSeconds := 2 * time.Hour.Seconds()
	if age[0].Value != wantSeconds {
		t.Errorf("sync age = %v, want %v", age[0].Value, wantSeconds)
	}
}

func TestCollectOmitsSyncAgeWhenSyncDisabled(t *testing.T) {
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": false,
				"onPremisesLastSyncDateTime": "2026-07-15T10:00:00Z"
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 0 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=0", enabled)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series when sync disabled, got %+v", age)
	}
}

func TestCollectOmitsSyncAgeWhenNeverSynced(t *testing.T) {
	// Cloud-only tenant: both fields null (the documented default).
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": null,
				"onPremisesLastSyncDateTime": null
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 0 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=0 for a cloud-only tenant", enabled)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series for a never-synced tenant, got %+v", age)
	}
}

func TestCollectOmitsSyncAgeWhenEnabledButLastSyncMissing(t *testing.T) {
	// onPremisesSyncEnabled true but onPremisesLastSyncDateTime null: age is
	// not computable, must not emit a misleading value.
	body := `{
		"value": [
			{
				"id": "tenant-1",
				"tenantType": "AAD",
				"onPremisesSyncEnabled": true,
				"onPremisesLastSyncDateTime": null
			}
		]
	}`
	g := &fakeGraph{bodies: map[string]string{orgURL: body}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series when last-sync timestamp is absent, got %+v", age)
	}
}

func TestCollectEmitsAgeDaysFromCreatedDateTime(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: liveOrganization}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(ageDaysMetricName)
	if len(pts) != 1 {
		t.Fatalf("age_days points = %+v, want exactly 1", pts)
	}
	wantDays := fixedNow.Sub(liveCreatedDateTime).Hours() / 24
	if pts[0].Value != wantDays {
		t.Errorf("age_days = %v, want %v", pts[0].Value, wantDays)
	}
}

func TestCollectEmitsVerifiedDomainsTotal(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: liveOrganization}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(verifiedDomainsMetricName)
	if len(pts) != 1 || pts[0].Value != 4 {
		t.Fatalf("verified domains points = %+v, want single point value=4 (the m7kni tenant's four verified domains)", pts)
	}
}

func TestCollectEmitsInfoGaugeWithBoundedTenantType(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: liveOrganization}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(infoMetricName)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("info points = %+v, want single point value=1", pts)
	}
	if got := pts[0].Attrs["tenant_type"]; got != "AAD" {
		t.Errorf("info tenant_type attr = %q, want %q", got, "AAD")
	}
}

func TestCollectHandlesEmptyOrganizationCollection(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: `{"value": []}`}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("expected no metrics for an empty /organization collection, got %v", names)
	}
}

func TestCollectSurfacesGraphFetchError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{orgURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("expected Collect to surface the /organization fetch error")
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("expected no metrics emitted on fetch failure, got %v", names)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.organization" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Organization.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Organization.Read.All]", perms)
	}
}

// TestCollectNeverEmitsHighCardinalityLabels is the cardinality guard the
// authoring guide requires: this is a single tenant-wide object, so nothing
// here may carry the tenant id or displayName (both high-cardinality across a
// fleet of tenants) as a metric label. tenant_id is applied by the scheduler,
// not by the collector. Only the bounded "tenant_type" attribute is allowed,
// and only on the info gauge.
func TestCollectNeverEmitsHighCardinalityLabels(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: liveOrganization}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for k, v := range p.Attrs {
				if k != "tenant_type" {
					t.Errorf("metric %s has unexpected attribute %q=%q (only tenant_type is allowed)", name, k, v)
				}
				// The live record's real tenant id and displayName: neither may
				// ever surface as a metric label value.
				if v == "4b8c18bd-2f9f-4227-af55-9f1061cf9c32" || v == "m7kni" {
					t.Errorf("metric %s attribute %q=%q looks like a leaked tenant id/displayName", name, k, v)
				}
			}
		}
	}
}

// TestCollectorEmitsLiveRecordEndToEnd drives the one verbatim /organization
// capture through Collect into a Recorder and pins the full metric surface it
// produces. It is what makes testdata/signals.json honest for this collector:
// the golden records the union of what the package's tests EMIT, so the real
// record has to reach the emitter for the golden to reflect a real response.
//
// The m7kni tenant is cloud-only, so this exercises the sync-disabled path:
// on_premises_sync_enabled=0, NO sync-age series (the deliberate omission when
// sync is off), age_days from the real 2025-08-08 createdDateTime, four
// verified domains, and tenant_type=AAD.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: liveOrganization}}
	rec := telemetrytest.New()

	c := newCollectorAt(g, fixedNow)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	enabled := rec.MetricPoints(syncEnabledMetricName)
	if len(enabled) != 1 || enabled[0].Value != 0 {
		t.Fatalf("on_premises_sync_enabled points = %+v, want single point value=0 (cloud-only tenant)", enabled)
	}
	if age := rec.MetricPoints(syncAgeMetricName); len(age) != 0 {
		t.Errorf("expected no sync-age series for the cloud-only live tenant, got %+v", age)
	}

	ageDays := rec.MetricPoints(ageDaysMetricName)
	wantDays := fixedNow.Sub(liveCreatedDateTime).Hours() / 24
	if len(ageDays) != 1 || ageDays[0].Value != wantDays {
		t.Errorf("age_days points = %+v, want single point value=%v", ageDays, wantDays)
	}

	vd := rec.MetricPoints(verifiedDomainsMetricName)
	if len(vd) != 1 || vd[0].Value != 4 {
		t.Errorf("verified_domains.total points = %+v, want single point value=4", vd)
	}

	info := rec.MetricPoints(infoMetricName)
	if len(info) != 1 || info[0].Value != 1 || info[0].Attrs["tenant_type"] != "AAD" {
		t.Errorf("info points = %+v, want single point value=1 tenant_type=AAD", info)
	}
}
