package conditionalaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors) and records
// the ConsistencyLevel header seen on each request. GetAllValues follows
// @odata.nextLink, but every fixture here is a single page.
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]string // url -> ConsistencyLevel
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]string{}
	}
	f.seenHeaders[url] = headers["ConsistencyLevel"]
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base         = "https://graph.microsoft.com/v1.0"
	policiesURL  = base + "/identity/conditionalAccess/policies"
	locationsURL = base + "/identity/conditionalAccess/namedLocations"
)

func policiesPage(policiesJSON string) string {
	return `{"value":[` + policiesJSON + `]}`
}

func locationsPage(locationsJSON string) string {
	return `{"value":[` + locationsJSON + `]}`
}

// livePolicies is a VERBATIM GET /identity/conditionalAccess/policies response
// from the m7kni tenant, read as graph2otel-poller `[live-measured 2026-07-17, #165]`. All five policies are
// state "enabled" on this tenant, so the live aggregate is enabled=5,
// disabled=0, enabled_for_reporting_but_not_enforced=0 — the zero-filled
// disabled/report-only buckets still emit at 0. The rich conditions /
// grantControls / sessionControls trees are on the wire in full and deliberately
// untouched by the mapper (per-policy detail belongs in the audit log stream,
// not a metric label); they are the reason a verbatim capture matters here.
// The synthetic single-state fixtures in TestCollectSkipsUnrecognizedPolicyStateAndLocationType
// still exercise the unrecognized-state skip the live all-enabled data cannot.
const livePolicies = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
  "value": [
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "All"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": null,
        "clientAppTypes": [
          "exchangeActiveSync",
          "other"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": null,
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [],
          "excludeUsers": [],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2025-09-24T12:59:05.2884951Z",
      "deletedDateTime": null,
      "displayName": "Block legacy authentication",
      "grantControls": {
        "authenticationStrength": null,
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('738ad89e-6820-4164-84f1-53d295360d42')/grantControls/authenticationStrength/$entity",
        "builtInControls": [
          "block"
        ],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "738ad89e-6820-4164-84f1-53d295360d42",
      "modifiedDateTime": "2025-10-05T16:20:33.7922016Z",
      "sessionControls": null,
      "state": "enabled",
      "templateId": "0b2282f9-2862-4178-88b5-d79340b36cb8"
    },
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "All"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": null,
        "clientAppTypes": [
          "all"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": {
          "excludeLocations": [],
          "includeLocations": [
            "07703061-c278-49cb-ad4d-caf29f8276dc"
          ]
        },
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [],
          "excludeUsers": [],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2025-09-24T13:00:26.0186551Z",
      "deletedDateTime": null,
      "displayName": "Reduced reauth frequency at home",
      "grantControls": null,
      "id": "3fa9321f-1213-47c8-87be-eeb71bb4e6fc",
      "modifiedDateTime": "2026-07-15T19:21:31.2182711Z",
      "sessionControls": {
        "applicationEnforcedRestrictions": null,
        "cloudAppSecurity": null,
        "disableResilienceDefaults": null,
        "persistentBrowser": null,
        "secureSignInSession": null,
        "signInFrequency": {
          "authenticationType": "primaryAndSecondaryAuthentication",
          "frequencyInterval": "timeBased",
          "isEnabled": true,
          "type": "days",
          "value": 5
        }
      },
      "state": "enabled",
      "templateId": "d8c51a9a-e6b1-454d-86af-554e7872e2c1"
    },
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "MicrosoftAdminPortals"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": null,
        "clientAppTypes": [
          "all"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": null,
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [
            "5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"
          ],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [],
          "excludeUsers": [],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2025-09-24T13:37:16.7413549Z",
      "deletedDateTime": null,
      "displayName": "Require multifactor authentication for Microsoft admin portals",
      "grantControls": {
        "authenticationStrength": {
          "allowedCombinations": [
            "windowsHelloForBusiness",
            "fido2",
            "x509CertificateMultiFactor",
            "deviceBasedPush",
            "temporaryAccessPassOneTime",
            "temporaryAccessPassMultiUse",
            "password,microsoftAuthenticatorPush",
            "password,softwareOath",
            "password,hardwareOath",
            "password,sms",
            "password,voice",
            "federatedMultiFactor",
            "microsoftAuthenticatorPush,federatedSingleFactor",
            "softwareOath,federatedSingleFactor",
            "hardwareOath,federatedSingleFactor",
            "sms,federatedSingleFactor",
            "voice,federatedSingleFactor"
          ],
          "combinationConfigurations": [],
          "combinationConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('d7195984-2fae-403d-abec-a7ccc55bf861')/grantControls/authenticationStrength/combinationConfigurations",
          "createdDateTime": "2021-12-01T08:00:00Z",
          "description": "Combinations of methods that satisfy strong authentication, such as a password + SMS",
          "displayName": "Multifactor authentication",
          "id": "00000000-0000-0000-0000-000000000002",
          "modifiedDateTime": "2021-12-01T08:00:00Z",
          "policyType": "builtIn",
          "requirementsSatisfied": "mfa"
        },
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('d7195984-2fae-403d-abec-a7ccc55bf861')/grantControls/authenticationStrength/$entity",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "d7195984-2fae-403d-abec-a7ccc55bf861",
      "modifiedDateTime": "2026-07-13T21:38:43.4212826Z",
      "sessionControls": null,
      "state": "enabled",
      "templateId": "6364131e-bc4a-47c4-a20b-33492d1fff6c"
    },
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "All"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": null,
        "clientAppTypes": [
          "all"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": null,
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [
            "5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"
          ],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [
            "d29b2b05-8046-44ba-8758-1e26182fcf32"
          ],
          "excludeUsers": [],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2025-09-25T09:48:27.4280922Z",
      "deletedDateTime": null,
      "displayName": "Require multifactor authentication for all users",
      "grantControls": {
        "authenticationStrength": null,
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('013f1d6b-785b-4520-b0f9-31bfaefb8e2b')/grantControls/authenticationStrength/$entity",
        "builtInControls": [
          "mfa"
        ],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "013f1d6b-785b-4520-b0f9-31bfaefb8e2b",
      "modifiedDateTime": "2026-07-13T21:38:44.551285Z",
      "sessionControls": null,
      "state": "enabled",
      "templateId": "a3d0a415-b068-4326-9251-f9cdf9feeb64"
    },
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "All"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": null,
        "clientAppTypes": [
          "all"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": null,
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [
            "5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"
          ],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [],
          "excludeUsers": [],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [
            "62e90394-69f5-4237-9190-012177145e10",
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
            "29232cdf-9323-42fd-ade2-1d097af3e4de",
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",
            "b0f54661-2d74-4c50-afa3-1ec803f12efe",
            "fe930be7-5e62-47db-91af-98c3a49a38b1",
            "c4e39bd9-1100-46d3-8c65-fb160da0071f",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
            "158c047a-c907-4556-b7ef-446551a6b5f7",
            "966707d0-3269-4727-9be2-8c3a10f19b9d",
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
            "e8611ab8-c189-46e8-94e1-60213ab1f814"
          ],
          "includeUsers": []
        }
      },
      "createdDateTime": "2025-10-04T15:53:14.1790576Z",
      "deletedDateTime": null,
      "displayName": "Require multifactor authentication for admins",
      "grantControls": {
        "authenticationStrength": null,
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('75d01079-c805-4a03-8153-78fdd7c641f2')/grantControls/authenticationStrength/$entity",
        "builtInControls": [
          "mfa"
        ],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "75d01079-c805-4a03-8153-78fdd7c641f2",
      "modifiedDateTime": "2026-07-13T21:38:45.4606131Z",
      "sessionControls": null,
      "state": "enabled",
      "templateId": "c7503427-338e-4c5e-902d-abe252abfb43"
    }
  ]
}`

// liveNamedLocations is a VERBATIM GET
// /identity/conditionalAccess/namedLocations response from the m7kni tenant
// `[live-measured 2026-07-17, #165]`. It carries both @odata.type subtypes: one ipNamedLocation
// (isTrusted:true) and one countryNamedLocation (no isTrusted property at all —
// trust is IP-range-only, so it counts as is_trusted=false, never a parse
// error). Live aggregate: ip/true=1, ip/false=0, country/true=0, country/false=1.
//
// One deviation from verbatim: the "Home" location's three real residential
// cidrAddress values are redacted to RFC 5737 / RFC 3849 documentation ranges
// (192.0.2.0/24, 2001:db8::/32). This is a public repo and those were the
// tenant owner's home IPs; the collector reads only @odata.type and isTrusted,
// never ipRanges, so the redaction changes nothing the fixture exercises.
const liveNamedLocations = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/namedLocations",
  "value": [
    {
      "@odata.type": "#microsoft.graph.ipNamedLocation",
      "createdDateTime": "2025-09-12T11:35:35.4195094Z",
      "deletedDateTime": null,
      "displayName": "Home",
      "id": "07703061-c278-49cb-ad4d-caf29f8276dc",
      "ipRanges": [
        {
          "@odata.type": "#microsoft.graph.iPv4CidrRange",
          "cidrAddress": "192.0.2.31/32"
        },
        {
          "@odata.type": "#microsoft.graph.iPv4CidrRange",
          "cidrAddress": "192.0.2.106/32"
        },
        {
          "@odata.type": "#microsoft.graph.iPv6CidrRange",
          "cidrAddress": "2001:db8:1f05::/48"
        }
      ],
      "isTrusted": true,
      "modifiedDateTime": "2026-06-19T21:00:40.4851777Z"
    },
    {
      "@odata.type": "#microsoft.graph.countryNamedLocation",
      "countriesAndRegions": [
        "GB"
      ],
      "countryLookupMethod": "clientIpAddress",
      "createdDateTime": "2025-09-24T13:34:29.5656965Z",
      "deletedDateTime": null,
      "displayName": "UK",
      "id": "15a23082-f571-45d9-bc6a-e092c282bf68",
      "includeUnknownCountriesAndRegions": false,
      "modifiedDateTime": "2025-09-24T13:34:29.5656965Z"
    }
  ]
}`

func fullFixture() map[string]string {
	return map[string]string{
		policiesURL:  livePolicies,
		locationsURL: liveNamedLocations,
	}
}

// TestCollectEmitsPolicyCountsByState drives the live policy catalog end-to-end.
// Every live policy is "enabled", so the aggregate is enabled=5 with the
// disabled and report-only buckets zero-filled at 0.
func TestCollectEmitsPolicyCountsByState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(policiesMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["state"]] = p.Value
	}
	want := map[string]float64{
		"enabled":                                5,
		"disabled":                               0,
		"enabled_for_reporting_but_not_enforced": 0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for state, v := range want {
		if got[state] != v {
			t.Errorf("series state=%s value = %v, want %v", state, got[state], v)
		}
	}
}

// TestCollectEmitsNamedLocationCountsByTypeAndTrust drives the live named
// location catalog end-to-end: one trusted IP location and one country location.
func TestCollectEmitsNamedLocationCountsByTypeAndTrust(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(namedLocationsMetricName)
	type key struct{ typ, trusted string }
	got := map[key]float64{}
	for _, p := range pts {
		got[key{p.Attrs["type"], p.Attrs["is_trusted"]}] = p.Value
	}
	want := map[key]float64{
		{"ip", "true"}:       1,
		{"ip", "false"}:      0,
		{"country", "true"}:  0,
		{"country", "false"}: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series type=%s is_trusted=%s value = %v, want %v", k.typ, k.trusted, got[k], v)
		}
	}
}

func TestCollectSkipsUnrecognizedPolicyStateAndLocationType(t *testing.T) {
	bodies := map[string]string{
		policiesURL: policiesPage(`
			{"id":"p1","state":"enabled"},
			{"id":"p2","state":"someFutureState"}
		`),
		locationsURL: locationsPage(`
			{"@odata.type":"#microsoft.graph.ipNamedLocation","id":"l1","isTrusted":true},
			{"@odata.type":"#microsoft.graph.someFutureLocationType","id":"l2"}
		`),
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	policyPts := rec.MetricPoints(policiesMetricName)
	var totalPolicies float64
	for _, p := range policyPts {
		totalPolicies += p.Value
	}
	if totalPolicies != 1 {
		t.Errorf("total policy count = %v, want 1 (unrecognized state excluded)", totalPolicies)
	}

	locPts := rec.MetricPoints(namedLocationsMetricName)
	var totalLocations float64
	for _, p := range locPts {
		totalLocations += p.Value
	}
	if totalLocations != 1 {
		t.Errorf("total named location count = %v, want 1 (unrecognized type excluded)", totalLocations)
	}
}

func TestCollectSetsConsistencyLevelHeaderIsNotRequired(t *testing.T) {
	// Conditional Access policies/namedLocations are plain collection reads
	// (no advanced $filter/$search), so unlike Count-based collectors this one
	// must NOT force ConsistencyLevel: eventual on every request.
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, cl := range g.seenHeaders {
		if cl != "" {
			t.Errorf("request %s had ConsistencyLevel=%q, want unset", url, cl)
		}
	}
}

func TestCollectIsResilientToPolicyFetchError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{policiesURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the policies fetch failure as an error")
	}

	if pts := rec.MetricPoints(policiesMetricName); len(pts) != 0 {
		t.Errorf("expected no policy series when the fetch failed, got %d", len(pts))
	}
	// Named locations must still emit even though policies failed.
	if pts := rec.MetricPoints(namedLocationsMetricName); len(pts) == 0 {
		t.Error("expected named location series to still be emitted despite policies failing")
	}
}

func TestCollectIsResilientToNamedLocationsFetchError(t *testing.T) {
	g := &fakeGraph{
		bodies: fullFixture(),
		errs:   map[string]error{locationsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the named locations fetch failure as an error")
	}

	if pts := rec.MetricPoints(namedLocationsMetricName); len(pts) != 0 {
		t.Errorf("expected no named location series when the fetch failed, got %d", len(pts))
	}
	if pts := rec.MetricPoints(policiesMetricName); len(pts) == 0 {
		t.Error("expected policy series to still be emitted despite named locations failing")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.conditional_access" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.All]", perms)
	}
}

func TestRequiredCapabilityIsEntraP1(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	var requirer license.CapabilityRequirer = c
	if got := requirer.RequiredCapability(); got != license.CapEntraP1 {
		t.Errorf("RequiredCapability() = %q, want %q", got, license.CapEntraP1)
	}
}

// TestNoPerEntitySeries guards the cardinality rule: neither metric may carry
// a per-policy or per-location identifier (id/displayName) as an attribute.
func TestNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedPolicyAttrs := map[string]bool{"state": true}
	for _, p := range rec.MetricPoints(policiesMetricName) {
		for k := range p.Attrs {
			if !allowedPolicyAttrs[k] {
				t.Errorf("policies series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	allowedLocationAttrs := map[string]bool{"type": true, "is_trusted": true}
	for _, p := range rec.MetricPoints(namedLocationsMetricName) {
		for k := range p.Attrs {
			if !allowedLocationAttrs[k] {
				t.Errorf("named locations series has unexpected attribute %q (possible per-entity leak): %v", k, p.Attrs)
			}
		}
	}

	// Cardinality is bounded regardless of how many policies/locations exist:
	// 3 states, at most 4 type x trust combos.
	if n := len(rec.MetricPoints(policiesMetricName)); n > 3 {
		t.Errorf("policies series count = %d, want <= 3", n)
	}
	if n := len(rec.MetricPoints(namedLocationsMetricName)); n > 4 {
		t.Errorf("named locations series count = %d, want <= 4", n)
	}
}
