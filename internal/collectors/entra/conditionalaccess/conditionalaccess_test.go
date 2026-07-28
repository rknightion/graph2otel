package conditionalaccess

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
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

// liveNamedLocations is captured-and-redacted (2026-07-28, #318) from the
// m7kni tenant as graph2otel-poller: a fresh live capture that replaced the
// prior [live-measured 2026-07-17, #165] snapshot once #318 needed the
// per-location log twin exercised against real shape. It carries both
// @odata.type subtypes: one ipNamedLocation (isTrusted:true) and one
// countryNamedLocation (no isTrusted property at all — trust is
// IP-range-only, so the aggregate gauge counts it as is_trusted=false, never
// a parse error — but see TestNamedLocationLogTwinCountryOmitsIsTrusted:
// the twin must NOT make that same collapse). Live aggregate: ip/true=1,
// ip/false=0, country/true=0, country/false=1.
//
// The ONLY substitution from verbatim: the "Home" location's three real
// residential cidrAddress values are deterministically replaced with
// realistic public ranges (51.148.203.77/32, 91.125.14.6/32, 2a02:8010:6::/48)
// that are NOT the tenant's — each substitute preserves its original range's
// IP version and prefix length 1:1. This is a public repo and those were the
// tenant owner's home IPs. Earlier revisions of this fixture used RFC 5737 /
// RFC 3849 documentation ranges (192.0.2.0/24, 2001:db8::/32) instead; the
// maintainer corrected that 2026-07-28 (#318) — a fixed-size, obviously
// synthetic documentation range exercises none of the variety real input has,
// and #318's log twin needs the mapper tested against realistic shape (mixed
// prefix lengths, a real-looking v4/v6 split), not a giveaway placeholder.
// Everything else on the wire is verbatim.
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
          "cidrAddress": "51.148.203.77/32"
        },
        {
          "@odata.type": "#microsoft.graph.iPv4CidrRange",
          "cidrAddress": "91.125.14.6/32"
        },
        {
          "@odata.type": "#microsoft.graph.iPv6CidrRange",
          "cidrAddress": "2a02:8010:6::/48"
        }
      ],
      "isTrusted": true,
      "modifiedDateTime": "2026-07-22T09:00:41.8577779Z"
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

// twinPolicies is a SEPARATE live-measured capture (2026-07-28, #318, real
// object GUIDs and displayNames verbatim per existing repo practice — no CIDR
// or other content in a CA policy response, so no redaction applies) from the
// m7kni tenant, purpose-picked from 16 real policies to exercise the
// entra.conditional_access_policy log twin mapper rather than to redrive the
// aggregate-gauge tests above (livePolicies stays untouched for those, so
// their pinned enabled=5 assertion is unaffected). The 7 policies here cover:
//   - all three state values: "enabled" (5), "disabled" (1, "Baseline
//     Security Mode: Require phishing-resistant..."), and
//     "enabledForReportingButNotEnforced" (1, the Insider Risk policy);
//   - grantControls == null (the "Reduced reauth frequency at home" policy —
//     the one case #318's decisions comment calls out: has_grant_controls
//     must read false, not a zero-value grantControls struct);
//   - sessionControls == null (4 of the 7) vs a populated object (3 of the
//     7, covering persistentBrowser and signInFrequency shapes);
//   - a null grantControls.authenticationStrength (most policies) vs a
//     populated one carrying only a displayName the mapper reads
//     ("Phishing-resistant MFA" / "Multifactor authentication" /
//     "Passwordless MFA");
//   - conditions.locations present with real named-location ids in both
//     includeLocations and excludeLocations (a natural join key onto the
//     entra.named_location twin's id attribute) and conditions.locations ==
//     null (most policies);
//   - conditions.signInRiskLevels populated (["high"]) alongside the empty
//     case;
//   - a 19-element conditions.users.includeRoles array — comfortably under
//     maxArrayAttr (50), so this fixture proves the un-truncated path; the
//     truncation path itself is proven by a synthetic fixture in
//     TestPolicyLogTwinCapsArraysAndRecordsTruncation, since no real tenant
//     policy here is large enough to exercise the cap.
const twinPolicies = `{
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
      "modifiedDateTime": "2026-07-20T15:49:20.8710912Z",
      "sessionControls": {
        "applicationEnforcedRestrictions": null,
        "cloudAppSecurity": null,
        "disableResilienceDefaults": null,
        "persistentBrowser": {
          "isEnabled": true,
          "mode": "always"
        },
        "secureSignInSession": null,
        "signInFrequency": null
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
          "excludeUsers": [
            "e755e472-f2eb-4ea6-829d-5a908600fdb1"
          ],
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
            "e8611ab8-c189-46e8-94e1-60213ab1f814",
            "17315797-102d-40b4-93e0-432062caca18",
            "e6d1a23a-da11-4be4-9570-befc86d067a7",
            "3a2c62db-5318-420d-8d74-23affee5d9d5",
            "44367163-eba1-44c3-98af-f5787879f96a",
            "11648597-926c-4cf3-9c36-bcebb0ba8dcc"
          ],
          "includeUsers": []
        }
      },
      "createdDateTime": "2026-04-10T19:26:21.4663612Z",
      "deletedDateTime": null,
      "displayName": "Baseline Security Mode: Require phishing-resistant multifactor authentication for admins",
      "grantControls": {
        "authenticationStrength": {
          "allowedCombinations": [
            "windowsHelloForBusiness",
            "fido2",
            "x509CertificateMultiFactor"
          ],
          "combinationConfigurations": [],
          "combinationConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('15ce9e54-75ab-49ad-ac41-76e0576fd777')/grantControls/authenticationStrength/combinationConfigurations",
          "createdDateTime": "2021-12-01T08:00:00Z",
          "description": "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
          "displayName": "Phishing-resistant MFA",
          "id": "00000000-0000-0000-0000-000000000004",
          "modifiedDateTime": "2021-12-01T08:00:00Z",
          "policyType": "builtIn",
          "requirementsSatisfied": "mfa"
        },
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('15ce9e54-75ab-49ad-ac41-76e0576fd777')/grantControls/authenticationStrength/$entity",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "15ce9e54-75ab-49ad-ac41-76e0576fd777",
      "modifiedDateTime": "2026-07-20T15:49:27.0652603Z",
      "sessionControls": null,
      "state": "disabled",
      "templateId": "4200930c-0da2-4e33-ca01-300000000011"
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
      "modifiedDateTime": "2026-07-20T15:49:22.3505172Z",
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
            "Office365"
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
        "insiderRiskLevels": "elevated",
        "locations": null,
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [],
          "excludeGuestsOrExternalUsers": {
            "externalTenants": {
              "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
              "membershipKind": "all"
            },
            "guestOrExternalUserTypes": "b2bDirectConnectUser,otherExternalUser,serviceProvider"
          },
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
      "createdDateTime": "2026-07-14T22:00:52.1349687Z",
      "deletedDateTime": null,
      "displayName": "Block access to Office Apps for users with Insider Risk (Preview)",
      "grantControls": {
        "authenticationStrength": null,
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('a6df9f3e-7215-497e-960a-e41a8cb6bdcd')/grantControls/authenticationStrength/$entity",
        "builtInControls": [
          "block"
        ],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "a6df9f3e-7215-497e-960a-e41a8cb6bdcd",
      "modifiedDateTime": "2026-07-20T15:49:28.028334Z",
      "sessionControls": null,
      "state": "enabledForReportingButNotEnforced",
      "templateId": "16aaa400-bfdf-4756-a420-ad2245d4cde8"
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
          "excludeLocations": [
            "15a23082-f571-45d9-bc6a-e092c282bf68",
            "07703061-c278-49cb-ad4d-caf29f8276dc"
          ],
          "includeLocations": [
            "All"
          ]
        },
        "platforms": null,
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [
            "5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"
          ],
          "excludeGuestsOrExternalUsers": {
            "externalTenants": {
              "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
              "membershipKind": "all"
            },
            "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
          },
          "excludeRoles": [],
          "excludeUsers": [
            "61851b42-fef7-4b43-ae43-4e335a60b306"
          ],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2026-07-19T16:33:03.1488208Z",
      "deletedDateTime": null,
      "displayName": "Extra scrutiny outside the UK",
      "grantControls": {
        "authenticationStrength": {
          "allowedCombinations": [
            "windowsHelloForBusiness",
            "fido2",
            "x509CertificateMultiFactor"
          ],
          "combinationConfigurations": [],
          "combinationConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('fe0958ad-29f7-4162-bb54-d37398fbdaef')/grantControls/authenticationStrength/combinationConfigurations",
          "createdDateTime": "2021-12-01T08:00:00Z",
          "description": "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key",
          "displayName": "Phishing-resistant MFA",
          "id": "00000000-0000-0000-0000-000000000004",
          "modifiedDateTime": "2021-12-01T08:00:00Z",
          "policyType": "builtIn",
          "requirementsSatisfied": "mfa"
        },
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('fe0958ad-29f7-4162-bb54-d37398fbdaef')/grantControls/authenticationStrength/$entity",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "fe0958ad-29f7-4162-bb54-d37398fbdaef",
      "modifiedDateTime": "2026-07-20T15:49:32.9913071Z",
      "sessionControls": {
        "applicationEnforcedRestrictions": null,
        "cloudAppSecurity": null,
        "disableResilienceDefaults": null,
        "persistentBrowser": null,
        "secureSignInSession": null,
        "signInFrequency": {
          "authenticationType": "primaryAndSecondaryAuthentication",
          "frequencyInterval": "everyTime",
          "isEnabled": true,
          "type": null,
          "value": null
        }
      },
      "state": "enabled",
      "templateId": null
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
        "signInRiskLevels": [
          "high"
        ],
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
      "createdDateTime": "2025-10-05T16:21:50.6941696Z",
      "deletedDateTime": null,
      "displayName": "Require multifactor authentication for risky sign-ins",
      "grantControls": {
        "authenticationStrength": {
          "allowedCombinations": [
            "windowsHelloForBusiness",
            "fido2",
            "x509CertificateMultiFactor",
            "deviceBasedPush"
          ],
          "combinationConfigurations": [],
          "combinationConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('b9418d00-e2af-4e02-a972-dbac104c6319')/grantControls/authenticationStrength/combinationConfigurations",
          "createdDateTime": "2021-12-01T08:00:00Z",
          "description": "Passwordless methods that satisfy strong authentication, such as Passwordless sign-in with the Microsoft Authenticator",
          "displayName": "Passwordless MFA",
          "id": "00000000-0000-0000-0000-000000000003",
          "modifiedDateTime": "2021-12-01T08:00:00Z",
          "policyType": "builtIn",
          "requirementsSatisfied": "mfa"
        },
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('b9418d00-e2af-4e02-a972-dbac104c6319')/grantControls/authenticationStrength/$entity",
        "builtInControls": [],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "b9418d00-e2af-4e02-a972-dbac104c6319",
      "modifiedDateTime": "2026-07-21T08:38:49.5382787Z",
      "sessionControls": {
        "applicationEnforcedRestrictions": null,
        "cloudAppSecurity": null,
        "disableResilienceDefaults": null,
        "persistentBrowser": null,
        "secureSignInSession": null,
        "signInFrequency": {
          "authenticationType": "primaryAndSecondaryAuthentication",
          "frequencyInterval": "everyTime",
          "isEnabled": true,
          "type": null,
          "value": null
        }
      },
      "state": "enabled",
      "templateId": "6b619f55-792e-45dc-9711-d83ec9d7ae90"
    }
  ]
}`

// twinFixture pairs twinPolicies with the (redacted) liveNamedLocations —
// used by the log-twin-focused tests below, distinct from fullFixture's
// livePolicies which the older aggregate-gauge tests are pinned against.
func twinFixture() map[string]string {
	return map[string]string{
		policiesURL:  twinPolicies,
		locationsURL: liveNamedLocations,
	}
}

// TestCollectEmitsPolicyCountsByState drives the live policy catalog end-to-end.
// Every live policy is "enabled", so the aggregate is enabled=5 with the
// disabled and report-only buckets zero-filled at 0.
func TestCollectEmitsPolicyCountsByState(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
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

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
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

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
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

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
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

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
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

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
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

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
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

// --- wire-assumption watchdog (#233/#234) --------------------------------
//
// Both of this collector's fields are METRIC LABELS, and both go further than
// the usual "unknown" bucket: an unrecognized value is SKIPPED, so the location
// or policy vanishes from the total. A new Microsoft subtype therefore does not
// move a series, it quietly makes one smaller — the hardest kind of wrong to
// spot, because a count that shrinks looks like a tenant that changed.

func findings(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		out[p.Attrs[semconv.AttrKind]+"/"+p.Attrs[semconv.AttrField]] += p.Value
	}
	return out
}

// The verbatim live capture is the steady state. A watchdog that fires on it is
// worse than no watchdog at all.
func TestLiveCaptureReportsNothingUnexpected(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := findings(rec); len(got) != 0 {
		t.Errorf("live capture produced findings %v, want none", got)
	}
}

// TestUnrecognizedValuesAreReportedAndStillSkipped pins both halves at once:
// the surprise is announced, and the pre-existing skip behavior is untouched.
// Report-only means report-only — a finding must never change a count, and the
// counts asserted here are exactly the ones
// TestCollectSkipsUnrecognizedPolicyStateAndLocationType already pins.
func TestUnrecognizedValuesAreReportedAndStillSkipped(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		policiesURL: policiesPage(`
			{"id":"p1","state":"enabled"},
			{"id":"p2","state":"someFutureState"}
		`),
		locationsURL: locationsPage(`
			{"@odata.type":"#microsoft.graph.ipNamedLocation","id":"l1","isTrusted":true},
			{"@odata.type":"#microsoft.graph.someFutureLocationType","id":"l2"}
		`),
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := findings(rec)
	for _, field := range []string{semconv.AttrType, semconv.AttrState} {
		key := wirecheck.KindUnmappedValue + "/" + field
		if got[key] != 1 {
			t.Errorf("findings[%s] = %v, want 1; all=%v", key, got[key], got)
		}
	}

	var policies, locations float64
	for _, p := range rec.MetricPoints(policiesMetricName) {
		policies += p.Value
	}
	for _, p := range rec.MetricPoints(namedLocationsMetricName) {
		locations += p.Value
	}
	if policies != 1 {
		t.Errorf("policy total = %v, want 1 — reporting must not change the count", policies)
	}
	if locations != 1 {
		t.Errorf("named location total = %v, want 1 — reporting must not change the count", locations)
	}
	// Both metrics still emit their full zero-filled series set: a surprise must
	// not cost a fetch or collapse the bounded dimension.
	if n := len(rec.MetricPoints(namedLocationsMetricName)); n != 4 {
		t.Errorf("named location series = %d, want 4 (zero-fill intact)", n)
	}
}

// TestWatchedSetsComeFromTheCollectorsOwnMappings is the anti-drift guard: both
// Enums must be DERIVED from the very tables the collector maps on, never a
// hand-restated list that can fall out of step with them (#234). Evidence for
// the members is this package's own constants — not Microsoft's documentation.
func TestWatchedSetsComeFromTheCollectorsOwnMappings(t *testing.T) {
	for _, odataType := range []string{odataTypeIPNamedLocation, odataTypeCountryNamedLocation} {
		if !knownNamedLocationTypes.Has(odataType) {
			t.Errorf("knownNamedLocationTypes is missing %q, a subtype this collector maps", odataType)
		}
		if _, ok := namedLocationType(odataType); !ok {
			t.Errorf("namedLocationType(%q) does not map — the watched set and the mapped set have diverged", odataType)
		}
	}
	if n := len(knownNamedLocationTypes); n != len(namedLocationTypes) {
		t.Errorf("knownNamedLocationTypes has %d members, namedLocationTypes maps %d — it must be derived, not restated", n, len(namedLocationTypes))
	}
	if n := len(knownPolicyStates); n != len(policyStates) {
		t.Errorf("knownPolicyStates has %d members, policyStates maps %d — it must be derived, not restated", n, len(policyStates))
	}
	for _, ps := range policyStates {
		if !knownPolicyStates.Has(ps.graphValue) {
			t.Errorf("knownPolicyStates is missing %q, a state this collector maps", ps.graphValue)
		}
	}
}

// --- log twins (#318) -----------------------------------------------------
//
// One entra.conditional_access_policy record per returned policy and one
// entra.named_location record per returned named location, ADDED alongside
// the aggregate gauges above (which stay exactly as they are — see the
// wire-assumption tests further up, all still passing against livePolicies/
// liveNamedLocations unchanged). Binding terms per #318: typed fixed
// attributes and arrays, no per-target/per-condition child record, and the
// absent-field-is-not-a-sentinel rule preserved for is_trusted.

// unmarshalPolicy is a small test helper: decode one policiesPage-shaped raw
// JSON object into the package's own conditionalAccessPolicy struct, so the
// mapper functions below can be driven directly without going through
// Collect()/fakeGraph for every case.
func unmarshalPolicy(t *testing.T, raw string) conditionalAccessPolicy {
	t.Helper()
	var p conditionalAccessPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal policy fixture: %v", err)
	}
	return p
}

func unmarshalLocation(t *testing.T, raw string) namedLocation {
	t.Helper()
	var l namedLocation
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		t.Fatalf("unmarshal location fixture: %v", err)
	}
	return l
}

// TestPolicyLogTwinEmitsTypedFixedAttributes pins the core scalar mapping —
// id/display_name/state/created_date_time/last_modified_date_time/
// template_id, plus the grantControls-present case (operator, builtInControls
// array, authentication_strength_display_name) — against the "Require
// multifactor authentication for Microsoft admin portals" live fixture
// policy.
func TestPolicyLogTwinEmitsTypedFixedAttributes(t *testing.T) {
	p := unmarshalPolicy(t, `{
		"id": "d7195984-2fae-403d-abec-a7ccc55bf861",
		"displayName": "Require multifactor authentication for Microsoft admin portals",
		"state": "enabled",
		"createdDateTime": "2025-09-24T13:37:16.7413549Z",
		"modifiedDateTime": "2026-07-20T15:49:22.3505172Z",
		"templateId": "6364131e-bc4a-47c4-a20b-33492d1fff6c",
		"grantControls": {
			"operator": "OR",
			"builtInControls": [],
			"authenticationStrength": {"displayName": "Multifactor authentication"}
		},
		"sessionControls": null
	}`)

	ev := policyLogEvent(p)

	want := map[string]any{
		semconv.AttrId:                                "d7195984-2fae-403d-abec-a7ccc55bf861",
		semconv.AttrDisplayName:                       "Require multifactor authentication for Microsoft admin portals",
		semconv.AttrState:                             "enabled",
		semconv.AttrCreatedDateTime:                   "2025-09-24T13:37:16.7413549Z",
		semconv.AttrLastModifiedDateTime:              "2026-07-20T15:49:22.3505172Z",
		semconv.AttrTemplateId:                        "6364131e-bc4a-47c4-a20b-33492d1fff6c",
		semconv.AttrHasGrantControls:                  true,
		semconv.AttrGrantControlsOperator:             "OR",
		semconv.AttrAuthenticationStrengthDisplayName: "Multifactor authentication",
		semconv.AttrHasSessionControls:                false,
	}
	for k, v := range want {
		got, ok := ev.Attrs[k]
		if !ok {
			t.Errorf("attrs[%q] absent, want %#v", k, v)
			continue
		}
		if got != v {
			t.Errorf("attrs[%q] = %#v, want %#v", k, got, v)
		}
	}
	// builtInControls is an empty array on the wire here, so it must be
	// OMITTED, not emitted as an empty slice.
	if v, ok := ev.Attrs[semconv.AttrBuiltInControls]; ok {
		t.Errorf("attrs[built_in_controls] = %#v present, want omitted for an empty builtInControls array", v)
	}
	if ev.Name != eventPolicy {
		t.Errorf("Name = %q, want %q", ev.Name, eventPolicy)
	}
}

// TestPolicyLogTwinNullGrantControlsReadsFalseNotZeroValue pins the exact
// trap #318's decision comment calls out for grantControls: a null
// grantControls must set has_grant_controls=false and omit
// grant_controls_operator/built_in_controls/authentication_strength_display_name
// entirely — never decode to a zero-value struct that looks like "operator
// is empty string" instead of "there is no grantControls at all".
func TestPolicyLogTwinNullGrantControlsReadsFalseNotZeroValue(t *testing.T) {
	p := unmarshalPolicy(t, `{
		"id": "3fa9321f-1213-47c8-87be-eeb71bb4e6fc",
		"displayName": "Reduced reauth frequency at home",
		"state": "enabled",
		"grantControls": null,
		"sessionControls": {"persistentBrowser": {"isEnabled": true, "mode": "always"}}
	}`)

	ev := policyLogEvent(p)

	if got, ok := ev.Attrs[semconv.AttrHasGrantControls]; !ok || got != false {
		t.Errorf("has_grant_controls = %#v (ok=%v), want false", got, ok)
	}
	for _, k := range []string{semconv.AttrGrantControlsOperator, semconv.AttrBuiltInControls, semconv.AttrAuthenticationStrengthDisplayName} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("attrs[%q] = %#v present, want omitted when grantControls is null", k, v)
		}
	}
	if got, ok := ev.Attrs[semconv.AttrHasSessionControls]; !ok || got != true {
		t.Errorf("has_session_controls = %#v (ok=%v), want true for a present sessionControls object", got, ok)
	}
}

// TestPolicyLogTwinPreservesTargetArraysNoChildRecords pins the maintainer's
// approved schema: conditions.users' six target-id arrays and
// conditions.locations' two arrays land as typed array ATTRIBUTES on the one
// policy record — never a per-target child record (the rejected normalised
// alternative, #318).
func TestPolicyLogTwinPreservesTargetArraysNoChildRecords(t *testing.T) {
	p := unmarshalPolicy(t, `{
		"id": "fe0958ad-29f7-4162-bb54-d37398fbdaef",
		"displayName": "Extra scrutiny outside the UK",
		"state": "enabled",
		"conditions": {
			"clientAppTypes": ["all"],
			"signInRiskLevels": ["high"],
			"users": {
				"includeUsers": ["All"],
				"excludeUsers": ["61851b42-fef7-4b43-ae43-4e335a60b306"],
				"includeGroups": [],
				"excludeGroups": ["5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"],
				"includeRoles": [],
				"excludeRoles": []
			},
			"locations": {
				"includeLocations": ["All"],
				"excludeLocations": ["15a23082-f571-45d9-bc6a-e092c282bf68", "07703061-c278-49cb-ad4d-caf29f8276dc"]
			}
		}
	}`)

	ev := policyLogEvent(p)

	assertStrs := func(key string, want []string) {
		t.Helper()
		got, ok := ev.Attrs[key].([]string)
		if !ok {
			t.Errorf("attrs[%q] = %#v, want []string", key, ev.Attrs[key])
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("attrs[%q] = %v, want %v", key, got, want)
		}
	}
	assertStrs(semconv.AttrClientAppTypes, []string{"all"})
	assertStrs(semconv.AttrSignInRiskLevels, []string{"high"})
	assertStrs(semconv.AttrIncludeUsers, []string{"All"})
	assertStrs(semconv.AttrExcludeUsers, []string{"61851b42-fef7-4b43-ae43-4e335a60b306"})
	assertStrs(semconv.AttrExcludeGroups, []string{"5ecf8b5f-0d08-4792-aa17-37e40f64b6bb"})
	assertStrs(semconv.AttrIncludeLocations, []string{"All"})
	assertStrs(semconv.AttrExcludeLocations, []string{"15a23082-f571-45d9-bc6a-e092c282bf68", "07703061-c278-49cb-ad4d-caf29f8276dc"})

	// includeGroups/includeRoles/excludeRoles/userRiskLevels are empty on the
	// wire here — omitted, not empty-array attributes.
	for _, k := range []string{semconv.AttrIncludeGroups, semconv.AttrIncludeRoles, semconv.AttrExcludeRoles, semconv.AttrUserRiskLevels} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("attrs[%q] = %#v present, want omitted for an empty array", k, v)
		}
	}
}

// TestPolicyLogTwinCapsArraysAndRecordsTruncation is synthetic (no real
// tenant policy here has 51+ entries in one target array) and proves the
// bound itself: an array over maxArrayAttr is capped to maxArrayAttr entries
// and arrays_truncated is set true. A policy whose arrays all stay within the
// bound (the live twinPolicies fixture) must never see arrays_truncated at
// all — pinned by TestCollectEmitsPolicyLogTwinsPerPolicy below.
func TestPolicyLogTwinCapsArraysAndRecordsTruncation(t *testing.T) {
	ids := make([]string, maxArrayAttr+5)
	for i := range ids {
		ids[i] = "11111111-1111-1111-1111-" + strconvPad(i)
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		t.Fatalf("marshal synthetic ids: %v", err)
	}
	p := unmarshalPolicy(t, `{
		"id": "synthetic",
		"state": "enabled",
		"conditions": {"users": {"includeUsers": `+string(idsJSON)+`}}
	}`)

	ev := policyLogEvent(p)

	got, ok := ev.Attrs[semconv.AttrIncludeUsers].([]string)
	if !ok {
		t.Fatalf("attrs[include_users] = %#v, want []string", ev.Attrs[semconv.AttrIncludeUsers])
	}
	if len(got) != maxArrayAttr {
		t.Errorf("len(include_users) = %d, want capped to %d", len(got), maxArrayAttr)
	}
	if !reflect.DeepEqual(got, ids[:maxArrayAttr]) {
		t.Error("include_users did not keep the first maxArrayAttr entries in order")
	}
	if v, ok := ev.Attrs[semconv.AttrArraysTruncated]; !ok || v != true {
		t.Errorf("arrays_truncated = %#v (ok=%v), want true", v, ok)
	}
}

// strconvPad zero-pads i to 12 hex-ish digits so each synthetic id in
// TestPolicyLogTwinCapsArraysAndRecordsTruncation is distinct and orderable.
func strconvPad(i int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 12)
	for pos := 11; pos >= 0; pos-- {
		b[pos] = digits[i%16]
		i /= 16
	}
	return string(b)
}

// TestNamedLocationLogTwinCountryOmitsIsTrusted is the load-bearing test named
// in #318's brief: a countryNamedLocation's twin must NEVER carry an
// is_trusted attribute at all, because the wire never carried the key — not
// even is_trusted=false. The aggregate gauge is allowed to keep collapsing
// the absence to false (see namedLocationPoints); the twin is not. This test
// fails loudly if that collapse ever leaks into the twin.
func TestNamedLocationLogTwinCountryOmitsIsTrusted(t *testing.T) {
	l := unmarshalLocation(t, `{
		"@odata.type": "#microsoft.graph.countryNamedLocation",
		"id": "15a23082-f571-45d9-bc6a-e092c282bf68",
		"displayName": "UK",
		"countriesAndRegions": ["GB"],
		"countryLookupMethod": "clientIpAddress",
		"includeUnknownCountriesAndRegions": false
	}`)

	ev := namedLocationLogEvent(l, "country")

	if v, ok := ev.Attrs[semconv.AttrIsTrusted]; ok {
		t.Fatalf("attrs[is_trusted] = %#v present, want ABSENT for a countryNamedLocation — the wire never carried the key, so the twin must never claim it returned false", v)
	}
	// includeUnknownCountriesAndRegions:false IS on the wire for this
	// subtype, so — unlike is_trusted — it must be emitted as the real bool
	// false, not omitted (that would be the same sentinel mistake in reverse).
	if v, ok := ev.Attrs[semconv.AttrIncludeUnknownCountriesAndRegions]; !ok || v != false {
		t.Errorf("include_unknown_countries_and_regions = %#v (ok=%v), want false (present)", v, ok)
	}
	if got := ev.Attrs[semconv.AttrCountries]; !reflect.DeepEqual(got, []string{"GB"}) {
		t.Errorf("countries = %#v, want [GB]", got)
	}
	if got := ev.Attrs[semconv.AttrCountryLookupMethod]; got != "clientIpAddress" {
		t.Errorf("country_lookup_method = %#v, want clientIpAddress", got)
	}
	// A country location has no ipRanges at all — both CIDR arrays must be
	// absent, not empty.
	for _, k := range []string{semconv.AttrIPv4CidrRanges, semconv.AttrIPv6CidrRanges} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("attrs[%q] = %#v present on a countryNamedLocation twin, want absent", k, v)
		}
	}
}

// TestNamedLocationLogTwinIPCarriesIsTrustedAndBothDiscriminators pins the
// other half of the trap: an ipNamedLocation DOES carry isTrusted (must be
// emitted, true or false, never omitted), and both @odata.type CIDR
// discriminators must survive into two separately typed arrays — telling a
// v4 range from a v6 range is part of the signal (#318).
func TestNamedLocationLogTwinIPCarriesIsTrustedAndBothDiscriminators(t *testing.T) {
	l := unmarshalLocation(t, `{
		"@odata.type": "#microsoft.graph.ipNamedLocation",
		"id": "07703061-c278-49cb-ad4d-caf29f8276dc",
		"displayName": "Home",
		"isTrusted": true,
		"ipRanges": [
			{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "51.148.203.77/32"},
			{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "91.125.14.6/32"},
			{"@odata.type": "#microsoft.graph.iPv6CidrRange", "cidrAddress": "2a02:8010:6::/48"}
		]
	}`)

	ev := namedLocationLogEvent(l, "ip")

	if v, ok := ev.Attrs[semconv.AttrIsTrusted]; !ok || v != true {
		t.Errorf("is_trusted = %#v (ok=%v), want true (present) for an ipNamedLocation", v, ok)
	}
	v4, ok := ev.Attrs[semconv.AttrIPv4CidrRanges].([]string)
	if !ok || !reflect.DeepEqual(v4, []string{"51.148.203.77/32", "91.125.14.6/32"}) {
		t.Errorf("ipv4_cidr_ranges = %#v, want [51.148.203.77/32 91.125.14.6/32]", ev.Attrs[semconv.AttrIPv4CidrRanges])
	}
	v6, ok := ev.Attrs[semconv.AttrIPv6CidrRanges].([]string)
	if !ok || !reflect.DeepEqual(v6, []string{"2a02:8010:6::/48"}) {
		t.Errorf("ipv6_cidr_ranges = %#v, want [2a02:8010:6::/48]", ev.Attrs[semconv.AttrIPv6CidrRanges])
	}
	// An ipNamedLocation has no country fields at all.
	for _, k := range []string{semconv.AttrCountries, semconv.AttrCountryLookupMethod, semconv.AttrIncludeUnknownCountriesAndRegions} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("attrs[%q] = %#v present on an ipNamedLocation twin, want absent", k, v)
		}
	}
}

// TestNamedLocationLogTwinIsTrustedFalseIsEmittedNotOmitted is the mirror
// case of the absent-field rule: an ipNamedLocation with isTrusted:false is a
// real configured fact ("this location is explicitly untrusted"), not an
// absence — it must be emitted as false, exactly like risk's is_processing.
func TestNamedLocationLogTwinIsTrustedFalseIsEmittedNotOmitted(t *testing.T) {
	l := unmarshalLocation(t, `{
		"@odata.type": "#microsoft.graph.ipNamedLocation",
		"id": "loc2",
		"isTrusted": false
	}`)

	ev := namedLocationLogEvent(l, "ip")

	v, ok := ev.Attrs[semconv.AttrIsTrusted]
	if !ok {
		t.Fatalf("is_trusted absent, want the bool false present")
	}
	if v != false {
		t.Errorf("is_trusted = %#v, want the bool false (not a string, not omitted)", v)
	}
}

// TestCollectEmitsPolicyLogTwinsPerPolicy drives Collect() end-to-end against
// twinPolicies (7 real policies) and pins: one entra.conditional_access_policy
// record per returned policy (regardless of state — including the
// unrecognized-state skip path, which still must not skip the twin), the
// EventName, and that no live policy in this fixture ever trips
// arrays_truncated (all its arrays are comfortably under maxArrayAttr).
func TestCollectEmitsPolicyLogTwinsPerPolicy(t *testing.T) {
	g := &fakeGraph{bodies: twinFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var policyRecords []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			policyRecords = append(policyRecords, r)
		}
	}
	if len(policyRecords) != 7 {
		t.Fatalf("got %d %s records, want 7 (one per returned policy)", len(policyRecords), eventPolicy)
	}
	for _, r := range policyRecords {
		if r.Attrs["id"] == "" {
			t.Errorf("record missing id: %+v", r)
		}
		if v, ok := r.Attrs[semconv.AttrArraysTruncated]; ok {
			t.Errorf("policy %s: arrays_truncated = %q present, want absent — no live fixture policy has an array over maxArrayAttr", r.Attrs["id"], v)
		}
	}
}

// TestCollectEmitsNamedLocationLogTwinsPerLocation is the named-location
// counterpart: one entra.named_location record per returned location, and the
// two live fixture locations preserve the is_trusted trap end-to-end (not
// just through the direct-mapper tests above).
func TestCollectEmitsNamedLocationLogTwinsPerLocation(t *testing.T) {
	g := &fakeGraph{bodies: fullFixture()}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventNamedLocation {
			byID[r.Attrs["id"]] = r
		}
	}
	if len(byID) != 2 {
		t.Fatalf("got %d %s records, want 2 (one per returned location)", len(byID), eventNamedLocation)
	}

	home := byID["07703061-c278-49cb-ad4d-caf29f8276dc"]
	if home.Attrs["is_trusted"] != "true" {
		t.Errorf("Home is_trusted = %q, want \"true\"", home.Attrs["is_trusted"])
	}
	if home.Attrs["ipv4_cidr_ranges"] != "51.148.203.77/32,91.125.14.6/32" {
		t.Errorf("Home ipv4_cidr_ranges = %q, want the two redacted-but-realistic v4 ranges", home.Attrs["ipv4_cidr_ranges"])
	}
	if home.Attrs["ipv6_cidr_ranges"] != "2a02:8010:6::/48" {
		t.Errorf("Home ipv6_cidr_ranges = %q, want the redacted-but-realistic v6 range", home.Attrs["ipv6_cidr_ranges"])
	}

	uk := byID["15a23082-f571-45d9-bc6a-e092c282bf68"]
	if _, ok := uk.Attrs["is_trusted"]; ok {
		t.Errorf("UK (country) is_trusted = %q present via the flattened recorder, want absent", uk.Attrs["is_trusted"])
	}
	if uk.Attrs["countries"] != "GB" {
		t.Errorf("UK countries = %q, want GB", uk.Attrs["countries"])
	}
}
