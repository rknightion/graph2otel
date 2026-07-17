package securescore

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors). It
// satisfies collectors.GraphClient without any live Graph call.
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

const base = "https://graph.microsoft.com/v1.0"

const scoreURL = base + "/security/secureScores?$top=1"
const profilesURL = base + "/security/secureScoreControlProfiles"

// profilesNextURL is the @odata.nextLink liveProfiles carries: the live control
// profile catalog is paginated (200+ entries live), and collectControlProfiles
// walks it via collectors.GetAllValues. The live end-to-end test stubs this
// continuation with an empty page so the one captured page is the whole set.
const profilesNextURL = base + "/security/secureScoreControlProfiles?$skiptoken=aa04d74d-ee0a-4724-a3df-7e74f7015e4b"

// liveScores is a VERBATIM GET /security/secureScores?$top=1 response from the
// m7kni tenant, read as graph2otel-poller `[live-measured 2026-07-17, #165]`.
// The single retained score for the day: currentScore 815.22 of maxScore 1376.
// Its controlScores array (232 entries live) is trimmed to the first 5, verbatim
// — the collector never reads controlScores (only currentScore/maxScore), so the
// trim keeps the fixture a faithful record of the wire shape without its bulk.
// This is the shape authority for a secureScore; twoScores below is a synthetic
// two-entry fixture kept ONLY to prove the collector emits the latest, not the
// full retained series, which a one-record live capture cannot exercise.
const liveScores = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/secureScores",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/secureScores?$top=1&$skiptoken=1b9f0b81-f058-4008-a985-2daf2e5eca5a",
  "value": [
    {
      "activeUserCount": 3,
      "averageComparativeScores": [
        {
          "appsScore": 45.81,
          "appsScoreMax": 120.83,
          "averageScore": 52.86,
          "basis": "AllTenants",
          "dataScore": 0.37,
          "dataScoreMax": 5.15,
          "deviceScore": 20.67,
          "deviceScoreMax": 35.04,
          "identityScore": 41.21,
          "identityScoreMax": 61.88,
          "infrastructureScore": 0.0,
          "infrastructureScoreMax": 0.0
        },
        {
          "SeatSizeRangeLowerValue": "1",
          "SeatSizeRangeUpperValue": "100",
          "appsScore": 53.64,
          "appsScoreMax": 146.11,
          "averageScore": 48.1,
          "basis": "TotalSeats",
          "dataScore": 0.36,
          "dataScoreMax": 6.26,
          "deviceScore": 16.59,
          "deviceScoreMax": 28.5,
          "identityScore": 40.39,
          "identityScoreMax": 61.22,
          "infrastructureScore": 0.0,
          "infrastructureScoreMax": 0.0
        }
      ],
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "controlScores": [
        {
          "controlCategory": "Identity",
          "controlName": "IntegratedApps",
          "description": "To reduce the risk of malicious applications attempting to trick users into granting them access to your organization's data, we recommend that you allow user consent only for applications that have been published by a verified publisher.",
          "implementationStatus": "You have a user consent policy in place.",
          "lastSynced": "2026-07-15T13:04:06Z",
          "on": "true",
          "score": 4.0,
          "scoreInPercentage": 100.0
        },
        {
          "controlCategory": "Identity",
          "controlName": "PWAgePolicyNew",
          "description": "Research has found that when periodic password resets are enforced, passwords become less secure. Users tend to pick a weaker password and vary it slightly for each reset. If a user creates a strong password (long, complex and without any pragmatic words present) it should remain just as strong in the future as it is today. It is Microsoft's official security position to not expire passwords periodically without a specific reason, and recommends that cloud-only tenants set the password policy to never expire.",
          "implementationStatus": "Your current policy is set to never let passwords expire.",
          "lastSynced": "2026-07-15T13:04:06Z",
          "score": 8.0,
          "scoreInPercentage": 100.0
        },
        {
          "controlCategory": "Identity",
          "controlName": "SelfServicePasswordReset",
          "count": "4",
          "description": "With self-service password reset in Microsoft Entra ID, users no longer need to engage help desk to reset passwords. This feature works well with Microsoft Entra ID dynamically banned passwords, which prevents easily guessable passwords from being used.",
          "implementationStatus": "You have 0 of 4 users who don't have self-service password reset enabled.",
          "lastSynced": "2026-07-15T13:04:06Z",
          "score": 1.0,
          "scoreInPercentage": 100.0,
          "total": "4"
        },
        {
          "controlCategory": "Identity",
          "controlName": "BlockLegacyAuthentication",
          "count": "1",
          "description": "Today, most compromising sign-in attempts come from legacy authentication. Older office clients such as Office 2010 don’t support modern authentication and use legacy protocols such as IMAP, SMTP, and POP3. Legacy authentication does not support multifactor authentication (MFA). Even if an MFA policy is configured in your environment, bad actors can bypass these enforcements through legacy protocols.",
          "implementationStatus": "You have 0 of 1 users that don't have legacy authentication blocked.",
          "lastSynced": "2026-07-15T13:04:06Z",
          "score": 8.0,
          "scoreInPercentage": 100.0,
          "total": "1"
        },
        {
          "controlCategory": "Identity",
          "controlName": "MFARegistrationV2",
          "count": "3",
          "description": "Multifactor authentication (MFA) helps protect devices and data that are accessible to these users. Adding more authentication methods, such as the Microsoft Authenticator app or a phone number, increases the level of protection if one factor is compromised.",
          "implementationStatus": "You have 0 out of 3 users that aren’t registered with MFA.",
          "lastSynced": "2026-07-15T13:04:06Z",
          "score": 9.0,
          "scoreInPercentage": 100.0,
          "total": "3"
        }
      ],
      "createdDateTime": "2026-07-17T00:00:00Z",
      "currentScore": 815.22,
      "enabledServices": [
        "HasAADP1",
        "HasAADP2",
        "HasOCAS",
        "HasMCAS",
        "HasAATP",
        "HasCLB",
        "HasMDOP1",
        "HasMDOP2",
        "HasEXOP2",
        "HasAIPP1",
        "HasAIPP2",
        "HasM365E5",
        "HasMDEP2",
        "HasSPOP2"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_2026-07-17",
      "licensedUserCount": 0,
      "maxScore": 1376.0,
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    }
  ]
}`

// liveProfiles is a VERBATIM GET /security/secureScoreControlProfiles response
// (first page) from the m7kni tenant `[live-measured 2026-07-17, #165]`. Every live profile on this tenant
// is controlCategory "Identity" with a single controlStateUpdates entry in
// state "Default" and a null updatedDateTime — so the live aggregate is category
// identity=5, status default=5. The synthetic mixedProfiles below is retained
// alongside it precisely because the live tenant exhibits no category/state
// variety: it exercises the Data category, the latest-by-time state selection,
// and the unknown-value collapse that the live data cannot. Note updatedDateTime
// is null on the wire — time.Time decodes null to the zero value, which
// latestState handles.
const liveProfiles = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/secureScoreControlProfiles",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$skiptoken=aa04d74d-ee0a-4724-a3df-7e74f7015e4b",
  "value": [
    {
      "actionType": "Config",
      "actionUrl": "https://support.google.com/a/answer/175197?hl=en&fl=1&sjid=9841521343371348963-NA",
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "complianceInformation": [],
      "controlCategory": "Identity",
      "controlStateUpdates": [
        {
          "assignedTo": null,
          "comment": null,
          "state": "Default",
          "updatedBy": null,
          "updatedDateTime": null
        }
      ],
      "deprecated": false,
      "id": "11770.MDA_Google_EnableTwoFactorAuth",
      "implementationCost": "Unknown",
      "lastModifiedDateTime": null,
      "maxScore": 7.0,
      "rank": 10,
      "remediation": "<p>Ensure password expiry <em>policy</em> for Google -</p> <ol> <li>Navigate to <em>Google admin center</em> - <a href=\"https://admin.google.com\">http://admin.google.com/</a></li> <li>Click <em>Security</em> &gt; <em>Password Management</em>.</li> <li>Chcek <em>Allow users to turn on 2-Step Verification</em>.</li> <li>Check&nbsp;<em>On</em> under&nbsp;<em>Enforcement</em>.</li> <li>Click <em>Save</em>.</li> </ol> <p>Follow steps 3-4 for every organizational unit.</p>",
      "remediationImpact": "<p>Follow the <a href=\"https://support.google.com/a/answer/9176657?fl=1&amp;sjid=9841521343371348963-NA\" target=\"_blank\">guideline</a>.</p>",
      "service": "MDA_Google",
      "threats": [
        "Account breach",
        "Data Exfiltration"
      ],
      "tier": "Core",
      "title": "Enable multi-factor authentication (MFA)",
      "userImpact": "Unknown",
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    },
    {
      "actionType": "Config",
      "actionUrl": "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide",
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "complianceInformation": [],
      "controlCategory": "Identity",
      "controlStateUpdates": [
        {
          "assignedTo": null,
          "comment": null,
          "state": "Default",
          "updatedBy": null,
          "updatedDateTime": null
        }
      ],
      "deprecated": false,
      "id": "aad_admin_accounts_separate_unassigned_cloud_only",
      "implementationCost": "Unknown",
      "lastModifiedDateTime": null,
      "maxScore": 3.0,
      "rank": 10,
      "remediation": " <p>1. Navigate to Microsoft 365 admin center <br />2. Click to expand Users select Active users.<br />3. Sort by the Licenses column.<br />4. For each user account in an administrative role verify the following:<br /> The account is Cloud only (not synced)<br /> The account is assigned a license that is not associated with applications i.e. (Microsoft Entra ID P1, Microsoft Entra ID P2)</p>",
      "remediationImpact": "Administrative users will have to switch accounts and utilizing login/logout functionality when performing Administrative tasks, as well as not benefiting from SSO.",
      "service": "AzureAD",
      "threats": [
        "Account breach"
      ],
      "tier": "Core",
      "title": "Ensure Administrative accounts are separate and cloud-only",
      "userImpact": "Unknown",
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    },
    {
      "actionType": "Config",
      "actionUrl": "https://aad.portal.azure.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings",
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "complianceInformation": [],
      "controlCategory": "Identity",
      "controlStateUpdates": [
        {
          "assignedTo": null,
          "comment": null,
          "state": "Default",
          "updatedBy": null,
          "updatedDateTime": null
        }
      ],
      "deprecated": false,
      "id": "aad_admin_consent_workflow",
      "implementationCost": "Unknown",
      "lastModifiedDateTime": null,
      "maxScore": 5.0,
      "rank": 10,
      "remediation": "<ol> <li>In the <em>Microsoft 365 Admin Center</em>, Select <em>Admin Centers,</em> and <em>Microsoft Entra ID</em>.</li> <li>Select <em>Enterprise applications </em>from the Azure Navigation pane.</li> <li>Under <em>Security </em>select <em>Consent and permissions</em>.</li> <li>Under <em>Manage</em> select <em>Admin consent settings and s</em>et <em>Users can request admin consent to apps they are unable to consent </em>to&nbsp;<em>Yes</em>.</li> <li>Under the <em>Reviewers </em>choose the Roles, Groups that you would like to review user generated app consent requests.</li> <li>Select <em>Save </em>at the top of the window.</li> </ol>",
      "remediationImpact": "None.",
      "service": "AzureAD",
      "threats": [
        "Data Exfiltration"
      ],
      "tier": "Core",
      "title": "Ensure the admin consent workflow is enabled",
      "userImpact": null,
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    },
    {
      "actionType": "Config",
      "actionUrl": "https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-configure-custom-password-protection",
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "complianceInformation": [],
      "controlCategory": "Identity",
      "controlStateUpdates": [
        {
          "assignedTo": null,
          "comment": null,
          "state": "Default",
          "updatedBy": null,
          "updatedDateTime": null
        }
      ],
      "deprecated": false,
      "id": "aad_custom_banned_passwords",
      "implementationCost": "Unknown",
      "lastModifiedDateTime": null,
      "maxScore": 5.0,
      "rank": 10,
      "remediation": "<p>Create a custom banned password list:</p> <ol> <li>Navigate to <em>Microsoft Entra ID admin center</em> <a href=\"https://entra.microsoft.com/\" target=\"_blank\">https://entra.microsoft.com/</a></li> <li>Click to expand <em>Microsoft Entra ID</em> &gt; <em>Protect &amp; Secure</em> &gt; <em>Authentication methods</em></li> <li>Select <em>Password protection</em></li> <li>Set <em>Enforce custom list</em> to <em>Yes</em></li> <li>In <em>Custom banned password list</em> create a list using suggestions outlined in this document.</li> <li>Click <em>Save</em></li> </ol> <p><strong>NOTE</strong>: Below is a list of examples that can be used as a starting place. Check the references section for more.</p> <ul> <li>Brand names</li> <li>Product names</li> <li>Locations, such as company headquarters</li> <li>Company-specific internal terms</li> <li>Abbreviations that have specific company meaning</li> </ul>",
      "remediationImpact": "<p>If a custom banned password list includes too many common dictionary words, or short words that are part of compound words, then perfectly secure passwords may be blocked. The organization should consider a balance between security and usability when creating a list.</p>",
      "service": "AzureAD",
      "threats": [
        "Data Exfiltration",
        "Password Cracking",
        "Account breach"
      ],
      "tier": "Core",
      "title": "Ensure custom banned passwords lists are used",
      "userImpact": "Unknown",
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    },
    {
      "actionType": "Config",
      "actionUrl": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-cloud-apps",
      "azureTenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
      "complianceInformation": [],
      "controlCategory": "Identity",
      "controlStateUpdates": [
        {
          "assignedTo": null,
          "comment": null,
          "state": "Default",
          "updatedBy": null,
          "updatedDateTime": null
        }
      ],
      "deprecated": false,
      "id": "aad_limited_administrative_roles",
      "implementationCost": "Unknown",
      "lastModifiedDateTime": null,
      "maxScore": 3.0,
      "rank": 10,
      "remediation": "<p><strong>To enable Microsoft Azure Management restrictions:</strong></p> <ol> <li>Navigate to the <strong>Microsoft Entra ID admin center</strong> <a href=\"https://entra.microsoft.com\">https://entra.microsoft.com</a>.</li> <li>Click expand <strong>Protection</strong> &gt; <strong>Conditional Access</strong> select <strong>Policies</strong>.</li> <li>Click <strong>New Policy</strong> and then name the policy.</li> <li>Select <strong>Users</strong> &gt; <strong>Include</strong> &gt; <strong>All Users</strong></li> <li>Select <strong>Users</strong> &gt; <strong>Exclude</strong> &gt; <strong>Directory roles</strong> and select only administrative roles (See below).</li> <li>Select <strong>Cloud apps or actions</strong> &gt; <strong>Select apps</strong> &gt; <strong>Select</strong> then click the box next to <strong>Windows Azure Service Management API</strong>.</li> <li>Click <strong>Select</strong>.</li> <li>Select <strong>Grant</strong> &gt; <strong>Block access</strong> and click <strong>Select</strong>.</li> <li>Ensure <strong>Enable Policy</strong> is <strong>On</strong> then click <strong>Create</strong>.</li> </ol> <p><strong>WARNING</strong>: <span style=\"color: #ff0000;\"><strong>Exclude Global Administrator at a minimum to avoid being locked out</strong></span>. Report-only is a good option to use when testing any Conditional Access policy for the first time.</p> <p><strong>Below is the list of administrative roles that can be excluded:</strong></p> <ul> <li>Application administrator</li> <li>Authentication administrator</li> <li>Billing administrator</li> <li>Cloud application administrator</li> <li>Conditional Access administrator</li> <li>Exchange administrator</li> <li>Global administrator</li> <li>Global reader</li> <li>Helpdesk administrator</li> <li>Password administrator</li> <li>Privileged authentication administrator</li> <li>Privileged role administrator</li> <li>Security administrator</li> <li>SharePoint administrator</li> <li>User administrator</li> </ul> <p><strong>Default Value</strong>:</p> <p>No - Non-administrators can access the Microsoft Entra ID administration portal.</p>",
      "remediationImpact": "<p>Because the policy is applied to the Azure management portal and API, services, or clients with an Azure API service dependency, can indirectly be impacted. For example:</p> <ul> <li>Classic deployment model APIs</li> <li>Azure PowerShell</li> <li>Azure CLI</li> <li>Azure DevOps</li> <li>Azure Data Factory portal</li> <li>Azure Event Hubs</li> <li>Azure Service Bus</li> <li>Azure SQL Database</li> <li>SQL Managed Instance</li> <li>Azure Synapse</li> <li>Visual Studio subscriptions administrator portal</li> <li>Microsoft IoT Central</li> </ul>",
      "service": "AzureAD",
      "threats": [
        "Data Exfiltration",
        "Account breach"
      ],
      "tier": "Core",
      "title": "Ensure 'Microsoft Azure Management' is limited to administrative roles",
      "userImpact": "Unknown",
      "vendorInformation": {
        "provider": "SecureScore",
        "providerVersion": null,
        "subProvider": null,
        "vendor": "Microsoft"
      }
    }
  ]
}`

const zeroMaxScore = `{
  "value": [
    {"currentScore": 0.0, "maxScore": 0.0}
  ]
}`

const emptyScores = `{"value": []}`

// twoScores is SYNTHETIC and deliberately has TWO entries in "value" to prove
// the collector only emits the latest (first) one, not the whole retained daily
// series. The live endpoint returns one score per request ($top=1), so this
// specific behavior cannot be pinned by liveScores; the shape authority for a
// real secureScore record is liveScores above.
const twoScores = `{
  "value": [
    {"currentScore": 387.0, "maxScore": 697.0},
    {"currentScore": 300.0, "maxScore": 700.0}
  ]
}`

// mixedProfiles is SYNTHETIC: it carries the category and state variety the live
// tenant lacks (see liveProfiles). The "SomeNewCategoryNotYetKnown" /
// "someBrandNewState" values deliberately exercise the unknown-value collapse,
// and the Data profile's two-entry controlStateUpdates exercises latest-by-time
// state selection. Kept alongside the live fixture, not replaced by it.
const mixedProfiles = `{
  "value": [
    {"controlCategory": "Identity", "controlStateUpdates": []},
    {"controlCategory": "Identity", "controlStateUpdates": [
      {"state": "reviewed", "updatedDateTime": "2026-01-01T00:00:00Z"}
    ]},
    {"controlCategory": "Data", "controlStateUpdates": [
      {"state": "ignored", "updatedDateTime": "2026-01-01T00:00:00Z"},
      {"state": "thirdParty", "updatedDateTime": "2026-02-01T00:00:00Z"}
    ]},
    {"controlCategory": "SomeNewCategoryNotYetKnown", "controlStateUpdates": [
      {"state": "someBrandNewState", "updatedDateTime": "2026-01-01T00:00:00Z"}
    ]}
  ]
}`

const emptyProfiles = `{"value": []}`

// TestCollectEmitsScoreGaugesFromLiveRecord drives the one real secureScore this
// project captured end-to-end through Collect into a Recorder, pinning the
// gauges against the live values (currentScore 815.22 of maxScore 1376).
func TestCollectEmitsScoreGaugesFromLiveRecord(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: liveScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertSingleGauge(t, rec, metricCurrent, 815.22)
	assertSingleGauge(t, rec, metricMax, 1376.0)
	wantPct := 815.22 / 1376.0 * 100
	assertSingleGaugeApprox(t, rec, metricPercentage, wantPct)
}

// TestCollectAggregatesLiveControlProfiles drives the live control-profile
// catalog page end-to-end. Every live profile is Identity/Default, so the
// aggregate is category identity=5, status default=5. It stubs the live
// @odata.nextLink with an empty page so the one captured page is the whole set.
func TestCollectAggregatesLiveControlProfiles(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		scoreURL:        emptyScores,
		profilesURL:     liveProfiles,
		profilesNextURL: emptyProfiles,
	}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotCat := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByCategory) {
		gotCat[p.Attrs["category"]] = p.Value
	}
	if len(gotCat) != 1 || gotCat["identity"] != 5 {
		t.Errorf("live category counts = %v, want {identity:5}", gotCat)
	}

	gotStatus := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByStatus) {
		gotStatus[p.Attrs["status"]] = p.Value
	}
	if len(gotStatus) != 1 || gotStatus["default"] != 5 {
		t.Errorf("live status counts = %v, want {default:5}", gotStatus)
	}
}

func TestCollectOnlyEmitsLatestScoreNotFullSeries(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: twoScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricCurrent)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want exactly 1 (only the latest score)", len(pts), metricCurrent)
	}
	if pts[0].Value != 387.0 {
		t.Errorf("%s = %v, want 387 (the first/latest entry, not the second)", metricCurrent, pts[0].Value)
	}
}

func TestCollectSkipsPercentageWhenMaxScoreZero(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: zeroMaxScore, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricPercentage); len(pts) != 0 {
		t.Errorf("got %d %s series with maxScore=0, want 0 (avoid divide-by-zero series)", len(pts), metricPercentage)
	}
}

func TestCollectHandlesNoPublishedScoreYet(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: emptyProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 0 {
		t.Errorf("got %d %s series with no published score, want 0", len(pts), metricCurrent)
	}
}

func TestCollectEmitsControlProfileCountsByCategoryAndStatus(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: mixedProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	gotCat := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByCategory) {
		gotCat[p.Attrs["category"]] = p.Value
	}
	wantCat := map[string]float64{"identity": 2, "data": 1, "unknown": 1}
	if len(gotCat) != len(wantCat) {
		t.Fatalf("got %d category series, want %d: %v", len(gotCat), len(wantCat), gotCat)
	}
	for cat, v := range wantCat {
		if gotCat[cat] != v {
			t.Errorf("category=%s = %v, want %v", cat, gotCat[cat], v)
		}
	}

	gotStatus := map[string]float64{}
	for _, p := range rec.MetricPoints(metricByStatus) {
		gotStatus[p.Attrs["status"]] = p.Value
	}
	// identity/no-updates -> default; identity/reviewed -> reviewed;
	// data/ignored+thirdParty (latest by time wins) -> third_party;
	// unknown-category profile with an unrecognized state -> unknown.
	wantStatus := map[string]float64{"default": 1, "reviewed": 1, "third_party": 1, "unknown": 1}
	if len(gotStatus) != len(wantStatus) {
		t.Fatalf("got %d status series, want %d: %v", len(gotStatus), len(wantStatus), gotStatus)
	}
	for st, v := range wantStatus {
		if gotStatus[st] != v {
			t.Errorf("status=%s = %v, want %v", st, gotStatus[st], v)
		}
	}
}

// TestNoUnboundedLabelsFromUnknownCategoryOrState pins the cardinality rule: a
// category or state Graph has never returned before must collapse into the
// bounded "unknown" bucket, never pass through as a fresh, unbounded label.
func TestNoUnboundedLabelsFromUnknownCategoryOrState(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{scoreURL: emptyScores, profilesURL: mixedProfiles}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, p := range rec.MetricPoints(metricByCategory) {
		if p.Attrs["category"] == "SomeNewCategoryNotYetKnown" {
			t.Error("raw unrecognized category value leaked through as a label; must normalize to a bounded bucket")
		}
	}
	for _, p := range rec.MetricPoints(metricByStatus) {
		if p.Attrs["status"] == "someBrandNewState" {
			t.Error("raw unrecognized state value leaked through as a label; must normalize to a bounded bucket")
		}
	}
}

func TestCollectIsResilientToSecureScoreFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{profilesURL: mixedProfiles},
		errs:   map[string]error{scoreURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the secure score failure as an error")
	}
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 0 {
		t.Errorf("got %d %s series despite score fetch failing, want 0", len(pts), metricCurrent)
	}
	// The control profile counts must still emit despite the score failure.
	if pts := rec.MetricPoints(metricByCategory); len(pts) == 0 {
		t.Error("control-profile categories absent despite succeeding independently of the score fetch")
	}
}

func TestCollectIsResilientToControlProfilesFailure(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{scoreURL: liveScores},
		errs:   map[string]error{profilesURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("expected Collect to surface the control-profiles failure as an error")
	}
	// The score gauges must still emit despite the control-profiles failure.
	if pts := rec.MetricPoints(metricCurrent); len(pts) != 1 {
		t.Errorf("got %d %s series despite score fetch succeeding independently, want 1", len(pts), metricCurrent)
	}
	if pts := rec.MetricPoints(metricByCategory); len(pts) != 0 {
		t.Errorf("got %d %s series despite control-profiles fetch failing, want 0", len(pts), metricByCategory)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.secure_score" {
		t.Errorf("Name = %q", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "SecurityEvents.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [SecurityEvents.Read.All]", perms)
	}
}

func assertSingleGauge(t *testing.T, rec *telemetrytest.Recorder, name string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(name)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), name)
	}
	if pts[0].Value != want {
		t.Errorf("%s = %v, want %v", name, pts[0].Value, want)
	}
}

// assertSingleGaugeApprox is assertSingleGauge for a value computed via
// floating-point division, where the OTEL SDK's own float64<->float32-adjacent
// plumbing can introduce a last-decimal-place difference irrelevant to the
// collector's correctness.
func assertSingleGaugeApprox(t *testing.T, rec *telemetrytest.Recorder, name string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(name)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want 1", len(pts), name)
	}
	const epsilon = 1e-9
	if diff := pts[0].Value - want; diff > epsilon || diff < -epsilon {
		t.Errorf("%s = %v, want %v", name, pts[0].Value, want)
	}
}
