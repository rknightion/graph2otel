package recommendations

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const listURL = "https://graph.microsoft.com/beta/directory/recommendations"

// liveRecommendations is a VERBATIM GET /beta/directory/recommendations
// response captured from the m7kni tenant, read as graph2otel-poller on
// 2026-07-17 `[live-measured 2026-07-17, #165]`. It replaces a docs-derived
// fixture that invented turnOnMFA/removeUnusedApps types and inline
// impactedResources arrays this endpoint does not return.
//
// The value array holds the real recommendations verbatim (each record whole,
// byte-for-byte). Note NO record carries an impactedResources property: on the
// collection endpoint it is an omitted navigation property, so every impacted
// count the collector derives is 0 — see the pinning test below.
const liveRecommendations = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#directory/recommendations",
  "value": [
    {
      "actionSteps": [
        {
          "actionUrl": {
            "displayName": "Go to Adaptive Protection.",
            "url": "https://go.microsoft.com/fwlink/?linkid=2261736"
          },
          "stepNumber": 1,
          "text": "1. Enable Adaptive Protection in Microsoft Purview. You must be a member of the Insider Risk Management or Insider Risk Management Admins role group in Microsoft Purview to configure Adaptive Protection. "
        },
        {
          "actionUrl": {
            "displayName": "Use this risk policy template",
            "url": "https://go.microsoft.com/fwlink/?linkid=2261903"
          },
          "stepNumber": 2,
          "text": "2. Create a Conditional Access policy that includes the Insider Risk condition. "
        },
        {
          "actionUrl": {
            "displayName": "Adaptive Protection and Insider Risk Conditional Access recommendation.",
            "url": "https://go.microsoft.com/fwlink/?linkid=2260505"
          },
          "stepNumber": 3,
          "text": "3. For more information about this recommendation and the associated features, see "
        }
      ],
      "benefits": "Enabling an Insider Risk-based Conditional Access policy offers crucial benefits, including early detection of anomalies, adaptive access controls, and real-time responses to insider threats. It prevents unauthorized access, enforces compliance, and reduces the impact of insider incidents. By fostering a security-aware culture, the policy integrates with the broader security ecosystem, providing a comprehensive approach to mitigate risks originating from within the organization, safeguarding sensitive data, and enhancing overall security posture.\u200b",
      "category": "identitySecureScore",
      "createdDateTime": "2025-09-11T08:14:22Z",
      "currentScore": 0.0,
      "displayName": "Protect your tenant with Insider Risk condition in Conditional Access policy",
      "featureAreas": [
        "conditionalAccess"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_insiderRiskPolicy",
      "impactStartDateTime": "2025-09-11T08:14:22Z",
      "impactType": "users",
      "insights": "You have 4 of 4 users that aren\u2019t covered by the Insider Risk condition in a Conditional Access policy.",
      "lastModifiedBy": "System",
      "lastModifiedDateTime": "2026-07-17T08:12:01Z",
      "maxScore": 5.0,
      "postponeUntilDateTime": null,
      "priority": "medium",
      "recommendationType": "insiderRiskPolicy",
      "releaseType": "generallyAvailable",
      "remediationImpact": "Upon policy activation, user actions will align with administrator configurations. Potential actions encompass the user being \"Blocked\" from application usage or activation of \"Terms of Use\" conditions. ",
      "requiredLicenses": "microsoftEntraIdP2",
      "status": "active"
    },
    {
      "actionSteps": [
        {
          "actionUrl": {
            "displayName": "see your license type under \"Basic information\" in the Microsoft Entra ID Overview.",
            "url": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview"
          },
          "stepNumber": 1,
          "text": "1. To implement this recommendation, you need Microsoft Entra ID Premium P2 licenses. Check what Microsoft Entra ID license you have under \u201cPrerequisites\u201d in Microsoft Secure Score or "
        },
        {
          "actionUrl": {
            "displayName": "Follow these steps to create a Conditional Access policy from scratch or by using a template",
            "url": "https://docs.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-risk-user"
          },
          "stepNumber": 2,
          "text": "2. If you\u2019ve invested in Microsoft Entra ID Premium P2 licenses, you can create a Conditional Access policy from scratch or by using a template. Note: Classic Conditional Access policies aren\u2019t scored. Use the recommended steps to receive credit. "
        },
        {
          "actionUrl": null,
          "stepNumber": 3,
          "text": "3. If you\u2019re not using Microsoft Entra ID Premium P2 licenses, we recommend you set the status for this action to \u201cDismissed\u201d or \u201cRisk accepted\u201d. "
        }
      ],
      "benefits": "With the user risk policy turned on, Microsoft Entra ID detects the probability that a user account has been compromised. As an administrator, you can configure a user risk Conditional Access policy to automatically respond to a specific user risk level. For example, you can block access to your resources or require a password change to get a user account back into a clean state.",
      "category": "identitySecureScore",
      "createdDateTime": "2025-09-25T08:12:18Z",
      "currentScore": 5.25,
      "displayName": "Protect all users with a user risk policy ",
      "featureAreas": [
        "conditionalAccess"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_userRiskPolicy",
      "impactStartDateTime": "2025-09-25T08:12:18Z",
      "impactType": "users",
      "insights": "You have 1 of 4 users that don\u2019t have a user risk policy enabled. ",
      "lastModifiedBy": "System",
      "lastModifiedDateTime": "2026-07-17T08:12:01Z",
      "maxScore": 7.0,
      "postponeUntilDateTime": null,
      "priority": "high",
      "recommendationType": "userRiskPolicy",
      "releaseType": "generallyAvailable",
      "remediationImpact": "When the policy triggers, access to the account will either be blocked or the user will be required to use multifactor authentication and change their password. Users who haven't registered multifactor authentication (MFA) on their account will be blocked from accessing it. If account access is blocked, an admin would need to recover the account. Thus, it is important to configure the MFA registration policy for all users who are a part of the user risk policy to ensure that they have registered for MFA.",
      "requiredLicenses": "microsoftEntraIdP2",
      "status": "active"
    },
    {
      "actionSteps": [
        {
          "actionUrl": {
            "displayName": "see your license type under \"Basic information\" in the Microsoft Entra ID Overview.",
            "url": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview"
          },
          "stepNumber": 1,
          "text": "1. To implement this recommendation, you need Microsoft Entra ID Premium P2 licenses. Check what Microsoft Entra ID license you have under \u201cPrerequisites\u201d in Microsoft Secure Score or "
        },
        {
          "actionUrl": {
            "displayName": "Follow these steps to create a Conditional Access policy from scratch or by using a template",
            "url": "https://docs.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-risk-user"
          },
          "stepNumber": 2,
          "text": "2. If you\u2019ve invested in Microsoft Entra ID Premium P2 licenses, you can create a Conditional Access policy from scratch or by using a template. "
        },
        {
          "actionUrl": null,
          "stepNumber": 3,
          "text": "3. If you\u2019re not using Microsoft Entra ID Premium P2 licenses, we recommend you set this action to \u201cDismissed\u201d or \u201cRisk accepted\u201d."
        }
      ],
      "benefits": "Turning on the sign-in risk policy ensures that suspicious sign-ins are challenged for multifactor authentication (MFA). ",
      "category": "identitySecureScore",
      "createdDateTime": "2026-07-15T08:10:23Z",
      "currentScore": 5.25,
      "displayName": "Protect all users with a sign-in risk policy",
      "featureAreas": [
        "conditionalAccess"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_signinRiskPolicy",
      "impactStartDateTime": "2026-07-15T08:10:23Z",
      "impactType": "users",
      "insights": "You have 1 of 4 users that don't have a sign-in risk policy turned on.",
      "lastModifiedBy": "System",
      "lastModifiedDateTime": "2026-07-17T08:12:01Z",
      "maxScore": 7.0,
      "postponeUntilDateTime": null,
      "priority": "high",
      "recommendationType": "signinRiskPolicy",
      "releaseType": "generallyAvailable",
      "remediationImpact": "When the policy triggers, the user will need MFA to access the account. If a user hasn't registered for MFA, they\u2019re blocked from accessing their account. If account access is blocked, an admin would need to recover the account.",
      "requiredLicenses": "microsoftEntraIdP2",
      "status": "active"
    },
    {
      "actionSteps": [
        {
          "actionUrl": {
            "displayName": "step-by-step guidance to enable self-service password reset",
            "url": "https://docs.microsoft.com/azure/active-directory/authentication/tutorial-enable-sspr"
          },
          "stepNumber": 1,
          "text": "1. Follow our "
        },
        {
          "actionUrl": {
            "displayName": "For more information, see this article",
            "url": "https://docs.microsoft.com/azure/active-directory/authentication/tutorial-enable-sspr-writeback?WT.mc_id=Portal-Microsoft_AAD_IAM"
          },
          "stepNumber": 2,
          "text": "2. If you have users that are synced from on-premises Microsoft Entra Connect using Microsoft Entra Connect, you may also need to enable the password writeback feature. "
        }
      ],
      "benefits": "With self-service password reset in Microsoft Entra ID, users no longer need to engage helpdesk to reset passwords. This feature works well with Microsoft Entra ID dynamically banned passwords, which prevents easily guessable passwords from being used.",
      "category": "identitySecureScore",
      "createdDateTime": "2026-07-17T06:05:21Z",
      "currentScore": 1.0,
      "displayName": "Enable self-service password reset",
      "featureAreas": [
        "applications"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_selfServicePasswordReset",
      "impactStartDateTime": "2026-07-17T06:05:21Z",
      "impactType": "users",
      "insights": "You have 0 of  users who don't have self-service password reset enabled. ",
      "lastModifiedBy": "System",
      "lastModifiedDateTime": "2026-07-17T06:05:21Z",
      "maxScore": 1.0,
      "postponeUntilDateTime": null,
      "priority": "low",
      "recommendationType": "selfServicePasswordReset",
      "releaseType": "generallyAvailable",
      "remediationImpact": "Users will be able to self-service password reset in Microsoft Entra ID and no longer need to engage helpdesk.",
      "requiredLicenses": "microsoftEntraIdP1",
      "status": "completedBySystem"
    },
    {
      "actionSteps": [
        {
          "actionUrl": {
            "displayName": "Go to Roles and administrators in Microsoft Entra ID",
            "url": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RolesAndAdministrators"
          },
          "stepNumber": 1,
          "text": "1. Identify the users in your organization with a persistent global administrator role assigned. Go to Microsoft Entra ID > Roles and administrators and select the Global administrator role in the table. Identify the global admins you want to reassign to a different role. "
        },
        {
          "actionUrl": {
            "displayName": "Check out this overview of available limited administrative roles",
            "url": "https://docs.microsoft.com/azure/active-directory/roles/delegate-by-task"
          },
          "stepNumber": 2,
          "text": "2. Assign these users to roles where they can complete necessary tasks with the least amount of privilege required. For example, if a user is primarily responsible for Exchange Online administration, they should be assigned that role instead of global administrator. Be sure to have at least two global admins designated to allow for full access to the network if one of the accounts is locked out or compromised. "
        },
        {
          "actionUrl": {
            "displayName": "Go to Roles and administrators in Microsoft Entra ID",
            "url": "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RolesAndAdministrators"
          },
          "stepNumber": 3,
          "text": "3. After these persistent global admins have been reassigned new roles, return to Roles and administrators and select the Global administrator role. Select the users that no longer need persistent access and then click Remove. "
        },
        {
          "actionUrl": {
            "displayName": "Learn more about emergency access accounts",
            "url": "https://docs.microsoft.com/azure/active-directory/roles/security-emergency-access"
          },
          "stepNumber": 4,
          "text": "4. Emergency access accounts: If the only other global admin accounts your organization has set up are for \"break-glass\" scenarios, which are ineligible for role reassignment, we recommend that you set the status of this action to \u201cDismissed\u201d or \u201cRisk accepted\u201d. "
        }
      ],
      "benefits": "Ensure that your administrators can accomplish their work with the least amount of privilege assigned to their account. Assigning users roles like Password Administrator or Exchange Online Administrator, instead of Global Administrator, reduces the likelihood of a global administrative privileged account being breached.",
      "category": "identitySecureScore",
      "createdDateTime": "2026-07-17T08:12:01Z",
      "currentScore": 1.0,
      "displayName": "Use least privileged administrative roles ",
      "featureAreas": [
        "applications"
      ],
      "id": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32_roleOverlap",
      "impactStartDateTime": "2026-07-17T08:12:01Z",
      "impactType": "users",
      "insights": "You currently have 12 users with privileged administrative roles. ",
      "lastModifiedBy": "System",
      "lastModifiedDateTime": "2026-07-17T08:12:01Z",
      "maxScore": 1.0,
      "postponeUntilDateTime": null,
      "priority": "low",
      "recommendationType": "roleOverlap",
      "releaseType": "generallyAvailable",
      "remediationImpact": "If an admin is assigned a more limited administrator role, they will lose some of the privileges that they had before. Make sure that these users have enough privileges to complete their day-to-day work.",
      "requiredLicenses": "microsoftEntraIdFree",
      "status": "completedBySystem"
    }
  ]
}`

// TestCollectEmitsStatusPriorityAndImpactedCounts drives the VERBATIM live
// recommendations response through the real collector into a recorder.
//
// Status x priority buckets track the wire: the capture holds two active/high
// records (userRiskPolicy, signinRiskPolicy), one active/medium
// (insiderRiskPolicy) and two completedBySystem/low (selfServicePasswordReset,
// roleOverlap).
//
// WIRE FACT (#165): the list endpoint returns NO impactedResources on any
// record — the property is a navigation property the collection response omits
// entirely, so every impacted count is 0. The collector reads impactedResources
// inline by design and its own doc comment anticipates the omission ("a beta
// schema that omits it simply yields a zero impacted count"); this test pins
// that the impacted metric is therefore always-zero on the real wire.
func TestCollectEmitsStatusPriorityAndImpactedCounts(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{listURL: liveRecommendations}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// status x priority counts
	counts := map[string]float64{}
	for _, p := range rec.MetricPoints(totalMetric) {
		counts[p.Attrs["status"]+"/"+p.Attrs["priority"]] = p.Value
	}
	if counts["active/high"] != 2 {
		t.Errorf("active/high = %v, want 2", counts["active/high"])
	}
	if counts["active/medium"] != 1 {
		t.Errorf("active/medium = %v, want 1", counts["active/medium"])
	}
	if counts["completedBySystem/low"] != 2 {
		t.Errorf("completedBySystem/low = %v, want 2", counts["completedBySystem/low"])
	}

	// impacted resources by recommendation type: one series per type, all zero,
	// because the list endpoint omits impactedResources on every record.
	impacted := map[string]float64{}
	for _, p := range rec.MetricPoints(impactedMetric) {
		impacted[p.Attrs["recommendation"]] = p.Value
	}
	for _, typ := range []string{
		"insiderRiskPolicy", "userRiskPolicy", "signinRiskPolicy",
		"selfServicePasswordReset", "roleOverlap",
	} {
		if v, present := impacted[typ]; !present {
			t.Errorf("impacted type %q missing a series", typ)
		} else if v != 0 {
			t.Errorf("impacted[%s] = %v, want 0 (list endpoint omits impactedResources)", typ, v)
		}
	}
}

func TestCollectGracefulOn403(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 403: {\"error\":{\"code\":\"Authorization_RequestDenied\"}}"),
	}}
	rec := telemetrytest.New()

	// A 403 (endpoint unavailable / unlicensed) must be skipped-and-logged, not
	// surfaced as a collector error.
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Errorf("Collect should swallow a 403 as skip-and-log, got: %v", err)
	}
	if len(rec.MetricNames()) != 0 {
		t.Errorf("no metrics should be emitted on a 403, got %v", rec.MetricNames())
	}
}

func TestCollectSurfacesNon4xxError(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		listURL: errors.New("graphclient: GET " + listURL + ": status 500: server error"),
	}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a 500 should surface as a collector error, not be swallowed")
	}
}

func TestExperimentalAndName(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if !c.Experimental() {
		t.Error("recommendations is a beta collector; Experimental() must be true")
	}
	if c.Name() != "entra.recommendations" {
		t.Errorf("Name = %q", c.Name())
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "DirectoryRecommendations.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
}
