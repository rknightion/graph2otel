package pimalerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector runs through collectors.GetAllValues with
// no live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	seen   []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.seen = append(f.seen, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func alertsURL() string         { return defaultBaseURL + alertsPath + scopeFilter }
func definitionsURL() string    { return defaultBaseURL + definitionsPath + scopeFilter }
func configurationsURL() string { return defaultBaseURL + configurationsPath + scopeFilter }

// The three live bodies below are the m7kni tenant's COMPLETE
// roleManagementAlerts response on each segment, copied verbatim off the beta
// wire (probed as graph2otel-poller, 2026-07-24, #256). The mapper is written
// against these and nothing else — never against documentation (#142).
//
// They carry, between them, every trap the collector has to survive: the .NET
// zero date on the three alerts that have never fired, an alertDefinitionId
// that is byte-identical to the row's own id, an alert-type suffix embedded
// behind the tenant GUID, and the per-@odata.type threshold fields that exist
// on only some configuration rows.

const liveAlertsBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#identityGovernance/roleManagementAlerts/alerts",
  "value": [
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_InvalidLicenseAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_InvalidLicenseAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 0,
      "isActive": false,
      "lastModifiedDateTime": "0001-01-01T08:00:00Z",
      "lastScannedDateTime": "2026-07-23T13:43:26.983Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_NoMfaOnRoleActivationAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_NoMfaOnRoleActivationAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 11,
      "isActive": true,
      "lastModifiedDateTime": "2026-07-23T13:00:56.373Z",
      "lastScannedDateTime": "2026-07-23T13:00:56.373Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 0,
      "isActive": false,
      "lastModifiedDateTime": "0001-01-01T08:00:00Z",
      "lastScannedDateTime": "2026-07-24T15:34:27.24Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RolesAssignedOutsidePimAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RolesAssignedOutsidePimAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 5,
      "isActive": true,
      "lastModifiedDateTime": "2026-07-21T14:12:04.74Z",
      "lastScannedDateTime": "2026-07-23T15:14:45.54Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_SequentialActivationRenewalsAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_SequentialActivationRenewalsAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 0,
      "isActive": false,
      "lastModifiedDateTime": "0001-01-01T08:00:00Z",
      "lastScannedDateTime": "2026-07-23T12:54:51.42Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 4,
      "isActive": true,
      "lastModifiedDateTime": "2026-07-23T13:37:20.33Z",
      "lastScannedDateTime": "2026-07-23T13:37:20.33Z"
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
      "scopeId": "/",
      "scopeType": "DirectoryRole",
      "incidentCount": 3,
      "isActive": true,
      "lastModifiedDateTime": "2026-06-12T19:53:26.757Z",
      "lastScannedDateTime": "2026-07-23T13:31:17.49Z"
    }
  ]
}`

const liveDefinitionsBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#identityGovernance/roleManagementAlerts/alertDefinitions",
  "value": [
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_InvalidLicenseAlert",
      "displayName": "The organization doesn't have Azure AD Premium P2",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "Azure AD Privileged Identity Management requires a license, but the tenant either doesn't have an Azure AD Premium P2 license, or a trial license has expired.  If you do not obtain a license, Azure AD Privileged Identity Management and its configuration will be removed from the tenant.",
      "severityLevel": "high",
      "securityImpact": "Administrators in the tenant will not be able to use Azure AD Privileged Identity Management for role activation, access reviews or other management tasks unless a license is present.",
      "mitigationSteps": "Purchase a license plan which includes Azure AD Premium P2 for all users who will be interacting with Azure AD PIM or with Azure AD Identity Protection.  More information on pricing and purchase options is at https://azure.microsoft.com/en-us/pricing/details/active-directory/",
      "howToPrevent": "To dismiss this alert, ensure there is a license on the tenant for Azure AD Premium P2.",
      "isRemediatable": false,
      "isConfigurable": false
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_NoMfaOnRoleActivationAlert",
      "displayName": "Roles don't require multi-factor authentication for activation",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "Roles are configured for activation without requiring multifactor authentication. This is highly discouraged.",
      "severityLevel": "medium",
      "securityImpact": "Without multi-factor authentication, compromised users can activate privileged roles.",
      "mitigationSteps": "Review the list of roles and require multi-factor authentication for every role.",
      "howToPrevent": "Every privileged role should be configured to require MFA for activation.",
      "isRemediatable": true,
      "isConfigurable": false
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "displayName": "Eligible administrators aren't activating their privileged role",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "0 user(s) haven't activated their privileged roles in the past 30 days",
      "severityLevel": "low",
      "securityImpact": "Users that have been assigned privileged roles they don't need increases the chance of an attack. It is also easier for attackers to remain unnoticed in accounts that are not actively being used.",
      "mitigationSteps": "Review the users in the list and remove them from privileged roles they do not need.",
      "howToPrevent": "·Assign privileged roles to users that have a business justification.\r\n·Schedule regular access reviews to verify that users still need their access.",
      "isRemediatable": true,
      "isConfigurable": true
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RolesAssignedOutsidePimAlert",
      "displayName": "Roles are being assigned outside of Privileged Identity Management",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "5 privileged assignment(s) were made outside of Microsoft Entra Privileged Identity Management (PIM)",
      "severityLevel": "high",
      "securityImpact": "Privileged role assignments made outside of Privileged Identity Management are not properly monitored and may indicate an active attack.",
      "mitigationSteps": "Review the users in the list and remove them from privileged roles assigned outside of PIM.",
      "howToPrevent": "Investigate where users are being assigned privileged roles outside of Privileged Identity Management and prohibit future assignments from there.",
      "isRemediatable": true,
      "isConfigurable": false
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_SequentialActivationRenewalsAlert",
      "displayName": "Roles are being activated too frequently",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "0 multiple activations for a privileged role were made by the same user",
      "severityLevel": "medium",
      "securityImpact": "Multiple activations to the same privileged role by the same user is a sign of an attack.",
      "mitigationSteps": "Review the users in the list and ensure that the activation duration for their privileged role is set long enough for them to perform their tasks.",
      "howToPrevent": "·Ensure that the activation duration for privileged roles is set long enough for users to perform their tasks.\r\n·Require multi-factor authentication for privileged roles that have accounts shared by multiple administrators.",
      "isRemediatable": false,
      "isConfigurable": true
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
      "displayName": "There are too many global administrators",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "The percentage of global administrators is high, relative to other privileged roles. It is recommended to use least privileged roles, with just enough privileges to perform the required tasks.",
      "severityLevel": "low",
      "securityImpact": "Global administrator is the highest privileged role. If a Global Administrator is compromised, the attacker gains access to all of their permissions, which puts your whole system at risk.",
      "mitigationSteps": "·Review the users in the list and remove any that do not absolutely need the Global Administrator role.\r\n·Assign lower privileged roles to these users instead.",
      "howToPrevent": "Assign users the least privileged role they need.",
      "isRemediatable": true,
      "isConfigurable": true
    },
    {
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
      "displayName": "Potential stale accounts in a privileged role",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "description": "2 account(s) in privileged roles that have not signed in to Azure AD in the past 30 day(s)",
      "severityLevel": "medium",
      "securityImpact": "Accounts in a privileged role have not signed in recently. These accounts might be service or shared accounts that aren't being maintained and are vulnerable to attackers.",
      "mitigationSteps": "Review the accounts in the list. If they no longer need access, remove them from their privileged roles.",
      "howToPrevent": "Regularly review accounts with privileged roles using <a href=\"https://docs.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview\" target=\"_blank\" >access reviews</a> and remove role assignments which are no longer needed.",
      "isRemediatable": true,
      "isConfigurable": true
    }
  ]
}`

const liveConfigurationsBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#identityGovernance/roleManagementAlerts/alertConfigurations",
  "value": [
    {
      "@odata.type": "#microsoft.graph.invalidLicenseAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_InvalidLicenseAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_InvalidLicenseAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true
    },
    {
      "@odata.type": "#microsoft.graph.noMfaOnRoleActivationAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_NoMfaOnRoleActivationAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_NoMfaOnRoleActivationAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true
    },
    {
      "@odata.type": "#microsoft.graph.redundantAssignmentAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true,
      "duration": "P30D"
    },
    {
      "@odata.type": "#microsoft.graph.rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RolesAssignedOutsidePimAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RolesAssignedOutsidePimAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true
    },
    {
      "@odata.type": "#microsoft.graph.sequentialActivationRenewalsAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_SequentialActivationRenewalsAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_SequentialActivationRenewalsAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true,
      "timeIntervalBetweenActivations": "PT10S",
      "sequentialActivationCounterThreshold": 3
    },
    {
      "@odata.type": "#microsoft.graph.tooManyGlobalAdminsAssignedToTenantAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true,
      "globalAdminCountThreshold": 3,
      "percentageOfGlobalAdminsOutOfRolesThreshold": 10
    },
    {
      "@odata.type": "#microsoft.graph.staleSignInAlertConfiguration",
      "id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true,
      "duration": "P30D"
    }
  ]
}`

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		alertsURL():         liveAlertsBody,
		definitionsURL():    liveDefinitionsBody,
		configurationsURL(): liveConfigurationsBody,
	}}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// twinFor finds the emitted twin for an alert type.
func twinFor(t *testing.T, rec *telemetrytest.Recorder, alertType string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrAlertType] == alertType {
			return l
		}
	}
	t.Fatalf("no twin for alert type %q", alertType)
	return telemetrytest.LogRecord{}
}

// TestRequestURLsCarryTheMandatoryFilter is the whole reason this collector can
// work at all: a bare list of any roleManagementAlerts segment returns
// `400 {"errorCode":"MissingProvider"}`, which reads like the endpoint not
// existing. The filter is not an optimization, it is the request (#256).
func TestRequestURLsCarryTheMandatoryFilter(t *testing.T) {
	g := liveGraph()
	collect(t, g)

	if len(g.seen) != 3 {
		t.Fatalf("issued %d requests, want 3 (alerts, definitions, configurations): %v", len(g.seen), g.seen)
	}
	for _, u := range g.seen {
		if !strings.Contains(u, "$filter=scopeId+eq+'/'+and+scopeType+eq+'DirectoryRole'") {
			t.Errorf("request %q omits the mandatory scope filter — Graph answers 400 MissingProvider without it", u)
		}
		if !strings.HasPrefix(u, "https://graph.microsoft.com/beta/") {
			t.Errorf("request %q is not on the beta root — v1.0 has no roleManagementAlerts segment", u)
		}
	}
}

func TestAlertGaugeIsBoundedByTypeSeverityAndActive(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(alertsMetricName)
	if len(points) != 7 {
		t.Fatalf("got %d alert series, want 7 (one per alert type): %+v", len(points), points)
	}
	want := map[[3]string]float64{
		{"InvalidLicenseAlert", "high", "false"}:                    1,
		{"NoMfaOnRoleActivationAlert", "medium", "true"}:            1,
		{"RedundantAssignmentAlert", "low", "false"}:                1,
		{"RolesAssignedOutsidePimAlert", "high", "true"}:            1,
		{"SequentialActivationRenewalsAlert", "medium", "false"}:    1,
		{"TooManyGlobalAdminsAssignedToTenantAlert", "low", "true"}: 1,
		{"StaleSignInAlert", "medium", "true"}:                      1,
	}
	for _, p := range points {
		if p.Kind != "gauge" {
			t.Errorf("metric kind = %q, want gauge", p.Kind)
		}
		key := [3]string{p.Attrs[semconv.AttrAlertType], p.Attrs[semconv.AttrSeverity], p.Attrs[semconv.AttrIsActive]}
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected series %+v", p.Attrs)
			continue
		}
		if p.Value != w {
			t.Errorf("series %v value = %v, want %v", key, p.Value, w)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing series: %v", want)
	}
}

// The alert type label must be the STRIPPED suffix, never the raw id: the raw id
// embeds the tenant GUID, which turns a 7-value label into a per-tenant one.
func TestAlertTypeLabelNeverCarriesTheTenantGuid(t *testing.T) {
	rec := collect(t, liveGraph())

	for _, name := range []string{alertsMetricName, incidentsMetricName, configurationsMetricName} {
		for _, p := range rec.MetricPoints(name) {
			got := p.Attrs[semconv.AttrAlertType]
			if strings.Contains(got, "4b8c18bd") || strings.Contains(got, "DirectoryRole_") {
				t.Errorf("%s alert_type = %q — the raw id embeds the tenant GUID and is not a bounded label", name, got)
			}
		}
	}
}

func TestIncidentGaugeCarriesMicrosoftsEntityCounts(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(incidentsMetricName)
	if len(points) != 7 {
		t.Fatalf("got %d incident series, want 7: %+v", len(points), points)
	}
	want := map[string]float64{
		"InvalidLicenseAlert":                      0,
		"NoMfaOnRoleActivationAlert":               11,
		"RedundantAssignmentAlert":                 0,
		"RolesAssignedOutsidePimAlert":             5,
		"SequentialActivationRenewalsAlert":        0,
		"TooManyGlobalAdminsAssignedToTenantAlert": 4,
		"StaleSignInAlert":                         3,
	}
	for _, p := range points {
		w, ok := want[p.Attrs[semconv.AttrAlertType]]
		if !ok {
			t.Errorf("unexpected incident series %+v", p.Attrs)
			continue
		}
		if p.Value != w {
			t.Errorf("%s incidents = %v, want %v", p.Attrs[semconv.AttrAlertType], p.Value, w)
		}
		delete(want, p.Attrs[semconv.AttrAlertType])
	}
	if len(want) != 0 {
		t.Errorf("missing incident series: %v", want)
	}
}

func TestConfigurationGaugeReportsWhetherAlertsAreSwitchedOn(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(configurationsMetricName)
	if len(points) != 7 {
		t.Fatalf("got %d configuration series, want 7: %+v", len(points), points)
	}
	for _, p := range points {
		if p.Attrs[semconv.AttrIsEnabled] != "true" {
			t.Errorf("%s is_enabled = %q, want true (every m7kni configuration is on)",
				p.Attrs[semconv.AttrAlertType], p.Attrs[semconv.AttrIsEnabled])
		}
		if p.Value != 1 {
			t.Errorf("%s configuration value = %v, want 1", p.Attrs[semconv.AttrAlertType], p.Value)
		}
	}
}

// A switched-off alert reports isActive:false forever and is indistinguishable
// from a healthy one unless the configuration is read. It must be visible on
// both the gauge and the twin, and it must not read as INFO.
func TestDisabledConfigurationIsVisibleAndWarns(t *testing.T) {
	g := liveGraph()
	g.bodies[configurationsURL()] = strings.Replace(liveConfigurationsBody,
		`"id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": true`,
		`"id": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "alertDefinitionId": "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_RedundantAssignmentAlert",
      "scopeType": "DirectoryRole",
      "scopeId": "/",
      "isEnabled": false`, 1)
	rec := collect(t, g)

	var disabled int
	for _, p := range rec.MetricPoints(configurationsMetricName) {
		if p.Attrs[semconv.AttrIsEnabled] == "false" {
			disabled++
			if p.Attrs[semconv.AttrAlertType] != "RedundantAssignmentAlert" {
				t.Errorf("disabled series is %q, want RedundantAssignmentAlert", p.Attrs[semconv.AttrAlertType])
			}
		}
	}
	if disabled != 1 {
		t.Errorf("got %d disabled configuration series, want 1", disabled)
	}

	tw := twinFor(t, rec, "RedundantAssignmentAlert")
	if tw.Attrs[semconv.AttrIsEnabled] != "false" {
		t.Errorf("twin is_enabled = %q, want false", tw.Attrs[semconv.AttrIsEnabled])
	}
	if tw.SeverityText != "WARN" {
		t.Errorf("switched-off alert twin severity = %q, want WARN — an alert that is off can never fire", tw.SeverityText)
	}
}

// A configuration row with no isEnabled at all must read "unknown", never
// "false": fabricating a switched-off finding is the same class of bug as
// publishing an omitted score as a real zero.
func TestMissingIsEnabledIsUnknownNotDisabled(t *testing.T) {
	g := liveGraph()
	// The id must be the LIVE one so the join to the alert actually lands —
	// otherwise this would pass because the configuration was never found, not
	// because a found configuration declined to state isEnabled.
	g.bodies[configurationsURL()] = `{"value":[
	 {"id":"DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert",
	  "alertDefinitionId":"DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert"}]}`
	rec := collect(t, g)

	points := rec.MetricPoints(configurationsMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d configuration series, want 1", len(points))
	}
	if got := points[0].Attrs[semconv.AttrIsEnabled]; got != unknownValue {
		t.Errorf("is_enabled = %q, want %q", got, unknownValue)
	}
	tw := twinFor(t, rec, "StaleSignInAlert")
	if _, ok := tw.Attrs[semconv.AttrIsEnabled]; ok {
		t.Errorf("twin carries is_enabled = %q for a row that never stated it", tw.Attrs[semconv.AttrIsEnabled])
	}
}

// The .NET zero date means "this alert has never fired". Emitting it as a real
// timestamp claims an event in year 1.
func TestZeroDateIsNeverEmittedAsATimestamp(t *testing.T) {
	rec := collect(t, liveGraph())

	never := twinFor(t, rec, "InvalidLicenseAlert")
	if got, ok := never.Attrs[semconv.AttrLastModifiedDateTime]; ok {
		t.Errorf("last_modified_date_time = %q for an alert that has never fired — want the attribute omitted", got)
	}
	if got := never.Attrs[semconv.AttrLastScannedDateTime]; got != "2026-07-23T13:43:26.983Z" {
		t.Errorf("last_scanned_date_time = %q, want the verbatim wire value", got)
	}

	fired := twinFor(t, rec, "StaleSignInAlert")
	if got := fired.Attrs[semconv.AttrLastModifiedDateTime]; got != "2026-06-12T19:53:26.757Z" {
		t.Errorf("last_modified_date_time = %q, want the verbatim wire value", got)
	}
}

func TestTwinJoinsTheDefinitionsRemediationText(t *testing.T) {
	rec := collect(t, liveGraph())

	if n := len(rec.LogRecords()); n != 7 {
		t.Fatalf("got %d twins, want 7 (one per alert)", n)
	}
	tw := twinFor(t, rec, "TooManyGlobalAdminsAssignedToTenantAlert")
	if tw.EventName != eventName {
		t.Errorf("EventName = %q, want %q", tw.EventName, eventName)
	}
	if !tw.Timestamp.IsZero() {
		t.Errorf("twin timestamp = %v, want zero (state snapshot, not an event)", tw.Timestamp)
	}
	want := map[string]string{
		semconv.AttrAlertId:        "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_TooManyGlobalAdminsAssignedToTenantAlert",
		semconv.AttrAlertType:      "TooManyGlobalAdminsAssignedToTenantAlert",
		semconv.AttrDisplayName:    "There are too many global administrators",
		semconv.AttrSeverity:       "low",
		semconv.AttrIsActive:       "true",
		semconv.AttrIncidentCount:  "4",
		semconv.AttrIsRemediatable: "true",
		semconv.AttrIsConfigurable: "true",
		semconv.AttrIsEnabled:      "true",
		semconv.AttrHowToPrevent:   "Assign users the least privileged role they need.",
	}
	for k, w := range want {
		if got := tw.Attrs[k]; got != w {
			t.Errorf("twin attr %s = %q, want %q", k, got, w)
		}
	}
	if !strings.HasPrefix(tw.Attrs[semconv.AttrSecurityImpact], "Global administrator is the highest privileged role.") {
		t.Errorf("security_impact = %q, want the definition's verbatim text", tw.Attrs[semconv.AttrSecurityImpact])
	}
	if !strings.Contains(tw.Attrs[semconv.AttrMitigationSteps], "remove any that do not absolutely need the Global Administrator role") {
		t.Errorf("mitigation_steps = %q, want the definition's verbatim text", tw.Attrs[semconv.AttrMitigationSteps])
	}
	if !strings.Contains(tw.Attrs[semconv.AttrDescription], "percentage of global administrators is high") {
		t.Errorf("description = %q, want the definition's verbatim text", tw.Attrs[semconv.AttrDescription])
	}
}

// The per-type threshold fields are polymorphic: each @odata.type carries its
// own, and most rows carry none. They must land on the row that has them and
// nowhere else — an absent threshold is absent, never a zero.
func TestConfigurationThresholdsRideTheirOwnTwin(t *testing.T) {
	rec := collect(t, liveGraph())

	admins := twinFor(t, rec, "TooManyGlobalAdminsAssignedToTenantAlert")
	if got := admins.Attrs[semconv.AttrGlobalAdminCountThreshold]; got != "3" {
		t.Errorf("global_admin_count_threshold = %q, want 3", got)
	}
	if got := admins.Attrs[semconv.AttrGlobalAdminPercentageThreshold]; got != "10" {
		t.Errorf("global_admin_percentage_threshold = %q, want 10", got)
	}

	seq := twinFor(t, rec, "SequentialActivationRenewalsAlert")
	if got := seq.Attrs[semconv.AttrSequentialActivationCounterThreshold]; got != "3" {
		t.Errorf("sequential_activation_counter_threshold = %q, want 3", got)
	}
	if got := seq.Attrs[semconv.AttrTimeBetweenActivationsSeconds]; got != "10" {
		t.Errorf("time_between_activations_seconds = %q, want 10 (PT10S)", got)
	}

	stale := twinFor(t, rec, "StaleSignInAlert")
	if got := stale.Attrs[semconv.AttrAlertEvaluationWindowSeconds]; got != "2.592e+06" {
		t.Errorf("alert_evaluation_window_seconds = %q, want 2.592e+06 (P30D)", got)
	}
	for _, k := range []string{
		semconv.AttrGlobalAdminCountThreshold,
		semconv.AttrGlobalAdminPercentageThreshold,
		semconv.AttrSequentialActivationCounterThreshold,
	} {
		if got, ok := stale.Attrs[k]; ok {
			t.Errorf("stale-sign-in twin carries %s = %q, a threshold its @odata.type does not have", k, got)
		}
	}
}

// Severity ladder: an active high-severity finding is an ERROR, an active
// medium/low one a WARN, and a finding that is not active is INFO.
func TestTwinSeverityLadder(t *testing.T) {
	rec := collect(t, liveGraph())

	want := map[string]string{
		"RolesAssignedOutsidePimAlert":             "ERROR", // active, high
		"StaleSignInAlert":                         "WARN",  // active, medium
		"TooManyGlobalAdminsAssignedToTenantAlert": "WARN",  // active, low
		"InvalidLicenseAlert":                      "INFO",  // high, but not active
		"RedundantAssignmentAlert":                 "INFO",  // not active
	}
	for alertType, w := range want {
		if got := twinFor(t, rec, alertType).SeverityText; got != w {
			t.Errorf("%s twin severity = %q, want %q", alertType, got, w)
		}
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard: the
// definition's prose and the alert's own id ride the twin, never a metric label.
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph())

	banned := map[string]bool{
		semconv.AttrAlertId:              true,
		semconv.AttrDisplayName:          true,
		semconv.AttrDescription:          true,
		semconv.AttrSecurityImpact:       true,
		semconv.AttrMitigationSteps:      true,
		semconv.AttrHowToPrevent:         true,
		semconv.AttrLastScannedDateTime:  true,
		semconv.AttrLastModifiedDateTime: true,
		semconv.AttrIncidentCount:        true,
	}
	allowed := map[string]bool{
		semconv.AttrAlertType: true,
		semconv.AttrSeverity:  true,
		semconv.AttrIsActive:  true,
		semconv.AttrIsEnabled: true,
	}
	for _, name := range []string{alertsMetricName, incidentsMetricName, configurationsMetricName} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if banned[k] {
					t.Errorf("%s carries per-entity metric label %q — it belongs on the %s twin (#112/#114)", name, k, eventName)
				}
				if !allowed[k] {
					t.Errorf("%s carries unexpected metric label %q", name, k)
				}
			}
		}
	}
}

// An alert with no matching definition still emits: the state is real even when
// the meaning cannot be joined. Its severity label degrades to "unknown" rather
// than to an empty label.
func TestAlertWithNoDefinitionStillEmits(t *testing.T) {
	g := liveGraph()
	g.bodies[definitionsURL()] = `{"value":[]}`
	rec := collect(t, g)

	if n := len(rec.LogRecords()); n != 7 {
		t.Fatalf("got %d twins, want 7 — a missing definition must not drop the alert", n)
	}
	for _, p := range rec.MetricPoints(alertsMetricName) {
		if got := p.Attrs[semconv.AttrSeverity]; got != unknownValue {
			t.Errorf("severity = %q with no definitions, want %q", got, unknownValue)
		}
	}
	tw := twinFor(t, rec, "StaleSignInAlert")
	if _, ok := tw.Attrs[semconv.AttrMitigationSteps]; ok {
		t.Error("twin carries mitigation_steps with no definition to join")
	}
}

// alertType strips the tenant GUID segment. An id that does not have the
// expected shape must never leak an unbounded value onto a metric label.
func TestAlertTypeStripsThePrefixAndBoundsTheLabel(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{"live shape", "DirectoryRole_4b8c18bd-2f9f-4227-af55-9f1061cf9c32_StaleSignInAlert", "StaleSignInAlert"},
		{"no underscore", "StaleSignInAlert", "StaleSignInAlert"},
		{"empty", "", unknownValue},
		{"trailing underscore", "DirectoryRole_4b8c18bd_", unknownValue},
		{"guid tail", "DirectoryRole_x_4b8c18bd-2f9f-4227-af55-9f1061cf9c32", unknownValue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := alertType(tc.id); got != tc.want {
				t.Errorf("alertType(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

func TestForbiddenSkipsGracefully(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{alertsURL(): errors.New("graphclient: GET ...: status 403: forbidden")}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.MetricPoints(alertsMetricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on 403")
	}
}

// MissingProvider with the filter ALREADY on the request is the tenant saying it
// has no PIM provider — a skip, not a failure. (Without the filter it would mean
// graph2otel built a bad URL, which TestRequestURLsCarryTheMandatoryFilter
// prevents.)
func TestMissingProviderSkipsGracefully(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{alertsURL(): errors.New(`graphclient: GET ...: status 400: {"errorCode":"MissingProvider","message":"The provider is missing."}`)}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("MissingProvider should be a graceful skip, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions when the tenant has no PIM provider")
	}
}

func TestListErrorIsSurfaced(t *testing.T) {
	g := liveGraph()
	g.errs = map[string]error{definitionsURL(): errors.New("boom")}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a non-403 fetch error must be surfaced")
	}
}

func TestEmptyCollectionEmitsNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		alertsURL():         `{"value":[]}`,
		definitionsURL():    `{"value":[]}`,
		configurationsURL(): `{"value":[]}`,
	}}
	rec := collect(t, g)
	if len(rec.LogRecords()) != 0 {
		t.Error("no rows => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "entra.pim_alerts" {
		t.Errorf("Name() = %q, want entra.pim_alerts", c.Name())
	}
	// v1.0 has no roleManagementAlerts segment at all (400, live-measured
	// 2026-07-24) — beta base URL, so Experimental (#183).
	if defaultBaseURL != "https://graph.microsoft.com/beta" {
		t.Errorf("defaultBaseURL = %q, want the beta root", defaultBaseURL)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "RoleManagementAlert.Read.Directory" {
		t.Errorf("RequiredPermissions = %v, want the single read-only alert scope", perms)
	}
	if c.DefaultInterval() != 6*time.Hour {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
}
