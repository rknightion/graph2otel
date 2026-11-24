package graphclient

import "testing"

func TestClassifyWorkload(t *testing.T) {
	tests := []struct {
		path string
		want Workload
	}{
		{"/v1.0/auditLogs/signIns", WorkloadReporting},
		{"/auditLogs/directoryAudits", WorkloadReporting},
		{"/auditLogs/provisioning", WorkloadReporting},
		{"/reports/applicationSignInSummary", WorkloadReporting},
		{"/reports/credentialUserRegistrationDetails", WorkloadReporting},
		{"/security/alerts_v2", WorkloadReporting},
		{"/v1.0/security/alerts_v2", WorkloadReporting},
		{"/identityProtection/riskyUsers", WorkloadIPC},
		{"/identityProtection/riskDetections", WorkloadIPC},
		{"/identityProtection/riskyServicePrincipals", WorkloadIPC},
		{"/identity/conditionalAccess/policies", WorkloadIPC},
		{"/identity/conditionalAccess/namedLocations", WorkloadIPC},
		{"/deviceManagement/managedDevices", WorkloadIntuneDevices},
		{"/deviceManagement/comanagedDevices", WorkloadIntuneDevices},
		{"/deviceManagement/reports/exportJobs", WorkloadIntuneExport},
		{"/deviceManagement/deviceConfigurations", WorkloadIntuneGeneral},
		{"/users", WorkloadDirectory},
		{"/users/00000000-0000-0000-0000-000000000000", WorkloadDirectory},
		{"/groups", WorkloadDirectory},
		{"/servicePrincipals", WorkloadDirectory},
		{"/applications", WorkloadDirectory},
		{"/devices", WorkloadDirectory},
		{"/directoryRoles", WorkloadDirectory},
		{"/teams", WorkloadDirectory},
		{"/teams/00000000-0000-0000-0000-000000000000", WorkloadDirectory},
		{"/v1.0/communications/callRecords/getPstnCalls(fromDateTime=2026-01-01T00:00:00Z,toDateTime=2026-01-02T00:00:00Z)", WorkloadTeamsPhone},
		{"/v1.0/communications/callRecords/getDirectRoutingCalls(from=2026-01-01,to=2026-01-02)", WorkloadTeamsPhone},
		{"/v1.0/communications/callRecords", WorkloadTeamsCallRecords},
		{"/v1.0/communications/callRecords/call-1", WorkloadTeamsCallRecords},
		{"/v1.0/communications/callRecords/call-1/sessions", WorkloadTeamsCallRecords},
		{"/v1.0/communications/callRecords/call-1/participants_v2", WorkloadTeamsCallRecords},
		{"/something/entirely/unrelated", WorkloadUnknown},
	}
	for _, tt := range tests {
		if got := ClassifyWorkload(tt.path); got != tt.want {
			t.Errorf("ClassifyWorkload(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// TestClassifyWorkloadExportBeforeGeneral is the specific ordering regression:
// the export subpath must win over the general /deviceManagement/ rule it
// nests under.
func TestClassifyWorkloadExportBeforeGeneral(t *testing.T) {
	got := ClassifyWorkload("/v1.0/deviceManagement/reports/exportJobs('abc')")
	if got != WorkloadIntuneExport {
		t.Errorf("ClassifyWorkload(export path) = %q, want %q", got, WorkloadIntuneExport)
	}
}
