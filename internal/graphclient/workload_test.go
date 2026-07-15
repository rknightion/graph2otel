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
