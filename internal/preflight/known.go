package preflight

// ExpectedExceptionScopes maps a Graph application permission scope that
// *looks* like over-privilege for a read-only telemetry exporter (typically
// a ReadWrite scope) to the reason it is nonetheless legitimately required.
// Check surfaces any required scope listed here via Report.ExpectedExceptions
// so an operator reading a MISSING list sees a proactive explanation instead
// of wondering why a metrics poller wants write access.
var ExpectedExceptionScopes = map[string]string{
	// The Intune reports-export API (used for device-compliance and other
	// bulk Intune reports) requires a ReadWrite scope just to CREATE the
	// export job, even though graph2otel only ever reads the exported
	// result back. This is documented Microsoft Graph behavior, not a
	// graph2otel design choice — see the "Reports export API needs a
	// write-level scope" gotcha in the project README/CLAUDE.md.
	"DeviceManagementManagedDevices.ReadWrite.All": "required only to CREATE an Intune reports-export job " +
		"(POST /deviceManagement/reports/exportJobs — used by the app-install, certificate-inventory, and " +
		"Defender-agent report collectors); graph2otel only reads the exported result back, never writes any " +
		"Intune configuration or device state. Any one of the three DeviceManagement*.ReadWrite.All scopes " +
		"authorizes the create call; this is the one graph2otel's export collectors declare.",
}

// NeverRequestScopes documents permission scopes graph2otel deliberately
// never requests, even though they would technically work — the second
// least-privilege trap (alongside the ReadWrite export exception above) that
// `check`'s help text calls out so an operator provisioning the app
// registration doesn't over-grant it.
var NeverRequestScopes = map[string]string{
	"DeviceManagementManagedDevices.PrivilegedOperations.All": "grants remote-wipe and other destructive device " +
		"actions; graph2otel is a read-only telemetry exporter and has no use for it. Do not grant this scope.",
}

// DocumentedRequiredScopes is a representative, non-exhaustive catalog of
// Graph application permissions graph2otel's collectors are expected to
// need, grouped by domain, surfaced in `check`'s help text so an operator
// provisioning an app registration ahead of the M2-M5 collectors landing
// knows roughly what to grant. It is documentation only — Check itself only
// ever compares against permissions collectors actually declare via
// PermissionRequirer, never against this list.
var DocumentedRequiredScopes = map[string][]string{
	"entra (directory, sign-ins, audits, provisioning, reports)": {
		"AuditLog.Read.All",
		"Reports.Read.All",
		"Directory.Read.All",
		"User.Read.All",
		"Group.Read.All",
		"Device.Read.All",
		"Application.Read.All",
		"Policy.Read.All",
		"Organization.Read.All",
	},
	"entra (identity protection / risk)": {
		"IdentityRiskyUser.Read.All",
		"IdentityRiskEvent.Read.All",
		"IdentityRiskyServicePrincipal.Read.All",
	},
	"entra (privileged role assignments)": {
		"RoleManagement.Read.Directory",
	},
	"intune": {
		"DeviceManagementManagedDevices.Read.All",
		"DeviceManagementConfiguration.Read.All",
		"DeviceManagementApps.Read.All",
		"DeviceManagementServiceConfig.Read.All",
	},
	"intune (reports export — see the ReadWrite exception note)": {
		"DeviceManagementManagedDevices.ReadWrite.All",
	},
}
