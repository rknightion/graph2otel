package graphclient

import "strings"

// Workload identifies which Microsoft Graph throttling ceiling a request falls
// under. Graph enforces several INDEPENDENT throttle budgets — a request that
// clears the directory read ceiling can still 429 against the much tighter
// reporting or Identity Protection ceilings — so every outbound request is
// classified before it is rate-limited (see WorkloadLimiter).
type Workload string

const (
	// WorkloadReporting covers the sign-in/audit/provisioning log endpoints and
	// the /reports/* summaries: 5 requests / 10s per app per tenant, with NO
	// Retry-After on a 429.
	WorkloadReporting Workload = "reporting"
	// WorkloadIPC covers Identity Protection + Conditional Access: 1 request /
	// second per TENANT, across ALL apps — the tightest ceiling Graph exposes,
	// and also NO Retry-After on a 429.
	WorkloadIPC Workload = "identity-protection"
	// WorkloadDirectory covers plain directory-object reads (users, groups,
	// service principals, applications, devices, directory roles). This
	// workload DOES send Retry-After, so Kiota's default retry handler already
	// covers most of it; the limiter here is a coarse, defensive backstop, not
	// a tightly-measured ceiling.
	WorkloadDirectory Workload = "directory"
	// WorkloadIntuneGeneral covers Intune device-management endpoints other
	// than the Devices and reports-export subpaths: ~1000 requests / 20s per
	// app per tenant.
	WorkloadIntuneGeneral Workload = "intune-general"
	// WorkloadIntuneDevices covers the elevated-ceiling Intune device
	// collections: ~2000 reads / 20s per app per tenant.
	WorkloadIntuneDevices Workload = "intune-devices"
	// WorkloadIntuneExport covers the Intune reports-export job endpoint, the
	// tightest Intune ceiling: 48 requests / minute per app.
	WorkloadIntuneExport Workload = "intune-export"
	// WorkloadUnknown is anything not matched by the table below. It gets no
	// client-side limiter (a generous, permissive default) rather than being
	// forced into one of the tuned ceilings above.
	WorkloadUnknown Workload = "unknown"
)

// workloadMatch is one entry of the classification table: a path substring and
// the workload it identifies. Order matters — classifyRules is walked in
// order and the first match wins, so more specific rules (a subpath) MUST
// precede the more general rule they nest under.
type workloadMatch struct {
	substr   string
	workload Workload
}

// classifyRules is the path -> Workload table. Entries are matched with
// strings.Contains against the request path, so they work whether or not the
// path carries a "/v1.0" or "/beta" API-version prefix.
var classifyRules = []workloadMatch{
	// Intune: reports-export and the Devices subpaths are their OWN ceilings
	// and must be matched BEFORE the general "/deviceManagement/" rule.
	{"/deviceManagement/reports/exportJobs", WorkloadIntuneExport},
	{"/deviceManagement/managedDevices", WorkloadIntuneDevices},
	{"/deviceManagement/comanagedDevices", WorkloadIntuneDevices},
	{"/deviceManagement/", WorkloadIntuneGeneral},

	// Identity Protection + Conditional Access.
	{"/identityProtection/riskDetections", WorkloadIPC},
	{"/identityProtection/riskyUsers", WorkloadIPC},
	{"/identityProtection/riskyServicePrincipals", WorkloadIPC},
	{"/identity/conditionalAccess/policies", WorkloadIPC},
	{"/identity/conditionalAccess/namedLocations", WorkloadIPC},

	// Reporting: the log-shaped audit endpoints plus the general /reports/*
	// summaries (applicationSignInSummary, credential-usage summaries, ...).
	{"/auditLogs/signIns", WorkloadReporting},
	{"/auditLogs/directoryAudits", WorkloadReporting},
	{"/auditLogs/provisioning", WorkloadReporting},
	{"/reports/", WorkloadReporting},
	// Security alerts (alerts_v2): the security workload has moderate limits —
	// not the 1 req/s IPC ceiling risk detections use — and no reliable
	// Retry-After, so route it through the reporting-class limiter as a
	// defensive backstop rather than leaving it unlimited (#25).
	{"/security/alerts", WorkloadReporting},

	// Directory object reads.
	{"/users", WorkloadDirectory},
	{"/groups", WorkloadDirectory},
	{"/servicePrincipals", WorkloadDirectory},
	{"/applications", WorkloadDirectory},
	{"/devices", WorkloadDirectory},
	{"/directoryRoles", WorkloadDirectory},
}

// ClassifyWorkload maps a request's URL path to the Graph throttling workload
// it falls under. Unmatched paths return WorkloadUnknown.
func ClassifyWorkload(urlPath string) Workload {
	for _, m := range classifyRules {
		if strings.Contains(urlPath, m.substr) {
			return m.workload
		}
	}
	return WorkloadUnknown
}
