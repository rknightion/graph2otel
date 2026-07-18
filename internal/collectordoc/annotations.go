package collectordoc

// annotations is the hand-written half of the collector reference: for each
// collector, the things the registry cannot know — what it is for, which Graph
// endpoints it polls, and any license gating that lives inside Collect()
// instead of in a declared interface.
//
// Everything else in a row (interval, lag, Experimental, the declared
// capability and scopes, a blob container and cursor key) is read off the live
// registry and must NOT be repeated here — a fact with two homes is a fact that
// drifts, which is the whole reason this file exists. What a collector emits
// is the same story, one level removed: it is read off its package's
// testdata/signals.json golden (#140, see signals.go), not hand-written here —
// this file used to carry an Emits field, and its prose drifted uncaught
// (annotations.go once claimed entra.organization emitted a metric name the
// collector never had).
//
// Adding a collector? TestCollectorAnnotationsCoverEveryCollector fails until
// there is an entry here, then TestCollectorReferenceDocInSync fails until
// docs/collectors.md is regenerated (`scripts/regen-generated.sh collectordoc`).
// A collector whose package has no testdata/signals.json golden fails Rows
// directly, by path, before either of those gates runs.
var annotations = map[string]Annotation{
	// ---- Entra ID — snapshot collectors ----
	"entra.agreements": {
		Collects: "Terms of Use agreements + acceptance state",
		Source:   "`/agreements`, `/agreements/{id}/acceptances`",
	},
	"entra.auth_methods_policy": {
		Collects: "Tenant-wide authentication methods policy (enabled methods, legacy methods)",
		Source:   "`/policies/authenticationMethodsPolicy`",
	},
	"entra.conditional_access": {
		Collects: "CA policy + named location inventory",
		Source:   "`/identity/conditionalAccess/policies`, `/identity/conditionalAccess/namedLocations`",
	},
	"entra.consent": {
		Collects: "OAuth2 permission grants + app-role assignment consent surface",
		Source:   "`/oauth2PermissionGrants`, app role assignments",
	},
	"entra.credential_expiry": {
		Collects: "App + service principal credential (secret/certificate) expiry buckets",
		Source:   "`/applications`, `/servicePrincipals` (`$select=keyCredentials,passwordCredentials`)",
	},
	"entra.devices": {
		Collects: "Directory device inventory: trust type, compliance, managed state, OS, staleness",
		Source:   "`/devices`, `/devices/$count`",
	},
	"entra.directory_counts": {
		Collects: "Tenant-wide directory object counts by type",
		Source:   "`/{type}/$count` per object type",
	},
	"entra.domains": {
		Collects: "Domain verification/authentication posture",
		Source:   "`/domains`",
	},
	"entra.groups": {
		Collects: "Group population by type/membership/security/mail-enabled, role-assignable count",
		Source:   "`/groups/$count` (filtered)",
	},
	"entra.licensing": {
		Collects: "SKU consumption + prepaid/enabled units",
		Source:   "`/subscribedSkus`",
	},
	"entra.mfa_registration": {
		Collects: "MFA/SSPR/passwordless registration + capability status, per-method counts, admin MFA-capable split",
		Source:   "`/reports/authenticationMethods/userRegistrationDetails`",
	},
	"entra.organization": {
		Collects: "Tenant posture: on-prem sync state/age, tenant age, verified domain count, tenant type",
		Source:   "`/organization`",
	},
	"entra.recommendations": {
		Collects: "Entra recommendations catalog (status, priority)",
		Source:   "`/directory/recommendations` (beta)",
	},
	"entra.risk": {
		Collects: "Current risky-users and risky-service-principals counts, with a log twin per risky entity",
		Source:   "`/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals`",
		Gating:   "risky users need `entra_p2`, risky SPs need `workload_identities_premium` — two INDEPENDENT partial gates checked inside Collect() against the tenant's capabilities, so each half runs and emits only if its own capability is present; neither is declared as a whole-collector requirement",
	},
	"entra.roles": {
		Collects: "Standing directory-role membership; PIM active/eligible/permanent assignment counts",
		Source:   "`/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances`",
		Gating:   "PIM half only needs `entra_p2`, checked inside Collect(): the standing-membership half runs on every tier, and without P2 the PIM assignment counts are skipped rather than zero-emitted",
	},
	"entra.secure_score": {
		Collects: "Latest secure score + control profile catalog (Microsoft publishes at most daily, hence the hourly poll)",
		Source:   "`/security/secureScores`, `/security/secureScoreControlProfiles`",
	},
	"entra.signin_activity": {
		Collects: "Stale service principals / app credentials (no recent sign-in), app sign-in result summary",
		Source:   "`/reports/servicePrincipalSignInActivities`, `/reports/appCredentialSignInActivities` (beta)",
	},
	"entra.syncerrors": {
		Collects: "Hybrid directory-sync provisioning errors (onPremisesProvisioningErrors) — UPN/proxy-address conflicts that fail silently while sync freshness stays green — bucketed by object type/category/property, plus a log twin per errored object carrying the conflicting value",
		Source:   "`/organization` (sync-state probe), `/users` (full page-walk, client-side filtered)",
		Gating:   "runs on every tier (both endpoints are v1.0 stable, not beta); no-ops without paging when the tenant is cloud-only, i.e. onPremisesSyncEnabled is false or null, so only hybrid-synced tenants pay the full /users sweep",
	},
	"entra.users": {
		Collects: "User population by account-enabled/user-type/on-prem-sync (marginal + joint user_type×account_enabled), staleness",
		Source:   "`/users`, `/users/$count` (`GET /users?…&$count=true` for signInActivity-based slices)",
		Gating:   "staleness slice only, checked inside Collect(): signInActivity needs `entra_p1` or `entra_p2`; the population counts run on every tier",
	},

	// ---- Entra ID — window collectors ----
	"entra.signins.interactive": {
		Collects: "Interactive sign-in events — the v1.0 default slice, the only sign-in stream that needs no filter and so the only one that is not beta",
		Source:   "`/auditLogs/signIns` (v1.0, unfiltered)",
	},
	"entra.signins.non_interactive": {
		Collects: "Non-interactive sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
	},
	"entra.signins.service_principal": {
		Collects: "Service principal sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
	},
	"entra.signins.managed_identity": {
		Collects: "Managed identity sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
	},
	"entra.directory_audits": {
		Collects: "Directory audit log events (source: graph|blob — poll `/auditLogs/directoryAudits`, or consume the `AuditLogs` diagnostic-settings container; exactly one per config)",
		Source:   "`/auditLogs/directoryAudits`",
		Category: "AuditLogs",
	},
	"entra.provisioning": {
		Collects: "Provisioning (sync) events (source: graph|blob — poll `/auditLogs/provisioning`, or consume the `ProvisioningLogs` diagnostic-settings container; exactly one per config)",
		Source:   "`/auditLogs/provisioning`",
		Category: "ProvisioningLogs",
	},
	"entra.risk_detections": {
		Collects: "Identity Protection risk detection events (`$top` capped at 500, not 1000)",
		Source:   "`/identityProtection/riskDetections`",
	},
	"entra.security_alerts": {
		Collects: "Security alerts (`alerts_v2`)",
		Source:   "`/security/alerts_v2`",
	},
	"entra.security_incidents": {
		Collects: "Security incidents — the correlation layer above `alerts_v2`, grouping related alerts into one investigation (`$top` capped at 50, not 1000)",
		Source:   "`/security/incidents`",
	},

	// ---- Entra ID — blob collectors ----
	"entra.graph_activity": {
		Collects: "One record per Graph API call made against the tenant: which app or user called which endpoint, with which permissions, from where, and what came back. Graph has no endpoint for its own API-call telemetry — none, permanently — so this signal exists only as diagnostic-settings output, and it is what justifies the whole blob path",
		Category: "MicrosoftGraphActivityLogs",
	},
	"entra.signins.microsoft_service_principal": {
		Collects: "Sign-ins by Microsoft's own first-party service principals. No `.blob` suffix because this category has no Graph route and so no polled twin to disambiguate from",
		Category: "MicrosoftServicePrincipalSignInLogs",
	},
	"entra.signins.service_principal.blob": {
		Collects: "Service principal sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.service_principal` (1375/1375), so exactly one of the pair may be enabled; registering both is refused at startup",
		Category: "ServicePrincipalSignInLogs",
	},
	"entra.signins.non_interactive.blob": {
		Collects: "Non-interactive sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.non_interactive` (18/18), so exactly one of the pair may be enabled; registering both is refused at startup",
		Category: "NonInteractiveUserSignInLogs",
	},

	// ---- Defender — blob collectors (advanced-hunting tables, #106) ----
	"defender.device_registry": {
		Collects: "One log per Windows registry create/set/delete Defender for Endpoint observes (`DeviceRegistryEvents`) — a primary persistence-hunting signal (Run keys, service installs, policy tampering) Graph exposes nowhere. Each record pairs the registry change with the full InitiatingProcess block, so a LogQL join answers which process wrote a key. Experimental + off by default (highest-volume surface; opt in per tenant)",
		Category: "AdvancedHunting-DeviceRegistryEvents",
	},

	// ---- Intune — snapshot collectors ----
	"intune.apple_tokens": {
		Collects: "APNS/VPP token expiry + synced device counts; DEP onboarding settings polled best-effort",
		Source:   "`/deviceManagement/applePushNotificationCertificate`, `/deviceAppManagement/vppTokens`, `/deviceManagement/depOnboardingSettings` (beta, isolated)",
		Gating:   "APNS/VPP are v1.0 and default-on; the DEP sub-fetch is beta but isolated, so it does not gate the collector",
	},
	"intune.app_protection": {
		Collects: "App protection (MAM) policy inventory + assignment state; flagged registrations; WIP policy count",
		Source:   "`/deviceAppManagement/iosManagedAppProtections`, `androidManagedAppProtections`, `targetedManagedAppConfigurations`, `windowsInformationProtectionPolicies`, `mdmWindowsInformationProtectionPolicies`",
	},
	"intune.autopilot": {
		Collects: "Autopilot device registration + deployment profile state",
		Source:   "`/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles",
	},
	"intune.certificates": {
		Collects: "Certificate state + days-until-expiry",
		Source:   "`/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates`",
	},
	"intune.compliance": {
		Collects: "Tenant-wide + per-policy compliance state rollups",
		Source:   "`/deviceManagement/deviceCompliancePolicies`, device compliance states",
	},
	"intune.config_profiles": {
		Collects: "Configuration profile status + version, per-setting state",
		Source:   "`/deviceManagement/deviceConfigurations` (fan-out per profile)",
	},
	"intune.connectors": {
		Collects: "Exchange/MTD/NDES connector health",
		Source:   "`/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated)",
		Gating:   "Exchange/MTD are default-on; the NDES sub-fetch is beta and isolated, so its failure does not gate the collector",
	},
	"intune.detected_apps": {
		Collects: "Detected-apps software inventory catalog",
		Source:   "`/deviceManagement/detectedApps`",
	},
	"intune.endpoint_analytics": {
		Collects: "UXA per-device scores, boot/login time histograms, app crash counts, battery health, resource performance — the heaviest collector",
		Source:   "`/deviceManagement/userExperienceAnalytics*` (v1.0 + beta)",
	},
	"intune.enrollment": {
		Collects: "Enrollment configuration inventory (restrictions, VPP, ESP, etc.) + priority + version",
		Source:   "`/deviceManagement/deviceEnrollmentConfigurations`",
	},
	"intune.gpo_analytics": {
		Collects: "GPO migration readiness/analytics reports",
		Source:   "`/deviceManagement/groupPolicyMigrationReports`, `/deviceManagement/groupPolicyConfigurations`",
	},
	"intune.malware": {
		Collects: "Tenant malware/Defender overview (detected devices, by severity/category), per-device Defender protection/product state",
		Source:   "`/deviceManagement/windowsMalwareOverview`, `/deviceManagement/managedDevices/{id}/windowsProtectionState`",
	},
	"intune.devices": {
		Collects: "Managed-device inventory, encryption, sync recency, enrolled/MDM/dual-enrolled overview, plus a log twin per device. The full-fleet page-walk is irreducible by design: the per-device twins ARE the deliverable, so the bounded `managedDeviceOverview` cross-check cannot replace it",
		Source:   "`/deviceManagement/managedDevices`, `managedDeviceOverview`",
	},
	"intune.mobile_apps": {
		Collects: "Mobile app catalog (type, publishing state); mobile app config policy status",
		Source:   "`/deviceAppManagement/mobileApps`, app configs",
	},
	"intune.scripts": {
		Collects: "Script/remediation inventory, run summaries, and remediation overview",
		Source:   "`/deviceManagement/deviceManagementScripts` (Windows), `deviceShellScripts` (macOS), `deviceHealthScripts` (+ `getRemediationSummary`)",
	},
	"intune.settings_catalog": {
		Collects: "Settings Catalog policy inventory, template-based intents + per-intent device state, security baseline device state",
		Source:   "`/deviceManagement/configurationPolicies` (beta), `/deviceManagement/intents` (+ `deviceStateSummary`), `/deviceManagement/templates/{id}/deviceStateSummary`",
	},
	"intune.updates": {
		Collects: "Windows Update rings + feature/quality/driver update profile state, pause/rollback",
		Source:   "`/deviceManagement/deviceConfigurations` (ring subtype only, v1.0), `/deviceManagement/windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`/`Policies`, `windowsDriverUpdateProfiles` (beta)",
		Gating:   "the whole collector is gated as one unit: its most-valuable signal — the feature/quality/driver profile families — is beta-only, and the ring metrics, though v1.0-sourced, ship inside the same opt-in rather than splitting into a separate v1.0-default collector",
	},
	"intune.app_install_status": {
		Collects: "Per-device app install status, via the Reports Export API: POST a job, poll it, download and parse the CSV. Uses the `AppInstallStatusAggregate` report — the per-app variant has no fleet-wide form",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.cert_inventory": {
		Collects: "Device certificate inventory (thumbprints, serials, subject/issuer), via the Reports Export API",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.defender_agents": {
		Collects: "Defender agent health, via the Reports Export API",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},

	// ---- Intune — window collectors ----
	"intune.audit_events": {
		Collects: "Intune audit events. Emits the NAMES of changed `modifiedProperties` but never their old/new values, which can carry credentials and certificates — the one genuine content exclusion in graph2otel",
		Source:   "`/deviceManagement/auditEvents`",
	},
	"intune.enrollment_events": {
		Collects: "Enrollment troubleshooting events. The endpoint rejects a server-side `$filter` on its time field, so the window is bounded client-side instead",
		Source:   "`/deviceManagement/troubleshootingEvents`",
	},
	"intune.autopilot_events": {
		Collects: "Autopilot deployment/enrollment events. Also rejects a server-side time `$filter`, so the window is bounded client-side",
		Source:   "`/deviceManagement/autopilotEvents` (beta, no v1.0 equivalent)",
	},

	// ---- M365 — window collectors ----
	"m365.unified_audit": {
		Collects: "The M365 unified audit log, via the async query API: POST a query, poll it, page the result. Its records are not Entra's, so they land under a top-level `m365.audit` event name. The same signal as `m365.activity` over a different transport — NOT superseded by it. The two trade against each other: this one loses on transport (beta-only, a >10-minute async query, and it 429s on rapid query creation) and wins on volume control, because it sends server-side `recordTypeFilters` and can therefore take Teams while excluding the `DLPEndpoint` firehose — which `m365.activity`'s five content-type buckets cannot express. Worth nothing where log storage is free, decisive where it is billed per GB. The uncomfortable part: the cheaper path is the beta one. Exactly one of the two may be enabled; registering both is refused at startup",
		Source:   "`POST /security/auditLog/queries` (beta — the documented v1.0 form 404s on a live tenant even under a token carrying the scope)",
	},
	"m365.activity": {
		Collects: "The same M365 unified audit records as `m365.unified_audit`, over the Office 365 Management Activity API instead: subscribe to a content type, list its content blobs, fetch each. Wins on transport — stable v1.0, 2,000 req/min per tenant, content ~2 minutes behind the event, and no async query — which is why this one is not Experimental. Loses on volume control: the API has NO server-side filtering, so `o365_activity.content_types` is the only knob and every record fetched is shipped. Defaults to Audit.Exchange + Audit.SharePoint; Audit.General is opt-in (it is the only route to Teams here, and it was 3,865 of 4,035 records Endpoint DLP on a 6-device tenant — the firehose `m365.unified_audit` can filter out server-side and this cannot), and Audit.AzureActiveDirectory is omitted because `entra.signins.interactive` and `entra.directory_audits` already emit those records. Exactly one of the two may be enabled; registering both is refused at startup",
		Source:   "`manage.office.com/api/v1.0/{tenant}/activity/feed` — a second first-party API, NOT Graph: different audience, and `POST /subscriptions/start` is a write (the second break in graph2otel's read-only property, after the reports-export job)",
	},

	// ---- Purview — snapshot collectors ----
	"purview.sensitivity_labels": {
		Collects: "Sensitivity label catalog: a count by applicable-to type, plus a log twin per label carrying its priority and `hasProtection` — which is how label encryption activation is readable at all. Bind the label's text to `name`: `displayName` is present but always null",
		Source:   "`/security/dataSecurityAndGovernance/sensitivityLabels`",
	},
	"purview.retention_labels": {
		Collects: "Retention label definitions + retention event types, each with a log twin. Blocked app-only on a live tenant — both endpoints 500 with `DataInsightsRequestError`/Forbidden even with the scope granted, because Microsoft documents Application access as not supported — so the collector recognizes that specific pair and reports unavailable rather than failing",
		Source:   "`/security/labels/retentionLabels`, `/security/triggerTypes/retentionEventTypes`",
	},
}
