package collectordoc

// annotations is the hand-written half of the collector reference: for each
// collector, the things the registry cannot know — what it is for, which Graph
// endpoints it polls, what it emits, and any license gating that lives inside
// Collect() instead of in a declared interface.
//
// Everything else in a row (interval, lag, Experimental, the declared
// capability and scopes, a blob container and cursor key) is read off the live
// registry and must NOT be repeated here — a fact with two homes is a fact that
// drifts, which is the whole reason this file exists.
//
// Adding a collector? TestCollectorAnnotationsCoverEveryCollector fails until
// there is an entry here, then TestCollectorReferenceDocInSync fails until
// docs/collectors.md is regenerated (`scripts/regen-generated.sh collectordoc`).
//
// Emits is prose rather than a generated column because metric and log-event
// names are string literals inside each collector's Collect(), invisible to the
// registry. Nothing gates them against the code today; declaring signals on the
// collector so they CAN be gated is separate work.
var annotations = map[string]Annotation{
	// ---- Entra ID — snapshot collectors ----
	"entra.agreements": {
		Collects: "Terms of Use agreements + acceptance state",
		Source:   "`/agreements`, `/agreements/{id}/acceptances`",
		Emits:    "`entra.agreements.total`, `.acceptances.total{agreement,state}`",
	},
	"entra.auth_methods_policy": {
		Collects: "Tenant-wide authentication methods policy (enabled methods, legacy methods)",
		Source:   "`/policies/authenticationMethodsPolicy`",
		Emits:    "`entra.auth_methods_policy.method.enabled{method}`, `.legacy_enabled.total{method}`",
	},
	"entra.conditional_access": {
		Collects: "CA policy + named location inventory",
		Source:   "`/identity/conditionalAccess/policies`, `/identity/conditionalAccess/namedLocations`",
		Emits:    "`entra.ca.policies.total{state}`, `entra.named_locations.total{type,is_trusted}`",
	},
	"entra.consent": {
		Collects: "OAuth2 permission grants + app-role assignment consent surface",
		Source:   "`/oauth2PermissionGrants`, app role assignments",
		Emits:    "`entra.consent.grants.total{consent_type,privilege}`",
	},
	"entra.credential_expiry": {
		Collects: "App + service principal credential (secret/certificate) expiry buckets",
		Source:   "`/applications`, `/servicePrincipals` (`$select=keyCredentials,passwordCredentials`)",
		Emits:    "`entra.credentials.expiring.total{owner_type,credential_type,expiry_bucket}`",
	},
	"entra.devices": {
		Collects: "Directory device inventory: trust type, compliance, managed state, OS, staleness",
		Source:   "`/devices`, `/devices/$count`",
		Emits:    "`entra.devices.total{trust_type}`, `.compliance.total{is_compliant}`, `.managed.total{is_managed}`, `.os.total{operating_system}`, `.stale.total{threshold_days}`",
	},
	"entra.directory_counts": {
		Collects: "Tenant-wide directory object counts by type",
		Source:   "`/{type}/$count` per object type",
		Emits:    "`entra.directory.objects.total{type}`",
	},
	"entra.domains": {
		Collects: "Domain verification/authentication posture",
		Source:   "`/domains`",
		Emits:    "`entra.domains.total{authentication_type,is_verified}`, `.federated.total`",
	},
	"entra.groups": {
		Collects: "Group population by type/membership/security/mail-enabled, role-assignable count",
		Source:   "`/groups/$count` (filtered)",
		Emits:    "`entra.groups.total{group_type,membership_type,security_enabled,mail_enabled}`, `.role_assignable.total`",
	},
	"entra.licensing": {
		Collects: "SKU consumption + prepaid/enabled units",
		Source:   "`/subscribedSkus`",
		Emits:    "`entra.license.consumed{sku}`, `.enabled{sku}`",
	},
	"entra.mfa_registration": {
		Collects: "MFA/SSPR/passwordless registration + capability status, per-method counts, admin MFA-capable split",
		Source:   "`/reports/authenticationMethods/userRegistrationDetails`",
		Emits:    "`entra.mfa.registration.users.total{status}`, `.methods.total{method}`, `.admin_mfa_capable.total{is_admin}`",
	},
	"entra.organization": {
		Collects: "Tenant posture: on-prem sync state/age, tenant age, verified domain count, tenant type",
		Source:   "`/organization`",
		Emits:    "`entra.organization.directory.sync.last_sync_age_seconds`, `.age_days`, `.verified_domains.total`, `.info{tenant_type}`",
	},
	"entra.recommendations": {
		Collects: "Entra recommendations catalog (status, priority)",
		Source:   "`/directory/recommendations` (beta)",
		Emits:    "`entra.recommendations.total{status,priority}`",
	},
	"entra.risk": {
		Collects: "Current risky-users and risky-service-principals counts, with a log twin per risky entity",
		Source:   "`/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals`",
		Gating:   "risky users need `entra_p2`, risky SPs need `workload_identities_premium` — two INDEPENDENT partial gates checked inside Collect() against the tenant's capabilities, so each half runs and emits only if its own capability is present; neither is declared as a whole-collector requirement",
		Emits:    "`entra.risky_users.total{risk_level,risk_state}`, `entra.risky_service_principals.total{risk_level,risk_state}`, plus a log twin per risky entity",
	},
	"entra.roles": {
		Collects: "Standing directory-role membership; PIM active/eligible/permanent assignment counts",
		Source:   "`/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances`",
		Gating:   "PIM half only needs `entra_p2`, checked inside Collect(): the standing-membership half runs on every tier, and without P2 the PIM assignment counts are skipped rather than zero-emitted",
		Emits:    "`entra.roles.members.total{role_name}`, `entra.pim.assignments.total{role_name,assignment_type}`, `entra.pim.permanent_assignments.total{role_name}`",
	},
	"entra.secure_score": {
		Collects: "Latest secure score + control profile catalog (Microsoft publishes at most daily, hence the hourly poll)",
		Source:   "`/security/secureScores`, `/security/secureScoreControlProfiles`",
		Emits:    "`entra.secure_score.current`/`.max`/`.percentage`, `.control_profiles.by_category{category}`, `.by_status{status}`",
	},
	"entra.signin_activity": {
		Collects: "Stale service principals / app credentials (no recent sign-in), app sign-in result summary",
		Source:   "`/reports/servicePrincipalSignInActivities`, `/reports/appCredentialSignInActivities` (beta)",
		Emits:    "`entra.serviceprincipal.signin.stale.total`, `entra.app.credential.signin.stale.total`, `entra.app.signin.summary.total`",
	},
	"entra.users": {
		Collects: "User population by account-enabled/user-type/on-prem-sync, staleness",
		Source:   "`/users`, `/users/$count` (`GET /users?…&$count=true` for signInActivity-based slices)",
		Gating:   "staleness slice only, checked inside Collect(): signInActivity needs `entra_p1` or `entra_p2`; the population counts run on every tier",
		Emits:    "`entra.users.total{account_enabled,user_type,on_premises_sync_enabled}`, `.stale.total{threshold_days}`",
	},

	// ---- Entra ID — window collectors ----
	"entra.signins.interactive": {
		Collects: "Interactive sign-in events — the v1.0 default slice, the only sign-in stream that needs no filter and so the only one that is not beta",
		Source:   "`/auditLogs/signIns` (v1.0, unfiltered)",
		Emits:    "`entra.signin`",
	},
	"entra.signins.non_interactive": {
		Collects: "Non-interactive sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
		Emits:    "`entra.signin`",
	},
	"entra.signins.service_principal": {
		Collects: "Service principal sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
		Emits:    "`entra.signin`",
	},
	"entra.signins.managed_identity": {
		Collects: "Managed identity sign-in events",
		Source:   "`/auditLogs/signIns` (beta, `signInEventTypes` filter)",
		Emits:    "`entra.signin`",
	},
	"entra.directory_audits": {
		Collects: "Directory audit log events",
		Source:   "`/auditLogs/directoryAudits`",
		Emits:    "`entra.directory_audit`",
	},
	"entra.provisioning": {
		Collects: "Provisioning (sync) events",
		Source:   "`/auditLogs/provisioning`",
		Emits:    "`entra.provisioning`",
	},
	"entra.risk_detections": {
		Collects: "Identity Protection risk detection events (`$top` capped at 500, not 1000)",
		Source:   "`/identityProtection/riskDetections`",
		Emits:    "`entra.risk_detection`",
	},
	"entra.security_alerts": {
		Collects: "Security alerts (`alerts_v2`)",
		Source:   "`/security/alerts_v2`",
		Emits:    "`entra.security_alert`",
	},
	"entra.security_incidents": {
		Collects: "Security incidents — the correlation layer above `alerts_v2`, grouping related alerts into one investigation (`$top` capped at 50, not 1000)",
		Source:   "`/security/incidents`",
		Emits:    "`entra.security_incident`",
	},

	// ---- Entra ID — blob collectors ----
	"entra.graph_activity": {
		Collects: "One record per Graph API call made against the tenant: which app or user called which endpoint, with which permissions, from where, and what came back. Graph has no endpoint for its own API-call telemetry — none, permanently — so this signal exists only as diagnostic-settings output, and it is what justifies the whole blob path",
		Category: "MicrosoftGraphActivityLogs",
		Emits:    "`entra.graph_activity`",
	},
	"entra.signins.microsoft_service_principal": {
		Collects: "Sign-ins by Microsoft's own first-party service principals. No `.blob` suffix because this category has no Graph route and so no polled twin to disambiguate from",
		Category: "MicrosoftServicePrincipalSignInLogs",
		Emits:    "`entra.signin`",
	},
	"entra.signins.service_principal.blob": {
		Collects: "Service principal sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`, so the two are dedupe-able downstream if both run",
		Category: "ServicePrincipalSignInLogs",
		Emits:    "`entra.signin`",
	},
	"entra.signins.non_interactive.blob": {
		Collects: "Non-interactive sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`, so the two are dedupe-able downstream if both run",
		Category: "NonInteractiveUserSignInLogs",
		Emits:    "`entra.signin`",
	},

	// ---- Intune — snapshot collectors ----
	"intune.apple_tokens": {
		Collects: "APNS/VPP token expiry + synced device counts; DEP onboarding settings polled best-effort",
		Source:   "`/deviceManagement/applePushNotificationCertificate`, `/deviceAppManagement/vppTokens`, `/deviceManagement/depOnboardingSettings` (beta, isolated)",
		Gating:   "APNS/VPP are v1.0 and default-on; the DEP sub-fetch is beta but isolated, so it does not gate the collector",
		Emits:    "`intune.apple_token.days_until_expiry{type,state,token_name}`, `.synced_device_count{token_name}`",
	},
	"intune.app_protection": {
		Collects: "App protection (MAM) policy inventory + assignment state; flagged registrations; WIP policy count",
		Source:   "`/deviceAppManagement/iosManagedAppProtections`, `androidManagedAppProtections`, `targetedManagedAppConfigurations`, `windowsInformationProtectionPolicies`, `mdmWindowsInformationProtectionPolicies`",
		Emits:    "`intune.app_protection.policy.count{platform,assigned}`, `.flagged_registrations{flagged_reason,platform}`, `intune.wip.policy.count{assigned}`",
	},
	"intune.autopilot": {
		Collects: "Autopilot device registration + deployment profile state",
		Source:   "`/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles",
		Emits:    "`intune.autopilot.devices{enrollment_state,group_tag}`, `.stale_contact.count{group_tag}`, `.profile.count{device_type,preprovisioning_allowed}`",
	},
	"intune.certificates": {
		Collects: "Certificate state + days-until-expiry",
		Source:   "`/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates`",
		Emits:    "`intune.certificate.days_until_expiry{expiry_bucket,state,cert_profile_name}`, `.state.count{state}`",
	},
	"intune.compliance": {
		Collects: "Tenant-wide + per-policy compliance state rollups",
		Source:   "`/deviceManagement/deviceCompliancePolicies`, device compliance states",
		Emits:    "`intune.compliance.devices{state}`, `.policy.devices{policy_name,state}`, `.policy.users{policy_name,state}`, `.policy.version{policy_name}`",
	},
	"intune.config_profiles": {
		Collects: "Configuration profile status + version, per-setting state",
		Source:   "`/deviceManagement/deviceConfigurations` (fan-out per profile)",
		Emits:    "`intune.config_profile.count{odata_type}`, `.status{profile_name,state}`, `.version{profile_name}`, `intune.setting.devices{setting_name,platform,state}`",
	},
	"intune.connectors": {
		Collects: "Exchange/MTD/NDES connector health",
		Source:   "`/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated)",
		Gating:   "Exchange/MTD are default-on; the NDES sub-fetch is beta and isolated, so its failure does not gate the collector",
		Emits:    "`intune.connector.state{connector_type,state}`, `.heartbeat_age_seconds{connector_type}`, `.mtd_platform.total{platform,enabled}`",
	},
	"intune.detected_apps": {
		Collects: "Detected-apps software inventory catalog",
		Source:   "`/deviceManagement/detectedApps`",
		Emits:    "`intune.detected_apps.device_count`, `.catalog_size`",
	},
	"intune.endpoint_analytics": {
		Collects: "UXA scores, boot/login time histograms, app crash counts, battery health, resource performance — the heaviest collector",
		Source:   "`/deviceManagement/userExperienceAnalytics*` (beta)",
		Emits:    "`intune.uxa.score{category,health_state}`, `.boot_time_ms`/`.login_time_ms{restart_category}`, `.app_crash_count{app_name}`",
	},
	"intune.enrollment": {
		Collects: "Enrollment configuration inventory (restrictions, VPP, ESP, etc.) + priority + version",
		Source:   "`/deviceManagement/deviceEnrollmentConfigurations`",
		Emits:    "`intune.enrollment_config.count{config_type}`, `.priority{config_type,config_name}`, `.version{config_name}`",
	},
	"intune.gpo_analytics": {
		Collects: "GPO migration readiness/analytics reports",
		Source:   "`/deviceManagement/groupPolicyMigrationReports`, `/deviceManagement/groupPolicyConfigurations`",
		Emits:    "`intune.gpo.migration_readiness`, `.supported_settings_percent`, `.config.count`",
	},
	"intune.malware": {
		Collects: "Tenant malware/Defender overview (detected devices, by severity/category), per-device Defender protection/product state",
		Source:   "`/deviceManagement/windowsMalwareOverview`, `/deviceManagement/managedDevices/{id}/windowsProtectionState`",
		Emits:    "`intune.malware.overview.detected_devices`/`.total`/`.by_severity{severity}`/`.by_category{category}`, `intune.defender.protection_state{signal}`, `.product_status{status}`",
	},
	"intune.devices": {
		Collects: "Managed-device inventory, encryption, sync recency, enrolled/MDM/dual-enrolled overview, plus a log twin per device. The full-fleet page-walk is irreducible by design: the per-device twins ARE the deliverable, so the bounded `managedDeviceOverview` cross-check cannot replace it",
		Source:   "`/deviceManagement/managedDevices`, `managedDeviceOverview`",
		Emits:    "`intune.devices.count{compliance_state,operating_system}`, `.encrypted.count{operating_system}`, `.sync_staleness_seconds{staleness_bucket}`, `.overview.total{os}`, `.overview.{enrolled,mdm_enrolled,dual_enrolled}_device_count`, plus a log twin per device",
	},
	"intune.mobile_apps": {
		Collects: "Mobile app catalog (type, publishing state); mobile app config policy status",
		Source:   "`/deviceAppManagement/mobileApps`, app configs",
		Emits:    "`intune.mobile_apps.count{app_type,publishing_state}`, `intune.mobile_app_config.status{policy_name,status}`",
	},
	"intune.scripts": {
		Collects: "Script/remediation inventory, run summaries, and remediation overview",
		Source:   "`/deviceManagement/deviceManagementScripts` (Windows), `deviceShellScripts` (macOS), `deviceHealthScripts` (+ `getRemediationSummary`)",
		Emits:    "`intune.script.run_summary`, `intune.remediation.summary`, `.remediated_cumulative_devices`, `.overview.script_count`, `.overview.remediated_device_count`",
	},
	"intune.settings_catalog": {
		Collects: "Settings Catalog policy inventory, template-based intents + per-intent device state, security baseline device state",
		Source:   "`/deviceManagement/configurationPolicies` (beta), `/deviceManagement/intents` (+ `deviceStateSummary`), `/deviceManagement/templates/{id}/deviceStateSummary`",
		Emits:    "`intune.settings_catalog.policy.count`, `intune.intent.count`, `.devices`, `intune.security_baseline.devices`",
	},
	"intune.updates": {
		Collects: "Windows Update rings + feature/quality/driver update profile state, pause/rollback",
		Source:   "`/deviceManagement/deviceConfigurations` (ring subtype only, v1.0), `/deviceManagement/windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`/`Policies`, `windowsDriverUpdateProfiles` (beta)",
		Gating:   "the whole collector is gated as one unit: its most-valuable signal — the feature/quality/driver profile families — is beta-only, and the ring metrics, though v1.0-sourced, ship inside the same opt-in rather than splitting into a separate v1.0-default collector",
		Emits:    "`intune.update_ring.{pause_state,pause_expiry_seconds,rollback_active,status}{ring_name,update_type,state}`, `intune.driver_update.pending_approval{profile_name}`",
	},
	"intune.app_install_status": {
		Collects: "Per-device app install status, via the Reports Export API: POST a job, poll it, download and parse the CSV. Uses the `AppInstallStatusAggregate` report — the per-app variant has no fleet-wide form",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
		Emits:    "`intune.app_install_status.*`",
	},
	"intune.cert_inventory": {
		Collects: "Device certificate inventory (thumbprints, serials, subject/issuer), via the Reports Export API",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
		Emits:    "`intune.cert_inventory.*`",
	},
	"intune.defender_agents": {
		Collects: "Defender agent health, via the Reports Export API",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
		Emits:    "`intune.defender_agents.*`",
	},

	// ---- Intune — window collectors ----
	"intune.audit_events": {
		Collects: "Intune audit events. Emits the NAMES of changed `modifiedProperties` but never their old/new values, which can carry credentials and certificates — the one genuine content exclusion in graph2otel",
		Source:   "`/deviceManagement/auditEvents`",
		Emits:    "`intune.audit_event`",
	},
	"intune.enrollment_events": {
		Collects: "Enrollment troubleshooting events. The endpoint rejects a server-side `$filter` on its time field, so the window is bounded client-side instead",
		Source:   "`/deviceManagement/troubleshootingEvents`",
		Emits:    "`intune.enrollment_event`",
	},
	"intune.autopilot_events": {
		Collects: "Autopilot deployment/enrollment events. Also rejects a server-side time `$filter`, so the window is bounded client-side",
		Source:   "`/deviceManagement/autopilotEvents` (beta, no v1.0 equivalent)",
		Emits:    "`intune.autopilot_event`",
	},

	// ---- M365 — window collectors ----
	"m365.unified_audit": {
		Collects: "The M365 unified audit log, via the async query API: POST a query, poll it, page the result. Its records are not Entra's, so they land under a top-level `m365.audit` event name. Superseded by `m365.activity`, which reaches the same records over a stable v1.0 transport — leave only one of the two enabled",
		Source:   "`POST /security/auditLog/queries` (beta — the documented v1.0 form 404s on a live tenant even under a token carrying the scope)",
		Emits:    "`m365.audit`",
	},
	"m365.activity": {
		Collects: "The same M365 unified audit records as `m365.unified_audit`, over the Office 365 Management Activity API instead: subscribe to a content type, list its content blobs, fetch each. Stable v1.0, 2,000 req/min per tenant, and no >10-minute async query — which is why this one is not Experimental. The API has NO server-side filtering, so `o365_activity.content_types` chooses what arrives and every record fetched is shipped. Defaults to Audit.Exchange + Audit.SharePoint; Audit.General is opt-in (it carries Teams, but also Endpoint DLP — 3,865 of 4,035 records on a 6-device tenant), and Audit.AzureActiveDirectory is omitted because `entra.signins.interactive` and `entra.directory_audits` already emit those records",
		Source:   "`manage.office.com/api/v1.0/{tenant}/activity/feed` — a second first-party API, NOT Graph: different audience, and `POST /subscriptions/start` is a write (the second break in graph2otel's read-only property, after the reports-export job)",
		Emits:    "`m365.audit` — the same event name and the same `id` as `m365.unified_audit`, deliberately: the Management API record IS the query API's `auditData` sub-object, so the two are drop-in equivalents and dedupe-able downstream",
	},

	// ---- Purview — snapshot collectors ----
	"purview.sensitivity_labels": {
		Collects: "Sensitivity label catalog: a count by applicable-to type, plus a log twin per label carrying its priority and `hasProtection` — which is how label encryption activation is readable at all. Bind the label's text to `name`: `displayName` is present but always null",
		Source:   "`/security/dataSecurityAndGovernance/sensitivityLabels`",
		Emits:    "`purview.labels.count{applicable_to}`, plus a log twin per label",
	},
	"purview.retention_labels": {
		Collects: "Retention label definitions + retention event types, each with a log twin. Blocked app-only on a live tenant — both endpoints 500 with `DataInsightsRequestError`/Forbidden even with the scope granted, because Microsoft documents Application access as not supported — so the collector recognizes that specific pair and reports unavailable rather than failing",
		Source:   "`/security/labels/retentionLabels`, `/security/triggerTypes/retentionEventTypes`",
		Emits:    "`purview.retention.labels.count`, `purview.retention.event_types.count`, plus a log twin per row",
	},
}
