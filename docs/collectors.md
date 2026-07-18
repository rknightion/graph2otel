# Collector reference

Every collector `graph2otel` ships: what it collects, where it reads from, the permission it needs,
license/beta gating, its poll interval, and what it emits. For how to grant Graph scopes, see
[`permissions.md`](./permissions.md); for the `collectors:` config block that enables/disables and
retunes them, see [`configuration.md`](./configuration.md).

> **The tables below are generated from the collector registry** — a collector cannot ship
> undocumented, because `go test` fails when a registered one has no entry
> ([#139](https://github.com/rknightion/graph2otel/issues/139)). Regenerate with
> `scripts/regen-generated.sh collectordoc`. Everything outside the generated block, including every
> note in this page, is hand-written and safe to edit.
>
> Facts read from the registry (interval, lag, license gate, beta flag, scopes, blob container and
> cursor key) are **not** editable here — fix the collector, then regenerate. The *Collects*,
> *Graph endpoint(s)*, and license-nuance columns are hand-written prose in
> `internal/collectordoc/annotations.go`, because they describe things the registry cannot see (what
> a collector is for, which endpoints it polls). The *Metric namespace* / *Log event* columns are
> **also generated** — from each collector package's committed `testdata/signals.json` golden
> ([#140](https://github.com/rknightion/graph2otel/issues/140)), not hand-written: that golden is a
> real capture of what the package's tests drove into an in-memory Recorder, so it cannot describe a
> signal that does not exist. Metric names show their attribute keys (`name{key1,key2}`); log event
> names appear bare — a log's attribute set runs 15–22 keys deep and is per-entity by design (see the
> cardinality rule below), so listing them here would be noise, not signal.

**Columns:**

- **License / beta** — `needs-license/<capability>` where the collector declares
  `license.CapabilityRequirer` and the composition root skips it entirely on an insufficient tier;
  `beta` where it implements `collectors.Experimental` (opt-in, off by default, backed by a Graph
  `beta`-only endpoint with no v1.0 equivalent). The capability is printed exactly as it appears in
  the skip log (`requires entra_p2`). A collector can carry both. Parenthesised text is
  hand-written nuance — most importantly for collectors that **partially** degrade: those check the
  tenant's capabilities inside `Collect()` rather than declaring a whole-collector requirement, so
  no interface reports it and the registry cannot know.
- **Interval** — the collector's `DefaultInterval()`; overridable per-collector (globally or
  per-tenant) via the `collectors:` config block.
- **Lag** — a window collector's `Lag()`: the trailing safety margin. The scheduler queries up to
  `now - Lag`, never to `now`, so records still arriving are not missed.
- **Namespace** — the `graph2otel.*` self-observability metrics (scrape duration/success/errors/
  staleness, `build_info`, series cardinality, export job stats, tenant license tier) apply to every
  collector uniformly and aren't repeated per row.

<!-- BEGIN GENERATED COLLECTOR REFERENCE (scripts/regen-generated.sh collectordoc) -->

## Entra ID — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `entra.agreements` | Terms of Use agreements + acceptance state | `/agreements`, `/agreements/{id}/acceptances` | `Agreement.Read.All`, `AgreementAcceptance.Read.All` | `needs-license/entra_p1` | 15m | `entra.agreements.acceptances.total{agreement,state}`, `entra.agreements.total` |
| `entra.auth_methods_policy` | Tenant-wide authentication methods policy (enabled methods, legacy methods) | `/policies/authenticationMethodsPolicy` | `Policy.Read.AuthenticationMethod` | — | 15m | `entra.auth_methods_policy.legacy_enabled.total`, `entra.auth_methods_policy.method.enabled{method}` |
| `entra.conditional_access` | CA policy + named location inventory | `/identity/conditionalAccess/policies`, `/identity/conditionalAccess/namedLocations` | `Policy.Read.All` | `needs-license/entra_p1` | 15m | `entra.ca.policies.total{state}`, `entra.named_locations.total{is_trusted,type}` |
| `entra.consent` | OAuth2 permission grants + app-role assignment consent surface | `/oauth2PermissionGrants`, app role assignments | `Directory.Read.All`, `Application.Read.All` | — | 15m | `entra.consent.grants.total{consent_type,privilege}`, plus a log twin per `entra.consent_grant` |
| `entra.credential_expiry` | App + service principal credential (secret/certificate) expiry buckets | `/applications`, `/servicePrincipals` (`$select=keyCredentials,passwordCredentials`) | `Application.Read.All` | — | 15m | `entra.credentials.expiring.total{credential_type,expiry_bucket,owner_type}`, plus a log twin per `entra.app_credential` |
| `entra.devices` | Directory device inventory: trust type, compliance, managed state, OS, staleness | `/devices`, `/devices/$count` | `Device.Read.All` | — | 15m | `entra.devices.compliance.total{is_compliant}`, `entra.devices.managed.total{is_managed}`, `entra.devices.os.total{operating_system}`, `entra.devices.stale.total{threshold_days}`, `entra.devices.total{trust_type}` |
| `entra.directory_counts` | Tenant-wide directory object counts by type | `/{type}/$count` per object type | `Directory.Read.All` | — | 5m | `entra.directory.objects.total{type}` |
| `entra.domains` | Domain verification/authentication posture | `/domains` | `Domain.Read.All` | — | 15m | `entra.domains.federated.total`, `entra.domains.total{authentication_type,is_verified}`, plus a log twin per `entra.domain` |
| `entra.groups` | Group population by type/membership/security/mail-enabled, role-assignable count | `/groups/$count` (filtered) | `Group.Read.All` | — | 5m | `entra.groups.role_assignable.total`, `entra.groups.total{group_type,mail_enabled,membership_type,security_enabled}` |
| `entra.licensing` | SKU consumption + prepaid/enabled units | `/subscribedSkus` | `LicenseAssignment.Read.All`, `Group.Read.All` | — | 15m | `entra.license.capability_status{sku,status}`, `entra.license.consumed{sku}`, `entra.license.enabled{sku}`, `entra.license.groups_with_errors.total`, `entra.license.units{sku,state}`, plus a log twin per `entra.license_group_error` |
| `entra.mfa_registration` | MFA/SSPR/passwordless registration + capability status, per-method counts, admin MFA-capable split | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | `needs-license/entra_p1` | 1h | `entra.mfa.registration.admin_mfa_capable.total{is_admin}`, `entra.mfa.registration.methods.total{method}`, `entra.mfa.registration.users.total{status,user_type}`, plus a log twin per `entra.user_registration` |
| `entra.organization` | Tenant posture: on-prem sync state/age, tenant age, verified domain count, tenant type | `/organization` | `Organization.Read.All` | — | 15m | `entra.directory.sync.last_sync_age_seconds`, `entra.organization.age_days`, `entra.organization.info{tenant_type}`, `entra.organization.on_premises_sync_enabled`, `entra.organization.verified_domains.total` |
| `entra.recommendations` | Entra recommendations catalog (status, priority) | `/directory/recommendations` (beta) | `DirectoryRecommendations.Read.All` | `beta` | 30m | `entra.recommendations.impacted_resources.total{recommendation}`, `entra.recommendations.total{priority,status}` |
| `entra.risk` | Current risky-users and risky-service-principals counts, with a log twin per risky entity | `/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals` | `IdentityRiskyUser.Read.All`, `IdentityRiskyServicePrincipal.Read.All` | risky users need `entra_p2`, risky SPs need `workload_identities_premium` — two INDEPENDENT partial gates checked inside Collect() against the tenant's capabilities, so each half runs and emits only if its own capability is present; neither is declared as a whole-collector requirement | 15m | `entra.risky_service_principals.total{risk_level,risk_state}`, `entra.risky_users.total{risk_level,risk_state}`, plus a log twin per `entra.risky_service_principal`, `entra.risky_user` |
| `entra.roles` | Standing directory-role membership; PIM active/eligible/permanent assignment counts | `/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances` | `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` | PIM half only needs `entra_p2`, checked inside Collect(): the standing-membership half runs on every tier, and without P2 the PIM assignment counts are skipped rather than zero-emitted | 10m | `entra.pim.assignments.total{assignment_type,role_name}`, `entra.pim.permanent_assignments.total{role_name}`, `entra.roles.members.total{role_name}`, plus a log twin per `entra.role_member` |
| `entra.secure_score` | Latest secure score + control profile catalog (Microsoft publishes at most daily, hence the hourly poll) | `/security/secureScores`, `/security/secureScoreControlProfiles` | `SecurityEvents.Read.All` | — | 1h | `entra.secure_score.control_profiles.by_category{category}`, `entra.secure_score.control_profiles.by_status{status}`, `entra.secure_score.current`, `entra.secure_score.max`, `entra.secure_score.percentage` |
| `entra.signin_activity` | Stale service principals / app credentials (no recent sign-in), app sign-in result summary | `/reports/servicePrincipalSignInActivities`, `/reports/appCredentialSignInActivities` (beta) | `AuditLog.Read.All`, `Reports.Read.All` | `needs-license/entra_p1`, `beta` | 1h | `entra.app.credential.signin.stale.total{threshold_days}`, `entra.app.signin.summary.total{result}`, `entra.serviceprincipal.signin.stale.total{threshold_days}`, plus a log twin per `entra.app_signin_activity` |
| `entra.syncerrors` | Hybrid directory-sync provisioning errors (onPremisesProvisioningErrors) — UPN/proxy-address conflicts that fail silently while sync freshness stays green — bucketed by object type/category/property, plus a log twin per errored object carrying the conflicting value | `/organization` (sync-state probe), `/users` (full page-walk, client-side filtered) | `User.Read.All`, `Organization.Read.All` | runs on every tier (both endpoints are v1.0 stable, not beta); no-ops without paging when the tenant is cloud-only, i.e. onPremisesSyncEnabled is false or null, so only hybrid-synced tenants pay the full /users sweep | 6h | `entra.directory.sync.errors.total{category,object_type,property_causing_error}`, plus a log twin per `entra.directory_sync_error` |
| `entra.users` | User population by account-enabled/user-type/on-prem-sync (marginal + joint user_type×account_enabled), staleness | `/users`, `/users/$count` (`GET /users?…&$count=true` for signInActivity-based slices) | `User.Read.All`, `AuditLog.Read.All` | staleness slice only, checked inside Collect(): signInActivity needs `entra_p1` or `entra_p2`; the population counts run on every tier | 15m | `entra.users.population{account_enabled,user_type}`, `entra.users.stale.total{threshold_days}`, `entra.users.total{account_enabled,on_premises_sync_enabled,user_type}` |

## Entra ID — logs (window collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Lag | Log event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `entra.directory_audits` | Directory audit log events (source: graph\|blob — poll `/auditLogs/directoryAudits`, or consume the `AuditLogs` diagnostic-settings container; exactly one per config) | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | — | 5m | 15m | `entra.directory_audit` |
| `entra.provisioning` | Provisioning (sync) events (source: graph\|blob — poll `/auditLogs/provisioning`, or consume the `ProvisioningLogs` diagnostic-settings container; exactly one per config) | `/auditLogs/provisioning` | `AuditLog.Read.All` | — | 15m | 15m | `entra.provisioning` |
| `entra.risk_detections` | Identity Protection risk detection events (`$top` capped at 500, not 1000) | `/identityProtection/riskDetections` | `IdentityRiskEvent.Read.All` | `needs-license/entra_p2` | 30m | 15m | `entra.risk_detection` |
| `entra.security_alerts` | Security alerts (`alerts_v2`) | `/security/alerts_v2` | `SecurityAlert.Read.All` | — | 10m | 15m | `entra.security_alert` |
| `entra.security_incidents` | Security incidents — the correlation layer above `alerts_v2`, grouping related alerts into one investigation (`$top` capped at 50, not 1000) | `/security/incidents` | `SecurityIncident.Read.All` | — | 12m | 15m | `entra.security_incident` |
| `entra.signins.interactive` | Interactive sign-in events — the v1.0 default slice, the only sign-in stream that needs no filter and so the only one that is not beta | `/auditLogs/signIns` (v1.0, unfiltered) | `AuditLog.Read.All` | `needs-license/entra_p1` | 5m | 15m | `entra.signin` |
| `entra.signins.non_interactive` | Non-interactive sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/entra_p1`, `beta` | 5m | 15m | `entra.signin` |
| `entra.signins.service_principal` | Service principal sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/entra_p1`, `beta` | 5m | 15m | `entra.signin` |
| `entra.signins.managed_identity` | Managed identity sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/entra_p1`, `beta` | 5m | 15m | `entra.signin` |

## Entra ID — logs (blob collectors)

| Collector | Collects | Container (diagnostic category) | Cursor key | Required role | License / beta | Interval | Log event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `entra.directory_audits` | Directory audit log events (source: graph\|blob — poll `/auditLogs/directoryAudits`, or consume the `AuditLogs` diagnostic-settings container; exactly one per config) | `insights-logs-auditlogs` (AuditLogs) | `insights-logs-auditlogs` | `Storage Blob Data Reader` | — | 5m | `entra.directory_audit` |
| `entra.graph_activity` | One record per Graph API call made against the tenant: which app or user called which endpoint, with which permissions, from where, and what came back. Graph has no endpoint for its own API-call telemetry — none, permanently — so this signal exists only as diagnostic-settings output, and it is what justifies the whole blob path | `insights-logs-microsoftgraphactivitylogs` (MicrosoftGraphActivityLogs) | `insights-logs-microsoftgraphactivitylogs` | `Storage Blob Data Reader` | — | 5m | `entra.graph_activity` |
| `entra.provisioning` | Provisioning (sync) events (source: graph\|blob — poll `/auditLogs/provisioning`, or consume the `ProvisioningLogs` diagnostic-settings container; exactly one per config) | `insights-logs-provisioninglogs` (ProvisioningLogs) | `insights-logs-provisioninglogs` | `Storage Blob Data Reader` | — | 5m | `entra.provisioning` |
| `entra.signins.microsoft_service_principal` | Sign-ins by Microsoft's own first-party service principals. No `.blob` suffix because this category has no Graph route and so no polled twin to disambiguate from | `insights-logs-microsoftserviceprincipalsigninlogs` (MicrosoftServicePrincipalSignInLogs) | `insights-logs-microsoftserviceprincipalsigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |
| `entra.signins.service_principal.blob` | Service principal sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.service_principal` (1375/1375), so exactly one of the pair may be enabled; registering both is refused at startup | `insights-logs-serviceprincipalsigninlogs` (ServicePrincipalSignInLogs) | `insights-logs-serviceprincipalsigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |
| `entra.signins.non_interactive.blob` | Non-interactive sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.non_interactive` (18/18), so exactly one of the pair may be enabled; registering both is refused at startup | `insights-logs-noninteractiveusersigninlogs` (NonInteractiveUserSignInLogs) | `insights-logs-noninteractiveusersigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |

## Intune — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `intune.app_install_status` | Per-device app install status, via the Reports Export API: POST a job, poll it, download and parse the CSV. Uses the `AppInstallStatusAggregate` report — the per-app variant has no fleet-wide form | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.app_install_status.installations{install_state,platform}`, plus a log twin per `intune.app_install_status` |
| `intune.apple_tokens` | APNS/VPP token expiry + synced device counts; DEP onboarding settings polled best-effort | `/deviceManagement/applePushNotificationCertificate`, `/deviceAppManagement/vppTokens`, `/deviceManagement/depOnboardingSettings` (beta, isolated) | `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All` | APNS/VPP are v1.0 and default-on; the DEP sub-fetch is beta but isolated, so it does not gate the collector | 6h | `intune.apple_token.days_until_expiry{state,token_name,type}`, `intune.apple_token.synced_device_count{token_name}` |
| `intune.app_protection` | App protection (MAM) policy inventory + assignment state; flagged registrations; WIP policy count | `/deviceAppManagement/iosManagedAppProtections`, `androidManagedAppProtections`, `targetedManagedAppConfigurations`, `windowsInformationProtectionPolicies`, `mdmWindowsInformationProtectionPolicies` | `DeviceManagementApps.Read.All` | — | 30m | `intune.app_protection.flagged_registrations{flagged_reason,platform}`, `intune.app_protection.policy.count{assigned,platform}`, `intune.wip.policy.count{assigned}`, plus a log twin per `intune.app_registration` |
| `intune.autopilot` | Autopilot device registration + deployment profile state | `/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles | `DeviceManagementServiceConfig.Read.All` | `beta` | 30m | `intune.autopilot.devices{enrollment_state,group_tag}`, `intune.autopilot.profile.assignments{profile_name}`, `intune.autopilot.profile.count{device_type,preprovisioning_allowed}`, `intune.autopilot.profile.esp_timeout_minutes{profile_name}`, `intune.autopilot.profile.setting{profile_name,setting}`, `intune.autopilot.stale_contact.count{group_tag}` |
| `intune.certificates` | Certificate state + days-until-expiry | `/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.certificate.days_until_expiry{cert_profile_name,expiry_bucket,state}`, `intune.certificate.state.count{state}`, plus a log twin per `intune.device_certificate` |
| `intune.cert_inventory` | Device certificate inventory (thumbprints, serials, subject/issuer), via the Reports Export API | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.cert_inventory.days_until_expiry{bucket,issuer}`, `intune.cert_inventory.state{state}`, plus a log twin per `intune.device_certificate` |
| `intune.compliance` | Tenant-wide + per-policy compliance state rollups | `/deviceManagement/deviceCompliancePolicies`, device compliance states | `DeviceManagementConfiguration.Read.All` | — | 15m | `intune.compliance.devices{state}`, `intune.compliance.policy.devices{policy_name,state}`, `intune.compliance.policy.users{policy_name,state}`, `intune.compliance.policy.version{policy_name}`, `intune.compliance.setting.devices{platform,setting_name,state}` |
| `intune.config_profiles` | Configuration profile status + version, per-setting state | `/deviceManagement/deviceConfigurations` (fan-out per profile) | `DeviceManagementConfiguration.Read.All` | — | 30m | `intune.config_profile.count{odata_type}`, `intune.config_profile.status{profile_name,state}`, `intune.config_profile.version{profile_name}` |
| `intune.connectors` | Exchange/MTD/NDES connector health | `/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated) | `DeviceManagementServiceConfig.Read.All` | Exchange/MTD are default-on; the NDES sub-fetch is beta and isolated, so its failure does not gate the collector | 15m | `intune.connector.heartbeat_age_seconds{connector_type}`, `intune.connector.mtd_platform.total{enabled,platform}`, `intune.connector.state{connector_type,state}` |
| `intune.defender_agents` | Defender agent health, via the Reports Export API | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.defender_agents.count{signal}`, `intune.defender_agents.product_status{status}`, plus a log twin per `intune.defender_agent` |
| `intune.detected_apps` | Detected-apps software inventory catalog | `/deviceManagement/detectedApps` | `DeviceManagementManagedDevices.Read.All` | — | 1h | `intune.detected_apps.catalog_size`, `intune.detected_apps.device_count{app_name,platform}` |
| `intune.endpoint_analytics` | UXA scores, boot/login time histograms, app crash counts, battery health, resource performance — the heaviest collector | `/deviceManagement/userExperienceAnalytics*` (beta) | `DeviceManagementManagedDevices.Read.All` | `beta` | 1h | `intune.uxa.app_crash_count{app_name}`, `intune.uxa.baseline_score{baseline_name,is_built_in}`, `intune.uxa.battery_health.device_count{health_state}`, `intune.uxa.battery_health_score{health_state}`, `intune.uxa.boot_time_ms{restart_category}`, `intune.uxa.login_time_ms{restart_category}`, `intune.uxa.resource_performance.device_count{health_state}`, `intune.uxa.resource_performance_score{health_state}`, `intune.uxa.score{category,health_state}` |
| `intune.enrollment` | Enrollment configuration inventory (restrictions, VPP, ESP, etc.) + priority + version | `/deviceManagement/deviceEnrollmentConfigurations` | `DeviceManagementServiceConfig.Read.All` | — | 15m | `intune.enrollment_config.count{config_type}`, `intune.enrollment_config.priority{config_name,config_type}`, `intune.enrollment_config.version{config_name}` |
| `intune.gpo_analytics` | GPO migration readiness/analytics reports | `/deviceManagement/groupPolicyMigrationReports`, `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | `beta` | 24h | `intune.gpo.config.count{ingestion_type}`, `intune.gpo.migration_readiness{readiness,report_name}`, `intune.gpo.supported_settings_percent{report_name}` |
| `intune.malware` | Tenant malware/Defender overview (detected devices, by severity/category), per-device Defender protection/product state | `/deviceManagement/windowsMalwareOverview`, `/deviceManagement/managedDevices/{id}/windowsProtectionState` | `DeviceManagementManagedDevices.Read.All` | — | 30m | `intune.defender.product_status{status}`, `intune.defender.protection_state{signal}`, `intune.malware.overview.by_category{category}`, `intune.malware.overview.by_severity{severity}`, `intune.malware.overview.detected_devices`, `intune.malware.overview.total`, plus a log twin per `intune.device_malware_state` |
| `intune.devices` | Managed-device inventory, encryption, sync recency, enrolled/MDM/dual-enrolled overview, plus a log twin per device. The full-fleet page-walk is irreducible by design: the per-device twins ARE the deliverable, so the bounded `managedDeviceOverview` cross-check cannot replace it | `/deviceManagement/managedDevices`, `managedDeviceOverview` | `DeviceManagementManagedDevices.Read.All` | — | 1h | `intune.devices.count{compliance_state,operating_system}`, `intune.devices.encrypted.count{operating_system}`, `intune.devices.os_version.count{operating_system,os_version}`, `intune.devices.overview.dual_enrolled_device_count`, `intune.devices.overview.enrolled_device_count`, `intune.devices.overview.mdm_enrolled_device_count`, `intune.devices.overview.total{os}`, `intune.devices.sync_staleness_seconds{staleness_bucket}`, plus a log twin per `intune.managed_device` |
| `intune.mobile_apps` | Mobile app catalog (type, publishing state); mobile app config policy status | `/deviceAppManagement/mobileApps`, app configs | `DeviceManagementApps.Read.All` | — | 30m | `intune.mobile_app_config.status{policy_name,status}`, `intune.mobile_apps.count{app_type,publishing_state}` |
| `intune.scripts` | Script/remediation inventory, run summaries, and remediation overview | `/deviceManagement/deviceManagementScripts` (Windows), `deviceShellScripts` (macOS), `deviceHealthScripts` (+ `getRemediationSummary`) | `DeviceManagementScripts.Read.All` | `beta` | 30m | `intune.remediation.overview.remediated_device_count`, `intune.remediation.overview.script_count`, `intune.remediation.remediated_cumulative_devices{script_name}`, `intune.remediation.summary{phase,script_name,state}`, `intune.script.run_summary{os,run_state,script_name,target}` |
| `intune.settings_catalog` | Settings Catalog policy inventory, template-based intents + per-intent device state, security baseline device state | `/deviceManagement/configurationPolicies` (beta), `/deviceManagement/intents` (+ `deviceStateSummary`), `/deviceManagement/templates/{id}/deviceStateSummary` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.intent.count{migrating}`, `intune.intent.devices{compliance_status,intent_name}`, `intune.security_baseline.devices{baseline_name,state}`, `intune.settings_catalog.policy.count{platform,technology,template_family}` |
| `intune.updates` | Windows Update rings + feature/quality/driver update profile state, pause/rollback | `/deviceManagement/deviceConfigurations` (ring subtype only, v1.0), `/deviceManagement/windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`/`Policies`, `windowsDriverUpdateProfiles` (beta) | `DeviceManagementConfiguration.Read.All` | `beta` (the whole collector is gated as one unit: its most-valuable signal — the feature/quality/driver profile families — is beta-only, and the ring metrics, though v1.0-sourced, ship inside the same opt-in rather than splitting into a separate v1.0-default collector) | 30m | `intune.driver_update.pending_approval{profile_name}`, `intune.driver_update.sync_staleness_seconds{profile_name}`, `intune.feature_update_profile.eol_target{feature_update_version,profile_name}`, `intune.quality_update_config.count{resource_type}`, `intune.update_ring.pause_expiry_seconds{ring_name,update_type}`, `intune.update_ring.pause_state{ring_name,update_type}`, `intune.update_ring.rollback_active{ring_name,update_type}`, `intune.update_ring.status{ring_name,state}` |

## Intune — logs (window collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Lag | Log event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `intune.audit_events` | Intune audit events. Emits the NAMES of changed `modifiedProperties` but never their old/new values, which can carry credentials and certificates — the one genuine content exclusion in graph2otel | `/deviceManagement/auditEvents` | `DeviceManagementApps.Read.All` | — | 15m | 15m | `intune.audit_event` |
| `intune.autopilot_events` | Autopilot deployment/enrollment events. Also rejects a server-side time `$filter`, so the window is bounded client-side | `/deviceManagement/autopilotEvents` (beta, no v1.0 equivalent) | `DeviceManagementManagedDevices.Read.All` | `beta` | 20m | — | `intune.autopilot_event` |
| `intune.enrollment_events` | Enrollment troubleshooting events. The endpoint rejects a server-side `$filter` on its time field, so the window is bounded client-side instead | `/deviceManagement/troubleshootingEvents` | `DeviceManagementManagedDevices.Read.All` | `needs-license/intune` | 20m | 15m | `intune.enrollment_event` |

## M365 — logs (window collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Lag | Log event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `m365.unified_audit` | The M365 unified audit log, via the async query API: POST a query, poll it, page the result. Its records are not Entra's, so they land under a top-level `m365.audit` event name. The same signal as `m365.activity` over a different transport — NOT superseded by it. The two trade against each other: this one loses on transport (beta-only, a >10-minute async query, and it 429s on rapid query creation) and wins on volume control, because it sends server-side `recordTypeFilters` and can therefore take Teams while excluding the `DLPEndpoint` firehose — which `m365.activity`'s five content-type buckets cannot express. Worth nothing where log storage is free, decisive where it is billed per GB. The uncomfortable part: the cheaper path is the beta one. Exactly one of the two may be enabled; registering both is refused at startup | `POST /security/auditLog/queries` (beta — the documented v1.0 form 404s on a live tenant even under a token carrying the scope) | `AuditLogsQuery.Read.All` | `beta` | 30m | 1h | `m365.audit` |
| `m365.activity` | The same M365 unified audit records as `m365.unified_audit`, over the Office 365 Management Activity API instead: subscribe to a content type, list its content blobs, fetch each. Wins on transport — stable v1.0, 2,000 req/min per tenant, content ~2 minutes behind the event, and no async query — which is why this one is not Experimental. Loses on volume control: the API has NO server-side filtering, so `o365_activity.content_types` is the only knob and every record fetched is shipped. Defaults to Audit.Exchange + Audit.SharePoint; Audit.General is opt-in (it is the only route to Teams here, and it was 3,865 of 4,035 records Endpoint DLP on a 6-device tenant — the firehose `m365.unified_audit` can filter out server-side and this cannot), and Audit.AzureActiveDirectory is omitted because `entra.signins.interactive` and `entra.directory_audits` already emit those records. Exactly one of the two may be enabled; registering both is refused at startup | `manage.office.com/api/v1.0/{tenant}/activity/feed` — a second first-party API, NOT Graph: different audience, and `POST /subscriptions/start` is a write (the second break in graph2otel's read-only property, after the reports-export job) | `ActivityFeed.Read` | — | 10m | 5m | `m365.audit` |

## Purview — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `purview.retention_labels` | Retention label definitions + retention event types, each with a log twin. Blocked app-only on a live tenant — both endpoints 500 with `DataInsightsRequestError`/Forbidden even with the scope granted, because Microsoft documents Application access as not supported — so the collector recognizes that specific pair and reports unavailable rather than failing | `/security/labels/retentionLabels`, `/security/triggerTypes/retentionEventTypes` | `RecordsManagement.Read.All` | `needs-license/purview_records_management` | 1h | `purview.retention.event_types.count`, `purview.retention.labels.count{action_after_retention,behavior_during_retention,retention_trigger}`, plus a log twin per `purview.retention_event_type`, `purview.retention_label` |
| `purview.sensitivity_labels` | Sensitivity label catalog: a count by applicable-to type, plus a log twin per label carrying its priority and `hasProtection` — which is how label encryption activation is readable at all. Bind the label's text to `name`: `displayName` is present but always null | `/security/dataSecurityAndGovernance/sensitivityLabels` | `SensitivityLabel.Read` | `needs-license/purview_information_protection` | 1h | `purview.labels.count{applicable_to}`, plus a log twin per `purview.sensitivity_label` |

<!-- END GENERATED COLLECTOR REFERENCE -->

## Notes

### The four polled sign-in streams are four collectors, not one

They all poll `/auditLogs/signIns`, but `signInEventTypes` filters cannot be combined into a single
query, so each event type needs its own poller. Each owns a distinct `CheckpointKey`
(`/auditLogs/signIns#<eventType>`) — without that they would share one checkpoint namespace and
dedupe each other's events away. The `beta` gate on three of them is about the `signInEventTypes`
filter, which returns HTTP 400 on v1.0; only the unfiltered interactive stream is v1.0 and
default-on. See `CLAUDE.md` for the verified live behavior.

### Blob collectors read Azure Storage, not Graph

The `entra.*` blob collectors exist for signals Graph has **no endpoint for at all** — permanently.
They read Azure Monitor diagnostic-settings output from blob storage, so they poll no Graph endpoint
and declare no Graph scope: they need the **`Storage Blob Data Reader`** data-plane role instead.
`Owner` is not enough — it grants container list/create but not blob *content* reads, and the
failure is silent, indistinguishable from "no data yet".

They **only register when `blob_ingest.account_url` is set** for the tenant. That one key is the
opt-in for the whole lane; a deployment that has not provisioned a storage account registers none of
them and is entirely untouched by this path.

They emit **no metrics** — only logs. Their cursor is a byte offset per blob rather than a
watermark, because Azure backfills records into already-closed hour buckets, which is also why they
are `SnapshotCollector`s despite emitting logs: the interface split is about the **cursor**, not the
signal shape. Azure's delivery is at-least-once (~2.3% of records arrive more than once), and the
blob engine does not dedupe today, so those duplicates ship — dedupe downstream on the `id`
attribute. For why this path exists and how to provision it, see
[`blob-ingest.md`](./blob-ingest.md).

### The export-report collectors need one write-level scope

`intune.app_install_status`, `intune.cert_inventory`, and `intune.defender_agents` poll the
**Reports Export API**: `POST /deviceManagement/reports/exportJobs`, then poll job status and
download the result. Creating that job requires `DeviceManagementManagedDevices.ReadWrite.All` —
a write-level scope, and the single break in graph2otel's read-only property. graph2otel never
writes Intune configuration or device state through it. All three are opt-in (`beta`). See
[`permissions.md`](./permissions.md#4-the-export-job-readwrite-caveat-gotcha-3) for the full
explanation.

### Cardinality

Every metric label above resolves to a bounded enum, a fixed threshold bucket, or an
admin-configured object name (policy/profile/ring/script name) — never a per-user, per-device, or
per-sign-in identifier. Per-entity detail is not withheld: it goes to the **logs**, which is what
the *Log event* column and the log twins in the *Metric namespace* column are. See
[`pii-cardinality-audit.md`](./pii-cardinality-audit.md) and `SECURITY.md` for the full boundary
rule and the confirmed-clean audit result.
