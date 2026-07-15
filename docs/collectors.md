# Collector reference

Every collector `graph2otel` ships, as of this writing: what it collects, the Graph API
endpoint(s) it polls, the Graph application permission scope(s) it declares via
`RequiredPermissions()`, license/beta gating, its default poll interval, and the metric or log
namespace it emits into. Scopes and gating were cross-checked against the collector source under
`internal/collectors/` (not just design notes) and against the least-privilege audit in
[`pii-cardinality-audit.md`](./pii-cardinality-audit.md). For how to grant these scopes, see
[`permissions.md`](./permissions.md); for the `collectors:` config block that enables/disables and
retunes them, see [`configuration.md`](./configuration.md).

**Columns:**

- **License / beta** — `needs-license/p1` or `needs-license/p2` (Entra ID P1/P2), `needs-license/
  workload-id-premium` (Entra Workload ID Premium), or `needs-license/intune` (an active Intune
  plan) where the collector — or a half of it — is gated on that capability; `beta` where the
  collector implements `collectors.Experimental` (opt-in, off by default, backed by a Microsoft
  Graph `beta`-only endpoint with no v1.0 equivalent). A collector can carry both a license gate and
  a beta flag.
- **Interval** — the collector's `DefaultInterval()`; overridable per-collector (globally or
  per-tenant) via the `collectors:` config block.
- **Namespace** — the `graph2otel.*` self-observability metrics (scrape duration/success/errors/
  staleness, `build_info`, series cardinality, export job stats, tenant license tier) apply to every
  collector uniformly and aren't repeated per row; see the M6 dashboard/alert lanes for that
  contract.

## Entra ID — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `entra.agreements` | Terms of Use agreements + acceptance state | `/agreements`, `/agreements/{id}/acceptances` | `Agreement.Read.All`, `AgreementAcceptance.Read.All` | `needs-license/p1` | 15m | `entra.agreements.total`, `.acceptances.total{agreement,state}` |
| `entra.auth_methods_policy` | Tenant-wide authentication methods policy (enabled methods, legacy methods) | `/policies/authenticationMethodsPolicy` | `Policy.Read.AuthenticationMethod` | — | 15m | `entra.auth_methods_policy.method.enabled{method}`, `.legacy_enabled.total{method}` |
| `entra.conditional_access` | CA policy + named location inventory | `/identity/conditionalAccess/policies`, `/identity/conditionalAccess/namedLocations` | `Policy.Read.All` | `needs-license/p1` | 15m | `entra.ca.policies.total{state}`, `entra.named_locations.total{type,is_trusted}` |
| `entra.consent` | OAuth2 permission grants + app-role assignment consent surface | `/oauth2PermissionGrants`, app role assignments | `Directory.Read.All`, `Application.Read.All` | — | 15m | `entra.consent.grants.total{consent_type,privilege}` |
| `entra.credential_expiry` | App + service principal credential (secret/certificate) expiry buckets | `/applications`, `/servicePrincipals` (`$select=keyCredentials,passwordCredentials`) | `Application.Read.All` | — | 15m | `entra.credentials.expiring.total{owner_type,credential_type,expiry_bucket}` |
| `entra.devices` | Directory device inventory: trust type, compliance, managed state, OS, staleness | `/devices`, `/devices/$count` | `Device.Read.All` | — | 15m | `entra.devices.total{trust_type}`, `.compliance.total{is_compliant}`, `.managed.total{is_managed}`, `.os.total{operating_system}`, `.stale.total{threshold_days}` |
| `entra.directory_counts` | Tenant-wide directory object counts by type | `/{type}/$count` per object type | `Directory.Read.All` | — | 5m | `entra.directory.objects.total{type}` |
| `entra.domains` | Domain verification/authentication posture | `/domains` | `Domain.Read.All` | — | 15m | `entra.domains.total{authentication_type,is_verified}`, `.federated.total` |
| `entra.groups` | Group population by type/membership/security/mail-enabled, role-assignable count | `/groups/$count` (filtered) | `Group.Read.All` | — | 5m | `entra.groups.total{group_type,membership_type,security_enabled,mail_enabled}`, `.role_assignable.total` |
| `entra.licensing` | SKU consumption + prepaid/enabled units | `/subscribedSkus` | `LicenseAssignment.Read.All` | — | 15m | `entra.license.consumed{sku}`, `.enabled{sku}` |
| `entra.mfa_registration` | MFA/SSPR/passwordless registration + capability status, per-method counts, admin MFA-capable split | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | `needs-license/p1` | 15m | `entra.mfa.registration.users.total{status}`, `.methods.total{method}`, `.admin_mfa_capable.total{is_admin}` |
| `entra.organization` | Tenant posture: on-prem sync state/age, tenant age, verified domain count, tenant type | `/organization` | `Organization.Read.All` | — | 15m | `entra.organization.directory.sync.last_sync_age_seconds`, `.age_days`, `.verified_domains.total`, `.info{tenant_type}` |
| `entra.recommendations` | Entra recommendations catalog (status, priority) | `/directory/recommendations` (beta) | `DirectoryRecommendations.Read.All` | `beta` | 30m | `entra.recommendations.total{status,priority}` |
| `entra.risk` | Current risky-users and risky-service-principals counts | `/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals` | `IdentityRiskyUser.Read.All`, `IdentityRiskyServicePrincipal.Read.All` | risky users: `needs-license/p2`; risky SPs: `needs-license/workload-id-premium` (independent gates — each half runs and emits only if its own capability is present) | 15m | `entra.risky_users.total{risk_level,risk_state}`, `entra.risky_service_principals.total{risk_level,risk_state}` |
| `entra.roles` | Standing directory-role membership; PIM active/eligible/permanent assignment counts | `/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances` | `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` | PIM half only: `needs-license/p2` (standing-membership half runs unconditionally; PIM assignment counts are skipped, not zero-emitted, without P2) | 10m | `entra.roles.members.total{role_name}`, `entra.pim.assignments.total{role_name,assignment_type}`, `entra.pim.permanent_assignments.total{role_name}` |
| `entra.secure_score` | Latest secure score + control profile catalog | `/security/secureScores`, `/security/secureScoreControlProfiles` | `SecurityEvents.Read.All` | — | 1h (Microsoft publishes at most daily) | `entra.secure_score.current`/`.max`/`.percentage`, `.control_profiles.by_category{category}`, `.by_status{status}` |
| `entra.signin_activity` | Stale service principals / app credentials (no recent sign-in), app sign-in result summary | `/reports/servicePrincipalSignInActivities`, `/reports/appCredentialSignInActivities` (beta) | `AuditLog.Read.All` | `needs-license/p1`, `beta` | 1h | `entra.serviceprincipal.signin.stale.total`, `entra.app.credential.signin.stale.total`, `entra.app.signin.summary.total` |
| `entra.users` | User population by account-enabled/user-type/on-prem-sync, staleness | `/users`, `/users/$count` (`GET /users?...&$count=true` for signInActivity-based slices) | `User.Read.All`, `AuditLog.Read.All` | staleness slice only: `needs-license/p1` or `p2` (signInActivity requires either) | 15m | `entra.users.total{account_enabled,user_type,on_premises_sync_enabled}`, `.stale.total{threshold_days}` |

## Entra ID — logs (window collectors)

All four sign-in streams poll the same `/auditLogs/signIns` path but each owns a distinct
`CheckpointKey` (see the `CLAUDE.md` gotcha on checkpoint collisions) — they are four independent
collectors, not variants of one.

| Collector | Collects | Graph endpoint | Required scope(s) | License / beta | Interval (lag) |
| --- | --- | --- | --- | --- | --- |
| `entra.signins.interactive` | Interactive sign-in events | `/auditLogs/signIns` (v1.0, unfiltered) | `AuditLog.Read.All` | `needs-license/p1` | 5m (15m lag) |
| `entra.signins.non_interactive` | Non-interactive sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/p1`, `beta` | 5m (15m lag) |
| `entra.signins.service_principal` | Service principal sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/p1`, `beta` | 5m (15m lag) |
| `entra.signins.managed_identity` | Managed identity sign-in events | `/auditLogs/signIns` (beta, `signInEventTypes` filter) | `AuditLog.Read.All` | `needs-license/p1`, `beta` | 5m (15m lag) |
| `entra.directory_audits` | Directory audit log events | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | — | 5m (15m lag) |
| `entra.provisioning` | Provisioning (sync) events | `/auditLogs/provisioning` | `AuditLog.Read.All` | — | 15m (15m lag) |
| `entra.risk_detections` | Identity Protection risk detection events (`$top` capped at 500) | `/identityProtection/riskDetections` | `IdentityRiskEvent.Read.All` | `needs-license/p2` | 30m (15m lag) |
| `entra.security_alerts` | Security alerts (`alerts_v2`) | `/security/alerts_v2` | `SecurityAlert.Read.All` | — | 10m (15m lag) |

Note: the `beta` gate above is about the `signInEventTypes` filter, which 400s on v1.0 — see
`CLAUDE.md`'s gotchas for the verified live behavior.

## Intune — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `intune.apple_tokens` | APNS/VPP token expiry + synced device counts; DEP onboarding settings polled best-effort | `/deviceManagement/applePushNotificationCertificate`, `/deviceAppManagement/vppTokens`, `/deviceManagement/depOnboardingSettings` (beta, isolated) | `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All` | — (APNS/VPP v1.0 default-on; DEP fetch is beta but isolated, doesn't gate the whole collector) | 6h | `intune.apple_token.days_until_expiry{type,state,token_name}`, `.synced_device_count{token_name}` |
| `intune.app_protection` | App protection (MAM) policy inventory + assignment state; flagged registrations; WIP policy count | `/deviceAppManagement/iosManagedAppProtections`, `androidManagedAppProtections`, `targetedManagedAppConfigurations`, `windowsInformationProtectionPolicies`, `mdmWindowsInformationProtectionPolicies` | `DeviceManagementApps.Read.All` | — | 30m | `intune.app_protection.policy.count{platform,assigned}`, `.flagged_registrations{flagged_reason,platform}`, `intune.wip.policy.count{assigned}` |
| `intune.autopilot` | Autopilot device registration + deployment profile state | `/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles | `DeviceManagementServiceConfig.Read.All` | `beta` | 30m | `intune.autopilot.devices{enrollment_state,group_tag}`, `.stale_contact.count{group_tag}`, `.profile.count{device_type,preprovisioning_allowed}` |
| `intune.certificates` | Certificate state + days-until-expiry | `/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.certificate.days_until_expiry{expiry_bucket,state,cert_profile_name}`, `.state.count{state}` |
| `intune.compliance` | Tenant-wide + per-policy compliance state rollups | `/deviceManagement/deviceCompliancePolicies`, device compliance states | `DeviceManagementConfiguration.Read.All` | — | 15m | `intune.compliance.devices{state}`, `.policy.devices{policy_name,state}`, `.policy.users{policy_name,state}`, `.policy.version{policy_name}` |
| `intune.config_profiles` | Configuration profile status + version, per-setting state | `/deviceManagement/deviceConfigurations` (fan-out per profile) | `DeviceManagementConfiguration.Read.All` | — | 30m | `intune.config_profile.count{odata_type}`, `.status{profile_name,state}`, `.version{profile_name}`, `intune.setting.devices{setting_name,platform,state}` |
| `intune.connectors` | Exchange/MTD/NDES connector health; NDES sub-fetch is isolated beta | `/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated) | `DeviceManagementServiceConfig.Read.All` | — (Exchange/MTD default-on; NDES beta failure isolated, doesn't gate the collector) | 15m | `intune.connector.state{connector_type,state}`, `.heartbeat_age_seconds{connector_type}`, `.mtd_platform.total{platform,enabled}` |
| `intune.detected_apps` | Detected-apps software inventory catalog | `/deviceManagement/detectedApps` | `DeviceManagementManagedDevices.Read.All` | — | 1h | `intune.detected_apps.device_count`, `.catalog_size` |
| `intune.endpoint_analytics` | UXA scores, boot/login time histograms, app crash counts, battery health, resource performance | `/deviceManagement/userExperienceAnalytics*` (beta) | `DeviceManagementManagedDevices.Read.All` | `beta` | 1h (heaviest collector) | `intune.uxa.score{category,health_state}`, `.boot_time_ms`/`.login_time_ms{restart_category}`, `.app_crash_count{app_name}` |
| `intune.enrollment` | Enrollment configuration inventory (restrictions, VPP, ESP, etc.) + priority + version | `/deviceManagement/deviceEnrollmentConfigurations` | `DeviceManagementServiceConfig.Read.All` | — | 15m | `intune.enrollment_config.count{config_type}`, `.priority{config_type,config_name}`, `.version{config_name}` |
| `intune.gpo_analytics` | GPO migration readiness/analytics reports | `/deviceManagement/groupPolicyMigrationReports`, `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | `beta` | 24h | `intune.gpo.migration_readiness`, `.supported_settings_percent`, `.config.count` |
| `intune.malware` | Tenant malware/Defender overview (detected devices, by severity/category), per-device Defender protection/product state | `/deviceManagement/windowsMalwareOverview`, `/deviceManagement/managedDevices/{id}/windowsProtectionState` | `DeviceManagementManagedDevices.Read.All` | — | 30m | `intune.malware.overview.detected_devices`/`.total`/`.by_severity{severity}`/`.by_category{category}`, `intune.defender.protection_state{signal}`, `.product_status{status}` |
| `intune.devices` | Managed-device inventory, encryption, sync recency, enrolled/MDM/dual-enrolled overview | `/deviceManagement/managedDevices`, overview | `DeviceManagementManagedDevices.Read.All` | — | 1h (full-fleet page) | `intune.devices.count{compliance_state,operating_system}`, `.encrypted.count{operating_system}`, `.sync_staleness_seconds{staleness_bucket}`, `.overview.total{os}`, `.overview.{enrolled,mdm_enrolled,dual_enrolled}_device_count` |
| `intune.mobile_apps` | Mobile app catalog (type, publishing state); mobile app config policy status | `/deviceAppManagement/mobileApps`, app configs | `DeviceManagementApps.Read.All` | — | 30m | `intune.mobile_apps.count{app_type,publishing_state}`, `intune.mobile_app_config.status{policy_name,status}` |
| `intune.scripts` | Script/remediation inventory, run summaries, and remediation overview | `/deviceManagement/deviceManagementScripts` (Windows), `deviceShellScripts` (macOS), `deviceHealthScripts` (+ `getRemediationSummary`) | `DeviceManagementScripts.Read.All` | `beta` | 30m | `intune.script.run_summary`, `intune.remediation.summary`, `.remediated_cumulative_devices`, `.overview.script_count`, `.overview.remediated_device_count` |
| `intune.settings_catalog` | Settings Catalog policy inventory, template-based intents + per-intent device state, security baseline device state | `/deviceManagement/configurationPolicies` (beta), `/deviceManagement/intents` (+ `deviceStateSummary`), `/deviceManagement/templates/{id}/deviceStateSummary` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.settings_catalog.policy.count`, `intune.intent.count`, `.devices`, `intune.security_baseline.devices` |
| `intune.updates` | Windows Update rings (`deviceConfigurations` subtype, v1.0) + feature/quality/driver update profile state (beta), pause/rollback | `/deviceManagement/deviceConfigurations` (ring subtype only), `/deviceManagement/windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`/`Policies`, `windowsDriverUpdateProfiles` (beta) | `DeviceManagementConfiguration.Read.All` | `beta` (the whole collector is gated Experimental as one unit — its most-valuable signal, the feature/quality/driver profile families, is beta-only; the ring metrics, though v1.0-sourced, ship inside the same opt-in rather than splitting into a separate v1.0-default collector) | 30m | `intune.update_ring.{pause_state,pause_expiry_seconds,rollback_active,status}{ring_name,update_type,state}`, `intune.driver_update.pending_approval{profile_name}` |

## Intune — logs (window collectors)

| Collector | Collects | Graph endpoint | Required scope(s) | License / beta | Interval |
| --- | --- | --- | --- | --- | --- |
| `intune.audit_events` | Intune audit events (redacts old/new property values; emits changed-property names only) | `/deviceManagement/auditEvents` | `DeviceManagementApps.Read.All` | — | 15m |
| `intune.enrollment_events` | Enrollment troubleshooting events | `/deviceManagement/troubleshootingEvents` | `DeviceManagementManagedDevices.Read.All` | `needs-license/intune` | 20m |
| `intune.autopilot_events` | Autopilot deployment/enrollment events | `/deviceManagement/autopilotEvents` (beta, no v1.0 equivalent) | `DeviceManagementManagedDevices.Read.All` | `beta` | 20m |

## Intune — export-report collectors (opt-in, write-level scope)

These three poll the **Reports Export API**: `POST /deviceManagement/reports/exportJobs`, then poll
job status and download the result. All three are `Experimental` (opt-in, off by default) and all
three declare `DeviceManagementManagedDevices.ReadWrite.All` — a write-level scope needed only to
**create** the export job; graph2otel never writes Intune configuration or device state through it.
See [`permissions.md`](./permissions.md#4-the-export-job-readwrite-caveat-gotcha-3) for the full
explanation.

| Collector | Collects | Required scope | Interval |
| --- | --- | --- | --- |
| `intune.app_install_status` | Per-device app install status export | `DeviceManagementManagedDevices.ReadWrite.All` | 6h |
| `intune.cert_inventory` | Device certificate inventory export (thumbprints, serials, subject/issuer) | `DeviceManagementManagedDevices.ReadWrite.All` | 6h |
| `intune.defender_agents` | Defender agent health export | `DeviceManagementManagedDevices.ReadWrite.All` | 6h |

## Cardinality note

Every metric label above resolves to a bounded enum, a fixed threshold bucket, or an
admin-configured object name (policy/profile/ring/script name) — never a per-user, per-device, or
per-sign-in identifier. See [`pii-cardinality-audit.md`](./pii-cardinality-audit.md) and
`SECURITY.md` for the full boundary rule and the confirmed-clean audit result.
