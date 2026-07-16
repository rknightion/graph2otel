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
> cursor key) are **not** editable here — fix the collector, then regenerate. The prose columns
> (*Collects*, *Graph endpoint(s)*, *Metric namespace* / *Log event*, and license nuance) are
> hand-written in `internal/collectordoc/annotations.go`, because they are string literals inside
> each collector's `Collect()` and the registry cannot see them.

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
| `entra.agreements` | Terms of Use agreements + acceptance state | `/agreements`, `/agreements/{id}/acceptances` | `Agreement.Read.All`, `AgreementAcceptance.Read.All` | `needs-license/entra_p1` | 15m | `entra.agreements.total`, `.acceptances.total{agreement,state}` |
| `entra.auth_methods_policy` | Tenant-wide authentication methods policy (enabled methods, legacy methods) | `/policies/authenticationMethodsPolicy` | `Policy.Read.AuthenticationMethod` | — | 15m | `entra.auth_methods_policy.method.enabled{method}`, `.legacy_enabled.total{method}` |
| `entra.conditional_access` | CA policy + named location inventory | `/identity/conditionalAccess/policies`, `/identity/conditionalAccess/namedLocations` | `Policy.Read.All` | `needs-license/entra_p1` | 15m | `entra.ca.policies.total{state}`, `entra.named_locations.total{type,is_trusted}` |
| `entra.consent` | OAuth2 permission grants + app-role assignment consent surface | `/oauth2PermissionGrants`, app role assignments | `Directory.Read.All`, `Application.Read.All` | — | 15m | `entra.consent.grants.total{consent_type,privilege}` |
| `entra.credential_expiry` | App + service principal credential (secret/certificate) expiry buckets | `/applications`, `/servicePrincipals` (`$select=keyCredentials,passwordCredentials`) | `Application.Read.All` | — | 15m | `entra.credentials.expiring.total{owner_type,credential_type,expiry_bucket}` |
| `entra.devices` | Directory device inventory: trust type, compliance, managed state, OS, staleness | `/devices`, `/devices/$count` | `Device.Read.All` | — | 15m | `entra.devices.total{trust_type}`, `.compliance.total{is_compliant}`, `.managed.total{is_managed}`, `.os.total{operating_system}`, `.stale.total{threshold_days}` |
| `entra.directory_counts` | Tenant-wide directory object counts by type | `/{type}/$count` per object type | `Directory.Read.All` | — | 5m | `entra.directory.objects.total{type}` |
| `entra.domains` | Domain verification/authentication posture | `/domains` | `Domain.Read.All` | — | 15m | `entra.domains.total{authentication_type,is_verified}`, `.federated.total` |
| `entra.groups` | Group population by type/membership/security/mail-enabled, role-assignable count | `/groups/$count` (filtered) | `Group.Read.All` | — | 5m | `entra.groups.total{group_type,membership_type,security_enabled,mail_enabled}`, `.role_assignable.total` |
| `entra.licensing` | SKU consumption + prepaid/enabled units | `/subscribedSkus` | `LicenseAssignment.Read.All` | — | 15m | `entra.license.consumed{sku}`, `.enabled{sku}` |
| `entra.mfa_registration` | MFA/SSPR/passwordless registration + capability status, per-method counts, admin MFA-capable split | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | `needs-license/entra_p1` | 1h | `entra.mfa.registration.users.total{status}`, `.methods.total{method}`, `.admin_mfa_capable.total{is_admin}` |
| `entra.organization` | Tenant posture: on-prem sync state/age, tenant age, verified domain count, tenant type | `/organization` | `Organization.Read.All` | — | 15m | `entra.organization.directory.sync.last_sync_age_seconds`, `.age_days`, `.verified_domains.total`, `.info{tenant_type}` |
| `entra.recommendations` | Entra recommendations catalog (status, priority) | `/directory/recommendations` (beta) | `DirectoryRecommendations.Read.All` | `beta` | 30m | `entra.recommendations.total{status,priority}` |
| `entra.risk` | Current risky-users and risky-service-principals counts, with a log twin per risky entity | `/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals` | `IdentityRiskyUser.Read.All`, `IdentityRiskyServicePrincipal.Read.All` | risky users need `entra_p2`, risky SPs need `workload_identities_premium` — two INDEPENDENT partial gates checked inside Collect() against the tenant's capabilities, so each half runs and emits only if its own capability is present; neither is declared as a whole-collector requirement | 15m | `entra.risky_users.total{risk_level,risk_state}`, `entra.risky_service_principals.total{risk_level,risk_state}`, plus a log twin per risky entity |
| `entra.roles` | Standing directory-role membership; PIM active/eligible/permanent assignment counts | `/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances` | `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` | PIM half only needs `entra_p2`, checked inside Collect(): the standing-membership half runs on every tier, and without P2 the PIM assignment counts are skipped rather than zero-emitted | 10m | `entra.roles.members.total{role_name}`, `entra.pim.assignments.total{role_name,assignment_type}`, `entra.pim.permanent_assignments.total{role_name}` |
| `entra.secure_score` | Latest secure score + control profile catalog (Microsoft publishes at most daily, hence the hourly poll) | `/security/secureScores`, `/security/secureScoreControlProfiles` | `SecurityEvents.Read.All` | — | 1h | `entra.secure_score.current`/`.max`/`.percentage`, `.control_profiles.by_category{category}`, `.by_status{status}` |
| `entra.signin_activity` | Stale service principals / app credentials (no recent sign-in), app sign-in result summary | `/reports/servicePrincipalSignInActivities`, `/reports/appCredentialSignInActivities` (beta) | `AuditLog.Read.All`, `Reports.Read.All` | `needs-license/entra_p1`, `beta` | 1h | `entra.serviceprincipal.signin.stale.total`, `entra.app.credential.signin.stale.total`, `entra.app.signin.summary.total` |
| `entra.users` | User population by account-enabled/user-type/on-prem-sync, staleness | `/users`, `/users/$count` (`GET /users?…&$count=true` for signInActivity-based slices) | `User.Read.All`, `AuditLog.Read.All` | staleness slice only, checked inside Collect(): signInActivity needs `entra_p1` or `entra_p2`; the population counts run on every tier | 15m | `entra.users.total{account_enabled,user_type,on_premises_sync_enabled}`, `.stale.total{threshold_days}` |

## Entra ID — logs (window collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Lag | Log event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `entra.directory_audits` | Directory audit log events | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | — | 5m | 15m | `entra.directory_audit` |
| `entra.provisioning` | Provisioning (sync) events | `/auditLogs/provisioning` | `AuditLog.Read.All` | — | 15m | 15m | `entra.provisioning` |
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
| `entra.graph_activity` | One record per Graph API call made against the tenant: which app or user called which endpoint, with which permissions, from where, and what came back. Graph has no endpoint for its own API-call telemetry — none, permanently — so this signal exists only as diagnostic-settings output, and it is what justifies the whole blob path | `insights-logs-microsoftgraphactivitylogs` (MicrosoftGraphActivityLogs) | `insights-logs-microsoftgraphactivitylogs` | `Storage Blob Data Reader` | — | 5m | `entra.graph_activity` |
| `entra.signins.microsoft_service_principal` | Sign-ins by Microsoft's own first-party service principals. No `.blob` suffix because this category has no Graph route and so no polled twin to disambiguate from | `insights-logs-microsoftserviceprincipalsigninlogs` (MicrosoftServicePrincipalSignInLogs) | `insights-logs-microsoftserviceprincipalsigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |
| `entra.signins.service_principal.blob` | Service principal sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.service_principal` (1375/1375), so exactly one of the pair may be enabled; registering both is refused at startup | `insights-logs-serviceprincipalsigninlogs` (ServicePrincipalSignInLogs) | `insights-logs-serviceprincipalsigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |
| `entra.signins.non_interactive.blob` | Non-interactive sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.non_interactive` (18/18), so exactly one of the pair may be enabled; registering both is refused at startup | `insights-logs-noninteractiveusersigninlogs` (NonInteractiveUserSignInLogs) | `insights-logs-noninteractiveusersigninlogs` | `Storage Blob Data Reader` | `needs-license/entra_p1` | 5m | `entra.signin` |

## Intune — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `intune.app_install_status` | Per-device app install status, via the Reports Export API: POST a job, poll it, download and parse the CSV. Uses the `AppInstallStatusAggregate` report — the per-app variant has no fleet-wide form | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.app_install_status.*` |
| `intune.apple_tokens` | APNS/VPP token expiry + synced device counts; DEP onboarding settings polled best-effort | `/deviceManagement/applePushNotificationCertificate`, `/deviceAppManagement/vppTokens`, `/deviceManagement/depOnboardingSettings` (beta, isolated) | `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All` | APNS/VPP are v1.0 and default-on; the DEP sub-fetch is beta but isolated, so it does not gate the collector | 6h | `intune.apple_token.days_until_expiry{type,state,token_name}`, `.synced_device_count{token_name}` |
| `intune.app_protection` | App protection (MAM) policy inventory + assignment state; flagged registrations; WIP policy count | `/deviceAppManagement/iosManagedAppProtections`, `androidManagedAppProtections`, `targetedManagedAppConfigurations`, `windowsInformationProtectionPolicies`, `mdmWindowsInformationProtectionPolicies` | `DeviceManagementApps.Read.All` | — | 30m | `intune.app_protection.policy.count{platform,assigned}`, `.flagged_registrations{flagged_reason,platform}`, `intune.wip.policy.count{assigned}` |
| `intune.autopilot` | Autopilot device registration + deployment profile state | `/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles | `DeviceManagementServiceConfig.Read.All` | `beta` | 30m | `intune.autopilot.devices{enrollment_state,group_tag}`, `.stale_contact.count{group_tag}`, `.profile.count{device_type,preprovisioning_allowed}` |
| `intune.certificates` | Certificate state + days-until-expiry | `/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.certificate.days_until_expiry{expiry_bucket,state,cert_profile_name}`, `.state.count{state}` |
| `intune.cert_inventory` | Device certificate inventory (thumbprints, serials, subject/issuer), via the Reports Export API | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.cert_inventory.*` |
| `intune.compliance` | Tenant-wide + per-policy compliance state rollups | `/deviceManagement/deviceCompliancePolicies`, device compliance states | `DeviceManagementConfiguration.Read.All` | — | 15m | `intune.compliance.devices{state}`, `.policy.devices{policy_name,state}`, `.policy.users{policy_name,state}`, `.policy.version{policy_name}` |
| `intune.config_profiles` | Configuration profile status + version, per-setting state | `/deviceManagement/deviceConfigurations` (fan-out per profile) | `DeviceManagementConfiguration.Read.All` | — | 30m | `intune.config_profile.count{odata_type}`, `.status{profile_name,state}`, `.version{profile_name}`, `intune.setting.devices{setting_name,platform,state}` |
| `intune.connectors` | Exchange/MTD/NDES connector health | `/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated) | `DeviceManagementServiceConfig.Read.All` | Exchange/MTD are default-on; the NDES sub-fetch is beta and isolated, so its failure does not gate the collector | 15m | `intune.connector.state{connector_type,state}`, `.heartbeat_age_seconds{connector_type}`, `.mtd_platform.total{platform,enabled}` |
| `intune.defender_agents` | Defender agent health, via the Reports Export API | `POST /deviceManagement/reports/exportJobs` | `DeviceManagementManagedDevices.ReadWrite.All` | `beta` (the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state) | 6h | `intune.defender_agents.*` |
| `intune.detected_apps` | Detected-apps software inventory catalog | `/deviceManagement/detectedApps` | `DeviceManagementManagedDevices.Read.All` | — | 1h | `intune.detected_apps.device_count`, `.catalog_size` |
| `intune.endpoint_analytics` | UXA scores, boot/login time histograms, app crash counts, battery health, resource performance — the heaviest collector | `/deviceManagement/userExperienceAnalytics*` (beta) | `DeviceManagementManagedDevices.Read.All` | `beta` | 1h | `intune.uxa.score{category,health_state}`, `.boot_time_ms`/`.login_time_ms{restart_category}`, `.app_crash_count{app_name}` |
| `intune.enrollment` | Enrollment configuration inventory (restrictions, VPP, ESP, etc.) + priority + version | `/deviceManagement/deviceEnrollmentConfigurations` | `DeviceManagementServiceConfig.Read.All` | — | 15m | `intune.enrollment_config.count{config_type}`, `.priority{config_type,config_name}`, `.version{config_name}` |
| `intune.gpo_analytics` | GPO migration readiness/analytics reports | `/deviceManagement/groupPolicyMigrationReports`, `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | `beta` | 24h | `intune.gpo.migration_readiness`, `.supported_settings_percent`, `.config.count` |
| `intune.malware` | Tenant malware/Defender overview (detected devices, by severity/category), per-device Defender protection/product state | `/deviceManagement/windowsMalwareOverview`, `/deviceManagement/managedDevices/{id}/windowsProtectionState` | `DeviceManagementManagedDevices.Read.All` | — | 30m | `intune.malware.overview.detected_devices`/`.total`/`.by_severity{severity}`/`.by_category{category}`, `intune.defender.protection_state{signal}`, `.product_status{status}` |
| `intune.devices` | Managed-device inventory, encryption, sync recency, enrolled/MDM/dual-enrolled overview, plus a log twin per device. The full-fleet page-walk is irreducible by design: the per-device twins ARE the deliverable, so the bounded `managedDeviceOverview` cross-check cannot replace it | `/deviceManagement/managedDevices`, `managedDeviceOverview` | `DeviceManagementManagedDevices.Read.All` | — | 1h | `intune.devices.count{compliance_state,operating_system}`, `.encrypted.count{operating_system}`, `.sync_staleness_seconds{staleness_bucket}`, `.overview.total{os}`, `.overview.{enrolled,mdm_enrolled,dual_enrolled}_device_count`, plus a log twin per device |
| `intune.mobile_apps` | Mobile app catalog (type, publishing state); mobile app config policy status | `/deviceAppManagement/mobileApps`, app configs | `DeviceManagementApps.Read.All` | — | 30m | `intune.mobile_apps.count{app_type,publishing_state}`, `intune.mobile_app_config.status{policy_name,status}` |
| `intune.scripts` | Script/remediation inventory, run summaries, and remediation overview | `/deviceManagement/deviceManagementScripts` (Windows), `deviceShellScripts` (macOS), `deviceHealthScripts` (+ `getRemediationSummary`) | `DeviceManagementScripts.Read.All` | `beta` | 30m | `intune.script.run_summary`, `intune.remediation.summary`, `.remediated_cumulative_devices`, `.overview.script_count`, `.overview.remediated_device_count` |
| `intune.settings_catalog` | Settings Catalog policy inventory, template-based intents + per-intent device state, security baseline device state | `/deviceManagement/configurationPolicies` (beta), `/deviceManagement/intents` (+ `deviceStateSummary`), `/deviceManagement/templates/{id}/deviceStateSummary` | `DeviceManagementConfiguration.Read.All` | `beta` | 30m | `intune.settings_catalog.policy.count`, `intune.intent.count`, `.devices`, `intune.security_baseline.devices` |
| `intune.updates` | Windows Update rings + feature/quality/driver update profile state, pause/rollback | `/deviceManagement/deviceConfigurations` (ring subtype only, v1.0), `/deviceManagement/windowsFeatureUpdateProfiles`, `windowsQualityUpdateProfiles`/`Policies`, `windowsDriverUpdateProfiles` (beta) | `DeviceManagementConfiguration.Read.All` | `beta` (the whole collector is gated as one unit: its most-valuable signal — the feature/quality/driver profile families — is beta-only, and the ring metrics, though v1.0-sourced, ship inside the same opt-in rather than splitting into a separate v1.0-default collector) | 30m | `intune.update_ring.{pause_state,pause_expiry_seconds,rollback_active,status}{ring_name,update_type,state}`, `intune.driver_update.pending_approval{profile_name}` |

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
| `m365.activity` | The same M365 unified audit records as `m365.unified_audit`, over the Office 365 Management Activity API instead: subscribe to a content type, list its content blobs, fetch each. Wins on transport — stable v1.0, 2,000 req/min per tenant, content ~2 minutes behind the event, and no async query — which is why this one is not Experimental. Loses on volume control: the API has NO server-side filtering, so `o365_activity.content_types` is the only knob and every record fetched is shipped. Defaults to Audit.Exchange + Audit.SharePoint; Audit.General is opt-in (it is the only route to Teams here, and it was 3,865 of 4,035 records Endpoint DLP on a 6-device tenant — the firehose `m365.unified_audit` can filter out server-side and this cannot), and Audit.AzureActiveDirectory is omitted because `entra.signins.interactive` and `entra.directory_audits` already emit those records. Exactly one of the two may be enabled; registering both is refused at startup | `manage.office.com/api/v1.0/{tenant}/activity/feed` — a second first-party API, NOT Graph: different audience, and `POST /subscriptions/start` is a write (the second break in graph2otel's read-only property, after the reports-export job) | `ActivityFeed.Read` | — | 10m | 5m | `m365.audit` — the same event name and the same `id` as `m365.unified_audit`, deliberately: the Management API record IS the query API's `auditData` sub-object, so the two are drop-in equivalents and switching transports needs no downstream change |

## Purview — metrics (snapshot collectors)

| Collector | Collects | Graph endpoint(s) | Required scope(s) | License / beta | Interval | Metric namespace |
| --- | --- | --- | --- | --- | --- | --- |
| `purview.sensitivity_labels` | Sensitivity label catalog: a count by applicable-to type, plus a log twin per label carrying its priority and `hasProtection` — which is how label encryption activation is readable at all. Bind the label's text to `name`: `displayName` is present but always null | `/security/dataSecurityAndGovernance/sensitivityLabels` | `InformationProtectionPolicy.Read.All` | `needs-license/purview_information_protection` | 1h | `purview.labels.count{applicable_to}`, plus a log twin per label |
| `purview.retention_labels` | Retention label definitions + retention event types, each with a log twin. Blocked app-only on a live tenant — both endpoints 500 with `DataInsightsRequestError`/Forbidden even with the scope granted, because Microsoft documents Application access as not supported — so the collector recognizes that specific pair and reports unavailable rather than failing | `/security/labels/retentionLabels`, `/security/triggerTypes/retentionEventTypes` | `RecordsManagement.Read.All` | `needs-license/purview_records_management` | 1h | `purview.retention.labels.count`, `purview.retention.event_types.count`, plus a log twin per row |

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
