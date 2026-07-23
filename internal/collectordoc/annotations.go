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
	"entra.agent_risk_detections": {
		Collects: "Identity Protection Entra Agent ID (AI-agent) risk detection events — the WHY an agent identity was flagged (admin-confirmed compromise, anomalous agent activity, …), one log per detection. The agent analog of `entra.risk_detections` (users) and `entra.service_principal_risk_detections` (workload identities); log-shaped, the agent-risk STATE gauge ships via `entra.risky_agents`. Beta/Experimental, ungated (200/empty or 403 where the feature is absent)",
		Source:   "`/beta/identityProtection/agentRiskDetections`",
	},
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
	"entra.deleted_items": {
		Collects: "Recycle-bin census: recoverable soft-deleted directory objects by type + near-purge state, log twin per object",
		Source:   "`/directory/deletedItems/microsoft.graph.{user,group,application,servicePrincipal,device}`",
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
		Collects: "Current risky-users and risky-service-principals counts, with a log twin per risky entity. The risky-users gauge is reconciled against the directory's deleted-items tombstones so a deleted-but-once-risky user is not counted forever (#155); the twin keeps the entity, marked with a reliable `is_deleted`",
		Source:   "`/identityProtection/riskyUsers`, `/identityProtection/riskyServicePrincipals`, `/directory/deletedItems/microsoft.graph.user`",
		Gating:   "risky users need `entra_p2`, risky SPs need `workload_identities_premium` — two INDEPENDENT partial gates checked inside Collect() against the tenant's capabilities, so each half runs and emits only if its own capability is present; neither is declared as a whole-collector requirement",
	},
	"entra.risky_agents": {
		Collects: "Current risky Entra Agent ID (AI-agent) identity counts by risk level and state, with a log twin per risky agent (id, agentDisplayName, riskDetail, the enabled/deleted/processing flags). The STATE feed behind `entra.agent_risk_detections`; the agent analog of `entra.risk`. Beta/Experimental, ungated (polls unconditionally; 200/empty or 403 where the feature is absent — a license gate would hide it on tenants where the endpoint works)",
		Source:   "`/beta/identityProtection/riskyAgents`",
	},
	"entra.risky_users": {
		Collects: "Blob transport for the risky-USER twin (#135-C): the `RiskyUsers` diagnostic-settings category, emitting the same `entra.risky_user` records the polled `entra.risk` twin would (reuses `logTwin`), bound to `riskLastUpdatedDateTime`. Log-only — a separate collector, NOT a source swap: `entra.risk` keeps polling for its bounded (riskLevel, riskState) gauge, and the composition root suppresses only its per-entity twin while this runs (keep-gauges/suppress-twin, blob twin XOR polled twin). Dodges the Identity Protection 1 req/s per-tenant ceiling for the per-entity stream",
		Source:   "`insights-logs-riskyusers` (RiskyUsers)",
		Category: "RiskyUsers",
	},
	"entra.roles": {
		Collects: "Standing directory-role membership; PIM active/eligible/permanent assignment counts",
		Source:   "`/directoryRoles`, `/roleManagement/directory/roleAssignmentScheduleInstances`, `.../roleEligibilityScheduleInstances`",
		Gating:   "PIM half only needs `entra_p2`, checked inside Collect(): the standing-membership half runs on every tier, and without P2 the PIM assignment counts are skipped rather than zero-emitted",
	},
	"entra.pim_role_policies": {
		Collects: "PIM role-activation policy requirements (#242) — what it takes to activate a role, the class of misconfiguration entra.roles cannot see. Bounded gauge counts policies by (requirement ∈ mfa_on_activation/approval_required/justification_required/auth_context_required/activation_expiry_required/eligibility_expiry_required, enabled, caller ∈ end_user/admin); one log twin per policy (role GUID joined from the policy assignments, enabled-rule list, approval + durations) that Warns when activation needs neither MFA nor approval",
		Source:   "`/policies/roleManagementPolicies?$expand=rules`, `/policies/roleManagementPolicyAssignments` (directory scope)",
		Gating:   "Entra ID P2 (PIM) — the PIM half of `entra.roles` is already live on this tenant. Runs on every tier; a 403 where PIM is absent is a graceful skip. The role display name is not resolved (GUID join key only)",
	},
	"entra.secure_score": {
		Collects: "Latest secure score with per-control state (score by category, peer-average benchmarks) and the control-profile catalog, plus a log twin per control and per profile carrying the remediation worklist — actionUrl, tier, threats — that the counts collapse away (#243). Microsoft publishes at most daily, hence the hourly poll",
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
	"entra.tenant_policy": {
		Collects: "Tenant policy posture (#245): CIS/benchmark switches as a 0/1 gauge by setting (users can create apps/groups/tenants, read other users; guest-invite restricted; MSOL PowerShell blocked; user consent for risky apps; SSPR; email-verified join; admin-consent workflow; app-management policy; app password-credential restriction), scoped-policy counts by kind, plus one log twin carrying the raw posture (guestUserRoleId, allowInvitesFrom, permission-grant policies)",
		Source:   "`/policies/authorizationPolicy`, `/policies/adminConsentRequestPolicy`, `/policies/defaultAppManagementPolicy`, `/policies/appManagementPolicies`, `/groupLifecyclePolicies`, `/policies/featureRolloutPolicies`",
		Gating:   "runs on every tier (v1.0, not beta); each singleton fetch is independent and degrades to a non-fatal error; the three scoped-policy collections are empty on m7kni so only their count is emitted (no field mapper written against unseen data)",
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
		Collects: "Directory audit log events (source: graph|blob — poll `/auditLogs/directoryAudits`, or consume the `AuditLogs` diagnostic-settings container; exactly one per config). Consent and role-change events additionally carry the changed `modified_property_names`, the assigned `role_name` (from a `Role.DisplayName` change), and the consented `granted_scope` (from an `AppRole.Value` change); property VALUES are never emitted (a `Credential` value can be the credential)",
		Source:   "`/auditLogs/directoryAudits`",
		Category: "AuditLogs",
	},
	"entra.provisioning": {
		Collects: "Provisioning (sync) events (source: graph|blob — poll `/auditLogs/provisioning`, or consume the `ProvisioningLogs` diagnostic-settings container; exactly one per config)",
		Source:   "`/auditLogs/provisioning`",
		Category: "ProvisioningLogs",
	},
	"entra.risk_detections": {
		Collects: "Identity Protection risk detection events (source: graph|blob — poll `/identityProtection/riskDetections`, `$top` capped at 500; or consume the `UserRiskEvents` diagnostic-settings container, which dodges the 1 req/s IPC ceiling — the blob `properties` IS the riskDetection resource, reusing mapRiskDetection; exactly one per config)",
		Source:   "`/identityProtection/riskDetections`",
		Category: "UserRiskEvents",
	},
	"entra.service_principal_risk_detections": {
		Collects: "Identity Protection SERVICE-PRINCIPAL (workload-identity) risk detection events — the WHY behind entra.risk's risky-SP gauge (leaked credentials, anomalous SP activity, admin-confirmed compromise, …). One log per detection; log-shaped like `entra.risk_detections`, the SP-risk STATE gauge already ships via `entra.risk`. Ungated (polls unconditionally; returns 200/empty or 403→WARN where the feature is absent — a license gate would hide it on tenants where the endpoint works)",
		Source:   "`/identityProtection/servicePrincipalRiskDetections`",
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
	"entra.graph_notifications": {
		Collects: "One record per Graph change-notification publish event: which app owns the subscription, which workload it targets, where it published, and whether it succeeded (`result_status_code`). A change-notification subscription is a persistence/supply-chain foothold — a durable low-noise feed of tenant changes — so `application_id` (the subscription owner) is the load-bearing attribute. Exists only as diagnostic-settings output",
		Category: "GraphNotificationsActivityLogs",
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
	"entra.signins.managed_identity.blob": {
		Collects: "Managed-identity sign-in events via storage rather than the beta `signInEventTypes` filter. A drop-in equivalent of the polled twin — same event name, same attributes, same `id`. Measured live at TOTAL id overlap with `entra.signins.managed_identity` (1/1, the tenant's only such sign-in), so exactly one of the pair may be enabled; registering both is refused at startup. On when blob ingest is configured (the polled twin is beta/opt-in)",
		Category: "ManagedIdentitySignInLogs",
	},

	// ---- Defender — blob collectors (advanced-hunting tables, #106) ----
	"defender.device_registry": {
		Collects: "One log per Windows registry create/set/delete Defender for Endpoint observes (`DeviceRegistryEvents`) — a primary persistence-hunting signal (Run keys, service installs, policy tampering) Graph exposes nowhere. Each record pairs the registry change with the full InitiatingProcess block, so a LogQL join answers which process wrote a key. The highest-volume Defender surface; on when blob ingest is configured",
		Category: "AdvancedHunting-DeviceRegistryEvents",
	},
	"defender.device_logon": {
		Collects: "One log per interactive/network/service logon Defender for Endpoint observes (`DeviceLogonEvents`) — the local and non-Entra logons Entra sign-in logs never see, with the initiating process, remote IP, and logon type. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceLogonEvents",
	},
	"defender.device_info": {
		Collects: "One log per periodic device-inventory snapshot from Defender for Endpoint (`DeviceInfo`) — OS, onboarding, exposure level, sensor health, and cloud-hosting metadata not in Graph. Snapshot-shaped (no ActionType), so it re-emits per cycle. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceInfo",
	},
	"defender.email": {
		Collects: "One log per message Defender for Office 365 processes (`EmailEvents`) — sender/recipient, delivery action, threat verdicts, and authentication results; zero MDO email coverage exists today. On when blob ingest is configured",
		Category: "AdvancedHunting-EmailEvents",
	},
	"defender.alert_evidence": {
		Collects: "One log per evidence row Defender attaches to an alert (`AlertEvidence`, absorbing #93) — the per-entity detail (real UPN/IP/geo/session/file) that `entra.security_alerts` collapses to a bare `evidence_count`. Joins to the alert on `alert_id`. On when blob ingest is configured",
		Category: "AdvancedHunting-AlertEvidence",
	},
	"defender.alert_info": {
		Collects: "One log per Defender XDR alert header (`AlertInfo`) — the alert's title, category (MITRE tactic), severity, detection/service source, and attack techniques, keyed by `alert_id`. The alert-level companion to `defender.alert_evidence`'s per-entity rows: join the two on `alert_id`. On when blob ingest is configured",
		Category: "AdvancedHunting-AlertInfo",
	},
	"defender.url_click_event": {
		Collects: "One log per Safe Links URL click Defender for Office 365 records (`UrlClickEvents`) — the clicked URL and its chain, the click verdict/action, whether the user clicked through a block, threat types, and the app/workload context, keyed by `network_message_id`. Zero coverage exists today. On when blob ingest is configured",
		Category: "AdvancedHunting-UrlClickEvents",
	},
	"defender.device_process": {
		Collects: "One log per process creation Defender for Endpoint observes (`DeviceProcessEvents`) — the process tree (created process + full initiating-process lineage, command lines, hashes, signer) that is the core of endpoint hunting. The largest-volume Defender table; on when blob ingest is configured",
		Category: "AdvancedHunting-DeviceProcessEvents",
	},
	"defender.device_file": {
		Collects: "One log per file create/modify/rename/delete Defender for Endpoint observes (`DeviceFileEvents`) — file hashes, paths, origin URL/IP, share and sensitivity-label context, with the initiating process. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceFileEvents",
	},
	"defender.device_network": {
		Collects: "One log per network connection Defender for Endpoint observes (`DeviceNetworkEvents`) — local/remote IP+port, URL, protocol, with the initiating process; the C2/exfil/lateral-movement signal. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceNetworkEvents",
	},
	"defender.device_event": {
		Collects: "One log per miscellaneous endpoint event Defender records (`DeviceEvents`) — the catch-all table spanning AMSI/`ScriptContent`, memory-injection API calls, USB mounts, WMI process creation, and more, keyed by `action_type`. `ScriptContent` (the full script body, inside `additional_fields`) ships verbatim per #106. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceEvents",
	},
	"defender.device_image_load": {
		Collects: "One log per image (DLL/module) load Defender for Endpoint observes (`DeviceImageLoadEvents`) — the DLL-side-load hunting signal, with the loaded file's hashes/path and the full initiating-process lineage. On when blob ingest is configured",
		Category: "AdvancedHunting-DeviceImageLoadEvents",
	},
	"defender.device_network_info": {
		Collects: "One log per device network-adapter snapshot (`DeviceNetworkInfo`) — MAC, adapter name/type/status/vendor, DHCP flags, tunnel type, and the (stringified) IP/DNS/gateway/connected-network lists. Enrichment companion to `device_network`. Snapshot; on when blob ingest is configured",
		Category: "AdvancedHunting-DeviceNetworkInfo",
	},
	"defender.device_file_certificate": {
		Collects: "One log per file code-signing certificate Defender observes (`DeviceFileCertificateInfo`) — signer/issuer + hashes, signature type, serial, validity window, CRL URLs, and trust/root-Microsoft flags. Companion to `device_file`/`device_process` for signing-trust hunting. Snapshot; on when blob ingest is configured",
		Category: "AdvancedHunting-DeviceFileCertificateInfo",
	},
	"defender.email_url": {
		Collects: "One log per URL found in a message (`EmailUrlInfo`) — the URL, its domain, and position in the redirect chain, joined to `defender.email` on `network_message_id`. On when blob ingest is configured",
		Category: "AdvancedHunting-EmailUrlInfo",
	},
	"defender.email_attachment": {
		Collects: "One log per email attachment (`EmailAttachmentInfo`) — file name/type/extension/size, `sha256` (malware-hash hunting), detection methods and threat verdicts, sender/recipient — joined to `defender.email` on `network_message_id`. On when blob ingest is configured",
		Category: "AdvancedHunting-EmailAttachmentInfo",
	},
	// ---- Defender for Office 365 — Exchange Online transport (snapshot) ----
	"defender.quarantine": {
		Collects: "How many messages are HELD in Defender for Office 365 quarantine right now — a bounded gauge by `quarantine_type` x `direction` x `entity_type`, plus one log per held message carrying sender, recipients, subject, the quarantine policy and tag, expiry, and the per-message permission flags (`permission_to_release=false` means the recipient cannot self-release). Queue DEPTH, not flow: released messages stay visible to the API for the rest of their retention and are deliberately not counted, so the number returns to zero when quarantine drains. The state third of graph2otel's quarantine coverage — `defender.email_post_delivery` carries the movement and `m365.unified_audit` the history, and all three join on `network_message_id`. No Graph endpoint exists for any of this. Off unless `exchange_online.enabled` is set",
		Source:   "`POST outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand` running `Get-QuarantineMessage -ReleaseStatus NOTRELEASED` — a fourth first-party API, NOT Graph. It needs TWO grants and neither alone does anything (live-measured: 401 with neither, 403 with the app role only, 200 with both): the app role `Exchange.ManageAsApp` on Office 365 Exchange Online, plus an Entra DIRECTORY role on the service principal, `Security Reader` being the least-privileged sufficient one. Both read-only. Quarantined TEAMS messages need `-EntityType Teams`, which `Security Reader` is denied, so they are covered via the audit trail instead",
	},
	"defender.email_post_delivery": {
		Collects: "One log per post-delivery action Defender for Office 365 takes on an already-delivered message (`EmailPostDeliveryEvents`) — ZAP, manual and automated remediation, and redelivery — with the action, its trigger and result, and the resulting `delivery_location`; the only signal that shows a message MOVING into or out of quarantine, joined to `defender.email` on `network_message_id`. On when blob ingest is configured",
		Category: "AdvancedHunting-EmailPostDeliveryEvents",
	},
	"defender.identity_logon": {
		Collects: "One log per identity logon Defender for Identity observes (`IdentityLogonEvents`) — on-prem/hybrid AD + cloud logons Entra sign-in logs never see, with account/target/destination, logon type, IP + geo/ISP, and the raw `additional_fields`. On when blob ingest is configured",
		Category: "AdvancedHunting-IdentityLogonEvents",
	},
	"defender.identity_info": {
		Collects: "One log per identity snapshot (`IdentityInfo`) — the enrichment Graph doesn't expose: `criticality_level`, `blast_radius`, `privileged_entra_pim_roles`, risk level, plus directory attributes (department/title/manager/on-prem+cloud SIDs). Snapshot; on when blob ingest is configured",
		Category: "AdvancedHunting-IdentityInfo",
	},
	"defender.cloud_app_event": {
		Collects: "One log per cloud-app activity Defender for Cloud Apps records (`CloudAppEvents`) — SharePoint/Exchange/OAuth file ops, ACL changes, mail access, sign-ins — with actor/app/object, IP+geo, admin/external/impersonation flags, and the raw event payload (`raw_event_data`). On when blob ingest is configured",
		Category: "AdvancedHunting-CloudAppEvents",
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
		Collects: "Autopilot device registration + deployment profile state, plus device-registration sync staleness (#248): sync_age_seconds (since the last OEM/partner sync) + sync_status, with a Warn twin when the sync is not healthy — so \"registrations stopped arriving\" is detectable",
		Source:   "`/deviceManagement/windowsAutopilotDeviceIdentities`, deployment profiles, `/beta/deviceManagement/windowsAutopilotSettings` (sync singleton)",
	},
	"intune.certificates": {
		Collects: "Certificate state + days-until-expiry",
		Source:   "`/deviceManagement/deviceConfigurations` (per-profile `managedDeviceCertificateStates`), `/deviceManagement/userPfxCertificates`",
	},
	"intune.compliance": {
		Collects: "Tenant-wide + per-policy compliance state rollups",
		Source:   "`/deviceManagement/deviceCompliancePolicies`, device compliance states",
	},
	"intune.compliance_alerts": {
		Collects: "One record per Intune compliance fired-event — the \"managed device X is not compliant\" alerts an operator acts on, naming the device (host/NetBIOS/DNS), its owner (`user_name`/`upn_suffix`), and which compliance rule failed (the setting path in `description`). Graph exposes only the notification templates, not the fired events (#94). Emitted Warn: a device fell out of compliance",
		Category: "OperationalLogs",
	},
	"intune.config_profiles": {
		Collects: "Configuration profile status + version, per-setting state",
		Source:   "`/deviceManagement/deviceConfigurations` (fan-out per profile)",
	},
	"intune.connectors": {
		Collects: "Exchange/MTD/NDES/Managed-Google-Play connector health. Managed Google Play (#248) folds in as a fourth connector_type on the existing state + heartbeat_age_seconds metrics (no new metric names) with a Warn twin — a broken Android Enterprise bind stops all Android app delivery silently",
		Source:   "`/deviceManagement/exchangeConnectors`, `/deviceManagement/mobileThreatDefenseConnectors`, NDES (beta, isolated), `/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings` (beta, isolated)",
		Gating:   "Exchange/MTD are default-on; the NDES and Managed-Google-Play sub-fetches are beta and isolated, so their failure does not gate the collector",
	},
	"intune.detected_apps": {
		Collects: "Detected-apps software inventory catalog. Every catalog row becomes a `device_count` series, summed across versions and folded case-insensitively (Intune emits casing variants of one application). The fixed eight-app allow-list this collector used to promote from was retired in #235 — the catalog is unbounded, but it is bounded by the central cardinality limiter now (top N by device count, tail into `app_name=\"other\"`) rather than by a standing guess about which applications matter, which on a real tenant promoted zero series",
		Source:   "`/deviceManagement/detectedApps`",
	},
	"intune.endpoint_analytics": {
		Collects: "UXA per-device scores, boot/login time histograms, app crash counts, battery health, resource performance, anomaly-severity counts, per-device Windows 11 upgrade-readiness (the Work-From-Anywhere metricDevices navigation — eligibility, failed hardware checks, cloud posture), per-process startup impact, and per-device app health — the heaviest collector. Every per-entity sub-fetch emits a log twin as of #225, which withdrew the #114 no-twin exception this collector used to carry: the bounded metrics answer \"how many devices are in this state\", the twins answer \"which device, and why\" — including the battery age and max-capacity behind a battery score, and the Windows crash-bucket identifiers (`restartStopCode`, `restartFaultBucket`) behind a blue-screen count. The startup twin is stamped with the boot's own `startTime` rather than poll time; startup processes are twin-only, since the (device, process) pair is unbounded. Application-level app health is twinned for EVERY application (`intune.app_health`), and `intune.uxa.app_crash_count` now covers every executable too: its fixed allow-list of ten common binaries was retired in #235, having discarded 100% of the live data on m7kni (the one row the tenant produces is `LogonUI.exe`) and made a line-of-business app crashing thousands of times structurally invisible. The executable set is unbounded, so the metric is bounded by the central cardinality limiter instead — top N by crash count, tail folded into `app_name=\"other\"` — which ranks by the thing a crash metric is for",
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
	"intune.devices_blob": {
		Collects: "Blob transport for the per-device twin (#135-F): the `Devices` diagnostic-settings category, emitting the same `intune.managed_device` records the polled `intune.devices` twin would (reuses `deviceLogTwin`) — but the blob report uses PascalCase field names AND different enum VALUES, so each field is normalized onto the Graph shape first (`CompliantState \"Compliant\"`→`compliant`, `OS \"MacOS\"`→`macOS`, `EncryptionStatusString \"True\"`→bool), verified against both live shapes. A separate log-only collector, NOT a source swap: `intune.devices` keeps polling for its bounded fleet gauges (the blob inventory dump can't produce counts), and the composition root suppresses only its per-device twin while this runs (keep-gauges/suppress-twin). Staleness is computed against the snapshot's envelope time; the per-batch Stats summary record is skipped",
		Source:   "`insights-logs-devices` (Devices)",
		Category: "Devices",
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
	"intune.config_assignment_status": {
		Collects: "Per-device configuration-policy assignment status/failures (succeeded/pending/error/conflict/noncompliant), via the Reports Export API. Uses the `DeviceAssignmentStatusByConfigurationPolicy` report — one row per device×policy assignment",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.config_profile_device_status": {
		Collects: "Per-(device, configuration profile) applied status — `ReportStatus` succeeded/error/**conflict**/noncompliant with the raw `PolicyStatus` code — via the Reports Export API. Uses the `DeviceStatusesByConfigurationProfile` report; metric counts by report_status, per-device detail on the log twin (WARN on error/conflict/noncompliant)",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.config_setting_status": {
		Collects: "Per-setting configuration-policy device summary — how many assigned devices are compliant, errored, or in **conflict** on each setting — via the Reports Export API. Uses the `PerSettingDeviceSummaryByConfigurationPolicy` report; metric sums compliant/error/conflict device counts (three bounded series), per-(policy, setting) counts on the log twin (WARN on any error or conflict device)",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.devices_without_compliance_policy": {
		Collects: "Managed devices with no compliance policy assigned — a posture blind-spot — via the Reports Export API. Uses the `DevicesWithoutCompliancePolicy` report; metric counts by OS, per-device detail on the log twin (always WARN). Empty is the healthy steady state",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.driver_update_summary": {
		Collects: "Windows driver-update policy device counts by deployment state (error/in_progress/success/cancelled), via the Reports Export API. Uses the `DriverUpdatePolicyStatusSummary` report — the driver sibling of the feature/quality update summaries; pre-aggregated gauge, no log twin",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.epm_denied": {
		Collects: "Endpoint Privilege Management denied elevations — which applications were blocked from elevating, for whom, and how often — via the Reports Export API. Uses the `EpmDeniedReport` report; metric counts by elevation_type, per-denial detail (device, user, file, hash) on the log twin (always WARN). Empty is the steady state on a tenant with no denials",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.firewall_status": {
		Collects: "Per-device endpoint firewall health (raw `FirewallStatus` code; 0 = Enabled), via the Reports Export API. Uses the `FirewallStatus` report; metric counts by firewall status code, per-device detail on the log twin (WARN when not enabled)",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.noncompliant_settings": {
		Collects: "Per-device, per-setting compliance failures — which specific setting is noncompliant on which device — via the Reports Export API. Uses the `NoncompliantDevicesAndSettings` report, the detail the summary-only `intune.compliance` gauges cannot answer",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.device_attestation": {
		Collects: "Per-device TPM/health attestation status (attestation state, TPM manufacturer/version, model), via the Reports Export API. Uses the `TpmAttestationStatus` report — the `deviceHealthAttestationState` managedDevice property is null tenant-wide (live-measured), so the export is the working path",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.device_boot_security": {
		Collects: "Per-device Windows boot-security posture (BitLocker, Secure Boot, Code Integrity, VBS, firmware protection, memory integrity, Secured-Core, System Management Mode, TPM), via the Reports Export API. Uses the `WindowsDeviceHealthAttestationReport` report — the deeper posture behind `intune.device_attestation`'s summary; the `deviceHealthAttestationState` managedDevice property is null tenant-wide, so the export is the working path",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.autopilot_deployment": {
		Collects: "Per-device Windows Autopilot device-preparation (V2) deployment outcome (provisioning phase, deployment status, duration, result code), via the Reports Export API. Uses the `AutopilotV2DeploymentStatus` report — V1 returns zero rows on a device-prep tenant. Raw Microsoft status/result codes are emitted verbatim, not decoded",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.autopilot_deployment_apps": {
		Collects: "Per-application install status during a Windows Autopilot device-preparation (V2) deployment — the \"Apps\" tab of the device-deployment-details pane — bucketed by raw `PolicyInstallStatus` code with per-(device, app) detail on the log twin. Uses the `AutopilotV2DeploymentStatusDetailedAppInfo` report. Status codes are emitted verbatim, not decoded; app status is independent of the device deployment outcome",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.autopilot_deployment_scripts": {
		Collects: "Per-script execution status during a Windows Autopilot device-preparation (V2) deployment — the \"Scripts\" tab of the device-deployment-details pane — bucketed by raw `PolicyInstallStatus` code with per-(device, script) detail on the log twin. Uses the `AutopilotV2DeploymentStatusDetailedScriptInfo` report. Empty is a valid steady state on a tenant with no device-prep scripts; status codes are emitted verbatim, not decoded",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.epm_elevations": {
		Collects: "Endpoint Privilege Management application elevations — which applications ran elevated, how often, and whether the elevation was policy-governed (unmanaged elevations are a security signal), via the Reports Export API. Uses the `EpmAggregationReportByApplication` report",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.epm_elevations_by_publisher": {
		Collects: "Endpoint Privilege Management elevations attributed to the signing PUBLISHER — whose software is being run elevated on managed devices, how often, and whether the elevation was policy-governed — via the Reports Export API. Uses the `EpmAggregationReportByPublisher` report, the publisher cut of the `intune.epm_elevations` application rollup. Metric sums `ElevationCount` by elevation type (wire enum verbatim), per-publisher detail on the log twin (WARN on an unmanaged elevation)",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.epm_elevations_by_user": {
		Collects: "Endpoint Privilege Management elevations attributed to the USER — who is elevating, how often, and how much of it is governed by an EPM policy — via the Reports Export API. Uses the `EpmAggregationReportByUser` report, the user cut of the `intune.epm_elevations` application rollup. Metric sums the per-user managed/unmanaged counts into exactly two bounded series (both always emitted, even at zero); the user's UPN and its three counts ride the log twin (WARN when the user has any unmanaged elevation). The `Upn` column is emitted verbatim — it is not always a real UPN (a down-level `AzureAD\\user` logon name is live-observed)",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.epm_elevation_events": {
		Collects: "Per-elevation Endpoint Privilege Management event stream — one log record per privilege elevation on a managed device (which binary ran elevated, by whom, on which device, under what EPM policy, and whether governed), via the Reports Export API. Uses the `EpmElevationReportElevationEvent` report — the per-event detail behind the `intune.epm_elevations` aggregate. Checkpoints a watermark + seen-id set over the export transport so each elevation is emitted exactly once (stamped with its own EventDateTime) rather than re-emitted on every poll; the metric is a bounded counter by elevation type and result, and per-event detail rides the log twin",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.feature_update_summary": {
		Collects: "Per-policy Windows feature-update deployment rollup (devices in-progress / errored / succeeded, by policy and target version), via the Reports Export API. Uses the `FeatureUpdatePolicyStatusSummary` report — the \"Deployment status per update ring\" Monitor report. Pre-aggregated, so it emits a bounded gauge keyed by policy and no per-device twin",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.quality_update_summary": {
		Collects: "Per-policy Windows quality/expedite-update deployment rollup (devices in-progress / errored / succeeded, by policy and expedite release date), via the Reports Export API. Uses the `QualityUpdatePolicyStatusSummary` report — the \"Security update status\" Monitor report. Pre-aggregated, so it emits a bounded gauge keyed by policy and no per-device twin",
		Source:   "`POST /deviceManagement/reports/exportJobs`",
		Gating:   "the ReadWrite scope creates the export JOB and nothing else; graph2otel never writes Intune configuration or device state",
	},
	"intune.remediation_run_states": {
		Collects: "Per-device proactive-remediation health — for each remediation (deviceHealthScript), which devices its detection script passed or FAILED, the detection script's own output message, and whether a remediation ran. Emits a bounded gauge counted by remediation, detection state and remediation state, plus a per-(remediation, device) log twin carrying the device, OS and detection message. Chosen read-only over the `DeviceRunStatesByProactiveRemediation` export report — same data, no write scope and no per-policy export fan-out",
		Source:   "`GET /deviceManagement/deviceHealthScripts/{id}/deviceRunStates` (beta)",
		Gating:   "read-only `DeviceManagementConfiguration.Read.All` + `DeviceManagementManagedDevices.Read.All`; beta endpoint, so opt-in via explicit enable",
	},

	"intune.device_encryption": {
		Collects: "Per-device disk-encryption posture: whether the disk is actually encrypted, whether the device is even READY to be encrypted, whether an encryption policy reached it, and — for Windows — the specific BitLocker blockers (`osVolumeUnprotected`, `tpmNotReady`, `osVolumeEncryptionMethodMismatch`, …). The complementary \"why is it not encrypted\" detail behind `intune.devices`' coarse `isEncrypted` boolean, which exists on no other surface. Two bounded gauges (encryption state × readiness × device type, and policy setting state) plus a per-device log twin; `deviceType` is emitted as the verbatim Intune wire enum (`windowsRT`, `macMDM`), and the comma-joined `advancedBitLockerStates` flag list rides the twin only — its combinations are unbounded",
		Source:   "`GET /deviceManagement/managedDeviceEncryptionStates` (beta — v1.0 has no such segment)",
		Gating:   "read-only `DeviceManagementManagedDevices.Read.All`; beta endpoint, so opt-in via explicit enable",
	},

	"intune.hardware_inventory": {
		Collects: "Per-device HARDWARE inventory — disk capacity and free space, TPM chip identity (specification triple, manufacturer, firmware version), system firmware/BIOS version, Windows Device Guard VBS + Credential Guard state, OS edition/product type/language, device licensing status, battery level, wired IPv4 addresses, and mobile identity (IMEI, eSIM, phone number, carrier). `hardwareInformation` exists only on the BETA managedDevice type and materializes only on a SINGLE-ENTITY GET — the list form returns a near-empty stub and `$expand` is rejected — so the fleet is swept through `POST /$batch` in chunks of 20, costing `1 + ceil(N/20)` requests per cycle (the most expensive fetch shape in graph2otel, which is why the interval is 24h: Intune refreshes hardware inventory on a multi-day cycle). Deliberately does NOT re-emit what `intune.devices` already carries (serial, model, wifi MAC, isEncrypted, UPN) — device id and name ride the twin purely as the join key back to `intune.managed_device`. Wire traps handled explicitly: `batteryHealthPercentage`/`batteryChargeCycles` read 0 on every device including working laptops (0 = \"not reported\", attribute omitted), `totalStorageSpace`=0 on a running Linux host is likewise excluded rather than summed as zero, `deviceGuard*` reports Windows-only values on macOS/iOS/Linux and is emitted verbatim (never a non-Windows security posture), and `tpmSpecificationVersion` is a comma-joined triple (`2.0, 0, 1.64`), not a version number",
		Source:   "`GET /deviceManagement/managedDevices` for ids, then `POST /$batch` of `GET /deviceManagement/managedDevices/{id}?$select=hardwareInformation` in chunks of 20 (beta — v1.0 has no `hardwareInformation` property)",
		Gating:   "read-only `DeviceManagementManagedDevices.Read.All`; beta-only property, so opt-in via explicit enable",
	},

	// ---- Intune — window collectors ----
	"intune.audit_events": {
		Collects: "Intune audit events. Emits the NAMES of changed `modifiedProperties` but never their old/new values, which can carry credentials and certificates — the one genuine content exclusion in graph2otel",
		Source:   "`/deviceManagement/auditEvents`",
	},
	"intune.cloud_pc_audit": {
		Collects: "One log per Windows 365 / Cloud PC admin operation (provisioning-policy create/patch/delete, user-setting change, group assignment, reprovision, grace-period end) — the CloudPC control-plane audit trail, which has no Graph endpoint and exists only as a diagnostic-settings category. The intune.audit_events peer for Cloud PC: actor, target resource(s), and the NAMES of changed properties (never their values, #112). On when blob ingest is configured",
		Category: "Windows365AuditLogs",
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
		Collects: "The M365 unified audit log, via the async query API: POST a query, poll it, page the result. Its records are not Entra's, so they land under a top-level `m365.audit` event name. The same signal as `m365.activity` over a different transport — NOT superseded by it. The two trade against each other: this one loses on transport (beta-only, a >10-minute async query, and it 429s on rapid query creation) and wins on volume control, because it sends server-side `recordTypeFilters` and can therefore take Teams while excluding the `DLPEndpoint` firehose — which `m365.activity`'s five content-type buckets cannot express. Worth nothing where log storage is free, decisive where it is billed per GB. The uncomfortable part: the cheaper path is the beta one. The include-list also covers the quarantine record types — a message held, released, previewed or deleted, plus quarantine-policy changes — which is low-volume and high-signal, and carries `network_message_id`, the join key onto `defender.email` / `defender.email_post_delivery` / `defender.email_url`, so a release event resolves to the message it released. Exactly one of the two may be enabled; registering both is refused at startup",
		Source:   "`POST /security/auditLog/queries` (beta — the documented v1.0 form 404s on a live tenant even under a token carrying the scope)",
	},
	"m365.activity": {
		Collects: "The same M365 unified audit records as `m365.unified_audit`, over the Office 365 Management Activity API instead: subscribe to a content type, list its content blobs, fetch each. Wins on transport — stable v1.0, 2,000 req/min per tenant, content ~2 minutes behind the event, and no async query — which is why this one is not Experimental. Loses on volume control: the API has NO server-side filtering, so `o365_activity.content_types` is the only knob and every record fetched is shipped. Defaults to Audit.Exchange + Audit.SharePoint; Audit.General is opt-in (it is the only route to Teams here, and it was 3,865 of 4,035 records Endpoint DLP on a 6-device tenant — the firehose `m365.unified_audit` can filter out server-side and this cannot), and Audit.AzureActiveDirectory is omitted because `entra.signins.interactive` and `entra.directory_audits` already emit those records. Exactly one of the two may be enabled; registering both is refused at startup",
		Source:   "`manage.office.com/api/v1.0/{tenant}/activity/feed` — a second first-party API, NOT Graph: different audience, and `POST /subscriptions/start` is a write (the second break in graph2otel's read-only property, after the reports-export job)",
	},

	// ---- Defender for Cloud Apps (MDCA) — window collectors ----
	"mdca.discovery_parse": {
		Collects: "Cloud Discovery parse health, the signal no uploader can see: a Cloud Discovery upload 200s the moment the blob lands and a parse task is QUEUED, but the parse runs asynchronously and writes its verdict ONLY to the governance log — so 22 consecutive silent parse failures on the live tenant (2026-07-17) produced no signal anywhere while every upload reported green. Emits one log twin (`mdca.discovery_parse`) per DiscoveryParseLogTask (template, is_success, input_stream_id, transactions/cloud-services counts; Error severity on failure, a queued task is `state=pending` and NOT a failure), a `mdca.discovery.parse.last_success.age` gauge per stream that keeps CLIMBING when uploads stop (the alert-on-silence signal a failure counter cannot produce), and a `mdca.discovery.parse.tasks` counter by outcome. Dedupes on `_id`+`updateTimestamp` because a task's status MUTATES after creation — a naive `_id` dedupe ships only the queued state and hides every verdict. Experimental: the legacy portal API has no Graph successor",
		Source:   "`{tenant}.{region}.portal.cloudappsecurity.com/api/v1/governance/` — the MDCA legacy portal API, NOT Graph: a static `Authorization: Token` credential (no azidentity, no app-role scope), 30 req/min per tenant, server-side filtering only on `timestamp` (taskName/status filters silently return empty, so they are applied client-side)",
	},

	// ---- M365 — snapshot collectors ----
	"m365.teams": {
		Collects: "Microsoft Teams inventory governance: teams by visibility, the OWNERLESS count (zero owners = an unmanageable orphan holding files — the headline signal, excluding archived teams, which are a desired end-state), the WITH-GUESTS count (external-guest exposure = a data-egress surface), and tenant-wide membership by role. Plus one `m365.team` log twin per team (id, name, visibility, owner/member/guest counts, is_archived), Warn severity on an ownerless team. Also the Teams SECURITY surface (#247), riding the same per-team fan-out: installed apps by distribution_method × has_rsc_permissions (a `m365.teams_app` twin, Warn on a SIDELOADED app or an RSC grant — resource-specific consent that `entra.consent` structurally cannot see), and channels by membership_type × is_archived (a `m365.team_channel` twin; a SHARED channel exposes content to an external tenant no guest count can see). Three calls/team now (`?$select=summary,isArchived`, `installedApps`, `channels`) — installedApps rejects $top and is paged by nextLink. Long default interval; degrades to a skip-and-log 403 when the read scopes are not yet granted",
		Source:   "`/teams`, `/teams/{id}?$select=summary,isArchived`, `/beta/teams/{id}/installedApps`, `/beta/teams/{id}/channels`",
	},
	"m365.servicehealth": {
		Collects: "M365 service health, so \"is this us or Microsoft?\" is answerable in-band. From ONE `?$expand=issues` fetch: service count by health status, a numeric status enum per service (mapping in `docs/signals.md`), open-issue count by classification+status, and a log twin (`m365.service_health_issue`) per UNRESOLVED issue carrying id/title/impactDescription/service/timestamps — resolved history is covered by the aggregate counts, not re-twinned every cycle. Snapshot, not a window collector (no delta/time filter); `endDateTime` is null while open, so no duration is derived",
		Source:   "`/admin/serviceAnnouncement/healthOverviews?$expand=issues`",
	},
	"m365.servicemessages": {
		Collects: "M365 message-center posts — the upcoming-change announcements (`planForChange`/`preventOrFixIssue`/`stayInformed`), a different question from service health. Bounded count by category+severity, plus a log twin (`m365.service_message`) per message carrying title/body/services/dates/`isMajorChange`/`actionRequiredByDateTime`. On by default; needs its own `ServiceMessage.Read.All` scope (the higher-volume half of the surface); a major change escalates the twin to Warn",
		Source:   "`/admin/serviceAnnouncement/messages`",
	},
	"m365.sharepoint_settings": {
		Collects: "Tenant SharePoint/OneDrive sharing posture from one `/admin/sharepoint/settings` fetch: external-sharing capability + domain-restriction mode, legacy-auth toggle, external-resharing, unmanaged-sync restriction, idle-session sign-out, and default storage/retention limits — as bounded security-posture gauges, plus a log twin carrying the full config including the sharing domain allow/block lists (unbounded, so log-only per #112). Legacy-auth-on escalates the twin to Warn",
		Source:   "`/admin/sharepoint/settings`",
	},
	"m365.storage": {
		Collects: "SharePoint + OneDrive storage utilization from the M365 usage-reporting API (`getSharePointSiteUsageStorage`/`getOneDriveUsageStorage` + the two `*Detail` functions, CSV via a 302). Tenant used/total bytes by drive type, and a drive count per derived quota state (`normal`/`nearing`/`critical`/`exceeded`, computed from used÷allocated — the live `quota.state` facet needs read-everything SharePoint scopes, so it is intentionally not used). One log twin per site/drive carries owner, site URL, byte counts, and quota state (unbounded, so log-only per #112). Reads `/admin/reportSettings` to warn when report name-concealment is on",
		Source:   "`/reports/getSharePointSiteUsageStorage`, `/reports/getOneDriveUsageStorage`, `/reports/getSharePointSiteUsageDetail`, `/reports/getOneDriveUsageAccountDetail`",
	},

	// ---- Purview — snapshot collectors ----
	"purview.ediscovery_cases": {
		Collects: "eDiscovery (Premium) case inventory: a bounded count of cases by status, plus a log twin per case (id, display name, custodial description, external id, real created/closed times). Opt-in and default-off — v1.0 GA, but a granted `eDiscovery.Read.All` scope is not enough: the app's service principal must also be registered in the Security & Compliance data plane (see `docs/data-plane-registration.md`), so a default deployment would 401 on every poll. The `0001-01-01` .NET-zero createdDateTime on the auto-created default case is dropped, not emitted as a year-0001 timestamp",
		Source:   "`/security/cases/ediscoveryCases`",
	},
	"purview.sensitivity_labels": {
		Collects: "Sensitivity label catalog: a count by applicable-to type, plus a log twin per label carrying its priority and `hasProtection` — which is how label encryption activation is readable at all. Bind the label's text to `name`: `displayName` is present but always null",
		Source:   "`/security/dataSecurityAndGovernance/sensitivityLabels`",
	},
	"purview.retention_labels": {
		Collects: "Retention label definitions + retention event types, each with a log twin. Blocked app-only on a live tenant — both endpoints 500 with `DataInsightsRequestError`/Forbidden even with the scope granted, because Microsoft documents Application access as not supported — so the collector recognizes that specific pair and reports unavailable rather than failing",
		Source:   "`/security/labels/retentionLabels`, `/security/triggerTypes/retentionEventTypes`",
	},
}
