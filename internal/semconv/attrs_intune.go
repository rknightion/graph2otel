package semconv

// Attribute keys used only by intune.* collectors.
const (
	AttrAccountSetupDurationSeconds      = "account_setup_duration_seconds"
	AttrAccountSetupStatus               = "account_setup_status"
	AttrActivityOperationType            = "activity_operation_type"
	AttrActivityResult                   = "activity_result"
	AttrActivityType                     = "activity_type"
	AttrActorApplicationDisplayName      = "actor_application_display_name"
	AttrActorApplicationId               = "actor_application_id"
	AttrActorIpAddress                   = "actor_ip_address"
	AttrActorType                        = "actor_type"
	AttrActorUserId                      = "actor_user_id"
	AttrActorUserPrincipalName           = "actor_user_principal_name"
	AttrAlertDisplayName                 = "alert_display_name"
	AttrAlertType                        = "alert_type"
	AttrAnomalySeverity                  = "anomaly_severity"
	AttrAntiMalwareVersion               = "anti_malware_version"
	AttrAppIdentifier                    = "app_identifier"
	AttrAppName                          = "app_name"
	AttrAppReliabilityScore              = "app_reliability_score"
	AttrAppType                          = "app_type"
	AttrAssigned                         = "assigned"
	AttrAssignmentStatusCode             = "assignment_status_code"
	AttrAttestationStatus                = "attestation_status"
	AttrAttestationStatusDetail          = "attestation_status_detail"
	AttrBaselineName                     = "baseline_name"
	AttrBatteryHealthScore               = "battery_health_score"
	AttrBucket                           = "bucket"
	AttrCertProfileName                  = "cert_profile_name"
	AttrCertificateProfileName           = "certificate_profile_name"
	AttrCertificateStatus                = "certificate_status"
	AttrComplianceGracePeriodExpiration  = "compliance_grace_period_expiration"
	AttrComplianceState                  = "compliance_state"
	AttrComplianceStatus                 = "compliance_status"
	AttrCompliantDeviceCount             = "compliant_device_count"
	AttrComponentName                    = "component_name"
	AttrConfigName                       = "config_name"
	AttrConfigType                       = "config_type"
	AttrConnectorType                    = "connector_type"
	AttrConflictDeviceCount              = "conflict_device_count"
	AttrDeploymentDurationSeconds        = "deployment_duration_seconds"
	AttrDeploymentState                  = "deployment_state"
	AttrDeviceDisplayName                = "device_display_name"
	AttrDeviceDnsDomain                  = "device_dns_domain"
	AttrDeviceHostName                   = "device_host_name"
	AttrDeviceId                         = "device_id"
	AttrDeviceName                       = "device_name"
	AttrDeviceNetBiosName                = "device_net_bios_name"
	AttrDevicePlatform                   = "device_platform"
	AttrDeviceSerialNumber               = "device_serial_number"
	AttrDeviceSetupDurationSeconds       = "device_setup_duration_seconds"
	AttrDeviceSetupStatus                = "device_setup_status"
	AttrDeviceState                      = "device_state"
	AttrDeviceStateCode                  = "device_state_code"
	AttrDeviceTag                        = "device_tag"
	AttrDeviceType                       = "device_type"
	AttrEnabled                          = "enabled"
	AttrEndpointAnalyticsScore           = "endpoint_analytics_score"
	AttrEngineVersion                    = "engine_version"
	AttrEnhancedKeyUsage                 = "enhanced_key_usage"
	AttrEnrollmentFailureDetails         = "enrollment_failure_details"
	AttrEnrollmentState                  = "enrollment_state"
	AttrEnrollmentType                   = "enrollment_type"
	AttrErrorCode                        = "error_code"
	AttrErrorDeviceCount                 = "error_device_count"
	AttrExpediteReleaseDate              = "expedite_release_date"
	AttrFailedDeviceCount                = "failed_device_count"
	AttrFailureCategory                  = "failure_category"
	AttrFailureReason                    = "failure_reason"
	AttrFeatureUpdateVersion             = "feature_update_version"
	AttrFileDescription                  = "file_description"
	AttrFirewallStatus                   = "firewall_status"
	AttrFlaggedReason                    = "flagged_reason"
	AttrFlaggedReasons                   = "flagged_reasons"
	AttrFullScanOverdue                  = "full_scan_overdue"
	AttrFullScanRequired                 = "full_scan_required"
	AttrGroupTag                         = "group_tag"
	AttrHash                             = "hash"
	AttrHealthState                      = "health_state"
	AttrIngestionType                    = "ingestion_type"
	AttrInstallState                     = "install_state"
	AttrInstalledDeviceCount             = "installed_device_count"
	AttrIntendedPurpose                  = "intended_purpose"
	AttrIntentName                       = "intent_name"
	AttrIntuneAccountId                  = "intune_account_id"
	AttrIntuneUserId                     = "intune_user_id"
	AttrIsAdminSelected                  = "is_admin_selected"
	AttrIsBuiltIn                        = "is_built_in"
	AttrIsEncrypted                      = "is_encrypted"
	AttrIsVirtualMachine                 = "is_virtual_machine"
	AttrIssuanceDateTime                 = "issuance_date_time"
	AttrIssuanceState                    = "issuance_state"
	AttrIssuer                           = "issuer"
	AttrIssuerName                       = "issuer_name"
	AttrKeyLength                        = "key_length"
	AttrKeyName                          = "key_name"
	AttrLastCheckin                      = "last_checkin"
	AttrLastFullScanDateTime             = "last_full_scan_date_time"
	AttrLastFullScanSignatureVersion     = "last_full_scan_signature_version"
	AttrLastIssuanceStateChangedDateTime = "last_issuance_state_changed_date_time"
	AttrLastQuickScanDateTime            = "last_quick_scan_date_time"
	AttrLastQuickScanSignatureVersion    = "last_quick_scan_signature_version"
	AttrLastReportedDateTime             = "last_reported_date_time"
	AttrLastSyncDateTime                 = "last_sync_date_time"
	AttrMalwareProtectionEnabled         = "malware_protection_enabled"
	AttrManufacturer                     = "manufacturer"
	AttrMigrating                        = "migrating"
	AttrModel                            = "model"
	AttrMonthElevationCount              = "month_elevation_count"
	AttrNetworkInspectionSystemEnabled   = "network_inspection_system_enabled"
	AttrNotApplicableDeviceCount         = "not_applicable_device_count"
	AttrNotInstalledDeviceCount          = "not_installed_device_count"
	AttrOdataType                        = "odata_type"
	AttrOperationalLogCategory           = "operational_log_category"
	AttrOs                               = "os"
	AttrOsVersion                        = "os_version"
	AttrOwnership                        = "ownership"
	AttrPartnerReportedThreatState       = "partner_reported_threat_state"
	AttrPendingInstallDeviceCount        = "pending_install_device_count"
	AttrPhase                            = "phase"
	AttrPlatform                         = "platform"
	AttrPlatformCode                     = "platform_code"
	AttrPolicyId                         = "policy_id"
	AttrPolicyInstallStatus              = "policy_install_status"
	AttrPolicyName                       = "policy_name"
	AttrPolicyPlatform                   = "policy_platform"
	AttrPolicyStatus                     = "policy_status"
	AttrPolicyType                       = "policy_type"
	AttrPreprovisioningAllowed           = "preprovisioning_allowed"
	AttrProductStatus                    = "product_status"
	AttrProductStatusCode                = "product_status_code"
	AttrProductStatusRaw                 = "product_status_raw"
	AttrProfileName                      = "profile_name"
	AttrProviderName                     = "provider_name"
	AttrPublisher                        = "publisher"
	AttrPublishingState                  = "publishing_state"
	AttrQuickScanOverdue                 = "quick_scan_overdue"
	AttrReadiness                        = "readiness"
	AttrRealTimeProtectionEnabled        = "real_time_protection_enabled"
	AttrRebootRequired                   = "reboot_required"
	AttrReportName                       = "report_name"
	AttrReportStatus                     = "report_status"
	AttrResourceDisplayNames             = "resource_display_names"
	AttrResourceIds                      = "resource_ids"
	AttrResourceType                     = "resource_type"
	AttrResourceTypes                    = "resource_types"
	AttrRestartCategory                  = "restart_category"
	AttrRevokeStatus                     = "revoke_status"
	AttrRingName                         = "ring_name"
	AttrRunState                         = "run_state"
	AttrScaleUnit                        = "scale_unit"
	AttrScenarioName                     = "scenario_name"
	AttrScriptName                       = "script_name"
	AttrSerialNumber                     = "serial_number"
	AttrSetting                          = "setting"
	AttrSettingDeviceStatus              = "setting_device_status"
	AttrSettingDisplayName               = "setting_display_name"
	AttrSettingId                        = "setting_id"
	AttrSettingName                      = "setting_name"
	AttrSettingStatus                    = "setting_status"
	AttrSettingStatusCode                = "setting_status_code"
	AttrSignal                           = "signal"
	AttrSignatureUpdateOverdue           = "signature_update_overdue"
	AttrSignatureVersion                 = "signature_version"
	AttrStalenessBucket                  = "staleness_bucket"
	AttrStartupPerformanceScore          = "startup_performance_score"
	AttrStateBucket                      = "state_bucket"
	AttrSubjectAlternativeNameFormat     = "subject_alternative_name_format"
	AttrSubjectName                      = "subject_name"
	AttrSubjectNameFormat                = "subject_name_format"
	AttrTamperProtectionEnabled          = "tamper_protection_enabled"
	AttrTarget                           = "target"
	AttrTechnology                       = "technology"
	AttrTemplateFamily                   = "template_family"
	AttrThumbprint                       = "thumbprint"
	AttrTokenName                        = "token_name"
	AttrTpmManufacturer                  = "tpm_manufacturer"
	AttrTpmVersion                       = "tpm_version"
	AttrUnifiedPolicyType                = "unified_policy_type"
	AttrUpdateDeploymentState            = "update_deployment_state"
	AttrUpdateType                       = "update_type"
	AttrUpn                              = "upn"
	AttrUpnSuffix                        = "upn_suffix"
	AttrUserName                         = "user_name"
	AttrValidFrom                        = "valid_from"
	AttrValidTo                          = "valid_to"
	AttrWifiMacAddress                   = "wifi_mac_address"
	AttrWorkFromAnywhereScore            = "work_from_anywhere_score"
)

// Attribute keys for the Intune reports-export collectors added in the #192–#195
// reporting build-out: device boot-security (WindowsDeviceHealthAttestationReport,
// #195), Autopilot device-prep deployment (AutopilotV2DeploymentStatus, #193), and
// Endpoint Privilege Management elevations (EpmAggregationReportByApplication,
// #193). AttrCompanyName / AttrFileName are reused from attrs_defender.go (one key,
// one const — enforced by the registry gate). Every value here is live-captured
// from the export CSV header, not a doc placeholder.
const (
	AttrAikKey                       = "aik_key"
	AttrAttestationError             = "attestation_error"
	AttrBitlockerStatus              = "bitlocker_status"
	AttrBootDebuggingStatus          = "boot_debugging_status"
	AttrCodeIntegrityStatus          = "code_integrity_status"
	AttrCurrentProvisioningPhase     = "current_provisioning_phase"
	AttrDepPolicy                    = "dep_policy"
	AttrDeploymentStatus             = "deployment_status"
	AttrElamDriverLoadedStatus       = "elam_driver_loaded_status"
	AttrElevationCount               = "elevation_count"
	AttrElevationType                = "elevation_type"
	AttrEnrollmentTime               = "enrollment_time"
	AttrFileHash                     = "file_hash"
	AttrFileVersion                  = "file_version"
	AttrFirmwareProtectionStatus     = "firmware_protection_status"
	AttrHealthCertIssuedDate         = "health_cert_issued_date"
	AttrInternalName                 = "internal_name"
	AttrIsBackgroundProcess          = "is_background_process"
	AttrMemoryAccessProtectionStatus = "memory_access_protection_status"
	AttrMemoryIntegrityProtection    = "memory_integrity_protection_status"
	AttrOsKernelDebuggingStatus      = "os_kernel_debugging_status"
	AttrPosture                      = "posture"
	AttrResultCode                   = "result_code"
	AttrSafeModeStatus               = "safe_mode_status"
	AttrSecureBootStatus             = "secure_boot_status"
	AttrSecuredCorePcStatus          = "secured_core_pc_status"
	AttrSystemManagementMode         = "system_management_mode"
	AttrVsmStatus                    = "vsm_status"
	AttrWinpeStatus                  = "winpe_status"
)

// Attribute keys for the intune.epm_elevation_events per-elevation SIEM stream
// (EpmElevationReportElevationEvent, #205) — the per-event detail behind the
// EpmAggregationReportByApplication rollup above. Every value is live-captured
// from the export CSV header (probed as graph2otel-poller 2026-07-20), not a doc
// placeholder. All are twin-only (per-entity) attributes; the metric carries only
// the bounded elevation_type/result pair (#112).
const (
	AttrElevationId       = "elevation_id"
	AttrFilePath          = "file_path"
	AttrIsSystemInitiated = "is_system_initiated"
	AttrJustification     = "justification"
	AttrParentProcessName = "parent_process_name"
	AttrProcessType       = "process_type"
	AttrProductName       = "product_name"
	AttrRuleId            = "rule_id"
)

// Attribute keys for intune.remediation_run_states (#207) — per-device proactive
// remediation (deviceHealthScripts) run state, read live from beta
// /deviceManagement/deviceHealthScripts/{id}/deviceRunStates. detection_state and
// remediation_state are the two bounded EPM/remediation enums the gauge is keyed
// by; the rest (the detection script's output message, script errors, timing)
// ride the log twin only.
const (
	AttrDetectionOutput        = "detection_output"
	AttrDetectionScriptError   = "detection_script_error"
	AttrDetectionState         = "detection_state"
	AttrLastStateUpdate        = "last_state_update"
	AttrRemediationId          = "remediation_id"
	AttrRemediationName        = "remediation_name"
	AttrRemediationScriptError = "remediation_script_error"
	AttrRemediationState       = "remediation_state"
)

// Attribute keys for intune.device_encryption (#199) — per-device disk-encryption
// posture from beta /deviceManagement/managedDeviceEncryptionStates (v1.0 has no
// such segment). encryption_state / encryption_readiness_state /
// encryption_policy_setting_state are the three bounded wire enums the gauges are
// keyed by (alongside the existing device_type); advanced_bitlocker_states is a
// comma-joined flag list whose COMBINATIONS are unbounded and file_vault_states is
// its Apple counterpart — both are twin-only, never a metric label (#112/#114).
// Every value is live-captured from the beta wire (probed as graph2otel-poller
// 2026-07-21), not a doc placeholder.
const (
	AttrAdvancedBitlockerStates      = "advanced_bitlocker_states"
	AttrEncryptionPolicySettingState = "encryption_policy_setting_state"
	AttrEncryptionReadinessState     = "encryption_readiness_state"
	AttrEncryptionState              = "encryption_state"
	AttrFileVaultStates              = "file_vault_states"
)

// Attribute keys for the Endpoint Analytics Work-From-Anywhere per-device Windows
// 11 upgrade-readiness signal (#194) — the metricDevices navigation under
// userExperienceAnalyticsWorkFromAnywhereMetrics. Values live-captured from the
// beta wire 2026-07-19 on m7kni.
const (
	AttrCloudIdentityScore            = "cloud_identity_score"
	AttrCloudManagementScore          = "cloud_management_score"
	AttrCloudProvisioningScore        = "cloud_provisioning_score"
	AttrOsCheckFailed                 = "os_check_failed"
	AttrProcessor64BitCheckFailed     = "processor_64bit_check_failed"
	AttrProcessorCoreCountCheckFailed = "processor_core_count_check_failed"
	AttrProcessorFamilyCheckFailed    = "processor_family_check_failed"
	AttrProcessorSpeedCheckFailed     = "processor_speed_check_failed"
	AttrRamCheckFailed                = "ram_check_failed"
	AttrSecureBootCheckFailed         = "secure_boot_check_failed"
	AttrStorageCheckFailed            = "storage_check_failed"
	AttrTpmCheckFailed                = "tpm_check_failed"
	AttrUpgradeEligibility            = "upgrade_eligibility"
	AttrWindowsScore                  = "windows_score"
)

// Attribute keys for the two Endpoint Privilege Management attribution cuts added
// in #201 — intune.epm_elevations_by_user (EpmAggregationReportByUser) and
// intune.epm_elevations_by_publisher (EpmAggregationReportByPublisher). Both are
// siblings of intune.epm_elevations (EpmAggregationReportByApplication), so
// elevation_type / elevation_count / company_name are reused above rather than
// redeclared. Every value here is live-captured from the export CSV header
// (probed as graph2otel-poller 2026-07-21 on m7kni), not a doc placeholder.
//
// AttrElevationGovernance is the by-user gauge's ONLY label: the report gives a
// managed/unmanaged split per user, and the two counts are summed into exactly two
// bounded series. The Upn column rides the log twin only — it identifies a user, so
// it can never be a metric label (#112), and it is emitted VERBATIM: one live row
// carried the down-level logon name `AzureAD\RobKnight` rather than a real UPN, so
// nothing here parses or validates it.
const (
	// Bare snake_case, not a dotted key: every domain attribute in this repo is
	// bare, and this one is a METRIC label, so a dot would survive to the wire
	// but reach PromQL normalized to an underscore (#82) — the golden, the docs
	// and the query surface would then disagree about the label's own name.
	AttrElevationGovernance = "elevation_governance"
	AttrManagedCount        = "managed_count"
	AttrTotalCount          = "total_count"
	AttrUnmanagedCount      = "unmanaged_count"
)

// Elevation-governance values for AttrElevationGovernance: the two bounded series
// intune.epm_elevations_by_user's gauge emits, always both, even at zero.
const (
	ElevationGovernanceManaged   = "managed"
	ElevationGovernanceUnmanaged = "unmanaged"
)
