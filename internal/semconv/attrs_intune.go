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

// Attribute keys for the intune.endpoint_analytics per-entity log twins added in
// #225, when the maintainer overrode the #114 no-twin exception this collector
// had carried since the original audit. Every key here is TWIN-ONLY: the bounded
// gauges and histograms keep their existing health_state / restart_category /
// category labels, and none of the per-device values below may become a metric
// label (#112) — device identity, boot timings and battery serial detail are all
// either unbounded or grow with fleet size.
//
// Values are live-captured from the beta/v1.0 wire (probed as graph2otel-poller
// against m7kni, 2026-07-21) except where noted on AttrCpuDisplayName's block,
// which is EDM-derived because the segment is empty on that tenant.
const (
	// Battery detail (userExperienceAnalyticsBatteryHealthDevicePerformance).
	// These are the fields that EXPLAIN a battery health score: a bare score of
	// 63 is not actionable, "63, 179 days old, 100% max capacity, 80 minutes
	// estimated runtime" is.
	AttrBatteryAgeDays          = "battery_age_days"
	AttrBatteryCount            = "battery_count"
	AttrBatteryIds              = "battery_ids"
	AttrEstimatedRuntimeMinutes = "estimated_runtime_minutes"
	AttrFullBatteryDrainCount   = "full_battery_drain_count"
	AttrMaxCapacityPercentage   = "max_capacity_percentage"

	// Boot-event detail (userExperienceAnalyticsDeviceStartupHistory). Unlike the
	// state twins, a startup history row is an EVENT with its own startTime, so
	// its twin is stamped with that time rather than poll time.
	// restart_stop_code / restart_fault_bucket are the Windows crash-bucket
	// identifiers — the only genuinely diagnostic fields in the set, and the
	// reason the per-boot twin was worth overriding the exception for.
	AttrCoreBootTimeMs          = "core_boot_time_ms"
	AttrCoreLoginTimeMs         = "core_login_time_ms"
	AttrFeatureUpdateBootTimeMs = "feature_update_boot_time_ms"
	AttrGroupPolicyBootTimeMs   = "group_policy_boot_time_ms"
	AttrGroupPolicyLoginTimeMs  = "group_policy_login_time_ms"
	AttrIsFeatureUpdate         = "is_feature_update"
	AttrIsFirstLogin            = "is_first_login"
	AttrResponsiveDesktopTimeMs = "responsive_desktop_time_ms"
	AttrRestartFaultBucket      = "restart_fault_bucket"
	AttrRestartStopCode         = "restart_stop_code"
	AttrTotalBootTimeMs         = "total_boot_time_ms"
	AttrTotalLoginTimeMs        = "total_login_time_ms"

	// Startup-process detail (userExperienceAnalyticsDeviceStartupProcesses).
	// process_name is per-process and combines with the device, so the pair is
	// unbounded — twin only. product_name and publisher are reused from above.
	AttrProcessName     = "process_name"
	AttrStartupImpactMs = "startup_impact_ms"

	// Per-device app-health detail (userExperienceAnalyticsAppHealthDevicePerformance),
	// the device-level sibling of the application-level segment that is empty on
	// m7kni under the 5-device Endpoint Analytics floor.
	AttrAppCrashCount            = "app_crash_count"
	AttrAppHangCount             = "app_hang_count"
	AttrCrashedAppCount          = "crashed_app_count"
	AttrDeviceAppHealthScore     = "device_app_health_score"
	AttrMeanTimeToFailureMinutes = "mean_time_to_failure_minutes"

	// AttrMeanResourceSpikeTimeScore is the sixth Endpoint Analytics score
	// category. It is on the wire of BOTH userExperienceAnalyticsDeviceScores and
	// userExperienceAnalyticsModelScores and was simply never mapped — the
	// original deviceScore struct predates it (live-measured 2026-07-24, #194:
	// 100.0 on wintest, 64.33/64.81/91.73/92.62 on the four load-generating VMs,
	// and the -1 sentinel on the rest).
	AttrMeanResourceSpikeTimeScore = "mean_resource_spike_time_score"

	// Per-APPLICATION app-health detail
	// (userExperienceAnalyticsAppHealthApplicationPerformance). Distinct from the
	// per-device block above: one row per application across the fleet, so the
	// app name is the entity. These are twin-only — the application set is
	// unbounded, which is exactly why intune.uxa.app_crash_count keeps a fixed
	// allow-list as its metric boundary while every row still gets a log record
	// (#114; the drop was the bug, the allow-list is not).
	AttrActiveDeviceCount = "active_device_count"
	AttrAppHealthScore    = "app_health_score"
	AttrAppUsageDuration  = "app_usage_duration"

	// Per-device resource detail (userExperienceAnalyticsResourcePerformance).
	// These names WERE EDM-derived while the segment was empty on m7kni; that
	// caveat is withdrawn — the segment returned a row on 2026-07-23 and every
	// mapped name matched the wire, so the whole block is now
	// [live-measured 2026-07-23, #194]. Values are still emitted only when
	// present, which is why a wrong name would have yielded an absent attribute
	// rather than a wrong one.
	//
	// The two *_threshold keys are the TENANT'S OWN policy values, not the
	// device's readings: they say what CPU/RAM spike percentage Endpoint
	// Analytics considers bad here (15% / 30% on m7kni), which is what turns a
	// bare "cpu_spike_time_percentage=12" into a judgement.
	AttrAverageSpikeTimeScore           = "average_spike_time_score"
	AttrCpuClockSpeedMhz                = "cpu_clock_speed_mhz"
	AttrCpuDisplayName                  = "cpu_display_name"
	AttrCpuSpikeTimePercentage          = "cpu_spike_time_percentage"
	AttrCpuSpikeTimePercentageThreshold = "cpu_spike_time_percentage_threshold"
	AttrCpuSpikeTimeScore               = "cpu_spike_time_score"
	AttrDiskType                        = "disk_type"
	AttrMachineType                     = "machine_type"
	AttrProcessorCoreCount              = "processor_core_count"
	AttrRamSpikeTimePercentage          = "ram_spike_time_percentage"
	AttrRamSpikeTimePercentageThreshold = "ram_spike_time_percentage_threshold"
	AttrRamSpikeTimeScore               = "ram_spike_time_score"
	AttrResourcePerformanceScore        = "resource_performance_score"
	AttrTotalRamMb                      = "total_ram_mb"
)

// Attribute keys for intune.hardware_inventory (#199) — the per-device
// `hardwareInformation` complex type, which exists ONLY on the beta managedDevice
// and only materializes on a SINGLE-ENTITY GET (the list form returns a stub).
// Every value here is live-captured from the beta wire via $batch (probed as
// graph2otel-poller 2026-07-21 on m7kni), not a doc placeholder.
//
// Only four of these are metric labels — AttrTpmSpecificationVersion,
// AttrVbsState, AttrCredentialGuardState and AttrStorageState — and each is a
// bounded wire enum or a per-fleet-constant version triple. Everything else is
// per-entity (storage bytes, TPM instance version, wired IPs, cellular identity)
// and rides the intune.device_hardware log twin only (#112/#114).
//
// device_id / device_name / operating_system / manufacturer / product_name /
// tpm_version / tpm_manufacturer are reused from above rather than redeclared —
// one key, one constant.
const (
	AttrBatteryChargeCycles                 = "battery_charge_cycles"
	AttrBatteryHealthPercentage             = "battery_health_percentage"
	AttrBatteryLevelPercentage              = "battery_level_percentage"
	AttrCellularTechnology                  = "cellular_technology"
	AttrCredentialGuardState                = "credential_guard_state"
	AttrDeviceGuardHardwareRequirementState = "device_guard_hardware_requirement_state"
	AttrDeviceLicensingStatus               = "device_licensing_status"
	AttrEsimIdentifier                      = "esim_identifier"
	AttrFreeStorageBytes                    = "free_storage_bytes"
	AttrImei                                = "imei"
	AttrIsSharedDevice                      = "is_shared_device"
	AttrIsSupervised                        = "is_supervised"
	AttrOperatingSystemEdition              = "operating_system_edition"
	AttrOperatingSystemLanguage             = "operating_system_language"
	AttrOperatingSystemProductType          = "operating_system_product_type"
	AttrPhoneNumber                         = "phone_number"
	AttrStorageState                        = "storage_state"
	AttrSubscriberCarrier                   = "subscriber_carrier"
	AttrSystemManagementBiosVersion         = "system_management_bios_version"
	// AttrTpmSpecificationVersion is DISTINCT from AttrTpmVersion. The wire
	// carries both, and they are not the same thing: the specification version is
	// a comma-joined triple ("2.0, 0, 1.64") that is constant across a fleet's TPM
	// revisions — bounded, so it is the gauge's label — while tpmVersion is the
	// chip's own firmware version ("8217.4131.22.13878"), per-entity and twin-only.
	AttrTpmSpecificationVersion = "tpm_specification_version"
	AttrTotalStorageBytes       = "total_storage_bytes"
	AttrVbsState                = "vbs_state"
	AttrWiredIpv4Addresses      = "wired_ipv4_addresses"
)

// Storage-state values for AttrStorageState: the two series
// intune.hardware_inventory.storage_bytes emits per operating system.
const (
	StorageStateTotal = "total"
	StorageStateFree  = "free"
)

// Attribute keys for the two #248 Intune device-management health folds, both
// reading a BETA singleton onto an existing collector's fetch cycle:
//
//   - intune/connectors — the Managed Google Play (Android managed store)
//     connector, added as a fourth connector_type on the existing
//     intune.connector.state / heartbeat_age_seconds metrics plus one
//     intune.connector log twin. bind_status / last_app_sync_status /
//     enrollment_target are twin-only; owner UPN reuses AttrOwnerPrincipalName,
//     connector_type / state / last_sync_date_time are reused from above.
//   - intune/autopilot — the windowsAutopilotSettings device-registration sync,
//     added as intune.autopilot.sync_age_seconds / sync_status plus one
//     intune.autopilot.sync log twin. sync_status is the metric label;
//     last_manual_sync_trigger_date_time is twin-only; id / last_sync_date_time
//     are reused from above.
//
// Every value here is live-captured from the beta wire (probed as
// graph2otel-poller against m7kni 2026-07-23), not a doc placeholder.
const (
	AttrBindStatus            = "bind_status"
	AttrEnrollmentTarget      = "enrollment_target"
	AttrLastAppSyncStatus     = "last_app_sync_status"
	AttrLastManualSyncTrigger = "last_manual_sync_trigger_date_time"
	AttrSyncStatus            = "sync_status"
)
