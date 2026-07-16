package activity

// recordtypes.go holds the two enum tables that make m365.activity and
// m365.unified_audit emit the SAME attribute values for the same event.
//
// # Why these tables exist at all
//
// The two collectors are two transports over one signal (the Management API
// record IS the query API's auditData sub-object), so they must be drop-in
// equivalents. But they disagree on TYPE for two fields:
//
//	emitted attr | query API (m365.unified_audit) | Management API (here)
//	record_type  | auditLogRecordType  STRING     | RecordType  INT
//	user_type    | userType            STRING     | UserType    INT
//
// Without these tables the same event emits record_type "DLPEndpoint" from one
// transport and 63 from the other, and nothing downstream joins them — with no
// error anywhere. This is the #89 durationMs-string-vs-int trap in a new place.
//
// # Why the target strings are PascalCase, when Graph's docs say camelCase
//
// Microsoft's Graph docs declare both as camelCase enums (auditLogRecordType,
// auditLogUserType — "regular", "system", …). The WIRE disagrees, and the wire
// is what has to match. The live capture in #98 from the m7kni tenant:
//
//	{ "auditLogRecordType": "AzureActiveDirectory", "service": "AzureActiveDirectory",
//	  "userType": "System",
//	  "auditData": { "RecordType": 8, "Workload": "AzureActiveDirectory", … } }
//
// PascalCase on both, and that single record also pins RecordType 8 <->
// "AzureActiveDirectory" — the one place where the int and the string appear
// side by side for the same event. #98 recorded the same asymmetry from the
// other direction: the recordTypeFilters REQUEST takes camelCase
// ("exchangeAdmin") while the RESPONSE returns PascalCase ("ExchangeAdmin").
// So the query API passes the classic O365 names straight through rather than
// serializing its own declared enum — which means the classic Management API
// schema's own table is the convergence table.
//
// # Provenance, and how much to trust each row
//
// Two tiers, deliberately not merged:
//
//   - LIVE-VERIFIED (trust these): the 20 members #98 observed on m7kni, plus
//     RecordType 8/9 which Microsoft's own examples pin to an int. These are
//     ground truth and are pinned by name in the tests.
//   - DOC-SOURCED (best effort): the rest, transcribed from the Office 365
//     Management Activity API schema's AuditLogRecordType table. A member
//     Microsoft has RENAMED is the known risk here — the docs show the new
//     display name while the wire keeps emitting the old enum name for
//     compatibility. Where that is visible (a name containing a space, which
//     cannot be an enum member) the row is OMITTED rather than guessed; see
//     recordTypeNames' trailing note.
//
// An unknown or omitted value is SAFE by construction: recordTypeName reports
// !ok, the mapper omits record_type and emits only record_type_id, and no wrong
// value is ever invented. Getting a row wrong is far worse than not having it.

// recordTypeNames maps the Management API's RecordType int to the PascalCase
// name the Graph audit query API returns in auditLogRecordType.
//
// Source: the Office 365 Management Activity API schema's AuditLogRecordType
// table, reconciled against the live members in #98 (every overlapping row
// agreed).
//
// DELIBERATE OMISSIONS — do not "fix" these by pasting the docs value:
//
//   - 22 and 216 are documented as "Viva Engage" and "Viva Goals", with a
//     SPACE. An enum member cannot contain a space, so those are Microsoft's
//     post-rename display text, not the wire value (22 was historically
//     "Yammer", and the wire will keep emitting the pre-rename name). Emitting
//     "Viva Engage" would be a silent convergence break; omitting them routes
//     both to the honest record_type_id-only path until a live record settles
//     the real name.
//   - Six record types observed LIVE on m7kni (#98) are absent from Microsoft's
//     published table entirely and so cannot be listed here at any int:
//     UAMOperation, MSDEIndicatorsSettings, MSDEResponseActions,
//     MSDEGeneralSettings, MAPGRemediation, AgentAdminActivity. RecordType 117
//     (Workload=AppGovernance, #100) is very probably MAPGRemediation, but
//     "very probably" is exactly the reasoning that produced three wrong
//     verdicts on this project (#109/#100/#130), so it is left unmapped.
//
// Those two facts together mean roughly a quarter of the record types this
// tenant actually emits resolve to record_type_id only. That is the honest
// state, and it is why record_type_id is emitted unconditionally.
var recordTypeNames = map[int64]string{
	1:   "ExchangeAdmin",
	2:   "ExchangeItem",
	3:   "ExchangeItemGroup",
	4:   "SharePoint",
	6:   "SharePointFileOperation",
	7:   "OneDrive",
	8:   "AzureActiveDirectory",
	9:   "AzureActiveDirectoryAccountLogon",
	10:  "DataCenterSecurityCmdlet",
	11:  "ComplianceDLPSharePoint",
	13:  "ComplianceDLPExchange",
	14:  "SharePointSharingOperation",
	15:  "AzureActiveDirectoryStsLogon",
	16:  "SkypeForBusinessPSTNUsage",
	17:  "SkypeForBusinessUsersBlocked",
	18:  "SecurityComplianceCenterEOPCmdlet",
	19:  "ExchangeAggregatedOperation",
	20:  "PowerBIAudit",
	21:  "CRM",
	23:  "SkypeForBusinessCmdlets",
	24:  "Discovery",
	25:  "MicrosoftTeams",
	28:  "ThreatIntelligence",
	29:  "MailSubmission",
	30:  "MicrosoftFlow",
	31:  "AeD",
	32:  "MicrosoftStream",
	33:  "ComplianceDLPSharePointClassification",
	34:  "ThreatFinder",
	35:  "Project",
	36:  "SharePointListOperation",
	37:  "SharePointCommentOperation",
	38:  "DataGovernance",
	39:  "Kaizala",
	40:  "SecurityComplianceAlerts",
	41:  "ThreatIntelligenceUrl",
	42:  "SecurityComplianceInsights",
	43:  "MIPLabel",
	44:  "VivaInsights",
	45:  "PowerAppsApp",
	46:  "PowerAppsPlan",
	47:  "ThreatIntelligenceAtpContent",
	48:  "LabelContentExplorer",
	49:  "TeamsHealthcare",
	50:  "ExchangeItemAggregated",
	51:  "HygieneEvent",
	52:  "DataInsightsRestApiAudit",
	53:  "InformationBarrierPolicyApplication",
	54:  "SharePointListItemOperation",
	55:  "SharePointContentTypeOperation",
	56:  "SharePointFieldOperation",
	57:  "MicrosoftTeamsAdmin",
	58:  "HRSignal",
	59:  "MicrosoftTeamsDevice",
	60:  "MicrosoftTeamsAnalytics",
	61:  "InformationWorkerProtection",
	62:  "Campaign",
	63:  "DLPEndpoint",
	64:  "AirInvestigation",
	65:  "Quarantine",
	66:  "MicrosoftForms",
	67:  "ApplicationAudit",
	68:  "ComplianceSupervisionExchange",
	69:  "CustomerKeyServiceEncryption",
	70:  "OfficeNative",
	71:  "MipAutoLabelSharePointItem",
	72:  "MipAutoLabelSharePointPolicyLocation",
	73:  "MicrosoftTeamsShifts",
	75:  "MipAutoLabelExchangeItem",
	76:  "CortanaBriefing",
	78:  "WDATPAlerts",
	79:  "PowerAppsResource",
	82:  "SensitivityLabelPolicyMatch",
	83:  "SensitivityLabelAction",
	84:  "SensitivityLabeledFileAction",
	85:  "AttackSim",
	86:  "AirManualInvestigation",
	87:  "SecurityComplianceRBAC",
	88:  "UserTraining",
	89:  "AirAdminActionInvestigation",
	90:  "MSTIC",
	91:  "PhysicalBadgingSignal",
	92:  "TeamsEasyApprovals",
	93:  "AipDiscover",
	94:  "AipSensitivityLabelAction",
	95:  "AipProtectionAction",
	96:  "AipFileDeleted",
	97:  "AipHeartBeat",
	98:  "MCASAlerts",
	99:  "OnPremisesFileShareScannerDlp",
	100: "OnPremisesSharePointScannerDlp",
	101: "ExchangeSearch",
	102: "SharePointSearch",
	103: "PrivacyInsights",
	105: "MyAnalyticsSettings",
	106: "SecurityComplianceUserChange",
	107: "ComplianceDLPExchangeClassification",
	109: "MipExactDataMatch",
	113: "MS365DCustomDetection",
	147: "CoreReportingSettings",
	148: "ComplianceConnector",
	154: "OMEPortal",
	157: "MipLabelAnalyticsAuditRecord",
	164: "ScorePlatformGenericAuditRecord",
	174: "DataShareOperation",
	181: "EduDataLakeDownloadOperation",
	183: "MicrosoftGraphDataConnectOperation",
	186: "PowerPagesSite",
	187: "PowerPlatformAdminDlp",
	188: "PlannerPlan",
	189: "PlannerCopyPlan",
	190: "PlannerTask",
	191: "PlannerRoster",
	192: "PlannerPlanList",
	193: "PlannerTaskList",
	194: "PlannerTenantSettings",
	195: "ProjectForThewebProject",
	196: "ProjectForThewebTask",
	197: "ProjectForThewebRoadmap",
	198: "ProjectForThewebRoadmapItem",
	199: "ProjectForThewebProjectSettings",
	200: "ProjectForThewebRoadmapSettings",
	202: "MicrosoftTodoAudit",
	206: "MicrosoftTeamsSensitivityLabelAction",
	217: "MicrosoftGraphDataConnectConsent",
	218: "AttackSimAdmin",
	230: "TeamsUpdates",
	231: "PlannerRosterSensitivityLabel",
	235: "MicrosoftDefenderForIdentityAudit",
	237: "DefenderExpertsforXDRAdmin",
	251: "VfamCreatePolicy",
	252: "VfamUpdatePolicy",
	253: "VfamDeletePolicy",
	256: "PowerPlatformAdministratorActivity",
	257: "Windows365CustomerLockbox",
	261: "CopilotInteraction",
	265: "VivaLearning",
	266: "VivaLearningAdmin",
	269: "PeopleAdminSettings",
	275: "OWAAuth",
	277: "SharePointESignature",
	278: "Dynamics365BusinessCentral",
	279: "MeshWorlds",
	280: "VivaPulseResponse",
	281: "VivaPulseOrganizer",
	282: "VivaPulseAdmin",
	283: "VivaPulseReport",
	284: "AIAppInteraction",
	285: "ComplianceDLMExchange",
	286: "ComplianceDLMSharePoint",
	287: "ProjectForThewebAssignedToMeSettings",
	288: "CloudPolicyService",
	291: "SensitiveInfoDiscovered",
	292: "InsiderRiskScopedUserInsights",
	293: "MicrosoftTeamsRetentionLabelAction",
	294: "AadRiskDetection",
	295: "AuditSearch",
	296: "AuditRetentionPolicy",
	297: "AuditConfig",
	298: "BackupPolicy",
	299: "RestoreTask",
	300: "RestoreItem",
	301: "BackupItem",
	302: "URBACAssignment",
	303: "URBACRole",
	304: "URBACEnableState",
	306: "PurviewInsiderRiskCases",
	307: "PurviewInsiderRiskAlerts",
	308: "InsiderRiskScopedUsers",
	310: "CreateCopilotPlugin",
	311: "UpdateCopilotPlugin",
	312: "DeleteCopilotPlugin",
	313: "EnableCopilotPlugin",
	314: "DisableCopilotPlugin",
	315: "CreateCopilotWorkspace",
	316: "UpdateCopilotWorkspace",
	317: "DeleteCopilotWorkspace",
	318: "EnableCopilotWorkspace",
	319: "DisableCopilotWorkspace",
	320: "CreateCopilotPromptBook",
	321: "UpdateCopilotPromptBook",
	322: "DeleteCopilotPromptBook",
	323: "EnableCopilotPromptBook",
	324: "DisableCopilotPromptBook",
	325: "UpdateCopilotSettings",
	328: "ConnectedAIAppInteraction",
	329: "PrivaPrivacyConsentOperation",
	330: "PrivaPrivacyAssessmentOperation",
	331: "DataCatalogAccessRequests",
	332: "ComplianceSettingsChange",
	333: "DataSecurityInvestigation",
	334: "TeamCopilotInteraction",
	335: "IRMActivityAuditTrail",
	336: "SharePointContentSecurityPolicy",
	337: "CloudUpdateProfileConfig",
	338: "CloudUpdateTenantConfig",
	339: "CloudUpdateDeviceConfig",
	341: "DeviceDiscoverySettingsExclusion",
	342: "DeviceDiscoverySettingsAuthenticatedScans",
	344: "DeviceDiscoverySettings",
	345: "USXWorkspaceOnboarding",
	346: "VivaGlintAdvancedConfiguration",
	347: "VivaGlintPulseProgram",
	348: "VivaGlintPulseProgramRespondentRate",
	349: "VivaGlintQuestion",
	350: "VivaGlintRole",
	351: "VivaGlintRubicon",
	352: "VivaGlintSupportAccess",
	353: "VivaGlintSystem",
	354: "VivaGlintUser",
	355: "VivaGlintUserGroup",
	356: "VivaGlintFeedbackProgram",
	357: "FabricAudit",
	358: "TrainableClassifier",
	359: "WebContentFiltering",
	360: "NoisyAlertPolicy",
	361: "DataScanClassification",
	362: "AIInteractionsExport",
	363: "Microsoft365CopilotScheduledPrompt",
	364: "PlacesDirectory",
	365: "SentinelNotebookOnLake",
	366: "SentinelJob",
	367: "SentinelKQLOnLake",
	368: "SentinelLakeOnboarding",
	369: "SentinelLakeDataOnboarding",
	370: "SentinelAITool",
	371: "SentinelGraph",
	372: "CrossTenantAccessPolicy",
	373: "OutlookCopilotAutomation",
	374: "VivaEngageNetworkAssociation",
	375: "AppAdminActivity",
	376: "AppSettingsAdminActivity",
	377: "UniversalPrintPrintJob",
	378: "VivaAmplifyOutlookSensitivityLabel",
	379: "AIInteractionsSubscription",
	380: "AIInteractionsChangeNotification",
	381: "FilteringMailMetadataExtended",
	382: "OfficeRestrictedModeAction",
	383: "CopilotForSecurityTrigger",
	384: "CopilotAgentManagement",
	385: "P4AIAssessmentFabricScannerRecord",
	386: "PlannerGoal",
	387: "PlannerGoalList",
	401: "PlannerChatMessage",
	402: "PlannerChatMessageList",
	414: "VivaEngageSegment",
	422: "VivaEngageEvents",
	427: "UniversalPrintManagement",
	430: "PurviewPostureAgent",
	431: "GranularBrowseTask",
	444: "TeamsEvalDataHubDataAccess",
	445: "TeamsEvalDataHubPermissionChange",
	454: "DragonCopilotAdmin",
	462: "MicrosoftTeamsUserConcern",
	463: "VivaGlintAgenticCampaign",
}

// userTypeNames maps the Management API's UserType int to the PascalCase name
// the Graph audit query API returns in userType.
//
// Source: the Office 365 Management Activity API schema's UserType table. The
// members and their order match Graph's declared auditLogUserType enum exactly
// (regular, reserved, admin, dcAdmin, system, application, servicePrincipal,
// customPolicy, systemPolicy, partnerTechnician, guest), which corroborates the
// numbering. UserType 4 <-> "System" is live-verified (#98); UserType 0 is the
// value the Management API returns live (#100).
//
// UNVERIFIED CELL: 3. The classic schema spells it "DCAdmin"; Graph's enum
// member is "dcAdmin", which would PascalCase to "DcAdmin". No live record of a
// dcAdmin action exists to settle it. "DCAdmin" is used because the live
// evidence shows the query API passing classic names through verbatim rather
// than serializing its own enum — but if a live DcAdmin record ever disagrees,
// this is the cell to fix.
var userTypeNames = map[int64]string{
	0:  "Regular",
	1:  "Reserved",
	2:  "Admin",
	3:  "DCAdmin",
	4:  "System",
	5:  "Application",
	6:  "ServicePrincipal",
	7:  "CustomPolicy",
	8:  "SystemPolicy",
	9:  "PartnerTechnician",
	10: "Guest",
}

// recordTypeName resolves a RecordType int to its query-API name. !ok means
// "this build cannot name it" — the caller must then emit the int alone rather
// than invent a name.
func recordTypeName(v int64) (string, bool) {
	n, ok := recordTypeNames[v]
	return n, ok
}

// userTypeName resolves a UserType int to its query-API name. !ok has the same
// meaning as in recordTypeName.
func userTypeName(v int64) (string, bool) {
	n, ok := userTypeNames[v]
	return n, ok
}
