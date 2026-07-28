package exposuregraph

import (
	"fmt"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// fieldMap binds one wire field name to the attribute key it publishes under.
type fieldMap struct{ attr, src string }

// nodeStrFields are the string-valued rawData fields attempted on every node,
// across every one of the 19 live-observed node labels. Absent fields are
// omitted by SetStr; this is what lets one builder serve every shape.
var nodeStrFields = []fieldMap{
	{semconv.AttrAccountDisplayName, "accountDisplayName"},
	{semconv.AttrAccountDomain, "accountDomain"},
	{semconv.AttrAccountUpn, "accountUpn"},
	{semconv.AttrEmailAddress, "emailAddress"},
	{semconv.AttrIdentityType, "identityType"},
	{semconv.AttrAppId, "appId"},
	{semconv.AttrServicePrincipalType, "servicePrincipalType"},
	{semconv.AttrAppOwnerOrganizationId, "appOwnerOrganizationId"},
	{semconv.AttrPublisherName, "publisherName"},
	{semconv.AttrPublisherDomain, "publisherDomain"},
	{semconv.AttrCreatedDateTime, "createdDateTime"},
	{semconv.AttrPrimaryProvider, "primaryProvider"},
	{semconv.AttrDeviceName, "deviceName"},
	{semconv.AttrDeviceType, "deviceType"},
	{semconv.AttrDeviceSubtype, "deviceSubtype"},
	{semconv.AttrDeviceCategory, "deviceCategory"},
	{semconv.AttrOsPlatform, "osPlatform"},
	{semconv.AttrOsVersion, "osVersion"},
	{semconv.AttrOsPlatformFriendlyName, "osPlatformFriendlyName"},
	{semconv.AttrOsVersionFriendlyName, "osVersionFriendlyName"},
	{semconv.AttrOnboardingStatus, "onboardingStatus"},
	{semconv.AttrSensorHealthState, "sensorHealthState"},
	{semconv.AttrRiskScore, "riskScore"},
	{semconv.AttrAadDeviceId, "aadDeviceId"},
	{semconv.AttrExposureScore, "exposureScore"},
	{semconv.AttrSeverity, "severity"},
	{semconv.AttrRecommendationCategory, "recommendationCategory"},
	{semconv.AttrVendor, "vendor"},
	{semconv.AttrSaasName, "saasName"},
	{semconv.AttrSubscriptionName, "subscriptionName"},
	{semconv.AttrHierarchyIdentifier, "hierarchyIdentifier"},
	{semconv.AttrHierarchyType, "hierarchyType"},
	{semconv.AttrFirstSeen, "firstSeenByInventory"},
	{semconv.AttrLastSeen, "lastSeen"},
}

// nodeBoolFields are the boolean rawData fields attempted on every node.
// boolFrom is used (not a bare type assertion) because these arrive as
// genuine JSON bools on this table, unlike the SByte-encoded typed columns
// internal/tvm's collectors read.
var nodeBoolFields = []fieldMap{
	{semconv.AttrAccountEnabled, "accountEnabled"},
	{semconv.AttrIsExcluded, "isExcluded"},
	{semconv.AttrIsHybridAzureAdJoined, "isHybridAzureADJoined"},
	{semconv.AttrIsCustomerFacing, "isCustomerFacing"},
	{semconv.AttrHasLeakedCredentials, "hasLeakedCredentials"},
	{semconv.AttrHasAdLeakedCredentials, "hasAdLeakedCredentials"},
	{semconv.AttrPublishedAgentIndicator, "publishedAgentIndicator"},
}

// nodeListFields are the []string-valued rawData fields attempted on every
// node.
var nodeListFields = []fieldMap{
	{semconv.AttrTags, "tags"},
	{semconv.AttrAlternativeNames, "alternativeNames"},
	{semconv.AttrDeviceRole, "deviceRole"},
}

// aiModelStrFields / aiModelBoolFields / aiModelListFields map the
// aiModelMetadata sub-object (label baseModel). depricationDate is
// Microsoft's typo, ON THE WIRE (live-observed, #350) — the mapper reads
// their spelling and publishes semconv.AttrDeprecationDate, which is spelled
// correctly.
var aiModelStrFields = []fieldMap{
	{semconv.AttrCreatedBy, "createdBy"},
	{semconv.AttrModelName, "modelName"},
	{semconv.AttrModelVersion, "modelVersion"},
	{semconv.AttrBaseModelName, "baseModelName"},
	{semconv.AttrBaseModelVersion, "baseModelVersion"},
	{semconv.AttrCollectionType, "collectionType"},
	{semconv.AttrDeprecationDate, "depricationDate"},
}

var aiModelBoolFields = []fieldMap{
	{semconv.AttrIsExpired, "isExpired"},
}

var aiModelListFields = []fieldMap{
	{semconv.AttrTaskCapabilities, "taskCapabilities"},
}

// aiAgentStrFields maps the aiAgentMetadata sub-object (label ai-agent). Its
// own `description` is not emitted — see the package doc on why finding/agent
// prose is excluded.
var aiAgentStrFields = []fieldMap{
	{semconv.AttrAgentName, "name"},
	{semconv.AttrAgentId, "id"},
	{semconv.AttrPlatform, "platform"},
	{semconv.AttrAgentVersion, "agentVersion"},
	{semconv.AttrPublishedStatus, "publishedStatus"},
}

// criticalityLevelNumFields / criticalityLevelListFields map the
// criticalityLevel sub-object (labels "SaaS Application" and user, at least).
var criticalityLevelNumFields = []fieldMap{
	{semconv.AttrCriticalityLevel, "criticalityLevel"},
	{semconv.AttrRuleBasedCriticalityLevel, "ruleBasedCriticalityLevel"},
}

var criticalityLevelListFields = []fieldMap{
	{semconv.AttrCriticalityRuleNames, "ruleNames"},
}

// securityIssueStrFields maps the securityIssue sub-object (finding-shaped
// labels). Its own field is also named "securityIssue", one level down.
var securityIssueStrFields = []fieldMap{
	{semconv.AttrSecurityIssue, "securityIssue"},
}

func setStrTable(attrs telemetry.Attrs, m map[string]any, table []fieldMap) {
	for _, f := range table {
		telemetry.SetStr(attrs, f.attr, str(m, f.src))
	}
}

func setBoolTable(attrs telemetry.Attrs, m map[string]any, table []fieldMap) {
	for _, f := range table {
		if b, ok := boolFrom(m[f.src]); ok {
			telemetry.SetBool(attrs, f.attr, b)
		}
	}
}

func setNumTable(attrs telemetry.Attrs, m map[string]any, table []fieldMap) {
	for _, f := range table {
		telemetry.SetNum(attrs, f.attr, m, f.src)
	}
}

// setListTable sets every list-valued field in table, capping at
// maxListItems and reporting (via the returned bool, OR'd into *truncated)
// whether any field needed capping.
func setListTable(attrs telemetry.Attrs, m map[string]any, table []fieldMap, truncated *bool) {
	for _, f := range table {
		list := toStringSlice(m[f.src])
		if len(list) == 0 {
			continue
		}
		capped, wasTrunc := capList(list)
		telemetry.SetStrs(attrs, f.attr, capped)
		if wasTrunc {
			*truncated = true
		}
	}
}

// nodeTwin renders one ExposureGraphNodes row as an OTLP log record: the
// per-entity detail the census gauge collapses. Timestamp is left zero (poll
// time) — see the package doc on why a state feed must not stamp its source
// time.
//
// Severity escalates to Warn when the node's properties report
// hasLeakedCredentials or hasAdLeakedCredentials true — a real, wire-visible
// compromise indicator. Everything else is Info.
func nodeTwin(row map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrNodeId, str(row, "NodeId"))
	telemetry.SetStr(attrs, semconv.AttrNodeName, str(row, "NodeName"))
	label := str(row, "NodeLabel")
	telemetry.SetStr(attrs, semconv.AttrNodeLabel, label)

	truncated := false
	if cats := toStringSlice(row["Categories"]); len(cats) > 0 {
		capped, wasTrunc := capList(cats)
		telemetry.SetStrs(attrs, semconv.AttrCategories, capped)
		if wasTrunc {
			truncated = true
		}
	}

	ids, types, idsTrunc := decodeEntityIDs(row["EntityIds"])
	telemetry.SetStrs(attrs, semconv.AttrEntityIds, ids)
	telemetry.SetStrs(attrs, semconv.AttrEntityIdTypes, types)
	if idsTrunc {
		truncated = true
	}

	rawData := rawDataOf(row, "NodeProperties")
	if rawData != nil {
		setStrTable(attrs, rawData, nodeStrFields)
		setBoolTable(attrs, rawData, nodeBoolFields)
		setListTable(attrs, rawData, nodeListFields, &truncated)

		if sub, ok := rawData["aiModelMetadata"].(map[string]any); ok {
			setStrTable(attrs, sub, aiModelStrFields)
			setBoolTable(attrs, sub, aiModelBoolFields)
			setListTable(attrs, sub, aiModelListFields, &truncated)
		}
		if sub, ok := rawData["aiAgentMetadata"].(map[string]any); ok {
			setStrTable(attrs, sub, aiAgentStrFields)
		}
		if sub, ok := rawData["criticalityLevel"].(map[string]any); ok {
			setNumTable(attrs, sub, criticalityLevelNumFields)
			setListTable(attrs, sub, criticalityLevelListFields, &truncated)
		}
		if sub, ok := rawData["securityIssue"].(map[string]any); ok {
			setStrTable(attrs, sub, securityIssueStrFields)
		}
		// entraCookiesSecretData (label entra-userCookie) is descended into
		// deliberately but contributes no attribute: its fields
		// (entraObjectId, tenantId) have no semconv key of their own —
		// tenantId in particular is stamped centrally by
		// telemetry.WithTenant, never per-record (#143). Descending without
		// panicking is the whole point: an unmapped sub-object must not
		// break the twin.
		_, _ = rawData["entraCookiesSecretData"].(map[string]any)
	}

	if truncated {
		telemetry.SetBool(attrs, semconv.AttrArraysTruncated, true)
	}

	hasLeaked, _ := boolFrom(safeGet(rawData, "hasLeakedCredentials"))
	hasAdLeaked, _ := boolFrom(safeGet(rawData, "hasAdLeakedCredentials"))
	severity := telemetry.SeverityInfo
	if hasLeaked || hasAdLeaked {
		severity = telemetry.SeverityWarn
	}

	name := str(row, "NodeName")
	if name == "" {
		name = "unknown"
	}
	return telemetry.Event{
		Name:     eventNode,
		Body:     fmt.Sprintf("exposure graph node %q (%s)", name, label),
		Severity: severity,
		Attrs:    attrs,
	}
}

// safeGet reads m[key] when m is non-nil, else returns nil — a small helper
// so nodeTwin's severity check does not need a nil guard at every call site.
func safeGet(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

// edgeTwin renders one ExposureGraphEdges row as an OTLP log record: which
// source can do what to which target. Timestamp is left zero, same reasoning
// as nodeTwin.
//
// Severity is always Info: no wire field on this table distinguishes an
// edge's own risk the way hasLeakedCredentials does for a node — the
// compromise signal lives on the node twins, not the relationship. Each of
// the four edge property shapes mapped below (userRightsOnDevice,
// delegatedPermissions/applicationPermissions, roles, primaryRefreshToken)
// carries a capability or authentication-path FACT, never a risk verdict, so
// escalating on any of their presence would be manufacturing a severity the
// wire does not assert.
func edgeTwin(row map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrEdgeId, str(row, "EdgeId"))
	edgeLabel := str(row, "EdgeLabel")
	telemetry.SetStr(attrs, semconv.AttrEdgeLabel, edgeLabel)
	telemetry.SetStr(attrs, semconv.AttrSourceNodeId, str(row, "SourceNodeId"))
	sourceName := str(row, "SourceNodeName")
	telemetry.SetStr(attrs, semconv.AttrSourceNodeName, sourceName)
	sourceLabel := str(row, "SourceNodeLabel")
	telemetry.SetStr(attrs, semconv.AttrSourceNodeLabel, sourceLabel)
	telemetry.SetStr(attrs, semconv.AttrTargetNodeId, str(row, "TargetNodeId"))
	targetName := str(row, "TargetNodeName")
	telemetry.SetStr(attrs, semconv.AttrTargetNodeName, targetName)
	targetLabel := str(row, "TargetNodeLabel")
	telemetry.SetStr(attrs, semconv.AttrTargetNodeLabel, targetLabel)

	truncated := false
	setWrapped := func(attr string, v any, valueKey string) {
		values, wasTrunc := decodeWrappedValues(v, valueKey)
		if len(values) == 0 {
			return
		}
		telemetry.SetStrs(attrs, attr, values)
		if wasTrunc {
			truncated = true
		}
	}

	if rawData := rawDataOf(row, "EdgeProperties"); rawData != nil {
		if urod, ok := rawData["userRightsOnDevice"].(map[string]any); ok {
			if rights := toStringSlice(urod["userRights"]); len(rights) > 0 {
				capped, wasTrunc := capList(rights)
				telemetry.SetStrs(attrs, semconv.AttrUserRights, capped)
				if wasTrunc {
					truncated = true
				}
			}
			if methods := toStringSlice(urod["logonMethods"]); len(methods) > 0 {
				capped, wasTrunc := capList(methods)
				telemetry.SetStrs(attrs, semconv.AttrLogonMethods, capped)
				if wasTrunc {
					truncated = true
				}
			}
			if b, ok := boolFrom(urod["isLocalAdmin"]); ok {
				telemetry.SetBool(attrs, semconv.AttrIsLocalAdmin, b)
			}
		}

		// `has permissions to`: delegatedPermissions.permissions and
		// applicationPermissions.permissions are each a collection of
		// wrapped {"permissionValue":"..."} elements — the SAME trap as
		// EntityIds, in a new place (#350 follow-up). An empty array (the
		// live sample's applicationPermissions.permissions is []) decodes to
		// zero values and SetStrs correctly omits the attribute rather than
		// publishing an empty list — absent-is-not-empty.
		if dp, ok := rawData["delegatedPermissions"].(map[string]any); ok {
			setWrapped(semconv.AttrDelegatedPermissions, dp["permissions"], "permissionValue")
		}
		if ap, ok := rawData["applicationPermissions"].(map[string]any); ok {
			setWrapped(semconv.AttrApplicationPermissions, ap["permissions"], "permissionValue")
		}

		// `has role on`: roles.rolePermissions, wrapped {"roleValue":"..."}.
		if roles, ok := rawData["roles"].(map[string]any); ok {
			setWrapped(semconv.AttrRolePermissions, roles["rolePermissions"], "roleValue")
		}

		// `has credentials of`: primaryRefreshToken.primaryRefreshToken is a
		// plain JSON bool, not wrapped — a PRT is the token that lets a
		// device act as the user, so its presence is a real
		// authentication-path fact. The token itself is never on the wire.
		if prt, ok := rawData["primaryRefreshToken"].(map[string]any); ok {
			if b, ok := boolFrom(prt["primaryRefreshToken"]); ok {
				telemetry.SetBool(attrs, semconv.AttrHasPrimaryRefreshToken, b)
			}
		}
	}
	if truncated {
		telemetry.SetBool(attrs, semconv.AttrArraysTruncated, true)
	}

	return telemetry.Event{
		Name: eventEdge,
		Body: fmt.Sprintf("exposure graph edge %q: %s (%s) -> %s (%s)",
			edgeLabel, sourceName, sourceLabel, targetName, targetLabel),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}
