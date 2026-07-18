// Package alertevidence is the Defender advanced-hunting AlertEvidence blob
// collector (#106, absorbed from #93): one OTLP log per evidence row Defender
// attaches to an alert — the per-entity detail (user, device, IP, file,
// mailbox, cloud resource, ...) that entra.security_alerts collapses to a bare
// evidence_count gauge.
//
// AlertEvidence is a per-evidence-row table, NOT a Device* table: it carries no
// ActionType and no InitiatingProcess block, so this mapper does not call
// defender.StampDeviceCommon or defender.StampInitiatingProcess — it maps
// DeviceId/DeviceName/MachineGroup itself alongside the rest of the evidence
// columns. The row shape is polymorphic by EntityType (User, Ip,
// CloudLogonRequest, and others Microsoft documents); AdditionalFields is a
// stringified-JSON blob whose keys vary by EntityType, so it is emitted
// verbatim for losslessness, with only the Ip case's geo sub-object promoted
// to its own attributes (live-sampled 2026-07-18, #106).
package alertevidence

import (
	"encoding/json"
	"fmt"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/defender"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// name is the stable collector key and config-enable key.
	name = "defender.alert_evidence"
	// table is the advanced-hunting table, lowercased into its container.
	table = "alertevidence"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.alert_evidence"
)

// evidenceStrFields is the AlertEvidence column set: the alert linkage, the
// entity classification, identity/device/network fields the entity may carry,
// and the alert-level fields (Title/Severity/Categories/...) the table repeats
// on every evidence row for that alert.
var evidenceStrFields = []defender.StrField{
	{Attr: semconv.AttrAlertId, Src: "AlertId"},
	{Attr: semconv.AttrEntityType, Src: "EntityType"},
	{Attr: semconv.AttrEvidenceRole, Src: "EvidenceRole"},
	{Attr: semconv.AttrEvidenceDirection, Src: "EvidenceDirection"},
	{Attr: semconv.AttrSha1, Src: "SHA1"},
	{Attr: semconv.AttrSha256, Src: "SHA256"},
	{Attr: semconv.AttrRemoteIp, Src: "RemoteIP"},
	{Attr: semconv.AttrLocalIp, Src: "LocalIP"},
	{Attr: semconv.AttrRemoteUrl, Src: "RemoteUrl"},
	{Attr: semconv.AttrAccountName, Src: "AccountName"},
	{Attr: semconv.AttrAccountDomain, Src: "AccountDomain"},
	{Attr: semconv.AttrAccountSid, Src: "AccountSid"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrDeviceId, Src: "DeviceId"},
	{Attr: semconv.AttrDeviceName, Src: "DeviceName"},
	{Attr: semconv.AttrThreatFamily, Src: "ThreatFamily"},
	{Attr: semconv.AttrServiceSource, Src: "ServiceSource"},
	{Attr: semconv.AttrDetectionSource, Src: "DetectionSource"},
	{Attr: semconv.AttrSeverity, Src: "Severity"},
	{Attr: semconv.AttrTitle, Src: "Title"},
	{Attr: semconv.AttrCategories, Src: "Categories"},
	{Attr: semconv.AttrAttackTechniques, Src: "AttackTechniques"},
	{Attr: semconv.AttrFileName, Src: "FileName"},
	{Attr: semconv.AttrFolderPath, Src: "FolderPath"},
	{Attr: semconv.AttrProcessCommandLine, Src: "ProcessCommandLine"},
	{Attr: semconv.AttrEmailSubject, Src: "EmailSubject"},
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrApplicationId, Src: "ApplicationId"},
	{Attr: semconv.AttrApplication, Src: "Application"},
	{Attr: semconv.AttrOauthApplicationId, Src: "OAuthApplicationId"},
	{Attr: semconv.AttrRegistryKey, Src: "RegistryKey"},
	{Attr: semconv.AttrRegistryValueName, Src: "RegistryValueName"},
	{Attr: semconv.AttrRegistryValueData, Src: "RegistryValueData"},
	{Attr: semconv.AttrCloudResource, Src: "CloudResource"},
	{Attr: semconv.AttrCloudPlatform, Src: "CloudPlatform"},
	{Attr: semconv.AttrResourceType, Src: "ResourceType"},
	{Attr: semconv.AttrMachineGroup, Src: "MachineGroup"},
	{Attr: semconv.AttrSubscriptionId, Src: "SubscriptionId"},
}

// evidenceNumFields is the numeric part of the evidence column set.
var evidenceNumFields = []defender.NumField{
	{Attr: semconv.AttrFileSize, Src: "FileSize"},
}

// severityFor maps the record's wire-capitalized Severity string ("High",
// "Medium", "Low", ...) to an OTLP log severity. Anything else (including
// absent) is SeverityInfo.
func severityFor(s string) telemetry.Severity {
	switch s {
	case "High":
		return telemetry.SeverityError
	case "Medium", "Low":
		return telemetry.SeverityWarn
	default:
		return telemetry.SeverityInfo
	}
}

// stampGeo parses AdditionalFields' Location sub-object and promotes it to its
// own attributes. Only the Ip EntityType carries a Location object
// (live-sampled 2026-07-18); other entity types no-op here since AdditionalFields
// decodes to a map with no "Location" key.
func stampGeo(attrs telemetry.Attrs, props map[string]any) {
	raw := defender.Str(props, "AdditionalFields")
	if raw == "" {
		return
	}
	var af map[string]any
	if err := json.Unmarshal([]byte(raw), &af); err != nil {
		return
	}
	loc, ok := af["Location"].(map[string]any)
	if !ok {
		return
	}
	if s, ok := loc["CountryCode"].(string); ok {
		telemetry.SetStr(attrs, semconv.AttrGeoCountry, s)
	}
	if s, ok := loc["State"].(string); ok {
		telemetry.SetStr(attrs, semconv.AttrGeoState, s)
	}
	if s, ok := loc["City"].(string); ok {
		telemetry.SetStr(attrs, semconv.AttrGeoCity, s)
	}
	if f, ok := loc["Asn"].(float64); ok {
		attrs[semconv.AttrGeoAsn] = f
	}
}

// mapRecord turns one raw AlertEvidence record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, stamp the evidence
// column family, emit AdditionalFields verbatim for losslessness, and promote
// the Ip entity's geo sub-object.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props := defender.Props(rec)
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := defender.EventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}

	attrs := telemetry.Attrs{}
	defender.StampStrings(attrs, props, evidenceStrFields)
	defender.StampNums(attrs, props, evidenceNumFields)
	telemetry.SetStr(attrs, semconv.AttrAdditionalFields, defender.Str(props, "AdditionalFields"))
	stampGeo(attrs, props)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s evidence (%s/%s): %s",
			defender.Str(props, "Title"), defender.Str(props, "EntityType"), defender.Str(props, "EvidenceRole"), defender.Str(props, "ServiceSource")),
		Severity:  severityFor(defender.Str(props, "Severity")),
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection (a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package).
type blobCollector struct {
	*blobpipeline.BlobCollector
}

func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	return blobCollector{defender.New(name, table, mapRecord, d)}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var _ collector.SnapshotCollector = blobCollector{}
