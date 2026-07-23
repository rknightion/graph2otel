// Package behaviorentities is the Defender advanced-hunting BehaviorEntities
// blob collector (#241): one OTLP log per entity row Defender attaches to a
// behavior — the per-entity detail (user, IP, cloud application, file, ...)
// that behaviorinfo collapses to a bare Description — read from the shared Azure
// Storage account.
//
// BehaviorEntities is the per-entity-row half of the behavior pair, joined to
// BehaviorInfo by BehaviorId — the same info+evidence shape as
// alertinfo/alertevidence. It is NOT a Device* table: no ActionType sequence, no
// InitiatingProcess block, so this mapper does not call defender.StampDeviceCommon
// or defender.StampInitiatingProcess — it maps DeviceId/DeviceName itself
// alongside the rest. The row is polymorphic by EntityType (Ip, User,
// CloudApplication, and others): each type populates a different subset of the
// ~37 columns, so most are null on any given row and omitted. AdditionalFields
// is a stringified-JSON blob whose keys vary by EntityType and is emitted
// verbatim for losslessness (its Location.CountryCode geo sub-object is NOT
// promoted here — the raw blob is retained).
//
// Categories and DataSources arrive as JSON-array-in-a-string on the wire and
// are emitted verbatim as strings, never parsed.
//
// m7kni volume is tiny (n=5 rows over 30d in the #241 sample, one behavior) —
// enough to write the mapper against, NOT enough to characterize volume.
package behaviorentities

import (
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
	name = "defender.behavior_entity"
	// table is the advanced-hunting table, lowercased into its container.
	table = "behaviorentities"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.behavior_entity"
)

// entityStrFields is the BehaviorEntities column set: the behavior linkage, the
// entity classification/role, and the identity/device/network/file/registry/app
// fields the entity may carry (most null on any given row, by EntityType).
var entityStrFields = []defender.StrField{
	{Attr: semconv.AttrBehaviorId, Src: "BehaviorId"},
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrCategories, Src: "Categories"},
	{Attr: semconv.AttrServiceSource, Src: "ServiceSource"},
	{Attr: semconv.AttrDetectionSource, Src: "DetectionSource"},
	{Attr: semconv.AttrDataSources, Src: "DataSources"},
	{Attr: semconv.AttrEntityType, Src: "EntityType"},
	{Attr: semconv.AttrEntityRole, Src: "EntityRole"},
	{Attr: semconv.AttrDetailedEntityRole, Src: "DetailedEntityRole"},
	{Attr: semconv.AttrFileName, Src: "FileName"},
	{Attr: semconv.AttrFolderPath, Src: "FolderPath"},
	{Attr: semconv.AttrSha1, Src: "SHA1"},
	{Attr: semconv.AttrSha256, Src: "SHA256"},
	{Attr: semconv.AttrThreatFamily, Src: "ThreatFamily"},
	{Attr: semconv.AttrRemoteIp, Src: "RemoteIP"},
	{Attr: semconv.AttrRemoteUrl, Src: "RemoteUrl"},
	{Attr: semconv.AttrAccountName, Src: "AccountName"},
	{Attr: semconv.AttrAccountDomain, Src: "AccountDomain"},
	{Attr: semconv.AttrAccountSid, Src: "AccountSid"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrDeviceId, Src: "DeviceId"},
	{Attr: semconv.AttrDeviceName, Src: "DeviceName"},
	{Attr: semconv.AttrLocalIp, Src: "LocalIP"},
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrEmailSubject, Src: "EmailSubject"},
	{Attr: semconv.AttrApplication, Src: "Application"},
	{Attr: semconv.AttrOauthApplicationId, Src: "OAuthApplicationId"},
	{Attr: semconv.AttrProcessCommandLine, Src: "ProcessCommandLine"},
	{Attr: semconv.AttrRegistryKey, Src: "RegistryKey"},
	{Attr: semconv.AttrRegistryValueName, Src: "RegistryValueName"},
	{Attr: semconv.AttrRegistryValueData, Src: "RegistryValueData"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// entityNumFields is the numeric part of the BehaviorEntities column set.
// ApplicationId and EmailClusterId arrive as JSON numbers on this table (a
// CloudApplication row carries ApplicationId=22110 in the #241 sample), so they
// are mapped as NumFields here — unlike alertevidence, where ApplicationId is a
// string.
var entityNumFields = []defender.NumField{
	{Attr: semconv.AttrFileSize, Src: "FileSize"},
	{Attr: semconv.AttrEmailClusterId, Src: "EmailClusterId"},
	{Attr: semconv.AttrApplicationId, Src: "ApplicationId"},
}

// mapRecord turns one raw BehaviorEntities record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// entity column families (AdditionalFields emitted verbatim via the StrField
// family for losslessness).
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
	defender.StampStrings(attrs, props, entityStrFields)
	defender.StampNums(attrs, props, entityNumFields)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s entity %s (%s)",
			defender.Str(props, "ActionType"), defender.Str(props, "EntityType"), defender.Str(props, "EntityRole")),
		Severity:  telemetry.SeverityInfo,
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
