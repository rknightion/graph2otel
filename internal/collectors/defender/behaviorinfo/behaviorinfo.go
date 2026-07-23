// Package behaviorinfo is the Defender advanced-hunting BehaviorInfo blob
// collector (#241): one OTLP log per Defender "behavior" — a higher-level
// analytic finding (impossible-travel, mass-download, ...) that Defender XDR
// and Defender for Cloud Apps raise above the raw event tables — read from the
// shared Azure Storage account.
//
// BehaviorInfo is the behavior-metadata half of a two-table pair: it carries
// the identity (BehaviorId), the ActionType, the human-readable Description,
// the MITRE Categories/AttackTechniques, and which service/detector raised it.
// The per-entity detail rows live in BehaviorEntities, joined by BehaviorId —
// the same info+evidence shape as alertinfo/alertevidence. This is NOT a
// Device* table: no InitiatingProcess block, no MachineGroup, no ActionType
// sequence — every column is mapped table-specifically, so this mapper does not
// call defender.StampDeviceCommon or defender.StampInitiatingProcess.
//
// Categories, AttackTechniques, and DataSources arrive as JSON-array-in-a-string
// on the wire (e.g. "[\"InitialAccess\"]") and are emitted verbatim as strings,
// never parsed — the same convention alertinfo uses for its array-ish columns.
// Description carries prose (a real ImpossibleTravelActivity naming a UPN in the
// #241 sample); that is alert detail and is in scope by design.
//
// m7kni volume is tiny (n=1 row over 30d in the #241 sample) — enough to write
// the mapper against, NOT enough to characterize volume.
package behaviorinfo

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
	name = "defender.behavior"
	// table is the advanced-hunting table, lowercased into its container.
	table = "behaviorinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.behavior"
)

// behaviorInfoStrFields is the BehaviorInfo column set: the behavior identity,
// its action/description, the MITRE Categories/AttackTechniques, which
// service/detector raised it, the observation window (Start/EndTime), the
// impacted account, and the verbatim AdditionalFields blob.
var behaviorInfoStrFields = []defender.StrField{
	{Attr: semconv.AttrBehaviorId, Src: "BehaviorId"},
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrDescription, Src: "Description"},
	{Attr: semconv.AttrCategories, Src: "Categories"},
	{Attr: semconv.AttrAttackTechniques, Src: "AttackTechniques"},
	{Attr: semconv.AttrServiceSource, Src: "ServiceSource"},
	{Attr: semconv.AttrDetectionSource, Src: "DetectionSource"},
	{Attr: semconv.AttrDataSources, Src: "DataSources"},
	{Attr: semconv.AttrDeviceId, Src: "DeviceId"},
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrStartTime, Src: "StartTime"},
	{Attr: semconv.AttrEndTime, Src: "EndTime"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// mapRecord turns one raw BehaviorInfo record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// behavior-metadata column family.
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
	defender.StampStrings(attrs, props, behaviorInfoStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s: %s", defender.Str(props, "ActionType"), defender.Str(props, "Description")),
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
