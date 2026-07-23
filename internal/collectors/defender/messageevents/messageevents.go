// Package messageevents is the Defender advanced-hunting MessageEvents blob
// collector (#241): one OTLP log per Microsoft Teams message Defender observed,
// read from the shared Azure Storage account.
//
// MessageEvents is the Teams-message analog of EmailEvents — a per-MESSAGE
// table, not a Device* table: there is no ActionType, no InitiatingProcess
// block, and no DeviceId/MachineGroup, so this mapper does not call
// defender.StampDeviceCommon or defender.StampInitiatingProcess. ReportId is a
// STRING (a composite message id), mapped as a StrField. RecipientDetails
// arrives as a JSON array of objects (SMTP address, display name, object id,
// type per recipient) and is emitted verbatim as a marshaled string for
// losslessness, never flattened.
//
// IsExternalThread paired with SenderType is the external-collaboration attack
// surface — both are stamped whenever present as a JSON bool (a false is
// meaningful and emitted, unlike a null which is omitted).
//
// ThreatTypes/DetectionMethods/ConfidenceLevel are mapped as StrFields matching
// EmailEvents, but were null on every row of the #241 sample (a healthy tenant
// with no Teams threats) — their on-wire shape when populated is docs-only /
// unvalidated.
//
// m7kni volume is tiny (n=3 rows over 30d in the #241 sample) — enough to write
// the mapper against, NOT enough to characterize volume.
package messageevents

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
	name = "defender.teams_message"
	// table is the advanced-hunting table, lowercased into its container.
	table = "messageevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.teams_message"
)

// messageStrFields is the table's full string-column set: message/thread
// identity, the sender block, the group/thread context, the message
// type/version, and the delivery/threat verdicts.
var messageStrFields = []defender.StrField{
	{Attr: semconv.AttrTeamsMessageId, Src: "TeamsMessageId"},
	{Attr: semconv.AttrLastEditedTime, Src: "LastEditedTime"},
	{Attr: semconv.AttrSenderEmailAddress, Src: "SenderEmailAddress"},
	{Attr: semconv.AttrSenderDisplayName, Src: "SenderDisplayName"},
	{Attr: semconv.AttrSenderObjectId, Src: "SenderObjectId"},
	{Attr: semconv.AttrSenderType, Src: "SenderType"},
	{Attr: semconv.AttrMessageId, Src: "MessageId"},
	{Attr: semconv.AttrParentMessageId, Src: "ParentMessageId"},
	{Attr: semconv.AttrGroupId, Src: "GroupId"},
	{Attr: semconv.AttrGroupName, Src: "GroupName"},
	{Attr: semconv.AttrThreadId, Src: "ThreadId"},
	{Attr: semconv.AttrThreadName, Src: "ThreadName"},
	{Attr: semconv.AttrThreadType, Src: "ThreadType"},
	{Attr: semconv.AttrThreadSubType, Src: "ThreadSubType"},
	{Attr: semconv.AttrMessageType, Src: "MessageType"},
	{Attr: semconv.AttrMessageSubtype, Src: "MessageSubtype"},
	{Attr: semconv.AttrMessageVersion, Src: "MessageVersion"},
	{Attr: semconv.AttrSubject, Src: "Subject"},
	{Attr: semconv.AttrThreatTypes, Src: "ThreatTypes"},
	{Attr: semconv.AttrDetectionMethods, Src: "DetectionMethods"},
	{Attr: semconv.AttrConfidenceLevel, Src: "ConfidenceLevel"},
	{Attr: semconv.AttrDeliveryAction, Src: "DeliveryAction"},
	{Attr: semconv.AttrDeliveryLocation, Src: "DeliveryLocation"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrSafetyTip, Src: "SafetyTip"},
}

// messageBoolFields is the table's boolean-column set: whether the tenant owns
// the thread, and whether the thread crosses an organizational boundary.
var messageBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsOwnedThread, Src: "IsOwnedThread"},
	{Attr: semconv.AttrIsExternalThread, Src: "IsExternalThread"},
}

// stampRecipientDetails emits the RecipientDetails JSON array verbatim as a
// marshaled string. An absent or null column omits the attribute.
func stampRecipientDetails(attrs telemetry.Attrs, props map[string]any) {
	raw, ok := props["RecipientDetails"]
	if !ok || raw == nil {
		return
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return
	}
	telemetry.SetStr(attrs, semconv.AttrRecipientDetails, string(b))
}

// mapRecord turns one raw MessageEvents record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// string/bool field families plus the RecipientDetails blob.
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
	defender.StampStrings(attrs, props, messageStrFields)
	defender.StampBools(attrs, props, messageBoolFields)
	stampRecipientDetails(attrs, props)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("Teams %s from %s in %s",
			defender.Str(props, "DeliveryAction"), defender.Str(props, "SenderEmailAddress"), defender.Str(props, "ThreadType")),
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
