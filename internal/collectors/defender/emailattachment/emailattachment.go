// Package emailattachment is the Defender advanced-hunting
// EmailAttachmentInfo blob collector (#106): one OTLP log per attachment
// found on a message Defender for Office 365 observed, read from the shared
// Azure Storage account.
//
// EmailAttachmentInfo is a per-attachment child of EmailEvents (joined by
// NetworkMessageId), like email's own per-message shape: there is no
// ActionType, no InitiatingProcess block, and no DeviceId/MachineGroup — do
// NOT call defender.StampDeviceCommon or defender.StampInitiatingProcess
// here. ReportId on this table is a STRING (a composite message+file id),
// not the numeric per-device sequence the Device* tables carry, so it is
// mapped as a StrField. FileSize is the only numeric column; the
// threat/detection columns are null on a clean attachment — omitted, never
// emitted empty.
package emailattachment

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
	name = "defender.email_attachment"
	// table is the advanced-hunting table, lowercased into its container.
	table = "emailattachmentinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.email_attachment"
)

// attachmentStrFields is the table's full string-column set: the message
// join key, the sender/recipient identity, the attachment's file identity
// and hash, and its threat/detection verdicts.
var attachmentStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrSenderFromAddress, Src: "SenderFromAddress"},
	{Attr: semconv.AttrSenderDisplayName, Src: "SenderDisplayName"},
	{Attr: semconv.AttrSenderObjectId, Src: "SenderObjectId"},
	{Attr: semconv.AttrRecipientEmailAddress, Src: "RecipientEmailAddress"},
	{Attr: semconv.AttrRecipientObjectId, Src: "RecipientObjectId"},
	{Attr: semconv.AttrFileName, Src: "FileName"},
	{Attr: semconv.AttrFileType, Src: "FileType"},
	{Attr: semconv.AttrSha256, Src: "SHA256"},
	{Attr: semconv.AttrThreatTypes, Src: "ThreatTypes"},
	{Attr: semconv.AttrThreatNames, Src: "ThreatNames"},
	{Attr: semconv.AttrDetectionMethods, Src: "DetectionMethods"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrFileExtension, Src: "FileExtension"},
}

// attachmentNumFields is the table's numeric-column set.
var attachmentNumFields = []defender.NumField{
	{Attr: semconv.AttrFileSize, Src: "FileSize"},
}

// mapRecord turns one raw EmailAttachmentInfo record into its OTLP log
// Event: unwrap properties, bind the timestamp to properties.Timestamp, and
// stamp the string and numeric field families.
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
	defender.StampStrings(attrs, props, attachmentStrFields)
	defender.StampNums(attrs, props, attachmentNumFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("attachment %s (%s) in message %s", defender.Str(props, "FileName"), defender.Str(props, "SHA256"), defender.Str(props, "NetworkMessageId")),
		Severity:  telemetry.SeverityInfo,
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection (a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package), and so Experimental() marks it opt-in.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// Experimental reports true: the Defender advanced-hunting tables are the
// highest-volume surface graph2otel touches, so each is off by default and
// enabled explicitly per tenant (#106).
func (blobCollector) Experimental() bool { return true }

func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	return blobCollector{defender.New(name, table, mapRecord, d)}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var (
	_ collector.SnapshotCollector = blobCollector{}
	_ collectors.Experimental     = blobCollector{}
)
