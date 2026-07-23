// Package emailpostdelivery is the Defender advanced-hunting
// EmailPostDeliveryEvents blob collector (#233): one OTLP log per action
// Defender for Office 365 takes on a message AFTER it was delivered — ZAP,
// manual and automated remediation, and redelivery — read from the shared
// Azure Storage account.
//
// This is the missing half of defender.email's delivery story: EmailEvents
// records where a message landed at delivery time, and only this table records
// it MOVING afterwards, into or out of quarantine. The two join on
// network_message_id.
//
// EmailPostDeliveryEvents is a per-MESSAGE table like EmailEvents, not one of
// the Device* tables: there is no DeviceId/MachineGroup and no
// InitiatingProcess block, so do NOT call defender.StampDeviceCommon or
// defender.StampInitiatingProcess here. Every column on it is a string — there
// are no numeric or boolean columns — and its ReportId is a composite STRING
// (network message id + sequence), not the numeric per-device sequence the
// Device* event tables carry, so it is mapped as a StrField.
package emailpostdelivery

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
	name = "defender.email_post_delivery"
	// table is the advanced-hunting table, lowercased into its container.
	table = "emailpostdeliveryevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.email_post_delivery"
)

// postDeliveryStrFields is the table's complete column set — message identity,
// the remediation action with its trigger and result, the recipient and the
// resulting delivery location, and the threat verdicts that justified it. All
// of them are strings on the wire; the table carries no numeric or boolean
// columns. Timestamp is consumed by defender.EventTime, not stamped.
var postDeliveryStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrInternetMessageId, Src: "InternetMessageId"},
	{Attr: semconv.AttrAction, Src: "Action"},
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrActionTrigger, Src: "ActionTrigger"},
	{Attr: semconv.AttrActionResult, Src: "ActionResult"},
	{Attr: semconv.AttrRecipientEmailAddress, Src: "RecipientEmailAddress"},
	{Attr: semconv.AttrDeliveryLocation, Src: "DeliveryLocation"},
	{Attr: semconv.AttrThreatTypes, Src: "ThreatTypes"},
	{Attr: semconv.AttrDetectionMethods, Src: "DetectionMethods"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrSenderFromAddress, Src: "SenderFromAddress"},
	{Attr: semconv.AttrEmailDirection, Src: "EmailDirection"},
}

// severity maps ActionResult to a log severity: a remediation that did not
// succeed is the interesting case, so anything other than Success (or an
// absent result) warns.
func severity(actionResult string) telemetry.Severity {
	if actionResult == "Success" || actionResult == "" {
		return telemetry.SeverityInfo
	}
	return telemetry.SeverityWarn
}

// mapRecord turns one raw EmailPostDeliveryEvents record into its OTLP log
// Event: unwrap properties, bind the timestamp to properties.Timestamp, and
// stamp the string columns.
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
	defender.StampStrings(attrs, props, postDeliveryStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s (%s) for %s: %s", defender.Str(props, "Action"), defender.Str(props, "ActionType"), defender.Str(props, "RecipientEmailAddress"), defender.Str(props, "ActionResult")),
		Severity:  severity(defender.Str(props, "ActionResult")),
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
