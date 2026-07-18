// Package email is the Defender advanced-hunting EmailEvents blob collector
// (#106): one OTLP log per inbound/outbound message Defender for Office 365
// observed, read from the shared Azure Storage account.
//
// EmailEvents is a per-MESSAGE table, unlike the Device* tables this package's
// siblings map: there is no ActionType, no InitiatingProcess block, and no
// DeviceId/MachineGroup — do NOT call defender.StampDeviceCommon or
// defender.StampInitiatingProcess here. ReportId on this table is a STRING
// (a composite message id), not the numeric per-device sequence the Device*
// tables carry, so it is mapped as a StrField. To/Cc arrive as native JSON
// arrays of strings, not the stringified scalars every other field on this
// table uses.
package email

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
	name = "defender.email"
	// table is the advanced-hunting table, lowercased into its container.
	table = "emailevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.email"
)

// emailStrFields is the table's full string-column set: message identity, the
// sender/recipient blocks, delivery/threat verdicts, and the policy/rule
// fields. AuthenticationDetails arrives as a stringified JSON blob on the wire
// and is emitted verbatim as a string, never parsed.
var emailStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrInternetMessageId, Src: "InternetMessageId"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrSenderMailFromAddress, Src: "SenderMailFromAddress"},
	{Attr: semconv.AttrSenderFromAddress, Src: "SenderFromAddress"},
	{Attr: semconv.AttrSenderDisplayName, Src: "SenderDisplayName"},
	{Attr: semconv.AttrSenderObjectId, Src: "SenderObjectId"},
	{Attr: semconv.AttrSenderMailFromDomain, Src: "SenderMailFromDomain"},
	{Attr: semconv.AttrSenderFromDomain, Src: "SenderFromDomain"},
	{Attr: semconv.AttrSenderIpv4, Src: "SenderIPv4"},
	{Attr: semconv.AttrSenderIpv6, Src: "SenderIPv6"},
	{Attr: semconv.AttrRecipientEmailAddress, Src: "RecipientEmailAddress"},
	{Attr: semconv.AttrRecipientObjectId, Src: "RecipientObjectId"},
	{Attr: semconv.AttrRecipientDomain, Src: "RecipientDomain"},
	{Attr: semconv.AttrSubject, Src: "Subject"},
	{Attr: semconv.AttrEmailDirection, Src: "EmailDirection"},
	{Attr: semconv.AttrDeliveryAction, Src: "DeliveryAction"},
	{Attr: semconv.AttrDeliveryLocation, Src: "DeliveryLocation"},
	{Attr: semconv.AttrThreatTypes, Src: "ThreatTypes"},
	{Attr: semconv.AttrThreatNames, Src: "ThreatNames"},
	{Attr: semconv.AttrThreatClassification, Src: "ThreatClassification"},
	{Attr: semconv.AttrDetectionMethods, Src: "DetectionMethods"},
	{Attr: semconv.AttrConfidenceLevel, Src: "ConfidenceLevel"},
	{Attr: semconv.AttrBulkComplaintLevel, Src: "BulkComplaintLevel"},
	{Attr: semconv.AttrEmailAction, Src: "EmailAction"},
	{Attr: semconv.AttrEmailActionPolicy, Src: "EmailActionPolicy"},
	{Attr: semconv.AttrEmailActionPolicyGuid, Src: "EmailActionPolicyGuid"},
	{Attr: semconv.AttrAuthenticationDetails, Src: "AuthenticationDetails"},
	{Attr: semconv.AttrEmailLanguage, Src: "EmailLanguage"},
	{Attr: semconv.AttrConnectors, Src: "Connectors"},
	{Attr: semconv.AttrOrgLevelAction, Src: "OrgLevelAction"},
	{Attr: semconv.AttrOrgLevelPolicy, Src: "OrgLevelPolicy"},
	{Attr: semconv.AttrUserLevelAction, Src: "UserLevelAction"},
	{Attr: semconv.AttrUserLevelPolicy, Src: "UserLevelPolicy"},
	{Attr: semconv.AttrExchangeTransportRule, Src: "ExchangeTransportRule"},
	{Attr: semconv.AttrDistributionList, Src: "DistributionList"},
	{Attr: semconv.AttrForwardingInformation, Src: "ForwardingInformation"},
	{Attr: semconv.AttrContext, Src: "Context"},
}

// emailNumFields is the table's numeric-column set.
var emailNumFields = []defender.NumField{
	{Attr: semconv.AttrEmailClusterId, Src: "EmailClusterId"},
	{Attr: semconv.AttrAttachmentCount, Src: "AttachmentCount"},
	{Attr: semconv.AttrUrlCount, Src: "UrlCount"},
	{Attr: semconv.AttrEmailSize, Src: "EmailSize"},
}

// emailBoolFields is the table's boolean-column set.
var emailBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsFirstContact, Src: "IsFirstContact"},
}

// strSlice reads a JSON array-of-strings column (To, Cc), dropping any
// non-string element. An absent or non-array column yields an empty slice.
func strSlice(props map[string]any, key string) []string {
	raw, _ := props[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// mapRecord turns one raw EmailEvents record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// string/numeric/bool field families plus the To/Cc recipient arrays.
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
	defender.StampStrings(attrs, props, emailStrFields)
	defender.StampNums(attrs, props, emailNumFields)
	defender.StampBools(attrs, props, emailBoolFields)
	telemetry.SetStrs(attrs, semconv.AttrTo, strSlice(props, "To"))
	telemetry.SetStrs(attrs, semconv.AttrCc, strSlice(props, "Cc"))

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s from %s: %q", defender.Str(props, "DeliveryAction"), defender.Str(props, "SenderFromAddress"), defender.Str(props, "Subject")),
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
