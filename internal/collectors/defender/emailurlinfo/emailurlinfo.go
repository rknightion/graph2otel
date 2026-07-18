// Package emailurlinfo is the Defender advanced-hunting EmailUrlInfo blob
// collector (#106): one OTLP log per URL found inside a message Defender for
// Office 365 observed, read from the shared Azure Storage account.
//
// EmailUrlInfo is a per-URL child of EmailEvents (joined by NetworkMessageId),
// like email's own per-message shape: there is no ActionType, no
// InitiatingProcess block, and no DeviceId/MachineGroup — do NOT call
// defender.StampDeviceCommon or defender.StampInitiatingProcess here.
// ReportId on this table is a STRING (a composite message+URL id), not the
// numeric per-device sequence the Device* tables carry, so it is mapped as a
// StrField. UrlChainId is null outside a redirect chain — omitted, never
// emitted empty.
package emailurlinfo

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
	name = "defender.email_url"
	// table is the advanced-hunting table, lowercased into its container.
	table = "emailurlinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.email_url"
)

// emailURLStrFields is the table's full string-column set: the message join
// key, the URL and its domain/location within the message, the composite
// ReportId, and the redirect-chain id.
var emailURLStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrUrl, Src: "Url"},
	{Attr: semconv.AttrUrlDomain, Src: "UrlDomain"},
	{Attr: semconv.AttrUrlLocation, Src: "UrlLocation"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrUrlChainId, Src: "UrlChainId"},
}

// emailURLNumFields is the table's numeric-column set.
var emailURLNumFields = []defender.NumField{
	{Attr: semconv.AttrUrlChainPosition, Src: "UrlChainPosition"},
}

// mapRecord turns one raw EmailUrlInfo record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp
// the string and numeric field families.
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
	defender.StampStrings(attrs, props, emailURLStrFields)
	defender.StampNums(attrs, props, emailURLNumFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("URL %s in message %s", defender.Str(props, "Url"), defender.Str(props, "NetworkMessageId")),
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
