// Package messageurlinfo is the Defender advanced-hunting MessageUrlInfo blob
// collector (#241): one OTLP log per URL found inside a Microsoft Teams message
// Defender observed, read from the shared Azure Storage account.
//
// MessageUrlInfo is the Teams-message analog of EmailUrlInfo — a per-URL child
// of MessageEvents joined by TeamsMessageId, not NetworkMessageId. Like
// emailurlinfo it carries no ActionType, no InitiatingProcess block, and no
// DeviceId/MachineGroup — do NOT call defender.StampDeviceCommon or
// defender.StampInitiatingProcess. ReportId on this table is a STRING (a
// composite message+URL id), so it is mapped as a StrField.
//
// m7kni volume is tiny (n=10 rows over 30d in the #241 sample) — enough to write
// the mapper against, NOT enough to characterize volume.
package messageurlinfo

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
	name = "defender.teams_message_url"
	// table is the advanced-hunting table, lowercased into its container.
	table = "messageurlinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.teams_message_url"
)

// messageURLStrFields is the table's full string-column set: the Teams message
// join key, the URL and its domain, and the composite ReportId.
var messageURLStrFields = []defender.StrField{
	{Attr: semconv.AttrTeamsMessageId, Src: "TeamsMessageId"},
	{Attr: semconv.AttrUrl, Src: "Url"},
	{Attr: semconv.AttrUrlDomain, Src: "UrlDomain"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
}

// mapRecord turns one raw MessageUrlInfo record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the string
// field family.
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
	defender.StampStrings(attrs, props, messageURLStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("URL %s in Teams message %s", defender.Str(props, "Url"), defender.Str(props, "TeamsMessageId")),
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
