// Package urlclickevents is the Defender advanced-hunting UrlClickEvents blob
// collector (#106): one OTLP log per Safe Links URL-click verdict — a user
// clicked a link inside a message/app Defender's Safe Links protection had
// rewritten, and this is the click-time detonation/allow decision — read from
// the shared Azure Storage account.
//
// UrlClickEvents is an EVENT table (it carries ActionType) but, like
// CloudAppEvents, is not a Device* table: it has no InitiatingProcess, no
// DeviceId. Its identity block is the account/message/URL involved, so every
// field here is mapped table-specifically.
package urlclickevents

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
	name = "defender.url_click_event"
	// table is the advanced-hunting table, lowercased into its container.
	table = "urlclickevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.url_click_event"
)

// urlClickStrFields is the table-specific string column set: the account and
// message identity, the URL clicked, and the app/workload context. UrlChain
// is included here rather than via jsonStr — on the wire it is a plain string
// column holding pre-serialized JSON (verified against a live sample,
// 2026-07-19), not a native JSON array like CloudAppEvents' object/array
// columns.
var urlClickStrFields = []defender.StrField{
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrAppName, Src: "AppName"},
	{Attr: semconv.AttrAppVersion, Src: "AppVersion"},
	{Attr: semconv.AttrIpAddress, Src: "IPAddress"},
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrSourceId, Src: "SourceId"},
	{Attr: semconv.AttrUrl, Src: "Url"},
	{Attr: semconv.AttrWorkload, Src: "Workload"},
	{Attr: semconv.AttrUrlChain, Src: "UrlChain"},
}

// urlClickBoolFields is the boolean column set.
var urlClickBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsClickedThrough, Src: "IsClickedThrough"},
}

// jsonStr re-marshals a native JSON value (object, array, or null) back to its
// JSON string form, for columns this table can carry as nested objects/arrays
// rather than scalars. nil (an absent or JSON-null column) and a marshal
// error both yield "", so the caller's SetStr omits the attribute rather than
// emitting a bogus value.
func jsonStr(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// mapRecord turns one raw UrlClickEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, stamp the
// string/bool field families (UrlChain included, as a plain string), then the
// object/array-shaped columns (DetectionMethods, ThreatTypes) re-marshaled to
// JSON strings when populated.
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
	defender.StampStrings(attrs, props, urlClickStrFields)
	defender.StampBools(attrs, props, urlClickBoolFields)

	telemetry.SetStr(attrs, semconv.AttrDetectionMethods, jsonStr(props["DetectionMethods"]))
	telemetry.SetStr(attrs, semconv.AttrThreatTypes, jsonStr(props["ThreatTypes"]))

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s %s by %s", defender.Str(props, "ActionType"), defender.Str(props, "Url"), defender.Str(props, "AccountUpn")),
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
