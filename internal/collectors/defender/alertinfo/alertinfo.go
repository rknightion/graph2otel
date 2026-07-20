// Package alertinfo is the Defender advanced-hunting AlertInfo blob collector
// (#106): one OTLP log per Defender alert's metadata row — the alert
// identity, title, category, severity, and which detection service raised
// it — read from the shared Azure Storage account.
//
// AlertInfo is an alert-metadata EVENT table, NOT a Device* table: it carries
// no ActionType, no InitiatingProcess block, and no device-common fields, so
// every column here is mapped table-specifically.
package alertinfo

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
	name = "defender.alert_info"
	// table is the advanced-hunting table, lowercased into its container.
	table = "alertinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.alert_info"
)

// alertInfoStrFields is the AlertInfo column set: the alert identity, its
// title/category/severity, which detection service raised it, and the
// machine group it is scoped to (JSON null on non-device alerts).
var alertInfoStrFields = []defender.StrField{
	{Attr: semconv.AttrAlertId, Src: "AlertId"},
	{Attr: semconv.AttrAttackTechniques, Src: "AttackTechniques"},
	{Attr: semconv.AttrCategory, Src: "Category"},
	{Attr: semconv.AttrDetectionSource, Src: "DetectionSource"},
	{Attr: semconv.AttrMachineGroup, Src: "MachineGroup"},
	{Attr: semconv.AttrServiceSource, Src: "ServiceSource"},
	{Attr: semconv.AttrSeverity, Src: "Severity"},
	{Attr: semconv.AttrTitle, Src: "Title"},
}

// severityFor maps the record's wire-capitalized Severity string ("High",
// "Medium", "Low", ...) to an OTLP log severity, same convention as
// alertevidence. Anything else (including absent) is SeverityInfo.
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

// mapRecord turns one raw AlertInfo record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// alert-metadata column family.
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
	defender.StampStrings(attrs, props, alertInfoStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s [%s] %s", defender.Str(props, "Severity"), defender.Str(props, "Category"), defender.Str(props, "Title")),
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
