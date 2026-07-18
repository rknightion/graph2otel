// Package deviceregistry is the Defender advanced-hunting DeviceRegistryEvents
// blob collector (#106): one OTLP log per Windows registry create/set/delete
// observed by Defender for Endpoint, read from the shared Azure Storage account.
//
// Registry writes are a primary persistence-hunting signal (Run keys, service
// installs, policy tampering), and Graph exposes none of it. The record pairs
// each registry change with the full InitiatingProcess block, so a LogQL join
// answers "which process wrote this key". Live-sampled 2026-07-18 (#106):
// AdditionalFields is absent on this table, and RegistryValueName/Data are null
// on a key-create — omitted, never dropped.
package deviceregistry

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
	name = "defender.device_registry"
	// table is the advanced-hunting table, lowercased into its container.
	table = "deviceregistryevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_registry"
)

// registryStrFields is the table-specific registry column set: the key/value
// being written and, on a value change, its previous key/value.
var registryStrFields = []defender.StrField{
	{Attr: semconv.AttrRegistryKey, Src: "RegistryKey"},
	{Attr: semconv.AttrRegistryValueName, Src: "RegistryValueName"},
	{Attr: semconv.AttrRegistryValueData, Src: "RegistryValueData"},
	{Attr: semconv.AttrRegistryValueType, Src: "RegistryValueType"},
	{Attr: semconv.AttrPreviousRegistryKey, Src: "PreviousRegistryKey"},
	{Attr: semconv.AttrPreviousRegistryValueName, Src: "PreviousRegistryValueName"},
	{Attr: semconv.AttrPreviousRegistryValueData, Src: "PreviousRegistryValueData"},
}

// mapRecord turns one raw DeviceRegistryEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess family, and this table's
// registry columns.
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
	defender.StampDeviceCommon(attrs, props)
	defender.StampInitiatingProcess(attrs, props)
	defender.StampStrings(attrs, props, registryStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s on %s: %s", defender.Str(props, "ActionType"), defender.Str(props, "DeviceName"), defender.Str(props, "RegistryKey")),
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
