// Package deviceimageload is the Defender advanced-hunting DeviceImageLoadEvents
// blob collector (#106): one OTLP log per DLL/image load observed by Defender
// for Endpoint, read from the shared Azure Storage account.
//
// Image loads are a primary DLL-hijacking and side-loading hunting signal, and
// Graph exposes none of it. The record pairs the loaded image (name, path,
// hashes) with the full InitiatingProcess block, so a LogQL join answers
// "which process loaded this DLL". Live-sampled 2026-07-18 (#106): the table's
// entire field set is the device-identity block, the InitiatingProcess family,
// and the loaded-file/hash block every Device* table already shares — there is
// no table-specific column.
package deviceimageload

import (
	"fmt"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/defender"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// name is the stable collector key and config-enable key.
	name = "defender.device_image_load"
	// table is the advanced-hunting table, lowercased into its container.
	table = "deviceimageloadevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_image_load"
)

// mapRecord turns one raw DeviceImageLoadEvents record into its OTLP log
// Event: unwrap properties, bind the timestamp to properties.Timestamp, and
// stamp the device-identity block, the shared InitiatingProcess family, and
// the loaded-file/hash block. Nothing else — this table's field set is fully
// covered by the three shared stampers.
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
	defender.StampFileHash(attrs, props)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s loaded %s on %s", defender.Str(props, "InitiatingProcessFileName"), defender.Str(props, "FileName"), defender.Str(props, "DeviceName")),
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
