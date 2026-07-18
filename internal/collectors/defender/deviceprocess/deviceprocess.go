// Package deviceprocess is the Defender advanced-hunting DeviceProcessEvents
// blob collector (#106): one OTLP log per Windows process creation observed by
// Defender for Endpoint, read from the shared Azure Storage account.
//
// Process creation is the core EDR signal — command lines, hashes, and the
// InitiatingProcess block that ties a new process back to what launched it —
// and Graph exposes none of it. The table's whole field set is exactly the
// five shared families defender.go already stamps (device identity,
// InitiatingProcess, the event-level account, the event-level file/hash, and
// the created-process block), so this mapper needs no table-specific field
// slice of its own.
package deviceprocess

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
	name = "defender.device_process"
	// table is the advanced-hunting table, lowercased into its container.
	table = "deviceprocessevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_process"
)

// mapRecord turns one raw DeviceProcessEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess family, the event-level
// account, the event-level file/hash, and the created-process block — the
// entire DeviceProcessEvents field set (#106).
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
	defender.StampAccount(attrs, props)
	defender.StampFileHash(attrs, props)
	defender.StampProcess(attrs, props)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s created %s on %s", defender.Str(props, "InitiatingProcessFileName"), defender.Str(props, "FileName"), defender.Str(props, "DeviceName")),
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
