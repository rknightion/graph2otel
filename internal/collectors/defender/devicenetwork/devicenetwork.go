// Package devicenetwork is the Defender advanced-hunting DeviceNetworkEvents
// blob collector (#106): one OTLP log per network connection observed by
// Defender for Endpoint, read from the shared Azure Storage account.
//
// Connection attempts/successes are a primary lateral-movement and
// exfiltration-hunting signal, and Graph exposes none of it. The record pairs
// each connection with the full InitiatingProcess block, so a LogQL join
// answers "which process opened this connection". Live-sampled 2026-07-18
// (#106): AdditionalFields is present on this table as a stringified-JSON
// blob and is emitted verbatim as a string, never parsed.
package devicenetwork

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
	name = "defender.device_network"
	// table is the advanced-hunting table, lowercased into its container.
	table = "devicenetworkevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_network"
)

// networkStrFields is the table-specific network column set: the local/remote
// endpoints and their type, the URL (when resolved instead of a bare IP), and
// the protocol. AdditionalFields is a stringified-JSON blob on this table
// (unlike DeviceRegistryEvents, where it is absent) and is stamped verbatim as
// a string — never parsed.
var networkStrFields = []defender.StrField{
	{Attr: semconv.AttrLocalIp, Src: "LocalIP"},
	{Attr: semconv.AttrLocalIpType, Src: "LocalIPType"},
	{Attr: semconv.AttrRemoteIp, Src: "RemoteIP"},
	{Attr: semconv.AttrRemoteIpType, Src: "RemoteIPType"},
	{Attr: semconv.AttrRemoteUrl, Src: "RemoteUrl"},
	{Attr: semconv.AttrProtocol, Src: "Protocol"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// networkNumFields is the table-specific numeric column set: the local/remote
// ports.
var networkNumFields = []defender.NumField{
	{Attr: semconv.AttrLocalPort, Src: "LocalPort"},
	{Attr: semconv.AttrRemotePort, Src: "RemotePort"},
}

// mapRecord turns one raw DeviceNetworkEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess family, and this
// table's network columns.
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
	defender.StampStrings(attrs, props, networkStrFields)
	defender.StampNums(attrs, props, networkNumFields)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s %s -> %s:%s on %s",
			defender.Str(props, "ActionType"),
			defender.Str(props, "LocalIP"),
			defender.Str(props, "RemoteIP"),
			defender.Str(props, "RemoteUrl"),
			defender.Str(props, "DeviceName"),
		),
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
