// Package deviceevent is the Defender advanced-hunting DeviceEvents blob
// collector (#106): one OTLP log per record on Defender for Endpoint's
// catch-all event table — everything that doesn't fit DeviceProcessEvents,
// DeviceFileEvents, DeviceNetworkEvents, or DeviceRegistryEvents (script
// execution, API calls like NtAllocateVirtualMemory/ReadProcessMemory, USB
// mounts, WMI process creation, CLR module loads, ...), read from the shared
// Azure Storage account.
//
// The table's ActionType column selects which of its ~66 columns are
// populated; every other column is null on a given record (live-sampled
// 2026-07-18, #106). AdditionalFields carries an ActionType-specific JSON blob
// as a string — on a ScriptContent record this is the entire script body.
// MAINTAINER DECISION (#106): ship AdditionalFields verbatim, like every other
// advanced-hunting field — never hash, truncate, or drop it.
package deviceevent

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
	name = "defender.device_event"
	// table is the advanced-hunting table, lowercased into its container.
	table = "deviceevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_event"
)

// eventStrFields is the table-specific string column set: registry, network
// (remote/local IP, remote URL/device), file-origin, and the catch-all
// AdditionalFields blob. Shipped verbatim per #106 — including ScriptContent,
// which arrives inside AdditionalFields on a ScriptContent ActionType record.
var eventStrFields = []defender.StrField{
	{Attr: semconv.AttrRegistryKey, Src: "RegistryKey"},
	{Attr: semconv.AttrRegistryValueName, Src: "RegistryValueName"},
	{Attr: semconv.AttrRegistryValueData, Src: "RegistryValueData"},
	{Attr: semconv.AttrRemoteIp, Src: "RemoteIP"},
	{Attr: semconv.AttrRemoteUrl, Src: "RemoteUrl"},
	{Attr: semconv.AttrRemoteDeviceName, Src: "RemoteDeviceName"},
	{Attr: semconv.AttrLocalIp, Src: "LocalIP"},
	{Attr: semconv.AttrFileOriginIp, Src: "FileOriginIP"},
	{Attr: semconv.AttrFileOriginUrl, Src: "FileOriginUrl"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// eventNumFields is the table-specific numeric column set: the network ports.
var eventNumFields = []defender.NumField{
	{Attr: semconv.AttrRemotePort, Src: "RemotePort"},
	{Attr: semconv.AttrLocalPort, Src: "LocalPort"},
}

// mapRecord turns one raw DeviceEvents record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess/Account/FileHash/Process
// families, and this table's own registry/network/AdditionalFields columns.
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
	defender.StampStrings(attrs, props, eventStrFields)
	defender.StampNums(attrs, props, eventNumFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s on %s", defender.Str(props, "ActionType"), defender.Str(props, "DeviceName")),
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
