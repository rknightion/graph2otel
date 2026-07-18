// Package devicefile is the Defender advanced-hunting DeviceFileEvents blob
// collector (#106): one OTLP log per file create/rename/delete/other file-system
// operation observed by Defender for Endpoint, read from the shared Azure
// Storage account.
//
// File events are the primary drop/stage forensics signal (malware landing on
// disk, DLL side-loading, exfil staging), and Graph exposes none of it. The
// record pairs each file operation with the full InitiatingProcess block, so a
// LogQL join answers "which process wrote this file". Live-sampled 2026-07-18
// (#106): FileOriginUrl/FileOriginIP/FileOriginReferrerUrl,
// SensitivityLabel/SensitivitySubLabel, IsAzureInfoProtectionApplied,
// ShareName, and RequestSourceIP/RequestSourcePort are null on a local
// FileCreated — omitted, never dropped. AdditionalFields arrives as a
// stringified-JSON blob (e.g. `{"FileType":"PortableExecutable"}`) and is
// emitted verbatim as one string attribute — this mapper never parses it.
package devicefile

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
	name = "defender.device_file"
	// table is the advanced-hunting table, lowercased into its container.
	table = "devicefileevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_file"
)

// fileStrFields is the table-specific string column set: where the file came
// from (origin URL/IP/referrer), its previous name/path on a rename, the
// request account/protocol that touched it over a network share, the share
// itself, its sensitivity labels, and the stringified-JSON AdditionalFields
// blob (emitted verbatim — never parsed).
var fileStrFields = []defender.StrField{
	{Attr: semconv.AttrFileOriginIp, Src: "FileOriginIP"},
	{Attr: semconv.AttrFileOriginUrl, Src: "FileOriginUrl"},
	{Attr: semconv.AttrFileOriginReferrerUrl, Src: "FileOriginReferrerUrl"},
	{Attr: semconv.AttrPreviousFileName, Src: "PreviousFileName"},
	{Attr: semconv.AttrPreviousFolderPath, Src: "PreviousFolderPath"},
	{Attr: semconv.AttrRequestAccountName, Src: "RequestAccountName"},
	{Attr: semconv.AttrRequestAccountDomain, Src: "RequestAccountDomain"},
	{Attr: semconv.AttrRequestAccountSid, Src: "RequestAccountSid"},
	{Attr: semconv.AttrRequestProtocol, Src: "RequestProtocol"},
	{Attr: semconv.AttrRequestSourceIp, Src: "RequestSourceIP"},
	{Attr: semconv.AttrShareName, Src: "ShareName"},
	{Attr: semconv.AttrSensitivityLabel, Src: "SensitivityLabel"},
	{Attr: semconv.AttrSensitivitySubLabel, Src: "SensitivitySubLabel"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// fileNumFields is the table-specific numeric column set.
var fileNumFields = []defender.NumField{
	{Attr: semconv.AttrRequestSourcePort, Src: "RequestSourcePort"},
}

// fileBoolFields is the table-specific boolean column set.
var fileBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsAzureInfoProtectionApplied, Src: "IsAzureInfoProtectionApplied"},
}

// mapRecord turns one raw DeviceFileEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess family, the event-level
// file/hash block, and this table's request/origin/sensitivity columns.
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
	defender.StampStrings(attrs, props, fileStrFields)
	defender.StampNums(attrs, props, fileNumFields)
	defender.StampBools(attrs, props, fileBoolFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s %s on %s", defender.Str(props, "ActionType"), defender.Str(props, "FileName"), defender.Str(props, "DeviceName")),
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
