// Package devicelogon is the Defender advanced-hunting DeviceLogonEvents blob
// collector (#106): one OTLP log per interactive/network/remote logon observed
// by Defender for Endpoint, read from the shared Azure Storage account.
//
// A logon pairs the account that authenticated with the InitiatingProcess block
// (the process that performed the logon, e.g. loginwindow, screensharingd,
// winlogon), so a LogQL join answers "which process logged which account in,
// from where". Live-sampled 2026-07-18 (#106): RemoteIP arrives as "" (not
// null) when there is no remote endpoint — SetStr already omits an empty
// string, so no special-casing is needed. AdditionalFields on this table is a
// large stringified-JSON blob (POSIX identity details on macOS); it is emitted
// verbatim as one string attribute, never parsed, to stay lossless.
package devicelogon

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
	name = "defender.device_logon"
	// table is the advanced-hunting table, lowercased into its container.
	table = "devicelogonevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_logon"
)

// logonStrFields is the table-specific logon column set: the account that
// authenticated, the logon's type/protocol/remote origin, and any failure
// reason.
var logonStrFields = []defender.StrField{
	{Attr: semconv.AttrAccountName, Src: "AccountName"},
	{Attr: semconv.AttrAccountDomain, Src: "AccountDomain"},
	{Attr: semconv.AttrAccountSid, Src: "AccountSid"},
	{Attr: semconv.AttrLogonType, Src: "LogonType"},
	{Attr: semconv.AttrRemoteIp, Src: "RemoteIP"},
	{Attr: semconv.AttrRemoteDeviceName, Src: "RemoteDeviceName"},
	{Attr: semconv.AttrRemoteIpType, Src: "RemoteIPType"},
	{Attr: semconv.AttrProtocol, Src: "Protocol"},
	{Attr: semconv.AttrFailureReason, Src: "FailureReason"},
	{Attr: semconv.AttrAdditionalFields, Src: "AdditionalFields"},
}

// logonNumFields is the numeric part of the logon column set.
var logonNumFields = []defender.NumField{
	{Attr: semconv.AttrLogonId, Src: "LogonId"},
	{Attr: semconv.AttrRemotePort, Src: "RemotePort"},
}

// logonBoolFields is the boolean part of the logon column set.
var logonBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsLocalAdmin, Src: "IsLocalAdmin"},
}

// mapRecord turns one raw DeviceLogonEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp the
// device-identity block, the shared InitiatingProcess family, and this table's
// logon columns.
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
	defender.StampStrings(attrs, props, logonStrFields)
	defender.StampNums(attrs, props, logonNumFields)
	defender.StampBools(attrs, props, logonBoolFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s %s on %s as %s", defender.Str(props, "ActionType"), defender.Str(props, "LogonType"), defender.Str(props, "DeviceName"), defender.Str(props, "AccountName")),
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
