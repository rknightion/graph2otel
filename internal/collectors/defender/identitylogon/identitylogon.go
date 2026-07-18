// Package identitylogon is the Defender advanced-hunting IdentityLogonEvents
// blob collector (#106): one OTLP log per authentication event Defender for
// Identity/Cloud Apps observed across on-prem AD and cloud identity providers,
// read from the shared Azure Storage account.
//
// IdentityLogonEvents is an EVENT table (it carries ActionType) but NOT a
// Device* table — it has no InitiatingProcess, file-hash, or device-identity
// block, so this mapper does not call StampInitiatingProcess/StampDeviceCommon/
// StampFileHash. Everything it emits is table-specific: the account performing
// the logon, the logon protocol/type, source/destination network and device
// identity, and Defender's own uncommon-for-user risk signals. Live-sampled
// 2026-07-18 (#106): AdditionalFields and LastSeenForUser arrive as native JSON
// objects (re-marshaled to a string attribute, never flattened), and most
// destination/target columns are null on an interactive sign-in — omitted,
// never dropped.
package identitylogon

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
	name = "defender.identity_logon"
	// table is the advanced-hunting table, lowercased into its container.
	table = "identitylogonevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.identity_logon"
)

// identityLogonStrFields is the table-specific string column set: the account
// performing the logon, the logon protocol/type, source location/network, the
// source and destination device identity, and the failure/target detail a
// non-interactive or failed logon carries.
var identityLogonStrFields = []defender.StrField{
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrLogonType, Src: "LogonType"},
	{Attr: semconv.AttrProtocol, Src: "Protocol"},
	{Attr: semconv.AttrAccountDisplayName, Src: "AccountDisplayName"},
	{Attr: semconv.AttrAccountUpn, Src: "AccountUpn"},
	{Attr: semconv.AttrAccountName, Src: "AccountName"},
	{Attr: semconv.AttrAccountDomain, Src: "AccountDomain"},
	{Attr: semconv.AttrAccountSid, Src: "AccountSid"},
	{Attr: semconv.AttrAccountObjectId, Src: "AccountObjectId"},
	{Attr: semconv.AttrIpAddress, Src: "IPAddress"},
	{Attr: semconv.AttrLocation, Src: "Location"},
	{Attr: semconv.AttrIsp, Src: "ISP"},
	{Attr: semconv.AttrApplication, Src: "Application"},
	{Attr: semconv.AttrDeviceName, Src: "DeviceName"},
	{Attr: semconv.AttrDeviceType, Src: "DeviceType"},
	{Attr: semconv.AttrOsPlatform, Src: "OSPlatform"},
	{Attr: semconv.AttrFailureReason, Src: "FailureReason"},
	{Attr: semconv.AttrDestinationDeviceName, Src: "DestinationDeviceName"},
	{Attr: semconv.AttrDestinationIpAddress, Src: "DestinationIPAddress"},
	{Attr: semconv.AttrTargetAccountDisplayName, Src: "TargetAccountDisplayName"},
	{Attr: semconv.AttrTargetDeviceName, Src: "TargetDeviceName"},
	{Attr: semconv.AttrLastSeenForUser, Src: "LastSeenForUser"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
}

// identityLogonNumFields is the numeric part: the source and destination
// network ports.
var identityLogonNumFields = []defender.NumField{
	{Attr: semconv.AttrPort, Src: "Port"},
	{Attr: semconv.AttrDestinationPort, Src: "DestinationPort"},
}

// identityLogonBoolFields is the boolean part: Defender's own "this logon is
// uncommon for this user" risk flag.
var identityLogonBoolFields = []defender.BoolField{
	{Attr: semconv.AttrUncommonForUser, Src: "UncommonForUser"},
}

// jsonStr re-marshals a native JSON value (AdditionalFields arrives as an
// object, not a string) back to its compact string form, "" when nil or
// unmarshalable.
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

// mapRecord turns one raw IdentityLogonEvents record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, stamp this
// table's string/numeric/boolean columns, and re-marshal AdditionalFields.
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
	defender.StampStrings(attrs, props, identityLogonStrFields)
	defender.StampNums(attrs, props, identityLogonNumFields)
	defender.StampBools(attrs, props, identityLogonBoolFields)
	telemetry.SetStr(attrs, semconv.AttrAdditionalFields, jsonStr(props["AdditionalFields"]))

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s %s for %s", defender.Str(props, "ActionType"), defender.Str(props, "LogonType"), defender.Str(props, "AccountUpn")),
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
