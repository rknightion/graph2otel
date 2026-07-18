// Package defender provides the shared plumbing for the Microsoft Defender XDR
// advanced-hunting blob collectors (#106). Each table (DeviceProcessEvents,
// DeviceFileEvents, EmailEvents, AlertEvidence, ...) lives in its own subpackage
// with its own mapper and signals golden; this package owns everything they
// share: the container-name and listing-prefix conventions, the event-time
// binding, the field accessors, and the two large field families (device
// identity + the ~30-field InitiatingProcess block) that the Device* tables
// repeat verbatim.
//
// Every collector built on this package is:
//
//   - a BLOB collector — its data is the Defender streaming API's output landing
//     in the shared Azure Storage account (`graph2otelm7kni`), read by
//     internal/blobpipeline, never polled from Graph. There is no advanced-hunting
//     Graph endpoint on the push path, and streaming to Storage consumes none of
//     the tenant-wide advanced-hunting CPU quota a poller would (#106).
//   - LOG-ONLY — an advanced-hunting row is an event, so it maps to exactly one
//     OTLP log record and no metric. Nothing here calls GaugeSnapshot/Histogram.
//   - EXPERIMENTAL + off by default — this is the highest-volume surface
//     graph2otel touches, so each table is opted in explicitly per #106 (the
//     subpackage's wrapper returns Experimental() == true).
//
// Event time is bound to properties.Timestamp on every table — the moment the
// sensor observed the event — never the envelope `time` or `_TimeReceivedBySvc`,
// which are Azure's export/ingest clocks and run seconds-to-minutes later
// (live-measured 2026-07-18, #106). There is no fallback: a record with no
// parseable Timestamp is dropped rather than mis-dated (CLAUDE.md emitter rule —
// misdated is wrong, and only wrong justifies a drop).
package defender

import (
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Interval is how often each Defender container is re-listed. Records land
// minutes behind the event and the floor is Azure-side, so polling faster only
// bills list operations (#89) — the same 5-minute cadence every blob collector
// uses.
const Interval = 5 * time.Minute

// Container returns the fixed Azure Monitor container name for a Defender
// advanced-hunting table: "insights-logs-advancedhunting-<table>", table
// lowercased. Verified live 2026-07-18 (#106) across all 18 enabled containers.
func Container(table string) string {
	return "insights-logs-advancedhunting-" + table
}

// Prefix returns the tenant-level listing prefix "tenantId=<guid>/" — the same
// layout the Entra diagnostic-settings categories use, verified to hold for the
// Defender containers too (#106), NOT the subscription-scoped
// "resourceId=/subscriptions/..." form Microsoft documents, which lists zero
// blobs and reports success forever (#89).
func Prefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// New builds the generic BlobCollector for a Defender table. A subpackage wraps
// the returned value in its own named type (so collectordoc can recover the
// subpackage by reflection) and adds Experimental(); this constructor owns the
// ContainerConfig assembly every table shares.
func New(name, table string, mapFn func(map[string]any) (telemetry.Event, bool), d collectors.BlobDeps) *blobpipeline.BlobCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     Container(table),
		Prefix:        Prefix(d.TenantID),
		Map:           mapFn,
		CollectorName: name,
	}
	return blobpipeline.NewBlobCollector(name, Interval, d.TenantID, cfg, d.Source, d.Store, d.Logger)
}

// Props returns the advanced-hunting record's inner `properties` object — the
// per-column payload every mapper reads. nil (and a dropped record) when absent.
func Props(rec map[string]any) map[string]any {
	p, _ := rec["properties"].(map[string]any)
	return p
}

// EventTime binds the record's real event time to properties.Timestamp, parsed
// as an instant. No fallback: absent or unparseable drops the record. See the
// package doc for why `time`/`_TimeReceivedBySvc` are never used.
func EventTime(props map[string]any) (time.Time, bool) {
	raw := Str(props, "Timestamp")
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Str reads a string column, "" when absent or non-string.
func Str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// StrField maps one advanced-hunting string column (Src) to its attribute key
// (Attr). A zero/absent/empty source omits the attribute (telemetry.SetStr).
type StrField struct {
	Attr string
	Src  string
}

// NumField maps one numeric column to its attribute key. A missing or
// non-numeric source omits the attribute (telemetry.SetNum). Advanced-hunting
// integers arrive as JSON numbers (float64 after decode); ids that Microsoft
// serializes as strings (e.g. ReportId on some tables) are mapped as StrFields
// instead.
type NumField struct {
	Attr string
	Src  string
}

// BoolField maps one boolean column to its attribute key.
type BoolField struct {
	Attr string
	Src  string
}

// StampStrings applies every StrField in fields, reading from props.
func StampStrings(attrs telemetry.Attrs, props map[string]any, fields []StrField) {
	for _, f := range fields {
		telemetry.SetStr(attrs, f.Attr, Str(props, f.Src))
	}
}

// StampNums applies every NumField, copying the float64 at props[Src] to attrs.
func StampNums(attrs telemetry.Attrs, props map[string]any, fields []NumField) {
	for _, f := range fields {
		telemetry.SetNum(attrs, f.Attr, props, f.Src)
	}
}

// StampBools applies every BoolField, but only for columns actually present as a
// JSON bool — a null/absent boolean omits the attribute rather than emitting a
// misleading "false" (Defender uses null, not false, for "unknown" on fields
// like IsInternetFacing).
func StampBools(attrs telemetry.Attrs, props map[string]any, fields []BoolField) {
	for _, f := range fields {
		if b, ok := props[f.Src].(bool); ok {
			telemetry.SetBool(attrs, f.Attr, b)
		}
	}
}

// initiatingProcessStrFields is the InitiatingProcess* string family shared
// verbatim by every Device* table (DeviceProcessEvents, DeviceFileEvents,
// DeviceNetworkEvents, DeviceEvents, DeviceLogonEvents, DeviceRegistryEvents).
// It describes the process that CAUSED the event — its account, image, hashes,
// command line, parent, integrity, remote-session origin, and file version
// metadata.
var initiatingProcessStrFields = []StrField{
	{semconv.AttrInitiatingProcessAccountDomain, "InitiatingProcessAccountDomain"},
	{semconv.AttrInitiatingProcessAccountName, "InitiatingProcessAccountName"},
	{semconv.AttrInitiatingProcessAccountObjectId, "InitiatingProcessAccountObjectId"},
	{semconv.AttrInitiatingProcessAccountSid, "InitiatingProcessAccountSid"},
	{semconv.AttrInitiatingProcessAccountUpn, "InitiatingProcessAccountUpn"},
	{semconv.AttrInitiatingProcessCommandLine, "InitiatingProcessCommandLine"},
	{semconv.AttrInitiatingProcessCreationTime, "InitiatingProcessCreationTime"},
	{semconv.AttrInitiatingProcessFileName, "InitiatingProcessFileName"},
	{semconv.AttrInitiatingProcessFolderPath, "InitiatingProcessFolderPath"},
	{semconv.AttrInitiatingProcessIntegrityLevel, "InitiatingProcessIntegrityLevel"},
	{semconv.AttrInitiatingProcessMd5, "InitiatingProcessMD5"},
	{semconv.AttrInitiatingProcessParentCreationTime, "InitiatingProcessParentCreationTime"},
	{semconv.AttrInitiatingProcessParentFileName, "InitiatingProcessParentFileName"},
	{semconv.AttrInitiatingProcessRemoteSessionDeviceName, "InitiatingProcessRemoteSessionDeviceName"},
	{semconv.AttrInitiatingProcessRemoteSessionIp, "InitiatingProcessRemoteSessionIP"},
	{semconv.AttrInitiatingProcessSha1, "InitiatingProcessSHA1"},
	{semconv.AttrInitiatingProcessSha256, "InitiatingProcessSHA256"},
	{semconv.AttrInitiatingProcessSignatureStatus, "InitiatingProcessSignatureStatus"},
	{semconv.AttrInitiatingProcessSignerType, "InitiatingProcessSignerType"},
	{semconv.AttrInitiatingProcessTokenElevation, "InitiatingProcessTokenElevation"},
	{semconv.AttrInitiatingProcessUniqueId, "InitiatingProcessUniqueId"},
	{semconv.AttrInitiatingProcessVersionInfoCompanyName, "InitiatingProcessVersionInfoCompanyName"},
	{semconv.AttrInitiatingProcessVersionInfoFileDescription, "InitiatingProcessVersionInfoFileDescription"},
	{semconv.AttrInitiatingProcessVersionInfoInternalFileName, "InitiatingProcessVersionInfoInternalFileName"},
	{semconv.AttrInitiatingProcessVersionInfoOriginalFileName, "InitiatingProcessVersionInfoOriginalFileName"},
	{semconv.AttrInitiatingProcessVersionInfoProductName, "InitiatingProcessVersionInfoProductName"},
	{semconv.AttrInitiatingProcessVersionInfoProductVersion, "InitiatingProcessVersionInfoProductVersion"},
}

// initiatingProcessNumFields is the numeric part of the InitiatingProcess family
// (pids, file size, session/logon ids).
var initiatingProcessNumFields = []NumField{
	{semconv.AttrInitiatingProcessId, "InitiatingProcessId"},
	{semconv.AttrInitiatingProcessParentId, "InitiatingProcessParentId"},
	{semconv.AttrInitiatingProcessFileSize, "InitiatingProcessFileSize"},
	{semconv.AttrInitiatingProcessSessionId, "InitiatingProcessSessionId"},
	{semconv.AttrInitiatingProcessLogonId, "InitiatingProcessLogonId"},
}

// initiatingProcessBoolFields is the boolean part (remote-session flag).
var initiatingProcessBoolFields = []BoolField{
	{semconv.AttrIsInitiatingProcessRemoteSession, "IsInitiatingProcessRemoteSession"},
}

// StampInitiatingProcess applies the entire InitiatingProcess field family. Every
// Device* mapper calls this so the family is defined once and can never drift
// between tables.
func StampInitiatingProcess(attrs telemetry.Attrs, props map[string]any) {
	StampStrings(attrs, props, initiatingProcessStrFields)
	StampNums(attrs, props, initiatingProcessNumFields)
	StampBools(attrs, props, initiatingProcessBoolFields)
}

// deviceCommonStrFields is the device-identity block every Device* table carries:
// which endpoint, its Defender DeviceId (a stable opaque hash consistent across
// all Device* tables — a good shared join key), the action, and the machine
// group. ReportId is a numeric per-device sequence on the event tables (handled
// via StampDeviceCommon's NumField), but a STRING on DeviceInfo/EmailEvents, so
// those tables map it themselves.
var deviceCommonStrFields = []StrField{
	{semconv.AttrDeviceId, "DeviceId"},
	{semconv.AttrDeviceName, "DeviceName"},
	{semconv.AttrActionType, "ActionType"},
	{semconv.AttrMachineGroup, "MachineGroup"},
	{semconv.AttrAppGuardContainerId, "AppGuardContainerId"},
}

// StampDeviceCommon applies the device-identity block plus the numeric ReportId
// the event tables carry. DeviceInfo (snapshot, string ReportId, no ActionType)
// does not use this — it maps its own identity fields.
func StampDeviceCommon(attrs telemetry.Attrs, props map[string]any) {
	StampStrings(attrs, props, deviceCommonStrFields)
	telemetry.SetNum(attrs, semconv.AttrReportId, props, "ReportId")
}

// FormatInt renders an integer-valued float64 column as a plain string, for the
// few id-like numeric fields a table wants as a string attribute. Absent/
// non-numeric yields "".
func FormatInt(props map[string]any, key string) string {
	if f, ok := props[key].(float64); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return ""
}
