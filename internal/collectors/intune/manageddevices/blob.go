package manageddevices

// blob.go adds a blob TRANSPORT for the per-device twin (#135-F): the `Devices`
// Intune Azure Monitor diagnostic-settings category, read from Azure Storage.
// Like entra.risky_users (#135-C), this is NOT a source swap — intune.devices is
// a SnapshotCollector whose bounded fleet gauges come from a page-walk the blob
// inventory dump cannot reproduce as counts. So the polled collector keeps
// polling for its gauges, and the composition root suppresses only its per-device
// twin while this runs (keep-gauges/suppress-twin; RegisterBlobTwinOwner below).
//
// # The blob shape is NOT the Graph shape
//
// The `Devices` report uses PascalCase Intune-report field names AND different
// enum VALUES than the Graph managedDevice resource. Emitting the blob twin
// naively would silently diverge from the polled twin (a transport-dependent
// value split — the #142 class). So this maps each field into the managedDevice
// shape and NORMALIZES the values, then reuses deviceLogTwin so the two
// transports are byte-identical. Every mapping below is verified against BOTH
// live shapes captured 2026-07-18 (#135):
//
//	blob CompliantState "Compliant"      -> managedDevice.ComplianceState "compliant"  (case-fold; polled is lowercase)
//	blob OS "MacOS"/"IOS"                -> OperatingSystem "macOS"/"iOS"               (enum re-map; NOT a fold)
//	blob EncryptionStatusString "True"   -> IsEncrypted true                            (string -> bool)
//	blob LastContact (no timezone)       -> LastSyncDateTime (parsed as UTC)
//	blob DeviceId/UPN/SerialNumber/...   -> ID/UserPrincipalName/SerialNumber/...       (rename)
//
// The DeviceComplianceOrg category (threat level, management agents) is a
// separate concern, not folded here (#135). partnerReportedThreatState is absent
// from `Devices`, so the blob twin omits it (SetStr drops empties) — the polled
// twin still carries it when source is graph.

import (
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// blobDevicesCollector is this collector's stable config/self-obs key — a
	// second, log-only collector distinct from the polled "intune.devices", but
	// emitting the same intune.managed_device records.
	blobDevicesCollector = "intune.devices_blob"
	// blobDevicesContainer is the Devices diagnostic-settings category's fixed
	// container name (the category lowercased).
	blobDevicesContainer = "insights-logs-devices"
	blobInterval         = 5 * time.Minute
	// lastContactLayout parses the blob's LastContact, which has no timezone
	// suffix (e.g. "2026-07-17T23:55:14.00258"); a layout with no zone yields UTC.
	lastContactLayout = "2006-01-02T15:04:05.999999999"
)

// osNormalize maps the blob Devices OS enum onto the Graph managedDevice
// operatingSystem enum so the twin's operating_system value is identical across
// transports. Verified pairs (2026-07-18): blob MacOS/IOS/Windows vs polled
// macOS/iOS/Windows. Values not in the map pass through unchanged (Windows,
// Linux, Android are the same string in both).
var osNormalize = map[string]string{
	"MacOS": "macOS",
	"IOS":   "iOS",
}

type blobCollector struct {
	*blobpipeline.BlobCollector
}

func newBlobDevices(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobDevicesContainer,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobDevice,
		CollectorName: blobDevicesCollector,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(blobDevicesCollector, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

func blobPrefix(tenantID string) string { return "tenantId=" + tenantID + "/" }

// mapBlobDevice turns one Devices diagnostic-settings record into the
// intune.managed_device twin. It skips the per-batch Stats summary record (which
// carries no DeviceId), normalizes the blob fields into a managedDevice, and
// renders it through the SAME deviceLogTwin the polled path uses. Staleness is
// computed against the snapshot's own envelope time (deterministic — no clock),
// and the log timestamp binds to that same instant.
func mapBlobDevice(rec map[string]any) (telemetry.Event, bool) {
	props, ok := rec["properties"].(map[string]any)
	if !ok {
		return telemetry.Event{}, false
	}
	deviceID := blobStr(props, "DeviceId")
	if deviceID == "" {
		// The trailing {properties:{Stats:{RecordCount}}} batch-summary record,
		// or anything without a device — not a per-device row.
		return telemetry.Event{}, false
	}
	snapshotTime, ok := blobEnvelopeTime(rec)
	if !ok {
		return telemetry.Event{}, false
	}

	d := managedDevice{
		ID:                         deviceID,
		DeviceName:                 blobStr(props, "DeviceName"),
		SerialNumber:               blobStr(props, "SerialNumber"),
		UserPrincipalName:          blobStr(props, "UPN"),
		ComplianceState:            strings.ToLower(blobStr(props, "CompliantState")),
		OperatingSystem:            normalizeOS(blobStr(props, "OS")),
		OsVersion:                  blobStr(props, "OSVersion"),
		IsEncrypted:                strings.EqualFold(blobStr(props, "EncryptionStatusString"), "true"),
		Model:                      blobStr(props, "Model"),
		Manufacturer:               blobStr(props, "Manufacturer"),
		WifiMacAddress:             blobStr(props, "WifiMacAddress"),
		PartnerReportedThreatState: "", // not present in the Devices category
	}
	if lc := blobStr(props, "LastContact"); lc != "" {
		if t, err := time.Parse(lastContactLayout, lc); err == nil {
			d.LastSyncDateTime = &t
		}
	}

	compliance := complianceBucketFor(d.ComplianceState)
	stale := stalenessBucketFor(snapshotTime, d.LastSyncDateTime)
	ev := deviceLogTwin(d, compliance, stale)
	ev.Timestamp = snapshotTime
	return ev, true
}

// blobEnvelopeTime parses the record's top-level `time` (RFC3339, with Z), the
// instant the inventory snapshot was taken. Unparseable drops the record.
func blobEnvelopeTime(rec map[string]any) (time.Time, bool) {
	raw, _ := rec["time"].(string)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func normalizeOS(blobOS string) string {
	if v, ok := osNormalize[blobOS]; ok {
		return v
	}
	return blobOS
}

func blobStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterBlob(newBlobDevices)
	collectors.RegisterBlobTwinOwner(eventManagedDevice, blobDevicesCollector)
}
