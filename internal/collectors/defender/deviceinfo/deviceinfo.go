// Package deviceinfo is the Defender advanced-hunting DeviceInfo blob collector
// (#106): one OTLP log per periodic device-inventory snapshot reported by
// Defender for Endpoint, read from the shared Azure Storage account.
//
// DeviceInfo is a SNAPSHOT-shaped table, not an event stream — it carries the
// device's current identity, OS, onboarding, exposure, and cloud-hosting
// metadata, refreshed periodically per device. There is no ActionType and no
// InitiatingProcess block (nothing "happened"; this is "what the device looks
// like right now"), so this mapper does not call defender.StampDeviceCommon or
// defender.StampInitiatingProcess — it stamps DeviceId/DeviceName/MachineGroup
// itself and skips ActionType entirely. ReportId is a STRING-precision integer
// column on this table (a huge per-report sequence, not the small numeric
// ReportId the event tables carry), so it is rendered via defender.FormatInt
// rather than defender.StampNums.
package deviceinfo

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
	name = "defender.device_info"
	// table is the advanced-hunting table, lowercased into its container.
	table = "deviceinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_info"
)

// deviceInfoStrFields is the DeviceInfo-specific string column set: client/OS
// identity, cloud-hosting metadata, tagging, exposure/onboarding state, and the
// merge/join lineage a device accrues over its Defender history.
var deviceInfoStrFields = []defender.StrField{
	{Attr: semconv.AttrClientVersion, Src: "ClientVersion"},
	{Attr: semconv.AttrPublicIp, Src: "PublicIP"},
	{Attr: semconv.AttrOsArchitecture, Src: "OSArchitecture"},
	{Attr: semconv.AttrOsPlatform, Src: "OSPlatform"},
	{Attr: semconv.AttrOsVersion, Src: "OSVersion"},
	{Attr: semconv.AttrOsVersionInfo, Src: "OSVersionInfo"},
	{Attr: semconv.AttrOsDistribution, Src: "OSDistribution"},
	{Attr: semconv.AttrOsBuildRevision, Src: "OsBuildRevision"},
	{Attr: semconv.AttrRegistryDeviceTag, Src: "RegistryDeviceTag"},
	{Attr: semconv.AttrAadDeviceId, Src: "AadDeviceId"},
	{Attr: semconv.AttrMergedDeviceIds, Src: "MergedDeviceIds"},
	{Attr: semconv.AttrMergedToDeviceId, Src: "MergedToDeviceId"},
	{Attr: semconv.AttrVendor, Src: "Vendor"},
	{Attr: semconv.AttrModel, Src: "Model"},
	{Attr: semconv.AttrOnboardingStatus, Src: "OnboardingStatus"},
	{Attr: semconv.AttrDeviceCategory, Src: "DeviceCategory"},
	{Attr: semconv.AttrDeviceType, Src: "DeviceType"},
	{Attr: semconv.AttrDeviceSubtype, Src: "DeviceSubtype"},
	{Attr: semconv.AttrJoinType, Src: "JoinType"},
	{Attr: semconv.AttrSensorHealthState, Src: "SensorHealthState"},
	{Attr: semconv.AttrExclusionReason, Src: "ExclusionReason"},
	{Attr: semconv.AttrExposureLevel, Src: "ExposureLevel"},
	{Attr: semconv.AttrAssetValue, Src: "AssetValue"},
	{Attr: semconv.AttrDeviceDynamicTags, Src: "DeviceDynamicTags"},
	{Attr: semconv.AttrDeviceManualTags, Src: "DeviceManualTags"},
	{Attr: semconv.AttrMitigationStatus, Src: "MitigationStatus"},
	{Attr: semconv.AttrHardwareUuid, Src: "HardwareUuid"},
	{Attr: semconv.AttrAzureVmId, Src: "AzureVmId"},
	{Attr: semconv.AttrAzureVmSubscriptionId, Src: "AzureVmSubscriptionId"},
	{Attr: semconv.AttrCloudPlatforms, Src: "CloudPlatforms"},
	{Attr: semconv.AttrHostDeviceId, Src: "HostDeviceId"},
	{Attr: semconv.AttrConnectivityType, Src: "ConnectivityType"},
	{Attr: semconv.AttrAwsResourceName, Src: "AwsResourceName"},
	{Attr: semconv.AttrGcpFullResourceName, Src: "GcpFullResourceName"},
	{Attr: semconv.AttrAzureResourceId, Src: "AzureResourceId"},
	// LoggedOnUsers arrives as a stringified JSON array (e.g.
	// `[{"UserName":"rob"}]`) — emitted verbatim as the string, never parsed.
	{Attr: semconv.AttrLoggedOnUsers, Src: "LoggedOnUsers"},
}

// deviceInfoNumFields is the numeric part: the OS build number.
var deviceInfoNumFields = []defender.NumField{
	{Attr: semconv.AttrOsBuild, Src: "OSBuild"},
}

// deviceInfoBoolFields is the boolean part: join/exclusion/exposure flags.
var deviceInfoBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsAzureAdJoined, Src: "IsAzureADJoined"},
	{Attr: semconv.AttrIsInternetFacing, Src: "IsInternetFacing"},
	{Attr: semconv.AttrIsExcluded, Src: "IsExcluded"},
	{Attr: semconv.AttrIsTransient, Src: "IsTransient"},
}

// mapRecord turns one raw DeviceInfo record into its OTLP log Event: unwrap
// properties, bind the timestamp to properties.Timestamp, and stamp the device
// identity (mapped directly — this snapshot table has no ActionType and no
// InitiatingProcess block, so defender.StampDeviceCommon does not apply) plus
// this table's OS/cloud/tagging columns.
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
	telemetry.SetStr(attrs, semconv.AttrDeviceId, defender.Str(props, "DeviceId"))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, defender.Str(props, "DeviceName"))
	telemetry.SetStr(attrs, semconv.AttrMachineGroup, defender.Str(props, "MachineGroup"))
	// ReportId is deliberately NOT emitted on DeviceInfo. It is an 18-digit
	// per-report sequence that exceeds float64's exact-integer range, so
	// encoding/json rounds it during decode (…463703 → …463744) before any
	// mapper sees it — the raw digits are unrecoverable from the decoded map.
	// The device's identity is DeviceId (a stable hash), which IS exact;
	// emitting a knowingly-rounded id as if precise is the kind of wrong data
	// CLAUDE.md's rules reject. The event tables keep ReportId because theirs is
	// small (≤ ~40k) and exact. See #106.
	defender.StampStrings(attrs, props, deviceInfoStrFields)
	defender.StampNums(attrs, props, deviceInfoNumFields)
	defender.StampBools(attrs, props, deviceInfoBoolFields)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s: %s %s, health=%s",
			defender.Str(props, "DeviceName"),
			defender.Str(props, "OSPlatform"),
			defender.Str(props, "OSVersion"),
			defender.Str(props, "SensorHealthState")),
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
