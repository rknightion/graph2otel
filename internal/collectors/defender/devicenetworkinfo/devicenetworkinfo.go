// Package devicenetworkinfo is the Defender advanced-hunting DeviceNetworkInfo
// blob collector (#106): one OTLP log per periodic network-adapter snapshot
// reported by Defender for Endpoint, read from the shared Azure Storage
// account.
//
// DeviceNetworkInfo is a SNAPSHOT-shaped table, not an event stream — it
// carries a device's current network-adapter state (name, type, status,
// tunnel, addresses), refreshed periodically per adapter. There is no
// ActionType and no InitiatingProcess block (nothing "happened"; this is
// "what this adapter looks like right now"), so this mapper does not call
// defender.StampDeviceCommon or defender.StampInitiatingProcess — it stamps
// DeviceId/DeviceName/MachineGroup itself. ReportId is deliberately NOT emitted:
// on this snapshot table it is an 18-digit sequence (live: 639199916335081329)
// that exceeds float64's exact-integer range, so encoding/json rounds it during
// decode before the mapper sees it — the same trap DeviceInfo documents. DeviceId
// is the stable identity; emitting a rounded id as if exact is the wrong-data
// case CLAUDE.md rejects (#106).
package devicenetworkinfo

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
	name = "defender.device_network_info"
	// table is the advanced-hunting table, lowercased into its container.
	table = "devicenetworkinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_network_info"
)

// networkInfoStrFields is the DeviceNetworkInfo-specific string column set:
// the adapter's identity/type/status/tunnel state and its address lists.
// IPAddresses/ConnectedNetworks/DnsAddresses/DefaultGateways arrive as
// stringified-JSON strings on the wire (e.g. IPAddresses:
// `[{"IPAddress":"100.88.109.22",...}]`) — emitted verbatim as the string,
// never parsed (live-sampled 2026-07-18, #106).
var networkInfoStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkAdapterName, Src: "NetworkAdapterName"},
	{Attr: semconv.AttrNetworkAdapterType, Src: "NetworkAdapterType"},
	{Attr: semconv.AttrNetworkAdapterStatus, Src: "NetworkAdapterStatus"},
	{Attr: semconv.AttrTunnelType, Src: "TunnelType"},
	{Attr: semconv.AttrConnectedNetworks, Src: "ConnectedNetworks"},
	{Attr: semconv.AttrDnsAddresses, Src: "DnsAddresses"},
	{Attr: semconv.AttrDefaultGateways, Src: "DefaultGateways"},
	{Attr: semconv.AttrMacAddress, Src: "MacAddress"},
	{Attr: semconv.AttrIpAddresses, Src: "IPAddresses"},
	{Attr: semconv.AttrNetworkAdapterVendor, Src: "NetworkAdapterVendor"},
}

// networkInfoBoolFields is the boolean part: DHCP-enabled flags for each IP
// family.
var networkInfoBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIpv4Dhcp, Src: "IPv4Dhcp"},
	{Attr: semconv.AttrIpv6Dhcp, Src: "IPv6Dhcp"},
}

// mapRecord turns one raw DeviceNetworkInfo record into its OTLP log Event:
// unwrap properties, bind the timestamp to properties.Timestamp, and stamp
// the device identity (mapped directly — this snapshot table has no
// ActionType and no InitiatingProcess block, so defender.StampDeviceCommon
// does not apply) plus this table's adapter/address columns.
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
	defender.StampStrings(attrs, props, networkInfoStrFields)
	defender.StampBools(attrs, props, networkInfoBoolFields)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("%s network info: %s (%s)",
			defender.Str(props, "DeviceName"),
			defender.Str(props, "MacAddress"),
			defender.Str(props, "NetworkAdapterName")),
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
