// Package devicefilecert is the Defender advanced-hunting
// DeviceFileCertificateInfo blob collector (#106): one OTLP log per
// certificate Defender for Endpoint observed signing a file on a device, read
// from the shared Azure Storage account.
//
// DeviceFileCertificateInfo is a SNAPSHOT table, unlike the Device* event
// tables this package's siblings map: it carries no ActionType and no
// InitiatingProcess block, only the device identity and the certificate's own
// fields (signer, issuer, hashes, validity window, trust flags). Live-sampled
// 2026-07-18 (#106).
package devicefilecert

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
	name = "defender.device_file_certificate"
	// table is the advanced-hunting table, lowercased into its container.
	table = "devicefilecertificateinfo"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.device_file_certificate"
)

// certStrFields is the table-specific certificate column set: the signed
// file's hash, the signer/issuer chain, the signature type, the certificate's
// validity window and serial number, and its CRL distribution points.
var certStrFields = []defender.StrField{
	{Attr: semconv.AttrSha1, Src: "SHA1"},
	{Attr: semconv.AttrIssuer, Src: "Issuer"},
	{Attr: semconv.AttrIssuerHash, Src: "IssuerHash"},
	{Attr: semconv.AttrSigner, Src: "Signer"},
	{Attr: semconv.AttrSignerHash, Src: "SignerHash"},
	{Attr: semconv.AttrSignatureType, Src: "SignatureType"},
	{Attr: semconv.AttrCertificateSerialNumber, Src: "CertificateSerialNumber"},
	{Attr: semconv.AttrCertificateCreationTime, Src: "CertificateCreationTime"},
	{Attr: semconv.AttrCertificateExpirationTime, Src: "CertificateExpirationTime"},
	{Attr: semconv.AttrCertificateCountersignatureTime, Src: "CertificateCountersignatureTime"},
	{Attr: semconv.AttrCrlDistributionPointUrls, Src: "CrlDistributionPointUrls"},
}

// certBoolFields is the table-specific trust-flag set.
var certBoolFields = []defender.BoolField{
	{Attr: semconv.AttrIsSigned, Src: "IsSigned"},
	{Attr: semconv.AttrIsTrusted, Src: "IsTrusted"},
	{Attr: semconv.AttrIsRootSignerMicrosoft, Src: "IsRootSignerMicrosoft"},
}

// mapRecord turns one raw DeviceFileCertificateInfo record into its OTLP log
// Event: unwrap properties, bind the timestamp to properties.Timestamp, and
// stamp the device identity, the ReportId, and this table's certificate
// columns. Unlike the Device* event tables, there is no ActionType and no
// InitiatingProcess block to stamp — this is a snapshot, not an event stream.
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
	telemetry.SetNum(attrs, semconv.AttrReportId, props, "ReportId")
	defender.StampStrings(attrs, props, certStrFields)
	defender.StampBools(attrs, props, certBoolFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("cert %s on %s (signer=%s)", defender.Str(props, "SHA1"), defender.Str(props, "DeviceName"), defender.Str(props, "Signer")),
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
