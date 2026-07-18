package devicefilecert

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real DeviceFileCertificateInfo envelope captured off the
// m7kni storage account as graph2otel-poller (cert on mbp14, 2026-07-18,
// #106). It is a signed, trusted, non-Microsoft-rooted certificate — the full
// shape a mapper must handle.
const liveRecord = `{
 "time": "2026-07-18T17:02:32.3990663Z",
 "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceFileCertificateInfo",
 "_TimeReceivedBySvc": "2026-07-18T17:00:39.4506035Z",
 "properties": {
  "DeviceId": "3db402e9217f30248e26406c0a48094b00a0062e",
  "DeviceName": "mbp14",
  "ReportId": 45720,
  "SHA1": "ccb3dbb0d5ddc219e90706834fd59c95adc5946e",
  "IsSigned": true,
  "IsRootSignerMicrosoft": false,
  "IsTrusted": true,
  "Signer": "Developer ID Application: Google LLC (EQHXZ8M8AV)",
  "SignerHash": "765bb3620a0f7a33500da39b20122b1cec41140f",
  "Issuer": "Developer ID Certification Authority",
  "IssuerHash": "3b166c3b7dc4b751c9fe2afab9135641e388e186",
  "SignatureType": "Embedded",
  "CertificateCreationTime": "2022-02-08T22:32:55Z",
  "CertificateExpirationTime": "2027-02-01T22:12:15Z",
  "CertificateCountersignatureTime": null,
  "CrlDistributionPointUrls": "[]",
  "CertificateSerialNumber": "0b4a9ab6ddcdb7b2",
  "Timestamp": "2026-07-18T17:00:30.754549Z",
  "MachineGroup": "main"
 },
 "Tenant": "DefaultTenant"
}`

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec
}

func TestMapRecordEmitsCertificateAndDeviceIdentity(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T17:00:30.754549Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrDeviceId:     "3db402e9217f30248e26406c0a48094b00a0062e",
		semconv.AttrDeviceName:   "mbp14",
		semconv.AttrMachineGroup: "main",
		semconv.AttrSha1:         "ccb3dbb0d5ddc219e90706834fd59c95adc5946e",
		semconv.AttrSigner:       "Developer ID Application: Google LLC (EQHXZ8M8AV)",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}

	// Numeric ReportId lands as a number, not a string.
	if rid, ok := ev.Attrs[semconv.AttrReportId].(float64); !ok || rid != 45720 {
		t.Errorf("report_id = %v, want float64(45720)", ev.Attrs[semconv.AttrReportId])
	}

	// The trust-flag bools are present and stamped as strings.
	if got, _ := ev.Attrs[semconv.AttrIsSigned].(string); got != "true" {
		t.Errorf("is_signed = %q, want \"true\"", got)
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-18T17:02:32Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"DeviceId":"d","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"DeviceId":"d"}}`)); ok {
		t.Error("record with no Timestamp should be dropped")
	}
}

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector runs end-to-end without Azure.
type staticSource struct {
	name string
	data []byte
}

func (s *staticSource) List(_ context.Context, _, prefix string) ([]blobpipeline.BlobInfo, error) {
	if !strings.HasPrefix(s.name, prefix) {
		return nil, nil
	}
	return []blobpipeline.BlobInfo{{Name: s.name, Size: int64(len(s.data))}}, nil
}

func (s *staticSource) ReadRange(_ context.Context, _, _ string, offset, count int64) ([]byte, error) {
	end := min(offset+count, int64(len(s.data)))
	if offset >= end {
		return nil, nil
	}
	return s.data[offset:end], nil
}

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		t.Fatalf("compacting the pinned record: %v", err)
	}
	return buf.String()
}

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the pinned
// live record — JSON Lines with the CRLF terminators Azure writes — and asserts
// what reaches the emitter. It is also what makes the signals golden substantive
// (#164): the golden captures the attributes THIS drives into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=18/h=17/m=00/PT1H.json",
		data: []byte(compactJSON(t, liveRecord) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newBlobCollector(collectors.BlobDeps{
		TenantID: tenant,
		Source:   src,
		Store:    checkpoint.NewStore(t.TempDir()),
		Logger:   slog.New(slog.DiscardHandler),
	})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1 — check the tenantId= listing prefix", len(logs))
	}
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-18T17:00:30.754549Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrSha1]; got != "ccb3dbb0d5ddc219e90706834fd59c95adc5946e" {
		t.Errorf("sha1 attr = %q, want the pinned SHA1", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
