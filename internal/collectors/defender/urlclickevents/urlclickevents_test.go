package urlclickevents

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

// liveRecord is a real UrlClickEvents envelope captured off the m7kni storage
// account as graph2otel-poller (cert on camden, 2026-07-19, #106): a Safe
// Links click-verdict on a SendGrid-relayed email link. ThreatTypes and
// DetectionMethods are JSON null on this record. UrlChain arrives as a plain
// STRING column holding pre-serialized JSON (verified against the live
// bytes — NOT a native JSON array like CloudAppEvents' array-shaped columns),
// so it is mapped as a StrField rather than through jsonStr.
const liveRecord = `{
  "time": "2026-07-19T17:04:32.3903696Z",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "operationName": "Publish",
  "category": "AdvancedHunting-UrlClickEvents",
  "_TimeReceivedBySvc": "2026-07-19T17:02:06.1314605Z",
  "properties": {
    "Timestamp": "2026-07-19T17:02:06.1314605Z",
    "Url": "https://u20216706.ct.sendgrid.net/ls/click?upn=u001.IQLfsj4kk-2BK7JhymNusRMkuuWNTB2xtKMTOzsaHXXCwjFnEY-2BNIgvSlyri5eb-2BkJ7yw2EarbDqOiOQWxFILr8-2BWox7jsMuQkGZRSIflvl9FAr-2FVrku-2BM2aGzDTA7DaoHzm3gh5G-2FEwRD8Gaw6MSTtY4vuM4k4AG-2FG5nJVHhyKtmSShAG1-2F22oJLaPLroeAN9q0XjKe8ZBbxEaewr0cl-2BvA-3D-3DQMAX_6N253QuG-2FdqJGM4e8Tk3j2CTH1Fmb0gDIqX-2B9YP-2F4LS6AM3exaOYuJw-2FPzwkSJ0Z4zu1Uhf8mhm8OWLftT-2FwJ3HphCPVm-2Frv5XJopCngBG7fXr4jWE2pSHpUxW-2FL1YevnCD5r5ldS4ID2Xc-2BH3kFCu8HIpDz7Y-2F5pfprcj0xfhu8uOOcw4NZDM37zbK9N4KObAg5jFbhN9dwvUU8WyCk0qoVrGwt4BA78SfD3auGMnuCRqY5A6swxIQrh94NMe0TdIXctndqDAqYCQO-2FfQkhxExxlRtuyro-2Bc9RWectG4vh0oKmJM9lVwW47H8VXNpcychZ11DMz2Q-2BIzpDKp2nsvvi6RpbMl3FwDcdf8lsDYGTQn7aYNy00PpQdW8Ho3xmWJ6KBA4yLRpvOkuf3rp61lg-3D-3D",
    "ActionType": "ClickAllowed",
    "AccountUpn": "rob@m7kni.io",
    "Workload": "Email",
    "NetworkMessageId": "53913957-73ec-4a39-d4ee-08dee5b715c8",
    "ThreatTypes": null,
    "DetectionMethods": null,
    "IPAddress": "2001:8b0:1f05::106c",
    "IsClickedThrough": false,
    "UrlChain": "[\"https://u20216706.ct.sendgrid.net/ls/click?upn=u001.IQLfsj4kk-2BK7JhymNusRMkuuWNTB2xtKMTOzsaHXXCwjFnEY-2BNIgvSlyri5eb-2BkJ7yw2EarbDqOiOQWxFILr8-2BWox7jsMuQkGZRSIflvl9FAr-2FVrku-2BM2aGzDTA7DaoHzm3gh5G-2FEwRD8Gaw6MSTtY4vuM4k4AG-2FG5nJVHhyKtmSShAG1-2F22oJLaPLroeAN9q0XjKe8ZBbxEaewr0cl-2BvA-3D-3DQMAX_6N253QuG-2FdqJGM4e8Tk3j2CTH1Fmb0gDIqX-2B9YP-2F4LS6AM3exaOYuJw-2FPzwkSJ0Z4zu1Uhf8mhm8OWLftT-2FwJ3HphCPVm-2Frv5XJopCngBG7fXr4jWE2pSHpUxW-2FL1YevnCD5r5ldS4ID2Xc-2BH3kFCu8HIpDz7Y-2F5pfprcj0xfhu8uOOcw4NZDM37zbK9N4KObAg5jFbhN9dwvUU8WyCk0qoVrGwt4BA78SfD3auGMnuCRqY5A6swxIQrh94NMe0TdIXctndqDAqYCQO-2FfQkhxExxlRtuyro-2Bc9RWectG4vh0oKmJM9lVwW47H8VXNpcychZ11DMz2Q-2BIzpDKp2nsvvi6RpbMl3FwDcdf8lsDYGTQn7aYNy00PpQdW8Ho3xmWJ6KBA4yLRpvOkuf3rp61lg-3D-3D\", \"https://platform.openai.com/invites/accept?token=invite-D3FdJeHzRWpNx3cVQVlwBTqi3b7b1960fb6823e5964bb363cf097f25f743bed67f9253e1db93c0fb3913e956\"]",
    "ReportId": "e2cf1de7-98af-47b5-4a2d-08dee5b77665",
    "AppName": "Mail",
    "AppVersion": "0.0.0000",
    "SourceId": "53913957-73ec-4a39-d4ee-08dee5b715c8"
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

func TestMapRecordEmitsUrlClickEvent(t *testing.T) {
	ev, ok := mapRecord(decode(t, liveRecord))
	if !ok {
		t.Fatal("mapRecord dropped a valid record")
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}

	// Timestamp bound to properties.Timestamp, as an instant — NOT the envelope
	// `time` or `_TimeReceivedBySvc`.
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-19T17:02:06.1314605Z")
	if !ev.Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %v, want %v (bound to properties.Timestamp)", ev.Timestamp, wantTS)
	}

	want := map[string]string{
		semconv.AttrAccountUpn:       "rob@m7kni.io",
		semconv.AttrActionType:       "ClickAllowed",
		semconv.AttrAppName:          "Mail",
		semconv.AttrAppVersion:       "0.0.0000",
		semconv.AttrIpAddress:        "2001:8b0:1f05::106c",
		semconv.AttrNetworkMessageId: "53913957-73ec-4a39-d4ee-08dee5b715c8",
		semconv.AttrReportId:         "e2cf1de7-98af-47b5-4a2d-08dee5b77665",
		semconv.AttrSourceId:         "53913957-73ec-4a39-d4ee-08dee5b715c8",
		semconv.AttrWorkload:         "Email",
	}
	for k, v := range want {
		got, _ := ev.Attrs[k].(string)
		if got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	if got, _ := ev.Attrs[semconv.AttrUrl].(string); !strings.HasPrefix(got, "https://u20216706.ct.sendgrid.net/ls/click") {
		t.Errorf("url = %q, want it to start with the sendgrid click-tracking link", got)
	}

	// Bool field is stamped as the string "false"/"true".
	if got, _ := ev.Attrs[semconv.AttrIsClickedThrough].(string); got != "false" {
		t.Errorf("is_clicked_through = %q, want \"false\"", got)
	}

	// UrlChain is a plain string column on the wire (pre-serialized JSON, not a
	// native array) — mapped verbatim via defender.Str, not re-marshaled.
	chain, _ := ev.Attrs[semconv.AttrUrlChain].(string)
	if chain == "" {
		t.Fatal("url_chain should be present and non-empty")
	}
	if !strings.Contains(chain, "platform.openai.com/invites/accept") {
		t.Errorf("url_chain = %q, want it to contain the second hop", chain)
	}
	var chainList []string
	if err := json.Unmarshal([]byte(chain), &chainList); err != nil || len(chainList) != 2 {
		t.Errorf("url_chain %q should decode as a 2-element JSON array, err=%v", chain, err)
	}

	// Null columns are omitted, never emitted as empty/zero values.
	for _, k := range []string{semconv.AttrDetectionMethods, semconv.AttrThreatTypes} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q should be omitted (null source), got %v", k, ev.Attrs[k])
		}
	}
}

func TestMapRecordDropsMalformed(t *testing.T) {
	// No properties → dropped.
	if _, ok := mapRecord(map[string]any{"time": "2026-07-19T17:04:32Z"}); ok {
		t.Error("record with no properties should be dropped")
	}
	// Unparseable Timestamp → dropped, never mis-dated (no fallback to envelope time).
	if _, ok := mapRecord(decode(t, `{"properties":{"ActionType":"ClickAllowed","Timestamp":"not-a-time"}}`)); ok {
		t.Error("record with unparseable Timestamp should be dropped")
	}
	// Missing Timestamp → dropped.
	if _, ok := mapRecord(decode(t, `{"properties":{"ActionType":"ClickAllowed"}}`)); ok {
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

// TestCollectorEmitsLiveRecordEndToEnd drives the whole collector over the
// pinned live record — JSON Lines with the CRLF terminators Azure writes —
// and asserts what reaches the emitter. It is also what makes the signals
// golden substantive (#164): the golden captures the attributes THIS drives
// into the Recorder.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=19/h=17/m=04/PT1H.json",
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
	wantTS, _ := time.Parse(time.RFC3339Nano, "2026-07-19T17:02:06.1314605Z")
	if !logs[0].Timestamp.Equal(wantTS) {
		t.Errorf("timestamp = %s, want %s", logs[0].Timestamp, wantTS)
	}
	if got := logs[0].Attrs[semconv.AttrActionType]; got != "ClickAllowed" {
		t.Errorf("action_type attr = %q, want ClickAllowed", got)
	}

	// Cursor persisted: a second tick over the unchanged blob emits nothing new.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1", got)
	}
}
