package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecord is a real Get-QuarantineMessage row captured from the m7kni tenant
// as graph2otel-poller on 2026-07-23, over
// POST https://outlook.office365.com/adminapi/beta/{tid}/InvokeCommand.
//
// The "@data.type"/"@odata.type" sidecar keys are on the wire verbatim and are
// kept here deliberately: the mapper must ignore them rather than trip over
// them, and a hand-trimmed fixture would not prove that.
const liveRecord = `{
  "Identity": "86bab6ca-b175-4b84-d76c-08dee7cf55a8\\3423484b-11a9-58cc-cf4e-784af1dcf73c",
  "ReceivedTime@data.type": "System.DateTime",
  "ReceivedTime": "2026-07-22T08:58:01.4564204+00:00",
  "Organization": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "MessageId": "<7d08ba65-02de-4233-8220-e3be296ab368@az.centralus.microsoft.com>",
  "SenderAddress": "microsoft-noreply@microsoft.com",
  "RecipientAddress@odata.type": "#Collection(String)",
  "RecipientAddress": ["rob@m7kni.io"],
  "Subject": "Passkeys by default and retirement of Microsoft-provided SMS and voice authentication",
  "Size@data.type": "System.Int32",
  "Size": 170641,
  "Type": "Spam",
  "PolicyType": "HostedContentFilterPolicy",
  "PolicyName": "Standard Preset Security Policy1784144691483",
  "TagName": "DefaultFullAccessWithNotificationPolicy",
  "PermissionToBlockSender": false,
  "PermissionToDelete": true,
  "PermissionToPreview": true,
  "PermissionToRelease": true,
  "PermissionToRequestRelease": false,
  "PermissionToViewHeader": false,
  "PermissionToDownload": true,
  "PermissionToAllowSender": true,
  "Released": false,
  "ReleaseStatus": "NOTRELEASED",
  "SystemReleased": false,
  "RecipientCount@data.type": "System.Int32",
  "RecipientCount": 1,
  "QuarantineTypes": "Spam",
  "Expires@data.type": "System.DateTime",
  "Expires": "2026-08-21T08:58:01.4564204+00:00",
  "RecipientTag@odata.type": "#Collection(String)",
  "RecipientTag": ["Priority Account"],
  "DeletedForRecipients@odata.type": "#Collection(String)",
  "DeletedForRecipients": [],
  "QuarantinedUser@odata.type": "#Collection(String)",
  "QuarantinedUser": [],
  "ReleasedUser@odata.type": "#Collection(String)",
  "ReleasedUser": [],
  "Reported": false,
  "Direction": "Inbound",
  "CustomData": null,
  "EntityType": "Email",
  "SourceId": "",
  "TeamsConversationType": "",
  "ApprovalUPN": "",
  "ApprovalId": "",
  "MoveToQuarantineAdminActionTakenBy": "",
  "MoveToQuarantineApprovalId": "",
  "OverrideReasonIntValue@data.type": "System.Int32",
  "OverrideReasonIntValue": 0,
  "OverrideReason": "None",
  "ReleasedCount@data.type": "System.Int32",
  "ReleasedCount": 0,
  "ReleasedBy@odata.type": "#Collection(String)",
  "ReleasedBy": []
}`

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return m
}

// fakeEXO serves canned pages and records every Invoke call, so the tests can
// assert the request shape as well as the mapping. It needs no HTTP and no
// Exchange grants.
type fakeEXO struct {
	pages   [][]map[string]any
	err     error
	cmdlets []string
	params  []map[string]any
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	f.cmdlets = append(f.cmdlets, cmdlet)
	f.params = append(f.params, params)
	if f.err != nil {
		return nil, f.err
	}
	i := len(f.params) - 1
	if i >= len(f.pages) {
		return nil, nil
	}
	return f.pages[i], nil
}

func newCollector(t *testing.T, f *fakeEXO) *Collector {
	t.Helper()
	return New(collectors.EXODeps{
		Client:   f,
		TenantID: "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
		Logger:   slog.New(slog.DiscardHandler),
	})
}

// TestCollectRequestsHeldMessagesOnly pins the request shape. Every element of
// it is load-bearing and was measured live (2026-07-23, #233).
func TestCollectRequestsHeldMessagesOnly(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.cmdlets) != 1 {
		t.Fatalf("invoked %d times, want 1 (a short page must stop paging)", len(f.cmdlets))
	}
	if f.cmdlets[0] != cmdlet {
		t.Errorf("cmdlet = %q, want %q", f.cmdlets[0], cmdlet)
	}
	p := f.params[0]
	// ReleaseStatus=NOTRELEASED is the true queue-depth query: held only, so the
	// count needs no client-side filtering. Measured 2026-07-23 — RELEASED
	// returned the 2 released messages, NOTRELEASED returned 0, complementary.
	if got := p["ReleaseStatus"]; got != heldOnly {
		t.Errorf("ReleaseStatus = %v, want %q", got, heldOnly)
	}
	if got := p["Page"]; got != 1 {
		t.Errorf("Page = %v, want 1 (the API pages 1-indexed)", got)
	}
	// PageSize=0 returns HTTP 200 with ZERO rows rather than erroring
	// (live-measured), so a zero here is permanent silence that looks like an
	// empty quarantine. It must never be sent.
	if got, ok := p["PageSize"].(int); !ok || got <= 0 {
		t.Errorf("PageSize = %v, want a positive int — 0 is silently empty on this API", p["PageSize"])
	}
	// EntityType is denied to Security Reader (403, live-measured), so sending
	// it would break the collector for the least-privileged identity that can
	// otherwise read quarantine.
	if _, present := p["EntityType"]; present {
		t.Error("EntityType must not be sent — it 403s at Security Reader")
	}
}

func TestCollectEmitsBoundedGauge(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricHeld)
	if len(pts) != 1 {
		t.Fatalf("gauge points = %d, want 1", len(pts))
	}
	if pts[0].Value != 1 {
		t.Errorf("held count = %v, want 1", pts[0].Value)
	}
	want := map[string]string{
		semconv.AttrQuarantineType: "Spam",
		semconv.AttrDirection:      "Inbound",
		semconv.AttrEntityType:     "Email",
	}
	for k, v := range want {
		if got := pts[0].Attrs[k]; got != v {
			t.Errorf("gauge label %q = %q, want %q", k, got, v)
		}
	}
	// The gauge must carry ONLY bounded enum labels. A per-message field here
	// (subject, sender, recipient, network message id) is a series per message
	// and is the cardinality bug #112 names.
	for _, banned := range []string{
		semconv.AttrSubject, semconv.AttrSenderAddress,
		semconv.AttrNetworkMessageId, semconv.AttrRecipientAddress,
	} {
		if _, present := pts[0].Attrs[banned]; present {
			t.Errorf("gauge carries per-entity label %q — that is a series per message", banned)
		}
	}
}

func TestCollectEmitsPerMessageLogTwin(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d log records, want 1", len(logs))
	}
	l := logs[0]
	if l.EventName != eventName {
		t.Errorf("event name = %q, want %q", l.EventName, eventName)
	}
	want := map[string]string{
		// Identity is "<NetworkMessageId>\<recipient-guid>". The leading segment
		// is the join key onto defender.email, defender.email_post_delivery and
		// the m365.unified_audit quarantine records — all four transports key on
		// the same id, which is what makes quarantine one dataset.
		semconv.AttrNetworkMessageId:  "86bab6ca-b175-4b84-d76c-08dee7cf55a8",
		semconv.AttrInternetMessageId: "<7d08ba65-02de-4233-8220-e3be296ab368@az.centralus.microsoft.com>",
		semconv.AttrSenderAddress:     "microsoft-noreply@microsoft.com",
		semconv.AttrQuarantineType:    "Spam",
		semconv.AttrPolicyType:        "HostedContentFilterPolicy",
		semconv.AttrTagName:           "DefaultFullAccessWithNotificationPolicy",
		semconv.AttrReleaseStatus:     "NOTRELEASED",
		semconv.AttrDirection:         "Inbound",
		semconv.AttrEntityType:        "Email",
		semconv.AttrOverrideReason:    "None",
		semconv.AttrReceivedTime:      "2026-07-22T08:58:01.4564204+00:00",
		semconv.AttrExpires:           "2026-08-21T08:58:01.4564204+00:00",
	}
	for k, v := range want {
		if got := l.Attrs[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	if got := l.Attrs[semconv.AttrRecipientAddress]; got != "rob@m7kni.io" {
		t.Errorf("recipient_address = %q, want rob@m7kni.io", got)
	}
	if got := l.Attrs[semconv.AttrSize]; got != "170641" {
		t.Errorf("size = %q, want 170641", got)
	}
}

// TestLogTwinIsStampedAtPollTime pins the STATE-feed timestamp rule. The same
// held message is re-emitted every cycle for as long as it stays held, so
// stamping it with ReceivedTime would pile every repeat onto one instant and
// make "what was held at 14:00" unanswerable — the whole point of the twin.
// The wire time is preserved as the received_time attribute instead. Same
// reasoning as entra/risk's log twin.
func TestLogTwinIsStampedAtPollTime(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if ts := rec.LogRecords()[0].Timestamp; !ts.IsZero() {
		t.Errorf("timestamp = %s, want zero (poll time) — this is a state feed", ts)
	}
	if got := rec.LogRecords()[0].Attrs[semconv.AttrReceivedTime]; got == "" {
		t.Error("received_time must carry the wire time the record timestamp deliberately does not")
	}
}

// TestPermissionFlagsAreEmitted covers the #114 hard rule: per-entity data that
// is fetched and is not a metric label becomes a log twin, never nothing. False
// is an answer here, not an absence — permission_to_release=false is precisely
// the interesting case (the recipient cannot self-release), so the flags are
// emitted even when false.
func TestPermissionFlagsAreEmitted(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	attrs := rec.LogRecords()[0].Attrs
	for k, want := range map[string]string{
		semconv.AttrPermissionToRelease:        "true",
		semconv.AttrPermissionToRequestRelease: "false",
		semconv.AttrPermissionToBlockSender:    "false",
		semconv.AttrPermissionToDownload:       "true",
	} {
		if got := attrs[k]; got != want {
			t.Errorf("attr %q = %q, want %q", k, got, want)
		}
	}
}

// TestCollectPagesUntilShortPage drives two full pages then a short one.
func TestCollectPagesUntilShortPage(t *testing.T) {
	full := make([]map[string]any, pageSize)
	for i := range full {
		full[i] = decode(t, liveRecord)
	}
	f := &fakeEXO{pages: [][]map[string]any{full, {decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(f.params) != 2 {
		t.Fatalf("invoked %d times, want 2", len(f.params))
	}
	if got := f.params[1]["Page"]; got != 2 {
		t.Errorf("second call Page = %v, want 2", got)
	}
	if got := len(rec.LogRecords()); got != pageSize+1 {
		t.Errorf("emitted %d twins, want %d", got, pageSize+1)
	}
}

// TestEmptyQuarantineIsNotAnError is the steady state on a healthy tenant, and
// on m7kni it is the CURRENT state — NOTRELEASED returned 0 rows on 2026-07-23.
// An empty result must be a clean zero, not an error.
func TestEmptyQuarantineIsNotAnError(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect over an empty quarantine: %v", err)
	}
	if got := len(rec.LogRecords()); got != 0 {
		t.Errorf("emitted %d twins over an empty quarantine, want 0", got)
	}
	// An empty GaugeSnapshot produces no data points at all, which is correct
	// and deliberate: the instrument is observable, so a series that no longer
	// applies drops out of the export instead of ghosting forever under forced
	// cumulative temporality. Same shape as entra.risky_users on a healthy
	// tenant. Alert on the series being ABOVE a threshold, never on its absence.
	if pts := rec.MetricPoints(metricHeld); len(pts) != 0 {
		t.Errorf("gauge points = %d, want 0 — an empty snapshot drops stale series", len(pts))
	}
}

func TestCollectPropagatesClientError(t *testing.T) {
	sentinel := errors.New("403: missing directory role")
	f := &fakeEXO{err: sentinel}
	rec := telemetrytest.New()
	err := newCollector(t, f).Collect(context.Background(), rec.Emitter())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Collect error = %v, want it to wrap %v", err, sentinel)
	}
}

// TestRecordsWithoutIdentityAreStillCounted guards the gauge against a mapper
// bug: a record whose Identity is missing or malformed still occupies space in
// quarantine, so it must count even though its join key is unrecoverable.
func TestRecordsWithoutIdentityAreStillCounted(t *testing.T) {
	rec0 := decode(t, liveRecord)
	delete(rec0, "Identity")
	f := &fakeEXO{pages: [][]map[string]any{{rec0}}}
	rec := telemetrytest.New()
	if err := newCollector(t, f).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricHeld)
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Errorf("gauge = %v, want one point valued 1", pts)
	}
	if _, present := rec.LogRecords()[0].Attrs[semconv.AttrNetworkMessageId]; present {
		t.Error("network_message_id must be omitted when Identity is absent, not emitted empty")
	}
}

// TestRecordsAreStampedWithTheExchangeOnlineTransport guards the #141 stamp.
//
// This is not decoration: there is no ingest engine on the EXO path, and the
// Scheduler's baseline is telemetry.TransportGraph, so a collector that only
// declares IngestTransport() and forgets telemetry.WithTransport ships records
// labeled `graph` that came from Exchange Online. Declaring the transport and
// stamping it are two different things — TransportOf only feeds the admin page.
func TestRecordsAreStampedWithTheExchangeOnlineTransport(t *testing.T) {
	f := &fakeEXO{pages: [][]map[string]any{{decode(t, liveRecord)}}}
	rec := telemetrytest.New()
	c := newCollector(t, f)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := rec.LogRecords()[0].Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportExchangeOnline) {
		t.Errorf("%s = %q, want %q — the Scheduler baseline is graph, so this must be stamped here",
			semconv.AttrIngestTransport, got, telemetry.TransportExchangeOnline)
	}
	// The declared value (admin page) and the stamped value (records) must be
	// the same constant, or the status page lies about a running collector.
	if got := c.IngestTransport(); got != telemetry.TransportExchangeOnline {
		t.Errorf("IngestTransport() = %q, want %q", got, telemetry.TransportExchangeOnline)
	}
	// Metrics must NOT carry it — a transport label would change series identity
	// (#82). It is log-only by design.
	if _, present := rec.MetricPoints(metricHeld)[0].Attrs[semconv.AttrIngestTransport]; present {
		t.Error("ingest_transport must not be a metric label — it would change series identity")
	}
}
