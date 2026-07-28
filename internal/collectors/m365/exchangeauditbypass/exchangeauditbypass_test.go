package exchangeauditbypass

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRecordHealthy is a real Get-MailboxAuditBypassAssociation record
// captured from the m7kni tenant as graph2otel-poller on 2026-07-28 over the
// Exchange Online admin API. All 242 rows returned that day had
// AuditBypassEnabled=false; this is one of them, trimmed of the
// "<Name>@data.type"/"@odata.type" sidecars EXCEPT one kept verbatim so the
// mapper proves it ignores them by exact-name reads.
const liveRecordHealthy = `{
  "ObjectId": "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}",
  "AuditBypassEnabled": false,
  "Name": "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}",
  "Identity": "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}",
  "Id": "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}",
  "IsValid": true,
  "DistinguishedName": "CN=SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c},OU=m7knio.onmicrosoft.com,OU=Microsoft Exchange Hosted Organizations,DC=gbrp265a018,DC=prod,DC=outlook,DC=com",
  "ObjectClass@odata.type": "#Collection(String)",
  "ObjectClass": ["top", "person", "organizationalPerson", "user"],
  "WhenChangedUTC@data.type": "System.DateTime",
  "WhenChangedUTC": "2026-07-15T16:40:06.0000000Z",
  "ExchangeObjectId@data.type": "System.Guid",
  "ExchangeObjectId": "01176116-2ff9-46a7-ba2a-ce67be8b4d8f",
  "OrganizationId": "gbrp265a018.prod.outlook.com/Microsoft Exchange Hosted Organizations/m7knio.onmicrosoft.com - gbrp265a018.prod.outlook.com/ConfigurationUnits/m7knio.onmicrosoft.com/Configuration",
  "Guid@data.type": "System.Guid",
  "Guid": "01176116-2ff9-46a7-ba2a-ce67be8b4d8f"
}`

// bypassedFixture is a synthesized row (no such row exists in the live
// capture — the tenant reads all-clear) with AuditBypassEnabled=true, to
// exercise the finding branch.
const bypassedFixture = `{
  "ObjectId": "user1@m7kni.onmicrosoft.com",
  "AuditBypassEnabled": true,
  "Name": "Test Bypassed Mailbox",
  "Identity": "user1@m7kni.onmicrosoft.com",
  "Id": "user1@m7kni.onmicrosoft.com",
  "IsValid": true,
  "DistinguishedName": "CN=Test User,OU=m7knio.onmicrosoft.com,DC=gbrp265a018,DC=prod,DC=outlook,DC=com",
  "ObjectClass": ["top", "person", "organizationalPerson", "user"],
  "WhenChangedUTC": "2026-07-20T09:00:00.0000000Z",
  "ExchangeObjectId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "OrganizationId": "gbrp265a018.prod.outlook.com/Microsoft Exchange Hosted Organizations/m7knio.onmicrosoft.com",
  "Guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}`

// indeterminateFixture has the AuditBypassEnabled key entirely absent from
// the wire response — distinct from the key being present and false.
const indeterminateFixture = `{
  "ObjectId": "Asc-2X1-weird-system-object",
  "Name": "Asc-2X1-weird-system-object",
  "Identity": "Asc-2X1-weird-system-object",
  "Id": "Asc-2X1-weird-system-object",
  "IsValid": true,
  "Guid": "11111111-2222-3333-4444-555555555555"
}`

// fakeEXO returns canned records for one cmdlet.
type fakeEXO struct {
	recs []map[string]any
	err  error
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
}

func recordsFrom(t *testing.T, docs ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func collect(t *testing.T, exo *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func TestCollect_HealthyTenant_NoBypassNoTwins(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: recordsFrom(t, liveRecordHealthy, liveRecordHealthy)})

	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("healthy tenant should emit no twins, got %d", len(logs))
	}

	examined := gaugeValue(t, rec, metricExamined)
	if examined != 2 {
		t.Errorf("examined = %v, want 2", examined)
	}
	bypassed := gaugeValue(t, rec, metricBypassed)
	if bypassed != 0 {
		t.Errorf("bypassed = %v, want 0", bypassed)
	}
}

func TestCollect_BypassedMailbox_EmitsTwinAndGauge(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: recordsFrom(t, liveRecordHealthy, bypassedFixture)})

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want exactly 1 twin (only the bypassed row), got %d", len(logs))
	}
	twin := logs[0]
	if twin.EventName != eventName {
		t.Errorf("event name = %q, want %q", twin.EventName, eventName)
	}
	if twin.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN", twin.SeverityText)
	}
	a := twin.Attrs
	if a[semconv.AttrName] != "Test Bypassed Mailbox" {
		t.Errorf("name attr = %q", a[semconv.AttrName])
	}
	if a[semconv.AttrIdentity] != "user1@m7kni.onmicrosoft.com" {
		t.Errorf("identity attr = %q", a[semconv.AttrIdentity])
	}
	if a[semconv.AttrGuid] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("guid attr = %q", a[semconv.AttrGuid])
	}
	if a[semconv.AttrWhenChangedUtc] == "" {
		t.Error("when_changed_utc should be present")
	}
	// The mailbox identity must never be a metric label (#112) — only the
	// bounded gauges below, neither of which may carry per-entity attrs.
	for _, p := range rec.MetricPoints(metricBypassed) {
		if len(p.Attrs) != 0 {
			t.Errorf("metricBypassed point carries attrs %v, want none (no per-entity label)", p.Attrs)
		}
	}

	examined := gaugeValue(t, rec, metricExamined)
	if examined != 2 {
		t.Errorf("examined = %v, want 2", examined)
	}
	bypassed := gaugeValue(t, rec, metricBypassed)
	if bypassed != 1 {
		t.Errorf("bypassed = %v, want 1", bypassed)
	}
}

// TestCollect_IndeterminateKeyAbsent proves the absent-key branch is neither
// counted as bypassed nor as healthy in the two gauges, and emits no twin
// (only ENABLED rows get a twin).
func TestCollect_IndeterminateKeyAbsent(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: recordsFrom(t, liveRecordHealthy, indeterminateFixture)})

	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("indeterminate row should not emit a twin, got %d", len(logs))
	}
	// Only the one row with the key present and false is "examined".
	examined := gaugeValue(t, rec, metricExamined)
	if examined != 1 {
		t.Errorf("examined = %v, want 1 (indeterminate row excluded)", examined)
	}
	bypassed := gaugeValue(t, rec, metricBypassed)
	if bypassed != 0 {
		t.Errorf("bypassed = %v, want 0", bypassed)
	}
}

func TestCollect_EmptyResult_NoEmit(t *testing.T) {
	rec := collect(t, &fakeEXO{recs: nil})
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("empty result should emit no twins, got %d", len(logs))
	}
	if pts := rec.MetricPoints(metricExamined); len(pts) != 0 {
		t.Errorf("empty result should emit no examined gauge, got %d points", len(pts))
	}
	if pts := rec.MetricPoints(metricBypassed); len(pts) != 0 {
		t.Errorf("empty result should emit no bypassed gauge, got %d points", len(pts))
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("want error when cmdlet fails")
	}
}

func TestCollect_Outcomes(t *testing.T) {
	outcomes := recordoutcome.NewRecorder()
	c := New(collectors.EXODeps{Client: &fakeEXO{recs: recordsFrom(t, liveRecordHealthy, bypassedFixture)}})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := outcomes.Snapshot().Summarize(nil, false)
	want := recordoutcome.Counts{Fetched: 2, Mapped: 1, Emitted: 1, Filtered: 1}
	if got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

func gaugeValue(t *testing.T, rec *telemetrytest.Recorder, metric string) float64 {
	t.Helper()
	pts := rec.MetricPoints(metric)
	if len(pts) != 1 {
		t.Fatalf("want exactly 1 point for %s, got %d", metric, len(pts))
	}
	return pts[0].Value
}
