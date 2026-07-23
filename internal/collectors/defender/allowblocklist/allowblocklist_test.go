package allowblocklist

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// The fixtures below are VERBATIM Get-TenantAllowBlockListItems /
// Get-TenantAllowBlockListSpoofItems records captured from the m7kni tenant as
// graph2otel-poller on 2026-07-23 over the Exchange Online admin API. Three
// distinct expiry shapes are represented on purpose, because they are what the
// severity rule turns on:
//
//   - liveSenderAllow: ExpirationDate null, RemoveAfter 45 -> bounded
//   - liveSenderBlock: ExpirationDate set, RemoveAfter null -> bounded
//   - liveIPAllow:     ExpirationDate null AND RemoveAfter null -> STANDING HOLE
//
// The malformed duplicate key "LastUsedDate(DateTime])" and the
// "<Name>@data.type" sidecars are on the wire verbatim and kept, so the mapper
// proves it reads by exact name and ignores them.
const liveSenderAllow = `{
  "LastUsedDate": null,
  "Error": null,
  "Identity": "RgAAAADVB5oW8Yh7SI7eE-8qL0PuBwAcKT5U0UQzSbJIId4TKZeIAABLFSjwAAAcKT5U0UQzSbJIId4TKZeIAABLFSzaAAAA0",
  "Value": "rob-knight.net",
  "Action": "Allow",
  "Notes": "allow mee",
  "SubmissionID": "Non-Submission",
  "ListSubType": "Tenant",
  "SysManaged": false,
  "LastModifiedDateTime@data.type": "System.DateTime",
  "LastModifiedDateTime": "2026-07-23T21:56:57.2320505Z",
  "ExpirationDate": null,
  "ObjectState": "Unchanged",
  "EntryValueHash": "R2aMQXCEq5/4ooUj6ArHZDbIAXAa6/Lg7k1Y7CTv8cI=",
  "ModifiedBy": "rob@m7kni.io",
  "LastUsedDate(DateTime])": null,
  "RemoveAfter@data.type": "System.Int32",
  "RemoveAfter": 45,
  "CreatedDateTime@data.type": "System.DateTime",
  "CreatedDateTime": "2026-07-23T21:56:57.3219519Z"
}`

const liveSenderAllow2 = `{
  "LastUsedDate": null, "Error": null,
  "Identity": "RgAAAADVB5oW8Yh7SI7eE-8qL0PuBwAcKT5U0UQzSbJIId4TKZeIAABLFSzZAAAA0",
  "Value": "rob-knight.com", "Action": "Allow", "Notes": "allow mee",
  "SubmissionID": "Non-Submission", "ListSubType": "Tenant", "SysManaged": false,
  "LastModifiedDateTime": "2026-07-23T21:56:57.2320352Z",
  "ExpirationDate": null, "ObjectState": "Unchanged",
  "EntryValueHash": "MMa//9f4d1eZiYPyaSq7C10bM9xC8hUqnS3fZ8F0nHY=",
  "ModifiedBy": "rob@m7kni.io", "LastUsedDate(DateTime])": null,
  "RemoveAfter@data.type": "System.Int32", "RemoveAfter": 45,
  "CreatedDateTime": "2026-07-23T21:56:57.2763203Z"
}`

const liveSenderBlock = `{
  "LastUsedDate": null, "Error": null,
  "Identity": "RgAAAADVB5oW8Yh7SI7eE-8qL0PuBwAcKT5U0UQzSbJIId4TKZeIAABLFSzYAAAA0",
  "Value": "fabrikam.com", "Action": "Block",
  "Notes": "optinal note is added hhehehhrrhhrheeeeee",
  "SubmissionID": "Non-Submission", "ListSubType": "Tenant", "SysManaged": false,
  "LastModifiedDateTime": "2026-07-23T21:56:18.9397206Z",
  "ExpirationDate@data.type": "System.DateTime",
  "ExpirationDate": "2026-07-23T23:00:00.0000000Z",
  "ObjectState": "Unchanged",
  "EntryValueHash": "E32FfJFjdk/d8vP6mPTgGeqr4xJHeJ7ZGXx10AJZwRs=",
  "ModifiedBy": "rob@m7kni.io", "LastUsedDate(DateTime])": null,
  "RemoveAfter": null,
  "CreatedDateTime": "2026-07-23T21:56:19.1745333Z"
}`

const liveSenderBlock2 = `{
  "LastUsedDate": null, "Error": null,
  "Identity": "RgAAAADVB5oW8Yh7SI7eE-8qL0PuBwAcKT5U0UQzSbJIId4TKZeIAABLFSzXAAAA0",
  "Value": "user@contoso.com", "Action": "Block",
  "Notes": "optinal note is added hhehehhrrhhrheeeeee",
  "SubmissionID": "Non-Submission", "ListSubType": "Tenant", "SysManaged": false,
  "LastModifiedDateTime": "2026-07-23T21:56:18.9393934Z",
  "ExpirationDate@data.type": "System.DateTime",
  "ExpirationDate": "2026-07-23T23:00:00.0000000Z",
  "ObjectState": "Unchanged",
  "EntryValueHash": "0k3+rSU1mwxWLIoCpqDm243kqLI11W4SKnWo4fLkc+4=",
  "ModifiedBy": "rob@m7kni.io", "LastUsedDate(DateTime])": null,
  "RemoveAfter": null,
  "CreatedDateTime": "2026-07-23T21:56:18.9953245Z"
}`

// liveIPAllow is the standing hole: an Allow with NO ExpirationDate and NO
// RemoveAfter. Nothing ever removes it.
const liveIPAllow = `{
  "LastUsedDate": null, "Error": null,
  "Identity": "RgAAAADVB5oW8Yh7SI7eE-8qL0PuBwAcKT5U0UQzSbJIId4TKZeIAABLFTK1AAAA0",
  "Value": "2001:8b0:1f05::106c", "Action": "Allow", "Notes": "home ipv6",
  "SubmissionID": "Non-Submission", "ListSubType": "Tenant", "SysManaged": false,
  "LastModifiedDateTime": "2026-07-23T21:58:57.7587412Z",
  "ExpirationDate": null, "ObjectState": "Unchanged",
  "EntryValueHash": "8xYSQBzqMxHqg7WmFja/4J1++saqK0q8R/3/XvoHRe8=",
  "ModifiedBy": "rob@m7kni.io", "LastUsedDate(DateTime])": null,
  "RemoveAfter": null,
  "CreatedDateTime": "2026-07-23T21:58:57.8079170Z"
}`

// liveSpoof is the whole record: spoof items carry a completely different, much
// smaller field set with NO expiry mechanism at all.
const liveSpoof = `{
  "Identity": "28b35e75-baa4-9df9-51a2-2f904f17f77c",
  "SpoofedUser": "user@contoso.com",
  "SendingInfrastructure": "fabrikam.com",
  "SpoofType": "External",
  "Action": "Block"
}`

// fixedNow is pinned so the expiry buckets are deterministic. The live Block
// entries expire 2026-07-23T23:00Z, ~1h after this instant.
var fixedNow = time.Date(2026, 7, 23, 22, 0, 0, 0, time.UTC)

// fakeEXO dispatches canned records by cmdlet and ListType parameter.
type fakeEXO struct {
	byListType map[string][]map[string]any
	spoof      []map[string]any
	err        error
	calls      []string
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	if cmdlet == spoofCmdlet {
		f.calls = append(f.calls, cmdlet)
		return f.spoof, nil
	}
	lt, _ := params[paramListType].(string)
	f.calls = append(f.calls, cmdlet+":"+lt)
	return f.byListType[lt], nil
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

// liveTenant is the m7kni tenant exactly as captured: 4 sender entries, 1 IP
// entry, empty Url and FileHash lists, 1 spoof entry.
func liveTenant(t *testing.T) *fakeEXO {
	t.Helper()
	return &fakeEXO{
		byListType: map[string][]map[string]any{
			listTypeSender: recordsFrom(t, liveSenderAllow, liveSenderAllow2, liveSenderBlock, liveSenderBlock2),
			listTypeIP:     recordsFrom(t, liveIPAllow),
			listTypeURL:    nil,
			listTypeFile:   nil,
		},
		spoof: recordsFrom(t, liveSpoof),
	}
}

func collect(t *testing.T, exo *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	c.now = func() time.Time { return fixedNow }
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// gaugeBy indexes a metric's points by the joined values of the given attr keys.
func gaugeBy(rec *telemetrytest.Recorder, metric string, keys ...string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		k := ""
		for i, key := range keys {
			if i > 0 {
				k += "/"
			}
			k += p.Attrs[key]
		}
		out[k] = p.Value
	}
	return out
}

func TestCollect_QueriesEveryListTypeAndSpoof(t *testing.T) {
	exo := liveTenant(t)
	collect(t, exo)
	want := []string{
		itemsCmdlet + ":" + listTypeSender,
		itemsCmdlet + ":" + listTypeURL,
		itemsCmdlet + ":" + listTypeFile,
		itemsCmdlet + ":" + listTypeIP,
		spoofCmdlet,
	}
	if len(exo.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", exo.calls, want)
	}
	for i, w := range want {
		if exo.calls[i] != w {
			t.Errorf("call %d = %q, want %q", i, exo.calls[i], w)
		}
	}
}

func TestCollect_EntriesGauge(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricEntries, semconv.AttrListType, semconv.AttrAction, semconv.AttrListSubtype)

	// Observed on the wire.
	if got[listTypeSender+"/"+actionAllow+"/"+subtypeTenant] != 2 {
		t.Errorf("Sender/Allow/Tenant = %v, want 2", got[listTypeSender+"/"+actionAllow+"/"+subtypeTenant])
	}
	if got[listTypeSender+"/"+actionBlock+"/"+subtypeTenant] != 2 {
		t.Errorf("Sender/Block/Tenant = %v, want 2", got[listTypeSender+"/"+actionBlock+"/"+subtypeTenant])
	}
	if got[listTypeIP+"/"+actionAllow+"/"+subtypeTenant] != 1 {
		t.Errorf("IP/Allow/Tenant = %v, want 1", got[listTypeIP+"/"+actionAllow+"/"+subtypeTenant])
	}
	// Seeded zeros: an empty list must still report a series, so "an allow
	// entry appeared" is a change from 0 rather than a series springing into
	// existence.
	if v, ok := got[listTypeURL+"/"+actionAllow+"/"+subtypeTenant]; !ok || v != 0 {
		t.Errorf("Url/Allow/Tenant = %v (present=%t), want a seeded 0", v, ok)
	}
	if v, ok := got[listTypeFile+"/"+actionBlock+"/"+subtypeTenant]; !ok || v != 0 {
		t.Errorf("FileHash/Block/Tenant = %v (present=%t), want a seeded 0", v, ok)
	}
	// Bounded: 4 list types x 2 actions x the observed subtypes only.
	if len(got) != 8 {
		t.Errorf("entries series = %d, want 8 (4 list types x 2 actions x 1 observed subtype)", len(got))
	}
}

// TestCollect_NonExpiringAllowGauge is the headline signal: a permanent hole
// past mail security. The two Sender allows are bounded by RemoveAfter, so only
// the IP allow counts.
func TestCollect_NonExpiringAllowGauge(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricNonExpiringAllow, semconv.AttrListType)

	if got[listTypeIP] != 1 {
		t.Errorf("IP non-expiring allows = %v, want 1", got[listTypeIP])
	}
	if got[listTypeSender] != 0 {
		t.Errorf("Sender non-expiring allows = %v, want 0 (RemoveAfter=45 bounds them)", got[listTypeSender])
	}
	if len(got) != 4 {
		t.Errorf("non_expiring_allow series = %d, want one per list type", len(got))
	}
}

func TestCollect_ExpiringSoonGauge(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricExpiringSoon, semconv.AttrListType, semconv.AttrAction)

	// Both Block entries expire ~1h from fixedNow.
	if got[listTypeSender+"/"+actionBlock] != 2 {
		t.Errorf("Sender/Block expiring soon = %v, want 2", got[listTypeSender+"/"+actionBlock])
	}
	// A never-expiring entry is NOT "expiring soon" — it is the opposite.
	if got[listTypeIP+"/"+actionAllow] != 0 {
		t.Errorf("IP/Allow expiring soon = %v, want 0", got[listTypeIP+"/"+actionAllow])
	}
	if len(got) != 8 {
		t.Errorf("expiring_soon series = %d, want 4 list types x 2 actions", len(got))
	}
}

func TestCollect_SpoofGauge(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricSpoofEntries, semconv.AttrSpoofType, semconv.AttrAction)

	if got["External/"+actionBlock] != 1 {
		t.Errorf("External/Block spoof entries = %v, want 1", got["External/"+actionBlock])
	}
	if len(got) != 4 {
		t.Errorf("spoof series = %d, want 2 spoof types x 2 actions", len(got))
	}
}

// TestCollect_TwinPerEntry enforces #114: every fetched entry gets a log twin,
// so "which one" is answerable. 5 list entries + 1 spoof entry.
func TestCollect_TwinPerEntry(t *testing.T) {
	rec := collect(t, liveTenant(t))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 6 {
		t.Errorf("twins = %d, want 6 (5 list entries + 1 spoof)", n)
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	rec := collect(t, liveTenant(t))
	var ip map[string]string
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrEntryValue] == "2001:8b0:1f05::106c" {
			ip = l.Attrs
		}
	}
	if ip == nil {
		t.Fatal("no twin for the IP allow entry")
	}
	if ip[semconv.AttrListType] != listTypeIP {
		t.Errorf("list_type = %q", ip[semconv.AttrListType])
	}
	if ip[semconv.AttrAction] != actionAllow {
		t.Errorf("action = %q", ip[semconv.AttrAction])
	}
	if ip[semconv.AttrNotes] != "home ipv6" {
		t.Errorf("notes = %q", ip[semconv.AttrNotes])
	}
	if ip[semconv.AttrModifiedBy] != "rob@m7kni.io" {
		t.Errorf("modified_by = %q", ip[semconv.AttrModifiedBy])
	}
	if ip[semconv.AttrSysManaged] != "false" {
		t.Errorf("sys_managed = %q", ip[semconv.AttrSysManaged])
	}
	if ip[semconv.AttrExpiryBucket] != bucketNever {
		t.Errorf("expiry_bucket = %q, want %q", ip[semconv.AttrExpiryBucket], bucketNever)
	}
	// Null ExpirationDate / RemoveAfter must be omitted, not stamped empty.
	if _, present := ip[semconv.AttrExpirationDateTime]; present {
		t.Error("null ExpirationDate should be omitted")
	}
	if _, present := ip[semconv.AttrRemoveAfterDays]; present {
		t.Error("null RemoveAfter should be omitted")
	}
}

// TestCollect_TwinReadsExactNames proves the malformed duplicate wire key
// "LastUsedDate(DateTime])" does not leak into an attribute, and that
// RemoveAfter is read as a number where present.
func TestCollect_TwinReadsExactNames(t *testing.T) {
	rec := collect(t, liveTenant(t))
	for _, l := range rec.LogRecords() {
		for k := range l.Attrs {
			if k == "LastUsedDate(DateTime])" || k == "RemoveAfter@data.type" {
				t.Errorf("sidecar/malformed wire key %q leaked into attributes", k)
			}
		}
		if l.Attrs[semconv.AttrEntryValue] == "rob-knight.net" {
			if l.Attrs[semconv.AttrRemoveAfterDays] != "45" {
				t.Errorf("remove_after_days = %q, want 45", l.Attrs[semconv.AttrRemoveAfterDays])
			}
			if l.Attrs[semconv.AttrExpiryBucket] != bucketRemoveAfterLastUse {
				t.Errorf("expiry_bucket = %q, want %q", l.Attrs[semconv.AttrExpiryBucket], bucketRemoveAfterLastUse)
			}
		}
	}
}

// TestEntryTwin_Severity drives the mapper directly (this project's
// telemetry.Severity scale, not the recorded log-severity scale).
func TestEntryTwin_Severity(t *testing.T) {
	standing := entryTwin(recordsFrom(t, liveIPAllow)[0], listTypeIP, fixedNow)
	if standing.Severity != telemetry.SeverityError {
		t.Errorf("non-expiring allow severity = %v, want Error", standing.Severity)
	}
	bounded := entryTwin(recordsFrom(t, liveSenderAllow)[0], listTypeSender, fixedNow)
	if bounded.Severity != telemetry.SeverityInfo {
		t.Errorf("bounded allow severity = %v, want Info", bounded.Severity)
	}
	block := entryTwin(recordsFrom(t, liveSenderBlock)[0], listTypeSender, fixedNow)
	if block.Severity != telemetry.SeverityInfo {
		t.Errorf("block severity = %v, want Info", block.Severity)
	}
}

// TestSpoofTwin_Severity: spoof entries have no expiry mechanism at all, so an
// allow is permanent by construction and takes the same Error as a standing
// allow on the other lists.
func TestSpoofTwin_Severity(t *testing.T) {
	block := spoofTwin(recordsFrom(t, liveSpoof)[0])
	if block.Severity != telemetry.SeverityInfo {
		t.Errorf("spoof block severity = %v, want Info", block.Severity)
	}
	if block.Attrs[semconv.AttrSpoofedUser] != "user@contoso.com" {
		t.Errorf("spoofed_user = %v", block.Attrs[semconv.AttrSpoofedUser])
	}
	if block.Attrs[semconv.AttrSendingInfrastructure] != "fabrikam.com" {
		t.Errorf("sending_infrastructure = %v", block.Attrs[semconv.AttrSendingInfrastructure])
	}
	allowRec := recordsFrom(t, liveSpoof)[0]
	allowRec["Action"] = actionAllow
	if s := spoofTwin(allowRec).Severity; s != telemetry.SeverityError {
		t.Errorf("spoof allow severity = %v, want Error", s)
	}
}

func TestExpiryBucketFor(t *testing.T) {
	now := fixedNow
	cases := []struct {
		name string
		exp  time.Time
		want string
	}{
		{"expired", now.Add(-time.Hour), bucketExpired},
		{"lt_7d", now.Add(6 * 24 * time.Hour), bucketLt7d},
		{"lt_30d", now.Add(20 * 24 * time.Hour), bucketLt30d},
		{"gt_30d", now.Add(60 * 24 * time.Hour), bucketGt30d},
	}
	for _, tc := range cases {
		if got := expiryBucketFor(now, tc.exp); got != tc.want {
			t.Errorf("%s: bucket = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCollect_EmptyTenantStillSeeds: a tenant with no entries at all must still
// publish the zero baseline, otherwise the first allow entry ever added looks
// like a new series rather than a change.
func TestCollect_EmptyTenantStillSeeds(t *testing.T) {
	rec := collect(t, &fakeEXO{byListType: map[string][]map[string]any{}})
	if got := len(rec.MetricPoints(metricEntries)); got != 8 {
		t.Errorf("entries series on an empty tenant = %d, want 8 seeded zeros", got)
	}
	if got := len(rec.MetricPoints(metricNonExpiringAllow)); got != 4 {
		t.Errorf("non_expiring_allow series on an empty tenant = %d, want 4", got)
	}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			t.Error("empty tenant should emit no twins")
		}
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when a cmdlet fails")
	}
}
