package credentialexpiry

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned collection-page bodies (or errors) and
// records the ConsistencyLevel header seen on each request (a plain $select
// list query needs no ConsistencyLevel, unlike $count/$filter/$search).
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]map[string]string // url -> headers
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]map[string]string{}
	}
	f.seenHeaders[url] = headers
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	base    = "https://graph.microsoft.com/v1.0"
	appsURL = base + "/applications?$select=id,appId,displayName,keyCredentials,passwordCredentials"
	spURL   = base + "/servicePrincipals?$select=id,appId,displayName,keyCredentials,passwordCredentials"
)

// liveApplications is a VERBATIM GET /applications?$select=id,appId,
// displayName,keyCredentials,passwordCredentials response from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It is the authority on what an
// application record — and its passwordCredential entries — actually look like
// on the wire, and it is what the docs-derived inline fixtures below used to
// stand in for.
//
// Trimmed only by dropping whole array elements: the live page carried five
// applications (three with no credentials, two each with a single
// passwordCredential and no keyCredentials). Two zero-credential apps were
// dropped; every field name and value on the records kept is byte-for-byte as
// captured, EXCEPT the `hint` values: Graph returns the first three characters
// of the live client secret there, so on this public repo they are redacted to
// "xxx" (the wire also carries `secretText`, null here). The `hint`/`secretText`
// KEYS are still present and are the point of the fixture: the mapper must read
// PAST them (see credential — it has no hint/secretText field), so they must
// never surface as an emitted attribute. See TestCollectEmitsLiveRecordsEndToEnd.
//
// What this live page does NOT contain, and therefore cannot verify (the branches
// exercised only by the synthetic tests below, each flagged where it lives):
//   - keyCredentials (certificates): zero on the wire, so the certificate emit
//     path (custom_key_identifier/key_type/key_usage) is UNVERIFIED against live
//     data — a #142-class blind spot recorded on #165.
//   - an owner carrying BOTH credential kinds.
//   - an already-expired credential: both live secrets end in 2028.
const liveApplications = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#applications(id,appId,displayName,keyCredentials,passwordCredentials)",
  "value": [
    {
      "appId": "63dfe505-bbbc-419f-bd61-4e98df12b268",
      "displayName": "PH - OTEL Demo",
      "id": "083b10f6-3cbb-4c5c-96ec-abe0c9da1664",
      "keyCredentials": [],
      "passwordCredentials": []
    },
    {
      "appId": "992d4404-467a-4b4c-8001-45b6ec4064fd",
      "displayName": "IntuneBrew Automation",
      "id": "1c52dd42-5645-4fd5-b4f4-1f9741d775a2",
      "keyCredentials": [],
      "passwordCredentials": [
        {
          "customKeyIdentifier": null,
          "displayName": "github-actions",
          "endDateTime": "2028-06-05T00:00:00Z",
          "hint": "xxx",
          "keyId": "d057c8cf-6a83-43c3-9c05-3bb4e0dee568",
          "secretText": null,
          "startDateTime": "2026-06-05T20:15:38.2619305Z"
        }
      ]
    },
    {
      "appId": "5f7d3d24-9d94-4f04-b2ce-546b927b3ba7",
      "displayName": "Tailscale Device Posture",
      "id": "20310cfa-a958-4e78-92f1-6094aace59c6",
      "keyCredentials": [],
      "passwordCredentials": [
        {
          "customKeyIdentifier": null,
          "displayName": "tailscale-device-posture",
          "endDateTime": "2028-06-04T17:36:33Z",
          "hint": "xxx",
          "keyId": "88cdb829-ffcc-43d9-b78c-2eb3ba1795dd",
          "secretText": null,
          "startDateTime": "2026-06-05T17:36:33.4280139Z"
        }
      ]
    }
  ]
}`

// liveServicePrincipals is a VERBATIM GET /servicePrincipals?$select=id,appId,
// displayName,keyCredentials,passwordCredentials response from the m7kni
// tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It is the same $select as the
// applications page and confirms the servicePrincipal resource carries the
// identical id/appId/displayName + keyCredentials/passwordCredentials shape.
//
// Trimmed by dropping whole array elements (the live first page carried five
// service principals). Every one on this page — and every one on the captured
// page — carried EMPTY credential arrays, so the service-principal owner_type
// exercises the no-credential branch only: this tenant has no SP-owned secret
// or certificate on the wire, so an SP credential's emit path is UNVERIFIED
// against live data (recorded on #165).
//
// The captured page also carried an `@odata.nextLink` (it was page 1 of many);
// that envelope pointer is dropped here so the fixture is a terminal page —
// nextLink following itself is covered by internal/collectors/graph_test.go.
const liveServicePrincipals = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals(id,appId,displayName,keyCredentials,passwordCredentials)",
  "value": [
    {
      "appId": "e933bd07-d2ee-4f1d-933c-3752b819567b",
      "displayName": "Azure Monitor Control Service",
      "id": "012a652a-fb9f-44cd-940e-6ffaf620a54c",
      "keyCredentials": [],
      "passwordCredentials": []
    },
    {
      "appId": "00000002-0000-0ff1-ce00-000000000000",
      "displayName": "Office 365 Exchange Online",
      "id": "01deb58a-8c47-4d14-888c-84c4a7844905",
      "keyCredentials": [],
      "passwordCredentials": []
    }
  ]
}`

// fixedNow anchors every bucket-boundary computation in the tests so they are
// deterministic regardless of wall-clock time.
var fixedNow = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func at(offset time.Duration) string {
	return fixedNow.Add(offset).Format(time.RFC3339)
}

const day = 24 * time.Hour

func withFixedClock(c *Collector) *Collector {
	c.now = func() time.Time { return fixedNow }
	return c
}

// logsNamed returns the recorded log records carrying the given EventName.
func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectEmitsLiveRecordsEndToEnd drives the two VERBATIM captured pages
// through the whole collector into an emitter, and is the AUTHORITY on the
// attribute set this collector produces for a real passwordCredential. It
// replaces the docs-derived inline fixtures that used placeholder ids
// ("app-obj-1", "11111111-...", "App One") — those were hand-written from the
// docs and so could never have caught a field the live wire names differently.
//
// With fixedNow = 2024-01-01 both live secrets (endDateTime 2028) land in
// gt_90d, so the live population emits exactly two secret log twins and no
// certificate at all. The certificate emit path is exercised synthetically in
// TestCollectEmitsSyntheticCertificateLogTwin, because the live capture carried
// zero keyCredentials (see liveApplications).
func TestCollectEmitsLiveRecordsEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{appsURL: liveApplications, spURL: liveServicePrincipals}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Both live secrets are application-owned and 2028-dated -> gt_90d; the two
	// live service principals carry no credentials.
	pts := rec.MetricPoints(metricName)
	if len(pts) != 20 {
		t.Fatalf("got %d series, want 20 (2 owner_type x 2 credential_type x 5 expiry_bucket, always dense)", len(pts))
	}
	for _, p := range pts {
		want := 0.0
		if p.Attrs["owner_type"] == "application" && p.Attrs["credential_type"] == "secret" && p.Attrs["expiry_bucket"] == "gt_90d" {
			want = 2
		}
		if p.Value != want {
			t.Errorf("series %v = %v, want %v", p.Attrs, p.Value, want)
		}
	}

	logs := logsNamed(rec.LogRecords(), eventAppCredential)
	if len(logs) != 2 {
		t.Fatalf("emitted %d %s logs, want 2 (one per live secret)", len(logs), eventAppCredential)
	}

	// The IntuneBrew github-actions secret, pinned as an exact attribute set:
	// this fails on a dropped field (missing attr) AND on a fabricated one
	// (unexpected attr) — the pair of mistakes #165 exists to prevent.
	var intunebrew *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].Attrs["key_id"] == "d057c8cf-6a83-43c3-9c05-3bb4e0dee568" {
			intunebrew = &logs[i]
		}
	}
	if intunebrew == nil {
		t.Fatalf("no log for the IntuneBrew secret keyId; got %+v", logs)
	}

	wantAttrs := map[string]string{
		"owner_type":              "application",
		"app_id":                  "992d4404-467a-4b4c-8001-45b6ec4064fd",
		"app_object_id":           "1c52dd42-5645-4fd5-b4f4-1f9741d775a2",
		"display_name":            "IntuneBrew Automation",
		"credential_type":         "secret",
		"key_id":                  "d057c8cf-6a83-43c3-9c05-3bb4e0dee568",
		"credential_display_name": "github-actions",
		"start_date_time":         "2026-06-05T20:15:38.2619305Z",
		"end_date_time":           "2028-06-05T00:00:00Z",
		"expiry_bucket":           "gt_90d",
	}
	gotKeys := make([]string, 0, len(intunebrew.Attrs))
	for k := range intunebrew.Attrs {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	wantKeys := make([]string, 0, len(wantAttrs))
	for k := range wantAttrs {
		wantKeys = append(wantKeys, k)
	}
	sort.Strings(wantKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("secret log attribute key set mismatch\n got: %v\nwant: %v", gotKeys, wantKeys)
	}
	for k, want := range wantAttrs {
		if got := intunebrew.Attrs[k]; got != want {
			t.Errorf("attr %q = %q, want %q", k, got, want)
		}
	}

	// Secret exclusion, checked on the emitted records rather than by
	// inspection: the wire records literally carry `hint` (three chars of the
	// password) and `secretText`, and passwordCredentials also carry a
	// customKeyIdentifier — none of these may reach the emitter under any key.
	forbidden := []string{"hint", "secretText", "secret_text", "key", "custom_key_identifier", "key_type", "key_usage"}
	for _, r := range logs {
		for _, bad := range forbidden {
			if v, ok := r.Attrs[bad]; ok {
				t.Errorf("secret log carries forbidden attribute %q=%q: %v", bad, v, r.Attrs)
			}
		}
	}
}

func TestCollectBucketsCredentialsByOwnerTypeCredentialTypeAndWindow(t *testing.T) {
	// SYNTHETIC dates by necessity: the live capture (liveApplications) carried
	// only 2028-dated secrets, so every live credential lands in gt_90d and the
	// other four bucket boundaries have no live example. This test constructs
	// one credential per (owner_type x credential_type x boundary) to prove the
	// expiryBucketFor math. The record SHAPE authority is liveApplications /
	// TestCollectEmitsLiveRecordsEndToEnd; only the endDateTime offsets here are
	// fabricated.
	apps := `{"value":[
		{"id":"app-obj-1","appId":"11111111-1111-1111-1111-111111111111","displayName":"App One",
		 "keyCredentials":[{"keyId":"cert-1","endDateTime":"` + at(-1*day) + `"},{"keyId":"cert-2","endDateTime":"` + at(3*day) + `"}],
		 "passwordCredentials":[{"keyId":"pwd-1","endDateTime":"` + at(15*day) + `"}]},
		{"id":"app-obj-2","appId":"22222222-2222-2222-2222-222222222222","displayName":"App Two",
		 "keyCredentials":[{"keyId":"cert-3","endDateTime":"` + at(200*day) + `"}],
		 "passwordCredentials":[{"keyId":"pwd-2","endDateTime":"` + at(60*day) + `"},{"keyId":"pwd-3","endDateTime":"` + at(7*day) + `"}]}
	]}`
	sps := `{"value":[
		{"id":"sp-obj-1","appId":"33333333-3333-3333-3333-333333333333","displayName":"SP One",
		 "keyCredentials":[{"keyId":"cert-4","endDateTime":"` + at(0) + `"}],
		 "passwordCredentials":[{"keyId":"pwd-4","endDateTime":"` + at(91*day) + `"}]}
	]}`

	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: sps}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 20 {
		t.Fatalf("got %d series, want 20 (2 owner_type x 2 credential_type x 5 expiry_bucket, always dense)", len(pts))
	}

	got := map[[3]string]float64{}
	for _, p := range pts {
		key := [3]string{p.Attrs["owner_type"], p.Attrs["credential_type"], p.Attrs["expiry_bucket"]}
		got[key] = p.Value
	}

	want := map[[3]string]float64{
		{"application", "certificate", "expired"}: 1,
		{"application", "certificate", "lt_7d"}:   1,
		{"application", "certificate", "lt_30d"}:  0,
		{"application", "certificate", "lt_90d"}:  0,
		{"application", "certificate", "gt_90d"}:  1,

		{"application", "secret", "expired"}: 0,
		{"application", "secret", "lt_7d"}:   1, // exactly +7d is inclusive
		{"application", "secret", "lt_30d"}:  1,
		{"application", "secret", "lt_90d"}:  1,
		{"application", "secret", "gt_90d"}:  0,

		{"service_principal", "certificate", "expired"}: 1, // exactly now is expired
		{"service_principal", "certificate", "lt_7d"}:   0,
		{"service_principal", "certificate", "lt_30d"}:  0,
		{"service_principal", "certificate", "lt_90d"}:  0,
		{"service_principal", "certificate", "gt_90d"}:  0,

		{"service_principal", "secret", "expired"}: 0,
		{"service_principal", "secret", "lt_7d"}:   0,
		{"service_principal", "secret", "lt_30d"}:  0,
		{"service_principal", "secret", "lt_90d"}:  0,
		{"service_principal", "secret", "gt_90d"}:  1, // exactly +91d is just past the 90d boundary
	}

	for k, v := range want {
		if got[k] != v {
			t.Errorf("owner_type=%s credential_type=%s expiry_bucket=%s = %v, want %v", k[0], k[1], k[2], got[k], v)
		}
	}
}

// TestCollectMetricsNeverCarryPerEntityAttrs pins the flagship cardinality
// guarantee even though this collector now decodes rich per-entity identity
// (appId/displayName/id/keyId) for the log twin: none of that identity may
// ever reach a metric attribute, however many applications/service
// principals/credentials a tenant has.
//
// STRUCTURAL by design: it dynamically builds 2000 synthetic applications to
// prove series count is bounded (not per-entity), a scale the ~two-credential
// live capture cannot reach. Leave it synthetic.
func TestCollectMetricsNeverCarryPerEntityAttrs(t *testing.T) {
	var apps strings.Builder
	apps.WriteString(`{"value":[`)
	const n = 2000
	for i := 0; i < n; i++ {
		if i > 0 {
			apps.WriteString(",")
		}
		apps.WriteString(`{"id":"app-` + string(rune('a'+i%26)) + `","appId":"11111111-1111-1111-1111-111111111111","displayName":"whatever",` +
			`"keyCredentials":[{"keyId":"11111111-1111-1111-1111-111111111111","displayName":"whatever","endDateTime":"` + at(200*day) + `","customKeyIdentifier":"abc123","type":"AsymmetricX509Cert","usage":"Verify"}],"passwordCredentials":[]}`)
	}
	apps.WriteString(`]}`)

	g := &fakeGraph{bodies: map[string]string{appsURL: apps.String(), spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 20 {
		t.Fatalf("got %d series for %d source credentials, want 20 (bounded, not per-entity)", len(pts), n)
	}

	forbidden := []string{
		"app_id", "appId", "app_object_id", "app_display_name", "displayName", "display_name",
		"key_id", "keyId", "id", "custom_key_identifier", "key_type", "key_usage",
		"start_date_time", "end_date_time",
	}
	for _, p := range pts {
		for _, bad := range forbidden {
			if _, ok := p.Attrs[bad]; ok {
				t.Errorf("series has forbidden per-entity attribute %q: %v", bad, p.Attrs)
			}
		}
		for k := range p.Attrs {
			if k != "owner_type" && k != "credential_type" && k != "expiry_bucket" {
				t.Errorf("series has unexpected attribute %q (only owner_type/credential_type/expiry_bucket allowed): %v", k, p.Attrs)
			}
		}
	}

	var total float64
	for _, p := range pts {
		if p.Attrs["owner_type"] == "application" && p.Attrs["credential_type"] == "certificate" && p.Attrs["expiry_bucket"] == "gt_90d" {
			total = p.Value
		}
	}
	if total != n {
		t.Errorf("gt_90d application/certificate count = %v, want %v", total, n)
	}

	logs := logsNamed(rec.LogRecords(), eventAppCredential)
	if len(logs) != n {
		t.Errorf("emitted %d %s logs, want %d (one per credential)", len(logs), eventAppCredential, n)
	}
}

func TestCollectIsResilientToPerOwnerTypeError(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{appsURL: liveApplications},
		errs:   map[string]error{spURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	err := c.Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the servicePrincipals failure as an error")
	}

	pts := rec.MetricPoints(metricName)
	if len(pts) != 10 {
		t.Fatalf("got %d series, want 10 (only application's 2 credential_type x 5 bucket; service_principal absent since its fetch failed)", len(pts))
	}
	for _, p := range pts {
		if p.Attrs["owner_type"] == "service_principal" {
			t.Errorf("service_principal series should be absent when its fetch failed, got %v", p.Attrs)
		}
	}

	// The application page (liveApplications) carries two live secrets.
	if got := logsNamed(rec.LogRecords(), eventAppCredential); len(got) != 2 {
		t.Errorf("emitted %d %s logs, want 2 (application's two live secrets; servicePrincipal fetch failed)", len(got), eventAppCredential)
	}
}

func TestCollectSkipsUnparsableEndDateTimeWithoutFailingOrLogging(t *testing.T) {
	apps := `{"value":[
		{"id":"app-obj-1","appId":"aaaaaaaa-1111-1111-1111-111111111111","displayName":"App",
		 "keyCredentials":[{"keyId":"cert-bad","endDateTime":"not-a-date"},{"keyId":"cert-good","endDateTime":"` + at(200*day) + `"}],"passwordCredentials":[]}
	]}`
	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricName)
	for _, p := range pts {
		if p.Attrs["owner_type"] == "application" && p.Attrs["credential_type"] == "certificate" && p.Attrs["expiry_bucket"] == "gt_90d" {
			if p.Value != 1 {
				t.Errorf("gt_90d application/certificate = %v, want 1 (the unparsable entry must be skipped, not counted)", p.Value)
			}
		}
	}

	// The unparsable entry must not produce a log twin either — its
	// expiry_bucket cannot be computed, so there is nothing correct to log.
	logs := logsNamed(rec.LogRecords(), eventAppCredential)
	if len(logs) != 1 {
		t.Fatalf("emitted %d %s logs, want 1 (only the parsable credential)", len(logs), eventAppCredential)
	}
	if logs[0].Attrs["key_id"] != "cert-good" {
		t.Errorf("logged credential key_id = %q, want %q", logs[0].Attrs["key_id"], "cert-good")
	}
}

func TestCollectSendsNoConsistencyLevelHeader(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{appsURL: `{"value":[]}`, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for url, h := range g.seenHeaders {
		if h["ConsistencyLevel"] != "" {
			t.Errorf("request %s sent ConsistencyLevel=%q, want none (plain $select needs no advanced-query header)", url, h["ConsistencyLevel"])
		}
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.credential_expiry" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Application.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Application.Read.All]", perms)
	}
}

// TestCollectEmitsLiveSecretLogTwinShape is the secret-side shape assertion
// driven off the VERBATIM Tailscale Device Posture record in liveApplications,
// checked at the emitter. It complements TestCollectEmitsLiveRecordsEndToEnd
// (which pins the IntuneBrew record) so both live secrets are individually
// pinned.
func TestCollectEmitsLiveSecretLogTwinShape(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{appsURL: liveApplications, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var tailscale *telemetrytest.LogRecord
	for _, r := range logsNamed(rec.LogRecords(), eventAppCredential) {
		if r.Attrs["key_id"] == "88cdb829-ffcc-43d9-b78c-2eb3ba1795dd" {
			r := r
			tailscale = &r
		}
	}
	if tailscale == nil {
		t.Fatal("no log for the Tailscale Device Posture secret")
	}

	want := map[string]string{
		"owner_type":              "application",
		"app_id":                  "5f7d3d24-9d94-4f04-b2ce-546b927b3ba7",
		"app_object_id":           "20310cfa-a958-4e78-92f1-6094aace59c6",
		"display_name":            "Tailscale Device Posture",
		"credential_type":         "secret",
		"key_id":                  "88cdb829-ffcc-43d9-b78c-2eb3ba1795dd",
		"credential_display_name": "tailscale-device-posture",
		"start_date_time":         "2026-06-05T17:36:33.4280139Z",
		"end_date_time":           "2028-06-04T17:36:33Z",
		"expiry_bucket":           "gt_90d",
	}
	for k, v := range want {
		if got := tailscale.Attrs[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
	// Certificate-only fields never attach to a secret.
	for _, k := range []string{"custom_key_identifier", "key_type", "key_usage"} {
		if v, ok := tailscale.Attrs[k]; ok {
			t.Errorf("secret log unexpectedly carries certificate-only attr %q=%q", k, v)
		}
	}
}

// TestCollectEmitsSyntheticCertificateLogTwin exercises the certificate emit
// path — custom_key_identifier/key_type/key_usage attached only when
// credential_type is "certificate".
//
// SYNTHETIC by necessity, and flagged as such: the live capture
// (liveApplications + liveServicePrincipals) carried ZERO keyCredentials, so no
// real certificate record exists to pin against. That is a #142-class blind
// spot — the certificate field NAMES (customKeyIdentifier/type/usage) are
// verified against the docs and the struct tags, NOT against the wire — and it
// is recorded on #165. The secret side of this test is pinned against the live
// wire instead (TestCollectEmitsLiveRecordsEndToEnd).
func TestCollectEmitsSyntheticCertificateLogTwin(t *testing.T) {
	apps := `{"value":[
		{"id":"app-obj-1","appId":"11111111-1111-1111-1111-111111111111","displayName":"Payments API",
		 "keyCredentials":[{"keyId":"cert-1","displayName":"prod cert","startDateTime":"` + at(-300*day) + `","endDateTime":"` + at(3*day) + `","customKeyIdentifier":"deadbeef","type":"AsymmetricX509Cert","usage":"Verify"}],
		 "passwordCredentials":[]}
	]}`
	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventAppCredential)
	if len(got) != 1 {
		t.Fatalf("emitted %d %s logs, want 1", len(got), eventAppCredential)
	}
	cert := got[0]

	wantCert := map[string]string{
		"owner_type":              "application",
		"app_id":                  "11111111-1111-1111-1111-111111111111",
		"app_object_id":           "app-obj-1",
		"display_name":            "Payments API",
		"credential_type":         "certificate",
		"key_id":                  "cert-1",
		"credential_display_name": "prod cert",
		"start_date_time":         at(-300 * day),
		"end_date_time":           at(3 * day),
		"expiry_bucket":           "lt_7d",
		"custom_key_identifier":   "deadbeef",
		"key_type":                "AsymmetricX509Cert",
		"key_usage":               "Verify",
	}
	for k, v := range wantCert {
		if cert.Attrs[k] != v {
			t.Errorf("cert log attr %q = %q, want %q", k, cert.Attrs[k], v)
		}
	}

	// The secret material itself must never be logged: no attribute holding a
	// raw key blob or generated password can appear, under any key name.
	forbiddenSecretAttrs := []string{"key", "secretText", "secret_text", "hint"}
	for _, bad := range forbiddenSecretAttrs {
		if _, ok := cert.Attrs[bad]; ok {
			t.Errorf("log carries forbidden secret-bearing attribute %q: %v", bad, cert.Attrs)
		}
	}
}

// TestLogTwinOmitsAbsentAttrs asserts a sparse credential (no displayName, no
// customKeyIdentifier) omits those attributes rather than emitting empty
// strings — setStr's contract.
func TestLogTwinOmitsAbsentAttrs(t *testing.T) {
	ev := credentialLogTwin(ownerTypes[0], "secret", ownerEntity{ID: "app-1"}, credential{KeyID: "pwd-1", EndDateTime: at(0)}, "expired")
	for _, k := range []string{"app_id", "display_name", "credential_display_name", "start_date_time", "custom_key_identifier", "key_type", "key_usage"} {
		if v, ok := ev.Attrs[k]; ok {
			t.Errorf("absent field %q should be omitted, got %q", k, v)
		}
	}
	if ev.Attrs["app_object_id"] != "app-1" {
		t.Errorf("app_object_id = %v, want app-1", ev.Attrs["app_object_id"])
	}
	if ev.Attrs["key_id"] != "pwd-1" {
		t.Errorf("key_id = %v, want pwd-1", ev.Attrs["key_id"])
	}
}

// TestLogTwinSeverityTracksExpiryBucket drives the mapper directly. Only
// already-expired and imminently-expiring (<7d) credentials escalate to WARN —
// the same "actionable now" cut the collector's own bucket boundaries encode;
// everything else is routine background state.
func TestLogTwinSeverityTracksExpiryBucket(t *testing.T) {
	for _, tc := range []struct {
		bucket string
		want   telemetry.Severity
	}{
		{"expired", telemetry.SeverityWarn},
		{"lt_7d", telemetry.SeverityWarn},
		{"lt_30d", telemetry.SeverityInfo},
		{"lt_90d", telemetry.SeverityInfo},
		{"gt_90d", telemetry.SeverityInfo},
	} {
		ev := credentialLogTwin(ownerTypes[0], "certificate", ownerEntity{ID: "app-1"}, credential{KeyID: "k1"}, tc.bucket)
		if ev.Severity != tc.want {
			t.Errorf("expiry_bucket=%q severity = %v, want %v", tc.bucket, ev.Severity, tc.want)
		}
	}
}
