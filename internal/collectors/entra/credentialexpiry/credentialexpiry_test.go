package credentialexpiry

import (
	"context"
	"errors"
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

func TestCollectBucketsCredentialsByOwnerTypeCredentialTypeAndWindow(t *testing.T) {
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
	apps := `{"value":[{"id":"app-obj-1","appId":"aaaaaaaa-1111-1111-1111-111111111111","displayName":"App",
		"keyCredentials":[{"keyId":"cert-1","endDateTime":"` + at(200*day) + `"}],"passwordCredentials":[]}]}`
	g := &fakeGraph{
		bodies: map[string]string{appsURL: apps},
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

	if got := logsNamed(rec.LogRecords(), eventAppCredential); len(got) != 1 {
		t.Errorf("emitted %d %s logs, want 1 (only application's credential; servicePrincipal fetch failed)", len(got), eventAppCredential)
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

// TestCollectEmitsAppCredentialLogTwin is the other half of the cardinality
// boundary: the per-credential detail the gauge cannot carry (which app, which
// key, which dates) must land in the LOGS pipeline, not be dropped. Without it
// the collector can answer "N credentials expire in 7 days" but never "WHICH
// app" — unactionable for both outage prevention and incident response.
func TestCollectEmitsAppCredentialLogTwin(t *testing.T) {
	apps := `{"value":[
		{"id":"app-obj-1","appId":"11111111-1111-1111-1111-111111111111","displayName":"Payments API",
		 "keyCredentials":[{"keyId":"cert-1","displayName":"prod cert","startDateTime":"` + at(-300*day) + `","endDateTime":"` + at(3*day) + `","customKeyIdentifier":"deadbeef","type":"AsymmetricX509Cert","usage":"Verify"}],
		 "passwordCredentials":[{"keyId":"pwd-1","displayName":"ci secret","startDateTime":"` + at(-300*day) + `","endDateTime":"` + at(15*day) + `"}]}
	]}`
	g := &fakeGraph{bodies: map[string]string{appsURL: apps, spURL: `{"value":[]}`}}
	rec := telemetrytest.New()
	c := withFixedClock(New(g, nil))

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventAppCredential)
	if len(got) != 2 {
		t.Fatalf("emitted %d %s logs, want 2 (one per credential)", len(got), eventAppCredential)
	}

	var cert, secret *telemetrytest.LogRecord
	for i := range got {
		switch got[i].Attrs["credential_type"] {
		case "certificate":
			cert = &got[i]
		case "secret":
			secret = &got[i]
		}
	}
	if cert == nil || secret == nil {
		t.Fatalf("expected one certificate and one secret log, got %+v", got)
	}

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

	wantSecret := map[string]string{
		"owner_type":              "application",
		"app_id":                  "11111111-1111-1111-1111-111111111111",
		"app_object_id":           "app-obj-1",
		"display_name":            "Payments API",
		"credential_type":         "secret",
		"key_id":                  "pwd-1",
		"credential_display_name": "ci secret",
		"start_date_time":         at(-300 * day),
		"end_date_time":           at(15 * day),
		"expiry_bucket":           "lt_30d",
	}
	for k, v := range wantSecret {
		if secret.Attrs[k] != v {
			t.Errorf("secret log attr %q = %q, want %q", k, secret.Attrs[k], v)
		}
	}
	// Secrets never carry certificate-only fields, even when absent from the
	// source JSON (they'd decode as zero values otherwise).
	for _, k := range []string{"custom_key_identifier", "key_type", "key_usage"} {
		if _, ok := secret.Attrs[k]; ok {
			t.Errorf("secret log unexpectedly carries certificate-only attr %q: %v", k, secret.Attrs)
		}
	}

	// The secret material itself must never be logged: no attribute holding a
	// raw key blob or generated password can appear, under any key name.
	forbiddenSecretAttrs := []string{"key", "secretText", "secret_text", "hint"}
	for _, r := range got {
		for _, bad := range forbiddenSecretAttrs {
			if _, ok := r.Attrs[bad]; ok {
				t.Errorf("log carries forbidden secret-bearing attribute %q: %v", bad, r.Attrs)
			}
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
