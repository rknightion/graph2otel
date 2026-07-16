package signinactivity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/beta"

// fixed reference time for deterministic age math.
var now = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func ago(days int) string {
	return now.AddDate(0, 0, -days).Format(time.RFC3339)
}

func fixtureBodies() map[string]string {
	return map[string]string{
		// SPs: one used 5d ago (fresh), one 45d ago (stale-30), one 200d ago
		// (stale-30 and stale-90, and carries the full signInActivity shape to
		// exercise decoding all six sub-fields), one never used (stale-all, and
		// deliberately sparse to exercise the omit-absent-attrs path).
		base + "/reports/servicePrincipalSignInActivities": `{"value":[
			{"id":"sp-a","appId":"a","lastSignInActivity":{"lastSignInDateTime":"` + ago(5) + `"}},
			{"id":"sp-b","appId":"b","lastSignInActivity":{"lastSignInDateTime":"` + ago(45) + `"}},
			{"id":"sp-c","appId":"c","lastSignInActivity":{
				"lastSignInDateTime":"` + ago(200) + `",
				"lastSignInRequestId":"req-c-interactive",
				"lastNonInteractiveSignInDateTime":"` + ago(150) + `",
				"lastNonInteractiveSignInRequestId":"req-c-noninteractive",
				"lastSuccessfulSignInDateTime":"` + ago(180) + `",
				"lastSuccessfulSignInRequestId":"req-c-success"
			}},
			{"appId":"d"}
		]}`,
		// App credentials: one 10d ago (fresh), one 100d ago (stale-30 & 90,
		// carrying the full identifying + credential-origin field set).
		base + "/reports/appCredentialSignInActivities": `{"value":[
			{"id":"cred-k1","appId":"a","keyId":"k1","signInActivity":{"lastSignInDateTime":"` + ago(10) + `"}},
			{
				"id":"cred-k2","appId":"b","appObjectId":"appobj-b",
				"servicePrincipalObjectId":"spobj-b","resourceId":"resource-b",
				"keyId":"k2","keyType":"certificate","keyUsage":"sign",
				"credentialOrigin":"application",
				"createdDateTime":"` + ago(365) + `",
				"expirationDateTime":"` + ago(-365) + `",
				"signInActivity":{"lastSignInDateTime":"` + ago(100) + `"}
			}
		]}`,
		// App sign-in summary (D7): two apps, summed to success/failure totals.
		base + "/reports/getAzureADApplicationSignInSummary(period='D7')": `{"value":[
			{"appId":"a","successfulSignInCount":100,"failedSignInCount":5},
			{"appId":"b","successfulSignInCount":20,"failedSignInCount":1}
		]}`,
	}
}

func p2caps() license.Capabilities { return license.Capabilities{license.CapEntraP2: true} }

func TestCollectEmitsBoundedStaleAndSummaryAggregates(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	spStale := map[string]float64{}
	for _, pt := range rec.MetricPoints(spStaleMetric) {
		spStale[pt.Attrs["threshold_days"]] = pt.Value
	}
	// stale-30: b(45), c(200), d(never) = 3; stale-90: c, d = 2.
	if spStale["30"] != 3 {
		t.Errorf("sp stale-30 = %v, want 3", spStale["30"])
	}
	if spStale["90"] != 2 {
		t.Errorf("sp stale-90 = %v, want 2", spStale["90"])
	}

	credStale := map[string]float64{}
	for _, pt := range rec.MetricPoints(credStaleMetric) {
		credStale[pt.Attrs["threshold_days"]] = pt.Value
	}
	// stale-30: k2(100) = 1; stale-90: k2 = 1.
	if credStale["30"] != 1 || credStale["90"] != 1 {
		t.Errorf("cred stale 30/90 = %v/%v, want 1/1", credStale["30"], credStale["90"])
	}

	summary := map[string]float64{}
	for _, pt := range rec.MetricPoints(summaryMetric) {
		summary[pt.Attrs["result"]] = pt.Value
	}
	if summary["success"] != 120 || summary["failure"] != 6 {
		t.Errorf("summary success/failure = %v/%v, want 120/6", summary["success"], summary["failure"])
	}
}

func TestCollectNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	allowed := map[string]bool{"threshold_days": true, "result": true}
	for _, name := range rec.MetricNames() {
		for _, pt := range rec.MetricPoints(name) {
			for k := range pt.Attrs {
				if !allowed[k] {
					t.Errorf("metric %s has disallowed per-entity attr %q", name, k)
				}
			}
		}
	}
}

func TestExperimentalAndCapabilityAndPerms(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if !c.Experimental() {
		t.Error("signinactivity is beta; Experimental() must be true")
	}
	if c.RequiredCapability() != license.CapEntraP1 {
		t.Errorf("RequiredCapability = %v, want CapEntraP1", c.RequiredCapability())
	}
	if got := c.RequiredPermissions(); len(got) != 2 ||
		got[0] != "AuditLog.Read.All" || got[1] != "Reports.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
	if c.Name() != "entra.signin_activity" {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestCollectResilientToPerEndpointError(t *testing.T) {
	b := fixtureBodies()
	delete(b, base+"/reports/appCredentialSignInActivities")
	g := &fakeGraph{
		bodies: b,
		errs:   map[string]error{base + "/reports/appCredentialSignInActivities": errors.New("boom")},
	}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }
	// The credential half fails, but SP stale + summary must still emit and the
	// error is surfaced.
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected the per-endpoint failure to surface as an error")
	}
	if len(rec.MetricPoints(spStaleMetric)) == 0 {
		t.Error("SP stale metric should still emit when the credential half fails")
	}
	// The credential half short-circuited before its twin: zero
	// entra.app_signin_activity logs should carry a key_id attr.
	for _, r := range logsNamed(rec.LogRecords(), eventSignInActivity) {
		if r.Attrs["key_id"] != "" {
			t.Errorf("credential half failed but its log twin still emitted: %+v", r)
		}
	}
}

func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectEmitsLogTwinPerEntity is the core of #114 for this collector:
// every service principal AND every app credential from the single existing
// fetch must also produce one entra.app_signin_activity log record, in
// addition to the bounded stale-count gauge.
func TestCollectEmitsLogTwinPerEntity(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventSignInActivity)
	// 4 service principals + 2 app credentials = 6 log records.
	if len(got) != 6 {
		t.Fatalf("emitted %d %s logs, want 6 (one per SP/credential)", len(got), eventSignInActivity)
	}

	var spC, credK2 *telemetrytest.LogRecord
	for i := range got {
		switch got[i].Attrs["id"] {
		case "sp-c":
			spC = &got[i]
		case "cred-k2":
			credK2 = &got[i]
		}
	}
	if spC == nil {
		t.Fatal("no log record for service principal sp-c")
	}
	if credK2 == nil {
		t.Fatal("no log record for app credential cred-k2")
	}

	// Service principal twin: identifying field + all six signInActivity
	// sub-fields decoded (not just lastSignInDateTime).
	wantSP := map[string]string{
		"app_id":                                  "c",
		"last_sign_in_date_time":                  ago(200),
		"last_sign_in_request_id":                 "req-c-interactive",
		"last_non_interactive_sign_in_date_time":  ago(150),
		"last_non_interactive_sign_in_request_id": "req-c-noninteractive",
		"last_successful_sign_in_date_time":       ago(180),
		"last_successful_sign_in_request_id":      "req-c-success",
	}
	for k, want := range wantSP {
		if got := spC.Attrs[k]; got != want {
			t.Errorf("sp-c attr %s = %q, want %q", k, got, want)
		}
	}
	// app_display_name must NEVER appear: neither beta resource carries a
	// display-name property (verified against learn.microsoft.com, 2026-07-16).
	if _, ok := spC.Attrs["app_display_name"]; ok {
		t.Error("spC log carries app_display_name, but servicePrincipalSignInActivity has no such field")
	}

	// App credential twin: identifying + credential-origin fields.
	wantCred := map[string]string{
		"app_id":                      "b",
		"app_object_id":               "appobj-b",
		"service_principal_object_id": "spobj-b",
		"resource_id":                 "resource-b",
		"key_id":                      "k2",
		"key_type":                    "certificate",
		"key_usage":                   "sign",
		"credential_origin":           "application",
		"created_date_time":           ago(365),
		"expiration_date_time":        ago(-365),
		"last_sign_in_date_time":      ago(100),
	}
	for k, want := range wantCred {
		if got := credK2.Attrs[k]; got != want {
			t.Errorf("cred-k2 attr %s = %q, want %q", k, got, want)
		}
	}

	// Sparse SP "d" (never signed in) must still emit a log with no
	// last_sign_in_date_time attr, not an empty-string one.
	var spD *telemetrytest.LogRecord
	for i := range got {
		if got[i].Attrs["app_id"] == "d" {
			spD = &got[i]
		}
	}
	if spD == nil {
		t.Fatal("no log record for service principal d (never signed in)")
	}
	if _, ok := spD.Attrs["last_sign_in_date_time"]; ok {
		t.Errorf("sp d never signed in but has last_sign_in_date_time attr: %q", spD.Attrs["last_sign_in_date_time"])
	}
	if _, ok := spD.Attrs["id"]; ok {
		t.Errorf("sp d has no id field in the fixture but log carries one: %q", spD.Attrs["id"])
	}
}

// TestSignInActivitySeverityEscalatesOnStaleness pins the severity rule this
// collector chose: escalate to Warn once an entity crosses the SAME 90-day
// threshold the stale-count gauge buckets on (or has never signed in at
// all), so the log severity and the metric agree on what "stale" means.
// Routine, recently-active workloads/credentials stay Info. Drives the
// mapper directly (the entra/risk idiom) rather than round-tripping through
// the recorder, since telemetrytest.LogRecord.Severity is the raw OTel
// numeric severity, not this package's telemetry.Severity enum.
func TestSignInActivitySeverityEscalatesOnStaleness(t *testing.T) {
	tests := []struct {
		ageDays float64
		want    telemetry.Severity
		why     string
	}{
		{5, telemetry.SeverityInfo, "used 5d ago: routine"},
		{45, telemetry.SeverityInfo, "used 45d ago: within the 90d threshold"},
		{90, telemetry.SeverityInfo, "used exactly 90d ago: not yet beyond threshold"},
		{200, telemetry.SeverityWarn, "used 200d ago: beyond the 90d threshold"},
		{1 << 30, telemetry.SeverityWarn, "never signed in: maximally stale"},
	}
	for _, tc := range tests {
		if got := stalenessSeverity(tc.ageDays); got != tc.want {
			t.Errorf("ageDays=%v: severity = %v, want %v (%s)", tc.ageDays, got, tc.want, tc.why)
		}
	}

	// And end-to-end through spLogTwin/credLogTwin, confirming the Event
	// carries the mapper's output.
	if ev := spLogTwin(spActivity{AppID: "c"}, 200); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("spLogTwin age=200: severity = %v, want Warn", ev.Severity)
	}
	if ev := spLogTwin(spActivity{AppID: "a"}, 5); ev.Severity != telemetry.SeverityInfo {
		t.Errorf("spLogTwin age=5: severity = %v, want Info", ev.Severity)
	}
	if ev := credLogTwin(credActivity{KeyID: "k2"}, 100); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("credLogTwin age=100: severity = %v, want Warn", ev.Severity)
	}
}

// TestSignInActivityLogTwinTimestampIsZero pins the STATE-feed convention: the
// Timestamp is left zero (poll time), never set to a source-reported sign-in
// date, because this entity is re-emitted every cycle for as long as it
// exists in the report — stamping it with a fixed source date would pile
// every cycle's repeat onto one instant. See entra/risk's logTwin for the
// precedent.
func TestSignInActivityLogTwinTimestampIsZero(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, r := range logsNamed(rec.LogRecords(), eventSignInActivity) {
		if !r.Timestamp.IsZero() {
			t.Errorf("log record for %+v has non-zero Timestamp %v, want zero (poll time)", r.Attrs, r.Timestamp)
		}
	}
}
