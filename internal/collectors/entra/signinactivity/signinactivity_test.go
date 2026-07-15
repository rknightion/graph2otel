package signinactivity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
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
		// (stale-30 and stale-90), one never used (stale-all).
		base + "/reports/servicePrincipalSignInActivities": `{"value":[
			{"appId":"a","lastSignInActivity":{"lastSignInDateTime":"` + ago(5) + `"}},
			{"appId":"b","lastSignInActivity":{"lastSignInDateTime":"` + ago(45) + `"}},
			{"appId":"c","lastSignInActivity":{"lastSignInDateTime":"` + ago(200) + `"}},
			{"appId":"d"}
		]}`,
		// App credentials: one 10d ago (fresh), one 100d ago (stale-30 & 90).
		base + "/reports/appCredentialSignInActivities": `{"value":[
			{"keyId":"k1","signInActivity":{"lastSignInDateTime":"` + ago(10) + `"}},
			{"keyId":"k2","signInActivity":{"lastSignInDateTime":"` + ago(100) + `"}}
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
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "AuditLog.Read.All" {
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
}
