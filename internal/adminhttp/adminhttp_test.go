package adminhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func testConfig(rec *telemetrytest.Recorder, limiter *rate.Limiter) Config {
	return Config{
		Metrics:            Metrics{Duration: "t.duration", HTTP4xx: "t.4xx", HTTP5xx: "t.5xx", Throttle: "t.throttle"},
		Descriptions:       Descriptions{Duration: "d", HTTP4xx: "4", HTTP5xx: "5", Throttle: "t"},
		DurationBuckets:    []float64{1, 2},
		LabelAttr:          "t.label",
		Label:              LabelFromRequest,
		ThrottleLogMessage: "throttled",
		ThrottleLogKey:     "label",
		Emitter:            rec.Emitter(),
		TenantID:           "tenant-a",
		Limiter:            limiter,
		Timeout:            5 * time.Second,
	}
}

func doGet(t *testing.T, c *http.Client, url, label string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(WithLabel(context.Background(), label), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestStatusClassesSelectInstruments(t *testing.T) {
	for _, tc := range []struct {
		status  int
		want    []string
		notWant []string
	}{
		{200, nil, []string{"t.4xx", "t.5xx", "t.throttle"}},
		{404, []string{"t.4xx"}, []string{"t.5xx", "t.throttle"}},
		{429, []string{"t.4xx", "t.throttle"}, []string{"t.5xx"}},
		{503, []string{"t.5xx"}, []string{"t.4xx", "t.throttle"}},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))
		rec := telemetrytest.New()
		doGet(t, NewClient(testConfig(rec, nil)), srv.URL, "lbl")
		srv.Close()

		if len(rec.MetricPoints("t.duration")) != 1 {
			t.Errorf("status %d: want one duration point", tc.status)
		}
		for _, n := range tc.want {
			if len(rec.MetricPoints(n)) == 0 {
				t.Errorf("status %d: %s not recorded", tc.status, n)
			}
		}
		for _, n := range tc.notWant {
			if len(rec.MetricPoints(n)) != 0 {
				t.Errorf("status %d: %s recorded unexpectedly", tc.status, n)
			}
		}
	}
}

func TestDurationAttributesAreBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	rec := telemetrytest.New()
	doGet(t, NewClient(testConfig(rec, nil)), srv.URL+"/secret/path?q=1", "lbl")

	attrs := rec.MetricPoints("t.duration")[0].Attrs
	want := map[string]string{
		AttrHTTPMethod: "GET", AttrHTTPStatusCode: "200", AttrTenantID: "tenant-a", "t.label": "lbl",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attr %s = %v, want %s", k, attrs[k], v)
		}
	}
	if len(attrs) != len(want)+1 || attrs[AttrServerAddress] == "" {
		t.Errorf("attrs = %v, want exactly %d keys plus server.address", attrs, len(want))
	}
}

func TestRedirectsAreRefusedOnlyWhenAsked(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits++ }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	cfg := testConfig(telemetrytest.New(), nil)
	cfg.RefuseRedirects = true
	if got := doGet(t, NewClient(cfg), redirector.URL, "x").StatusCode; got != http.StatusFound || targetHits != 0 {
		t.Errorf("refusing: status %d, target hits %d; want 302 and 0", got, targetHits)
	}

	cfg.RefuseRedirects = false
	if got := doGet(t, NewClient(cfg), redirector.URL, "x").StatusCode; got != http.StatusOK || targetHits != 1 {
		t.Errorf("following: status %d, target hits %d; want 200 and 1", got, targetHits)
	}
}

func TestLimiterGatesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	c := NewClient(testConfig(telemetrytest.New(), rate.NewLimiter(rate.Every(150*time.Millisecond), 1)))

	start := time.Now()
	doGet(t, c, srv.URL, "x")
	doGet(t, c, srv.URL, "x")
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("second request took %v in total; limiter did not gate", elapsed)
	}
}

func TestNilEmitterPassesThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }))
	defer srv.Close()
	cfg := testConfig(telemetrytest.New(), nil)
	cfg.Emitter = nil
	if got := doGet(t, NewClient(cfg), srv.URL, "x").StatusCode; got != 429 {
		t.Errorf("status %d, want 429", got)
	}
}
