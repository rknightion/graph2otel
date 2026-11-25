package teamsadminclient

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestDefaultLimiterIsFreshPerCall(t *testing.T) {
	a, b := DefaultLimiter(), DefaultLimiter()
	if a == b {
		t.Error("DefaultLimiter returned a shared limiter")
	}
	if float64(a.Limit()) != 1 || a.Burst() != 2 {
		t.Errorf("limit %v burst %d, want 1/s burst 2", a.Limit(), a.Burst())
	}
}

func TestResourceFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/Skype.Policy/configurations/TenantNetworkSite": "TenantNetworkSite",
		"/Teams.VoiceApps/auto-attendants":               "auto-attendants",
		"/Teams.VoiceApps/callqueues":                    "callqueues",
		"/something/else":                                "other",
		"/":                                              "other",
	} {
		if got := resourceFromPath(path); got != want {
			t.Errorf("resourceFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestErrorStatusesAreCountedAndNotRetried(t *testing.T) {
	for _, tc := range []struct {
		status      int
		wantCounted []string
		wantNot     []string
	}{
		{429, []string{metricHTTPClient4xx, metricThrottleCount}, []string{metricHTTPClient5xx}},
		{500, []string{metricHTTPClient5xx}, []string{metricHTTPClient4xx, metricThrottleCount}},
		{503, []string{metricHTTPClient5xx}, []string{metricHTTPClient4xx, metricThrottleCount}},
		{404, []string{metricHTTPClient4xx}, []string{metricHTTPClient5xx, metricThrottleCount}},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			var hits atomic.Int32
			srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"code":"x","message":"y"}`)
			})
			rec := telemetrytest.New()
			c, _ := newTestClient(t, srv, func(o *Options) { o.Emitter = rec.Emitter() })
			if _, err := c.Configurations(context.Background(), "TenantNetworkSite"); err == nil {
				t.Fatal("nil error")
			}
			if hits.Load() != 1 {
				t.Errorf("server hit %d times, want exactly 1 (no retry)", hits.Load())
			}
			for _, m := range tc.wantCounted {
				pts := rec.MetricPoints(m)
				if len(pts) != 1 || pts[0].Value != 1 {
					t.Errorf("%s = %+v, want one point of 1", m, pts)
					continue
				}
				if pts[0].Attrs["teams_admin.resource"] != "TenantNetworkSite" || pts[0].Attrs["tenant_id"] != testTenantID {
					t.Errorf("%s attrs = %v", m, pts[0].Attrs)
				}
			}
			for _, m := range tc.wantNot {
				if pts := rec.MetricPoints(m); len(pts) != 0 {
					t.Errorf("%s recorded for status %d: %+v", m, tc.status, pts)
				}
			}
		})
	}
}

func TestNoMetricAttributeHoldsAURL(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Skip") != "0" {
			_, _ = io.WriteString(w, `{"CallQueues":[]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	})
	rec := telemetrytest.New()
	c, _ := newTestClient(t, srv, func(o *Options) { o.Emitter = rec.Emitter() })
	_, _ = c.VoiceApps(context.Background(), CallQueues)

	names := rec.MetricNames()
	if len(names) == 0 {
		t.Fatal("no metrics recorded")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "graph2otel.teams_admin.") {
			t.Errorf("metric %q is outside the graph2otel.teams_admin namespace", name)
		}
		for _, pt := range rec.MetricPoints(name) {
			for k, v := range pt.Attrs {
				if strings.Contains(v, "://") || strings.ContainsAny(v, "?=&") || strings.Contains(k, "url") ||
					strings.Contains(v, "First") || strings.Contains(v, "Skip") {
					t.Errorf("%s attribute %s=%q looks like a URL or query", name, k, v)
				}
			}
			if name == metricHTTPClientDuration && pt.Attrs["teams_admin.resource"] != "callqueues" {
				t.Errorf("duration resource = %q, want callqueues", pt.Attrs["teams_admin.resource"])
			}
		}
	}
}
