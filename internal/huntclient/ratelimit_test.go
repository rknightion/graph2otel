package huntclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestDefaultLimiterIsConservative pins the deliberately-slow default. The
// advanced-hunting request ceiling is documented (45/min), but the CPU budget is
// shared with humans (#106), so the default must stay well under the request
// ceiling — a poll issues only a handful of queries every several hours.
func TestDefaultLimiterIsConservative(t *testing.T) {
	l := DefaultLimiter()
	if l == nil {
		t.Fatal("DefaultLimiter() = nil, want a limiter")
	}
	if got := float64(l.Limit()); got != DefaultRequestsPerSecond {
		t.Errorf("Limit() = %v/s, want %v/s", got, DefaultRequestsPerSecond)
	}
	// 45/min documented ceiling = 0.75/s. Stay under it.
	if DefaultRequestsPerSecond >= 0.75 {
		t.Errorf("DefaultRequestsPerSecond = %v — must stay under the documented 45/min (0.75/s) ceiling",
			DefaultRequestsPerSecond)
	}
}

// TestDefaultLimiterReturnsIndependentLimiters keeps one tenant's exhausted
// bucket from gating another's.
func TestDefaultLimiterReturnsIndependentLimiters(t *testing.T) {
	first, second := DefaultLimiter(), DefaultLimiter()
	if first == second {
		t.Error("DefaultLimiter() returned the same limiter twice — two tenants would share one bucket")
	}
}

// TestThrottleObserved proves a 429 is counted on graph2otel.hunt.throttle.count
// so an operator can see the shared CPU budget being hit even though the request
// limiter stayed under the documented rate.
func TestThrottleObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"throttled"}}`))
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	ta := &auth.TenantAuth{TenantID: "test-tenant", Cred: fakeCred{}}
	c, err := NewClient(ta, Options{BaseURL: srv.URL, Emitter: rec.Emitter()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Query(context.Background(), "vuln", "T"); err == nil {
		t.Fatal("want error on 429")
	}
	if pts := rec.MetricPoints("graph2otel.hunt.throttle.count"); len(pts) == 0 {
		t.Error("429 should increment graph2otel.hunt.throttle.count")
	}
}
