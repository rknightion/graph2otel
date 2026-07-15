package graphclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestRateLimitTransportObservesThrottleHeaders drives the transport against a
// 429 response carrying both a Retry-After (so the transport's own backoff
// sleep is skipped — this test is only about the self-obs signals, not
// timing) and the x-ms-throttle-* hint headers, and asserts the counter +
// gauge land with bounded (workload, tenant_id) attributes.
func TestRateLimitTransportObservesThrottleHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerRetryAfter, "0.01")
		w.Header().Set(headerThrottleLimitPercentage, "87.5")
		w.Header().Set(headerThrottleScope, "Tenant")
		w.Header().Set(headerThrottleInformation, "reason=\"tenant throttled\"")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	rt := &rateLimitTransport{
		next:     http.DefaultTransport,
		tenantID: "tenant-a",
		emitter:  rec.Emitter(),
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/auditLogs/signIns", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}

	counters := rec.MetricPoints(metricThrottleCount)
	if len(counters) != 1 {
		t.Fatalf("throttle count points = %d, want 1: %+v", len(counters), counters)
	}
	if got := counters[0].Value; got != 1 {
		t.Errorf("throttle count value = %v, want 1", got)
	}
	if got := counters[0].Attrs[attrWorkload]; got != string(WorkloadReporting) {
		t.Errorf("throttle count workload attr = %q, want %q", got, WorkloadReporting)
	}
	if got := counters[0].Attrs[attrTenantID]; got != "tenant-a" {
		t.Errorf("throttle count tenant_id attr = %q, want %q", got, "tenant-a")
	}
	// Bounded attrs only: exactly workload + tenant_id.
	if len(counters[0].Attrs) != 2 {
		t.Errorf("throttle count attrs = %+v, want exactly {workload, tenant_id}", counters[0].Attrs)
	}

	gauges := rec.MetricPoints(metricThrottleLimitPercentage)
	if len(gauges) != 1 {
		t.Fatalf("throttle limit_percentage points = %d, want 1: %+v", len(gauges), gauges)
	}
	if got := gauges[0].Value; got != 87.5 {
		t.Errorf("throttle limit_percentage value = %v, want 87.5", got)
	}
}

// TestRateLimitTransportSleepsOwnBackoffWithoutRetryAfter asserts the
// workload-aware backoff sleep actually happens when a 429 carries no
// Retry-After header at all.
func TestRateLimitTransportSleepsOwnBackoffWithoutRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	rt := &rateLimitTransport{
		next:     http.DefaultTransport,
		tenantID: "tenant-a",
		backoff:  &Backoff{Base: 20 * time.Millisecond, Max: 100 * time.Millisecond, jitter: noJitter},
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/users", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	start := time.Now()
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("RoundTrip returned after %s, want >= backoff base %s (no Retry-After present)", elapsed, 20*time.Millisecond)
	}
}

// TestRateLimitTransportGatesThroughLimiter asserts the transport calls
// through to the WorkloadLimiter before forwarding: a pre-exhausted bucket
// with a short-deadline context yields the limiter's error rather than a
// round-tripped request.
func TestRateLimitTransportGatesThroughLimiter(t *testing.T) {
	var served bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	limiter := NewWorkloadLimiter()
	// Drain the IPC burst (capacity 1) up front.
	if err := limiter.Wait(context.Background(), "tenant-a", WorkloadIPC); err != nil {
		t.Fatalf("priming wait: %v", err)
	}

	rt := &rateLimitTransport{
		next:     http.DefaultTransport,
		limiter:  limiter,
		tenantID: "tenant-a",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/identityProtection/riskyUsers", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := rt.RoundTrip(req); err == nil {
		t.Error("RoundTrip did not block on an exhausted limiter bucket")
	}
	if served {
		t.Error("request reached the server despite the limiter being exhausted")
	}
}
