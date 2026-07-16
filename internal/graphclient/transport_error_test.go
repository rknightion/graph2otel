package graphclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestTransportRecordsHTTP4xx asserts the self-observability 4xx counter is
// emitted for graph2otel's OWN outbound Graph responses, broken out by the
// bounded (tenant, workload, status code) dimensions and never as a 5xx. A 404
// is used because Kiota's retry handler only retries 429/503/504, so exactly one
// attempt reaches the transport.
func TestTransportRecordsHTTP4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	client := newGraphHTTPClient(Options{Emitter: rec.Emitter(), TenantID: "tenant-a"})

	resp, err := client.Get(srv.URL + "/users/abc")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	pts := rec.MetricPoints(metricHTTPClient4xx)
	if len(pts) != 1 {
		t.Fatalf("http_4xx points = %d, want 1: %+v", len(pts), pts)
	}
	p := pts[0]
	if !p.Monotonic {
		t.Errorf("http_4xx must be a monotonic counter")
	}
	if p.Value != 1 {
		t.Errorf("http_4xx value = %v, want 1", p.Value)
	}
	if p.Attrs[attrTenantID] != "tenant-a" {
		t.Errorf("tenant attr = %q, want tenant-a; attrs=%v", p.Attrs[attrTenantID], p.Attrs)
	}
	if p.Attrs[attrWorkload] != string(WorkloadDirectory) {
		t.Errorf("workload attr = %q, want %q; attrs=%v", p.Attrs[attrWorkload], WorkloadDirectory, p.Attrs)
	}
	if p.Attrs[attrHTTPStatusCode] != "404" {
		t.Errorf("status attr = %q, want 404; attrs=%v", p.Attrs[attrHTTPStatusCode], p.Attrs)
	}
	if got := rec.MetricPoints(metricHTTPClient5xx); len(got) != 0 {
		t.Errorf("http_5xx points = %d, want 0 (a 4xx must not be counted as a 5xx)", len(got))
	}
}

// TestTransportRecordsHTTP5xx is the 5xx analog. A 500 is used because it is
// NOT in Kiota's retriable set (429/503/504), so exactly one attempt reaches the
// transport and the workload attribute reflects the request path.
func TestTransportRecordsHTTP5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	client := newGraphHTTPClient(Options{Emitter: rec.Emitter(), TenantID: "tenant-b"})

	resp, err := client.Get(srv.URL + "/deviceManagement/managedDevices")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	pts := rec.MetricPoints(metricHTTPClient5xx)
	if len(pts) != 1 {
		t.Fatalf("http_5xx points = %d, want 1: %+v", len(pts), pts)
	}
	p := pts[0]
	if !p.Monotonic {
		t.Errorf("http_5xx must be a monotonic counter")
	}
	if p.Value != 1 {
		t.Errorf("http_5xx value = %v, want 1", p.Value)
	}
	if p.Attrs[attrTenantID] != "tenant-b" {
		t.Errorf("tenant attr = %q, want tenant-b; attrs=%v", p.Attrs[attrTenantID], p.Attrs)
	}
	if p.Attrs[attrWorkload] != string(WorkloadIntuneDevices) {
		t.Errorf("workload attr = %q, want %q; attrs=%v", p.Attrs[attrWorkload], WorkloadIntuneDevices, p.Attrs)
	}
	if p.Attrs[attrHTTPStatusCode] != "500" {
		t.Errorf("status attr = %q, want 500; attrs=%v", p.Attrs[attrHTTPStatusCode], p.Attrs)
	}
	if got := rec.MetricPoints(metricHTTPClient4xx); len(got) != 0 {
		t.Errorf("http_4xx points = %d, want 0 (a 5xx must not be counted as a 4xx)", len(got))
	}
}

// TestTransportDoesNotCountSuccess asserts 2xx/3xx responses emit neither the
// 4xx nor the 5xx self-obs counter (only client/server errors are counted).
func TestTransportDoesNotCountSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	client := newGraphHTTPClient(Options{Emitter: rec.Emitter(), TenantID: "tenant-c"})

	resp, err := client.Get(srv.URL + "/users")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if got := rec.MetricPoints(metricHTTPClient4xx); len(got) != 0 {
		t.Errorf("http_4xx points = %d, want 0 for a 2xx", len(got))
	}
	if got := rec.MetricPoints(metricHTTPClient5xx); len(got) != 0 {
		t.Errorf("http_5xx points = %d, want 0 for a 2xx", len(got))
	}
}

// TestTransportErrorCounterNilEmitter guards that a nil Emitter is a no-op, not
// a panic, on the error-counting path.
func TestTransportErrorCounterNilEmitter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newGraphHTTPClient(Options{}) // no emitter
	resp, err := client.Get(srv.URL + "/users")
	if err != nil {
		t.Fatalf("request with nil emitter: %v", err)
	}
	resp.Body.Close()
}
