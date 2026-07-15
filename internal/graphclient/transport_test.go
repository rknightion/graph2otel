package graphclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// TestTransportRetries429 is the regression guard for the latent m365-exporter
// bug: passing a custom (non-nil) http.Client to the Graph SDK adapter silently
// drops Kiota's default middleware chain — INCLUDING the 429/503 retry handler —
// and there is no compensating retry anywhere. graph2otel re-attaches the default
// middlewares under its own instrumented transport, so a 429 MUST be retried.
// Without the re-attach, this test fails (the first 429 surfaces to the caller).
func TestTransportRetries429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			// No Retry-After header: proves our re-attached retry handler backs
			// off on its own for a 429 that carries no server hint.
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	// RetryDelaySeconds:1 keeps the single backoff short so the test is fast while
	// still exercising the real Kiota retry handler (the thing under test).
	client := newGraphHTTPClient(Options{Emitter: rec.Emitter(), RetryDelaySeconds: 1})

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request through retrying transport: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200 (429 should have been retried)", resp.StatusCode)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("server saw %d calls, want >= 2 (a 429 must be retried, not surfaced)", got)
	}
}

// TestTransportRecordsOTELMetric asserts the OTEL HTTP instrumentation is present
// in the chain: an outbound request records a duration metric to the in-memory
// recorder.
func TestTransportRecordsOTELMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rec := telemetrytest.New()
	client := newGraphHTTPClient(Options{Emitter: rec.Emitter()})

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	found := false
	for _, n := range rec.MetricNames() {
		if n == metricHTTPClientDuration {
			found = true
		}
	}
	if !found {
		t.Errorf("expected metric %q to be recorded; got %v", metricHTTPClientDuration, rec.MetricNames())
	}
}

// TestTransportNilEmitter: instrumentation must be a no-op (not a panic) when no
// emitter is supplied, so the transport is usable without telemetry wired.
func TestTransportNilEmitter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newGraphHTTPClient(Options{})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request with nil emitter: %v", err)
	}
	resp.Body.Close()
}
