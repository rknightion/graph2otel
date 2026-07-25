package exoclient

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const signalCaptureTenantID = "signal-capture-tenant"

var signalCaptureRecorder = telemetrytest.New()

func TestMain(m *testing.M) {
	update := flag.Bool("update", false, "rewrite this package's testdata/signals.json golden")
	if !flag.Parsed() {
		flag.Parse()
	}

	code := m.Run()
	if code == 0 {
		if err := signalcapture.GoldenAt(
			"testdata/signals.json",
			*update,
			signalCaptureRecorder,
		); err != nil {
			fmt.Fprintf(os.Stderr, "\nsignal drift: %v\n\n", err)
			code = 1
		}
	}
	os.Exit(code)
}

// TestSignalCatalogCapturesClientTelemetry drives the real Client through each
// response class that defines its self-observability surface. A direct
// transport call would miss the production option wiring and tenant source.
func TestSignalCatalogCapturesClientTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		wantMetrics []string
	}{
		{
			name:        "duration",
			status:      http.StatusOK,
			body:        `{"value":[]}`,
			wantMetrics: []string{metricHTTPClientDuration},
		},
		{
			name:        "4xx",
			status:      http.StatusForbidden,
			body:        `{"error":{"code":"AccessDenied","message":"Invalid Operation"}}`,
			wantMetrics: []string{metricHTTPClientDuration, metricHTTPClient4xx},
		},
		{
			name:        "5xx",
			status:      http.StatusInternalServerError,
			body:        `{"error":{"code":"InternalServerError","message":"Invalid Operation"}}`,
			wantMetrics: []string{metricHTTPClientDuration, metricHTTPClient5xx},
		},
		{
			name:        "429 throttle",
			status:      http.StatusTooManyRequests,
			body:        `{"error":{"code":"TooManyRequests","message":"Invalid Operation"}}`,
			wantMetrics: []string{metricHTTPClientDuration, metricHTTPClient4xx, metricThrottleCount},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)

			client, err := NewClient(
				&auth.TenantAuth{
					TenantID: signalCaptureTenantID,
					Cred:     &fakeCredential{token: "signal-capture-token"},
				},
				Options{
					Emitter: signalCaptureRecorder.Emitter(),
					BaseURL: srv.URL,
					Limiter: rate.NewLimiter(rate.Inf, 1),
					Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
				},
			)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			_, invokeErr := client.Invoke(context.Background(), "Get-QuarantineMessage", nil)
			if tc.status == http.StatusOK && invokeErr != nil {
				t.Fatalf("Invoke: %v", invokeErr)
			}
			if tc.status != http.StatusOK && invokeErr == nil {
				t.Fatalf("Invoke status %d = nil error, want typed service error", tc.status)
			}

			for _, metric := range tc.wantMetrics {
				requireSignalMetricWithTenant(t, metric)
			}
		})
	}
}

func requireSignalMetricWithTenant(t *testing.T, metric string) {
	t.Helper()
	points := signalCaptureRecorder.MetricPoints(metric)
	if len(points) == 0 {
		t.Fatalf("no %s recorded", metric)
	}
	for _, point := range points {
		if got := point.Attrs[attrTenantID]; got != signalCaptureTenantID {
			t.Fatalf("%s tenant_id = %q, want %q", metric, got, signalCaptureTenantID)
		}
	}
}
