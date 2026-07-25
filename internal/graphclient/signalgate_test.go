package graphclient

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "update testdata/signals.json")

// TestSignalGolden drives every outbound Graph HTTP self-observability branch
// through the production client construction path. Each branch owns a recorder
// so this package's wider test suite cannot silently expand the catalog.
func TestSignalGolden(t *testing.T) {
	t.Helper()

	var recs []*telemetrytest.Recorder
	for _, tc := range []struct {
		name       string
		statusCode int
		path       string
	}{
		{name: "2xx", statusCode: http.StatusOK, path: "/users"},
		{name: "4xx", statusCode: http.StatusNotFound, path: "/users/missing"},
		{name: "5xx", statusCode: http.StatusInternalServerError, path: "/deviceManagement/managedDevices"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := telemetrytest.New()
			recs = append(recs, rec)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			client := newGraphHTTPClient(Options{Emitter: rec.Emitter(), TenantID: "tenant-capture"})
			resp, err := client.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()
		})
	}

	t.Run("429", func(t *testing.T) {
		rec := telemetrytest.New()
		recs = append(recs, rec)
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.Header().Set(headerRetryAfter, "0.01")
				w.Header().Set(headerThrottleLimitPercentage, "87.5")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
		defer srv.Close()

		client := newGraphHTTPClient(Options{
			Emitter:           rec.Emitter(),
			TenantID:          "tenant-capture",
			Limiter:           NewWorkloadLimiter(),
			RetryDelaySeconds: 1,
		})
		resp, err := client.Get(srv.URL + "/auditLogs/signIns")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
		if calls.Load() < 2 {
			t.Fatalf("server calls = %d, want retry after 429", calls.Load())
		}
	})

	if err := signalcapture.GoldenAt(
		filepath.Join("testdata", "signals.json"),
		*updateSignalGolden,
		recs...,
	); err != nil {
		t.Fatal(err)
	}
}
