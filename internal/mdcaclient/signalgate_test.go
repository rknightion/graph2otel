package mdcaclient

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

var updateSignalGolden = flag.Bool("update", false, "rewrite this package's testdata/signals.json golden")

// TestSelfObservabilitySignalGolden drives the real client transport chain
// through every response class that emits a self-observability metric. A
// dedicated recorder keeps this package's catalog independent of unrelated
// synthetic metrics in the wider test suite.
func TestSelfObservabilitySignalGolden(t *testing.T) {
	rec := telemetrytest.New()

	for _, status := range []int{
		http.StatusOK,
		http.StatusBadRequest,
		http.StatusInternalServerError,
		http.StatusTooManyRequests,
	} {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = io.WriteString(w, `{"total":0,"data":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"error":"signal capture"}`)
			}))
			t.Cleanup(srv.Close)

			client, err := NewClient("signal-gate-tenant", Options{
				BaseURL:    srv.URL,
				Token:      "signal-gate-token",
				Emitter:    rec.Emitter(),
				MaxRetries: 1,
				retryBase:  time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			_, _ = client.Governance(context.Background(), GovernanceQuery{})
		})
	}

	if err := signalcapture.GoldenAt(
		filepath.Join("testdata", "signals.json"),
		*updateSignalGolden,
		rec,
	); err != nil {
		t.Fatal(err)
	}
}
