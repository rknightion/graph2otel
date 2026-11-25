// Package phonefixture drives registered Teams Phone snapshots with fixture responses.
package phonefixture

import (
	"context"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/inventory"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Graph serves one fixture body per expected request URL.
type Graph map[string]string

// RawGet serves a request without custom headers.
func (f Graph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

// RawGetWithHeaders serves the expected URL or returns an error.
func (f Graph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	body, ok := f[url]
	if !ok {
		return nil, fmt.Errorf("unexpected GET %s", url)
	}
	return []byte(body), nil
}

// Collect runs a registered collector and checks that its outcome accounts for every twin.
func Collect(t *testing.T, poller string, pages Graph) *telemetrytest.Recorder {
	t.Helper()
	for _, build := range collectors.All() {
		c := build(collectors.Deps{Graph: pages})
		if c.Name() != poller {
			continue
		}
		rec := telemetrytest.New()
		counts := recordoutcome.NewRecorder()
		if err := c.Collect(t.Context(), rec.Emitter(), counts); err != nil {
			t.Fatalf("collect %s: %v", poller, err)
		}
		var twins uint64
		for _, log := range rec.LogRecords() {
			if log.EventName != inventory.CompletionEvent {
				twins++
			}
		}
		if got := counts.Snapshot().Summarize(nil, false); got.Result != recordoutcome.ResultSuccess || got.Counts.Fetched != twins || got.Counts.Fetched != got.Counts.Emitted {
			t.Errorf("outcomes do not reconcile with twins: %+v", got)
		}
		return rec
	}
	t.Fatalf("no registered snapshot named %s", poller)
	return nil
}
