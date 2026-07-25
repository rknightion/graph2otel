package wirecheck_test

import (
	"flag"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/rknightion/graph2otel/internal/signalcapture"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

var updateSignalGolden = flag.Bool("update", false, "update testdata/signals.json")

// TestSignalGolden captures the production reporter's unexpected-value counter
// through a dedicated recorder; unrelated wirecheck tests cannot alter it.
func TestSignalGolden(t *testing.T) {
	rec := telemetrytest.New()
	reporter := wirecheck.New(
		"capture.collector",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	reporter.Value(
		telemetry.WithTenant(rec.Emitter(), "tenant-capture"),
		"capture_field",
		"new_value",
		wirecheck.NewEnum("known_value"),
	)

	if err := signalcapture.GoldenAt(
		filepath.Join("testdata", "signals.json"),
		*updateSignalGolden,
		rec,
	); err != nil {
		t.Fatal(err)
	}
}
