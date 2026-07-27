package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/startupevent"
	buildversion "github.com/rknightion/graph2otel/internal/version"
)

// TestRun_EmitsTheStartupMarker is the wiring assertion for #310: the composition
// root really emits graph2otel.startup through the live telemetry pipeline, with
// the canonical build version and the effective config's fingerprint.
//
// It asserts on the stdout exporter's output rather than on a fake, because the
// failure this guards against is the marker never being wired at all — which a
// unit test of internal/startupevent cannot see.
func TestRun_EmitsTheStartupMarker(t *testing.T) {
	const wantVersion = "9.9.9-startup-test"
	oldVersion := buildversion.Version
	buildversion.Version = wantVersion
	t.Cleanup(func() { buildversion.Version = oldVersion })

	path := writeTempConfig(t, validStdoutYAML)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	wantFingerprint, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cancel() // shut down immediately; the marker is emitted before the run loop

	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"-config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	want := []string{
		startupevent.EventName,
		semconv.AttrConfigFingerprint,
		wantFingerprint,
		wantVersion,
	}
	var missing []string
	for _, w := range want {
		if !strings.Contains(out, w) {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		// The exported payload is dumped ONCE, not once per missing string: it is
		// several KB of resource attributes and repeating it buries the finding.
		t.Errorf("exported telemetry is missing %v; got:\n%s", missing, out)
	}
	if len(want) != 4 {
		t.Fatalf("inspected %d expectations, want 4", len(want))
	}
	if strings.Contains(stderr.String(), "startup marker not emitted") {
		t.Errorf("run reported the startup marker as not emitted; stderr=%s", stderr.String())
	}
}
