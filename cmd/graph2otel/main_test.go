package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validStdoutYAML = `
otlp:
  protocol: stdout
`

const invalidYAML = `
otlp:
  protocol: not-a-real-protocol
`

// adminEnabledStdoutYAML boots the telemetry provider (stdout) and the admin
// server on an ephemeral port, exercising the M1 composition-root wiring.
const adminEnabledStdoutYAML = `
otlp:
  protocol: stdout
admin:
  enabled: true
  addr: "127.0.0.1:0"
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestRun_Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Errorf("stdout = %q, want %q", got, version)
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_InvalidConfig(t *testing.T) {
	path := writeTempConfig(t, invalidYAML)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
	}
	if stderr.String() == "" {
		t.Errorf("stderr should contain the validation error")
	}
}

func TestRun_MissingFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.String() == "" {
		t.Errorf("stderr should contain the load error")
	}
}

// TestRun_StartsAndShutsDownCleanly exercises the normal path: a valid config
// (stdout mode needs no tenants) starts the process, and canceling ctx makes
// it return cleanly instead of hanging.
func TestRun_StartsAndShutsDownCleanly(t *testing.T) {
	path := writeTempConfig(t, validStdoutYAML)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cancel() // shut down immediately; we're only testing the clean-exit path

	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "starting") {
		t.Errorf("stderr = %q, want a startup log line", stderr.String())
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("stderr = %q, want a shutdown log line", stderr.String())
	}
}

// TestRun_AdminEnabledBootsAndShutsDown exercises the M1 composition root with
// the admin server enabled: the telemetry provider and admin HTTP server start,
// and canceling ctx returns cleanly (the admin server self-shuts-down).
func TestRun_AdminEnabledBootsAndShutsDown(t *testing.T) {
	path := writeTempConfig(t, adminEnabledStdoutYAML)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	// Cancel shortly after boot so the server has bound before shutdown.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("stderr = %q, want a shutdown log line", stderr.String())
	}
}

// TestOtelErrorHandlerLogsThroughTheAppLogger asserts SDK errors reach
// graph2otel's own structured logger at ERROR rather than Go's default log
// package. This channel carries OTLP export rejections — the backend refuses a
// log record older than its 7-day accept window with a 400 naming the limit
// (#226) — so it has to be visible to whatever an operator filters on, and a
// dropped record has to read as an error rather than a note.
func TestOtelErrorHandlerLogsThroughTheAppLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	otelErrorHandler(logger).Handle(errors.New("has timestamp too old: 2026-07-08T13:05:10Z"))

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("output %q, want it logged at ERROR — a rejected record is data loss", out)
	}
	if !strings.Contains(out, "has timestamp too old") {
		t.Errorf("output %q, want the underlying error text preserved", out)
	}
}
