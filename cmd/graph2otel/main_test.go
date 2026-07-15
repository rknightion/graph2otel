package main

import (
	"bytes"
	"context"
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
