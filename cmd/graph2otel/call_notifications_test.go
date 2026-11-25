package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_CallNotificationsRequireExplicitOptIn(t *testing.T) {
	// The certificate/key are not needed or opened on ordinary poll-only startup.
	config := validStdoutYAML + "\ncall_notifications:\n  tls_key_file: /nonexistent/synthetic-key.pem\n"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"-config", writeTempConfig(t, config)}, &stdout, &stderr); code != 0 {
		t.Fatalf("disabled notification config returned %d: %s", code, stderr.String())
	}
}

func TestRun_CallNotificationsRejectUnreadableSecretBeforeTenantAuth(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "synthetic-client-state")
	path := writeTempConfig(t, validStdoutYAML+fmt.Sprintf(`
call_notifications:
  enabled: true
  addr: ":8443"
  public_url: https://receiver.example.invalid/graph/call-records
  tls_cert_file: /nonexistent/synthetic-cert.pem
  tls_key_file: /nonexistent/synthetic-key.pem
tenants:
  - tenant_id: "00000000-0000-0000-0000-000000000000"
    call_notification_client_state_file: %q
`, missing))
	// Never start ambient tenant auth if the startup check is bypassed.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"-config", path}, &stdout, &stderr)
	if got := stderr.String(); code != 1 || !strings.Contains(got, "cannot open call notification client_state_file") || strings.Contains(got, missing) {
		t.Fatalf("expected a preflight failure without secret details, exit %d, stderr %s", code, got)
	}
}
