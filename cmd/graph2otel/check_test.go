package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/preflight"
)

// fakePermissionSource is an in-memory preflight.PermissionSource so these
// tests never build a real azidentity credential or touch a live tenant.
type fakePermissionSource map[string][]string

func (f fakePermissionSource) GrantedPermissions(_ context.Context, tenantID string) ([]string, error) {
	return f[tenantID], nil
}

func TestRunCheckCore_AllSatisfied(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	source := fakePermissionSource{"tenant-a": {"AuditLog.Read.All"}}
	reqs := func(string) []preflight.CollectorReq {
		return []preflight.CollectorReq{{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}}}
	}

	var stdout, stderr bytes.Buffer
	code := runCheckCore(context.Background(), cfg, source, reqs, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCheckCore() = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "[OK]") {
		t.Errorf("stdout missing OK line:\n%s", stdout.String())
	}
}

func TestRunCheckCore_MissingPermission(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	source := fakePermissionSource{"tenant-a": {}}
	reqs := func(string) []preflight.CollectorReq {
		return []preflight.CollectorReq{{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}}}
	}

	var stdout, stderr bytes.Buffer
	code := runCheckCore(context.Background(), cfg, source, reqs, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runCheckCore() = %d, want 1 (non-zero on missing permission); stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "MISSING") {
		t.Errorf("stdout missing MISSING line:\n%s", stdout.String())
	}
}

func TestRunCheckCore_NoTenants(t *testing.T) {
	cfg := &config.Config{}
	var stdout, stderr bytes.Buffer
	code := runCheckCore(context.Background(), cfg, fakePermissionSource{}, requiredCollectorPermissions, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCheckCore() = %d, want 0 for zero tenants; stderr=%s", code, stderr.String())
	}
}

// TestDispatch_Check exercises the "check" subcommand routing end-to-end
// through dispatch with a real config file, but a protocol/tenant
// combination (stdout, zero tenants) that means preflight.Run's tenant loop
// never runs and so never needs a real credential — the only combination
// Validate() allows with no tenants configured. This proves dispatch wires
// "check" to runCheck (flag parsing, config load/validate, auth.BuildAll)
// without hitting a live tenant.
func TestDispatch_Check(t *testing.T) {
	path := writeTempConfig(t, validStdoutYAML)
	var stdout, stderr bytes.Buffer
	code := dispatch(context.Background(), []string{"check", "-config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dispatch(check) = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestDispatch_Check_InvalidConfig(t *testing.T) {
	path := writeTempConfig(t, invalidYAML)
	var stdout, stderr bytes.Buffer
	code := dispatch(context.Background(), []string{"check", "-config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("dispatch(check) = %d, want 1 for invalid config", code)
	}
}

// TestDispatch_FallsThroughToRun confirms dispatch still routes non-"check"
// args (including flags like -version, which do not equal "check") to the
// original run, so main.go's existing behavior is unchanged.
func TestDispatch_FallsThroughToRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch(context.Background(), []string{"-version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("dispatch(-version) = %d, want 0; stderr=%s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Errorf("stdout = %q, want %q", got, version)
	}
}
