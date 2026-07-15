package preflight

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

// fakeSource is an in-memory PermissionSource fixture for Run's tests, so
// they never touch a real credential or tenant.
type fakeSource struct {
	granted map[string][]string
	err     map[string]error
}

func (f fakeSource) GrantedPermissions(_ context.Context, tenantID string) ([]string, error) {
	if err, ok := f.err[tenantID]; ok {
		return nil, err
	}
	return f.granted[tenantID], nil
}

func TestRun_AllSatisfied(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	src := fakeSource{granted: map[string][]string{"tenant-a": {"AuditLog.Read.All"}}}
	reqs := func(string) []CollectorReq {
		return []CollectorReq{{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}}}
	}

	var out bytes.Buffer
	ok, err := Run(context.Background(), RunOptions{Config: cfg, Source: src, Requirements: reqs, Out: &out})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !ok {
		t.Errorf("Run() ok = false, want true; output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "[OK]") {
		t.Errorf("output missing OK line:\n%s", out.String())
	}
}

func TestRun_MissingPermission(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	src := fakeSource{granted: map[string][]string{"tenant-a": {}}}
	reqs := func(string) []CollectorReq {
		return []CollectorReq{{Name: "sign_ins", Permissions: []string{"AuditLog.Read.All"}}}
	}

	var out bytes.Buffer
	ok, err := Run(context.Background(), RunOptions{Config: cfg, Source: src, Requirements: reqs, Out: &out})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if ok {
		t.Error("Run() ok = true, want false when a required permission is missing")
	}
	if !strings.Contains(out.String(), "MISSING") {
		t.Errorf("output missing MISSING line:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "AuditLog.Read.All") {
		t.Errorf("output missing the missing permission name:\n%s", out.String())
	}
}

func TestRun_SourceError(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	src := fakeSource{err: map[string]error{"tenant-a": errors.New("token request failed")}}

	var out bytes.Buffer
	ok, err := Run(context.Background(), RunOptions{Config: cfg, Source: src, Out: &out})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil (per-tenant errors are reported in output, not returned)", err)
	}
	if ok {
		t.Error("Run() ok = true, want false when a tenant's permission enumeration fails")
	}
	if !strings.Contains(out.String(), "ERROR") {
		t.Errorf("output missing ERROR line:\n%s", out.String())
	}
}

func TestRun_NilRequirements_TrivallyOK(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	src := fakeSource{granted: map[string][]string{"tenant-a": nil}}

	var out bytes.Buffer
	ok, err := Run(context.Background(), RunOptions{Config: cfg, Source: src, Out: &out})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !ok {
		t.Errorf("Run() ok = false, want true when no requirements are declared yet; output:\n%s", out.String())
	}
}

func TestRun_NilConfig(t *testing.T) {
	var out bytes.Buffer
	if _, err := Run(context.Background(), RunOptions{Source: fakeSource{}, Out: &out}); err == nil {
		t.Fatal("Run() error = nil, want error for nil Config")
	}
}

func TestRun_NilSource(t *testing.T) {
	var out bytes.Buffer
	if _, err := Run(context.Background(), RunOptions{Config: &config.Config{}, Out: &out}); err == nil {
		t.Fatal("Run() error = nil, want error for nil Source")
	}
}

func TestRun_ExportExceptionNoted(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	src := fakeSource{granted: map[string][]string{"tenant-a": {"DeviceManagementManagedDevices.ReadWrite.All"}}}
	reqs := func(string) []CollectorReq {
		return []CollectorReq{{Name: "intune_reports_export", Permissions: []string{"DeviceManagementManagedDevices.ReadWrite.All"}}}
	}

	var out bytes.Buffer
	ok, err := Run(context.Background(), RunOptions{Config: cfg, Source: src, Requirements: reqs, Out: &out})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !ok {
		t.Errorf("Run() ok = false, want true; output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "expected exception") {
		t.Errorf("output missing the expected-exception note:\n%s", out.String())
	}
}
