package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/version"
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

// TestRunCheckCore_EnabledCollectorMissingPermission exercises the composition
// root rather than an injected fixture: an enabled collector's declared Graph
// role must make `check` fail when the token has no roles.
//
// It fails if requirement selection is replaced with an empty inventory, if
// collector declarations are not read, or if a missing role is reported OK.
func TestRunCheckCore_EnabledCollectorMissingPermission(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	reqs, err := requiredCollectorPermissions(cfg, "tenant-a", license.Capabilities{})
	if err != nil {
		t.Fatalf("requiredCollectorPermissions() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCheckCore(context.Background(), cfg, fakePermissionSource{"tenant-a": {}}, func(string) []preflight.CollectorReq {
		return reqs
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runCheckCore() = %d, want 1 when enabled collector roles are absent; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "[MISSING]") {
		t.Errorf("stdout missing MISSING line for actual enabled collector:\n%s", stdout.String())
	}
}

func TestRequiredCollectorPermissions_SelectionMatchesRuntimeGates(t *testing.T) {
	falseValue := false
	trueValue := true
	cfg := &config.Config{
		Tenants: []config.TenantConfig{{
			TenantID:   "tenant-a",
			BlobIngest: config.BlobIngestConfig{AccountURL: "https://example.blob.core.windows.net"},
			MDCA:       config.MDCAConfig{PortalURL: "https://contoso.portal.cloudappsecurity.com", TokenFile: "unused"},
			ExchangeOnline: config.ExchangeOnlineConfig{
				Enabled: true,
			},
			Hunting: config.HuntingConfig{Enabled: true},
			Collectors: map[string]config.CollectorConfig{
				"entra.users":            {Enabled: &falseValue},
				"m365.message_trace":     {Enabled: &trueValue},
				"mdca.discovery_parse":   {Enabled: &trueValue},
				"entra.directory_audits": {Source: "blob"},
			},
		}},
	}

	reqs, err := requiredCollectorPermissions(cfg, "tenant-a", license.Capabilities{
		license.CapEntraP1:                   true,
		license.CapEntraP2:                   true,
		license.CapWorkloadIdentitiesPremium: true,
		license.CapIntune:                    true,
		license.CapPurviewInfoProtection:     true,
		license.CapPurviewRecordsMgmt:        true,
	})
	if err != nil {
		t.Fatalf("requiredCollectorPermissions() error = %v", err)
	}

	byName := make(map[string]preflight.CollectorReq, len(reqs))
	for _, req := range reqs {
		byName[req.Name] = req
	}
	if _, ok := byName["entra.users"]; ok {
		t.Error("disabled collector entra.users contributed a requirement")
	}
	if _, ok := byName["m365.message_trace"]; !ok {
		t.Error("explicitly enabled high-volume collector m365.message_trace was not selected")
	}
	if got := byName["entra.directory_audits"].UnverifiablePrereqs; len(got) == 0 {
		t.Error("source=blob collector entra.directory_audits did not carry its blob prerequisite")
	} else if strings.Contains(strings.Join(byName["entra.directory_audits"].Permissions, ","), "AuditLog.Read.All") {
		t.Error("graph transport permissions contributed for source=blob collector entra.directory_audits")
	}

	for _, name := range []string{
		"m365.activity",              // O365 factory
		"mdca.discovery_parse",       // MDCA factory
		"m365.exchange_audit_config", // EXO factory
		"defender.oauth_app",         // hunting factory
	} {
		if _, ok := byName[name]; !ok {
			t.Errorf("seven-path coverage: requirement inventory missing %q", name)
		}
	}
}

func TestRequiredCollectorPermissions_O365RolesRemainManual(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{
		TenantID:     "tenant-a",
		O365Activity: config.O365ActivityConfig{ContentTypes: []string{"DLP.All"}},
	}}}
	reqs, err := requiredCollectorPermissions(cfg, "tenant-a", license.Capabilities{})
	if err != nil {
		t.Fatalf("requiredCollectorPermissions() error = %v", err)
	}
	for _, req := range reqs {
		if req.Name != "m365.activity" {
			continue
		}
		if len(req.Permissions) != 0 {
			t.Fatalf("m365.activity Graph permissions = %v, want none for manage.office.com roles", req.Permissions)
		}
		manual := strings.Join(req.UnverifiablePrereqs, "\n")
		if !strings.Contains(manual, "ActivityFeed.Read") || !strings.Contains(manual, "ActivityFeed.ReadDlp") {
			t.Errorf("m365.activity manual prerequisites = %q, want ActivityFeed.Read and ActivityFeed.ReadDlp", manual)
		}
		return
	}
	t.Fatal("m365.activity missing from O365 requirement inventory")
}

func TestRequiredCollectorPermissions_ExchangeWindowRemainsManual(t *testing.T) {
	trueValue := true
	cfg := &config.Config{Tenants: []config.TenantConfig{{
		TenantID:       "tenant-a",
		ExchangeOnline: config.ExchangeOnlineConfig{Enabled: true},
		Collectors: map[string]config.CollectorConfig{
			"m365.message_trace": {Enabled: &trueValue},
		},
	}}}
	reqs, err := requiredCollectorPermissions(cfg, "tenant-a", license.Capabilities{})
	if err != nil {
		t.Fatalf("requiredCollectorPermissions() error = %v", err)
	}
	var messageTrace preflight.CollectorReq
	for _, req := range reqs {
		if req.Name == "m365.message_trace" {
			messageTrace = req
			break
		}
	}
	if messageTrace.Name == "" {
		t.Fatal("m365.message_trace missing from enabled Exchange window inventory")
	}
	if len(messageTrace.Permissions) != 0 {
		t.Fatalf("m365.message_trace Graph permissions = %v, want none", messageTrace.Permissions)
	}
	if got := strings.Join(messageTrace.UnverifiablePrereqs, "\n"); !strings.Contains(got, "Exchange.ManageAsApp") {
		t.Errorf("m365.message_trace manual prerequisites = %q, want Exchange.ManageAsApp", got)
	}

	report := preflight.Check(nil, []preflight.CollectorReq{messageTrace})
	var out bytes.Buffer
	preflight.WriteReport(&out, "tenant-a", report)
	if !strings.Contains(out.String(), "[MANUAL]  m365.message_trace") {
		t.Errorf("WriteReport() omitted Exchange manual prerequisite:\n%s", out.String())
	}
	if strings.Contains(out.String(), "[OK]      m365.message_trace") || strings.Contains(out.String(), "all enabled collectors satisfied.") {
		t.Errorf("WriteReport() falsely claimed Exchange prerequisite proof:\n%s", out.String())
	}
}

func TestPreflightRequirements_UsesDetectedCapabilitiesAndBaseTierOnFailure(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	auths := []*auth.TenantAuth{{TenantID: "tenant-a"}}

	licensed, warnings, err := preflightRequirements(context.Background(), cfg, auths, func(context.Context, *auth.TenantAuth) (license.Capabilities, error) {
		return license.Capabilities{license.CapEntraP1: true}, nil
	})
	if err != nil {
		t.Fatalf("preflightRequirements() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("preflightRequirements() warnings = %v, want none", warnings)
	}
	if !hasRequirement(licensed["tenant-a"], "entra.signins.interactive") {
		t.Error("licensed tenant omitted entra.signins.interactive")
	}

	baseTier, warnings, err := preflightRequirements(context.Background(), cfg, auths, func(context.Context, *auth.TenantAuth) (license.Capabilities, error) {
		return nil, errors.New("subscribedSkus unavailable")
	})
	if err != nil {
		t.Fatalf("preflightRequirements() detection failure error = %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("preflightRequirements() warnings = %v, want one detection warning", warnings)
	}
	if hasRequirement(baseTier["tenant-a"], "entra.signins.interactive") {
		t.Error("base-tier fallback selected the Entra P1 sign-in collector")
	}
}

func TestPreflightRequirements_RejectsMissingTenantAuthByTenantID(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}, {TenantID: "tenant-b"}}}
	_, _, err := preflightRequirements(context.Background(), cfg, []*auth.TenantAuth{{TenantID: "tenant-a"}}, func(context.Context, *auth.TenantAuth) (license.Capabilities, error) {
		return license.Capabilities{}, nil
	})
	if err == nil {
		t.Fatal("preflightRequirements() error = nil, want missing tenant auth error")
	}
	if !strings.Contains(err.Error(), `missing TenantAuth for configured tenant "tenant-b"`) {
		t.Errorf("preflightRequirements() error = %q, want missing tenant-b association", err)
	}
}

func hasRequirement(reqs []preflight.CollectorReq, name string) bool {
	for _, req := range reqs {
		if req.Name == name {
			return true
		}
	}
	return false
}

func TestRunCheckCore_NoTenants(t *testing.T) {
	cfg := &config.Config{}
	var stdout, stderr bytes.Buffer
	code := runCheckCore(context.Background(), cfg, fakePermissionSource{}, func(string) []preflight.CollectorReq { return nil }, &stdout, &stderr)
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
	if got, want := strings.TrimSpace(stdout.String()), version.String(); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}
