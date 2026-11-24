package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const profileTestTenant = "00000000-0000-0000-0000-000000000001"

func TestCollectorProfilesAtStartupAndPreflight(t *testing.T) {
	cfg := loadProfileTestConfig(t, `profiles: [graph]
collectors:
  entra.domains: {enabled: false}
  entra.users: {enabled: true}
  entra.organization: {enabled: true}
tenants:
  - tenant_id: "`+profileTestTenant+`"
    profiles: [teams]
    collectors:
      entra.domains: {enabled: true}
      entra.users: {enabled: false}
`)
	source := setupProfileTestTenant(t, cfg)
	want := []string{"entra.domains", "entra.organization", "m365.collaboration_activity", "m365.servicehealth", "m365.teams"}
	if got := profileTestRegistryNames(source); !slices.Equal(got, want) {
		t.Errorf("registered collectors = %v, want %v", got, want)
	}
	assertProfilesInStatus(t, source)
	reqs, err := requiredCollectorPermissions(cfg, profileTestTenant, allAvailabilityTestCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, req := range reqs {
		got = append(got, req.Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("preflight collectors = %v, want %v", got, want)
	}
	granted := fakePermissionSource{profileTestTenant: {
		"Domain.Read.All", "Organization.Read.All", "Reports.Read.All", "ServiceHealth.Read.All",
		"Team.ReadBasic.All", "TeamSettings.Read.All", "TeamsAppInstallation.Read.All", "Channel.ReadBasic.All",
	}}
	var output, errs strings.Builder
	if exit := runCheckCore(t.Context(), cfg, granted, func(string) []preflight.CollectorReq { return reqs }, &output, &errs); exit != 0 {
		t.Errorf("preflight exit = %d; want success with only selected scopes\n%s\n%s", exit, &output, &errs)
	}
}

func assertProfilesInStatus(t *testing.T, source admin.CollectorSource) {
	t.Helper()
	server := admin.New(config.AdminConfig{Enabled: true}, []admin.CollectorSource{source}, nil, nil, nil, nil, nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/status.json", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d", response.Code)
	}
	var payload struct {
		Tenants []struct {
			Collectors []admin.CollectorStatus
		}
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Tenants) != 1 {
		t.Fatalf("decode status response: %v, tenants %d", err, len(payload.Tenants))
	}
	want := map[string]string{"entra.users": "disabled_by_config", "entra.groups": "profile_not_selected", "m365.activity": "profile_not_selected"}
	for _, row := range payload.Tenants[0].Collectors {
		if reason, ok := want[row.Name]; ok {
			if row.Enabled || row.Availability == nil || row.Availability.State != "disabled" || string(row.Availability.Reason) != reason {
				t.Errorf("%s status: enabled=%v, availability=%+v; want disabled/%s", row.Name, row.Enabled, row.Availability, reason)
			}
			delete(want, row.Name)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing status rows: %v", want)
	}
}

func TestDefaultGraphProfilePreservesLegacyStartup(t *testing.T) {
	// Captured from the same startup with all capabilities and no optional
	// transports on the pre-profile base b538fdd.
	contents, err := os.ReadFile("testdata/graph-default-collectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(contents))
	for name, profiles := range map[string]string{"implicit": "", "explicit": "profiles: [graph]\n"} {
		t.Run(name, func(t *testing.T) {
			cfg := loadProfileTestConfig(t, profiles+`tenants: [{tenant_id: "`+profileTestTenant+`"}]`)
			if got := profileTestRegistryNames(setupProfileTestTenant(t, cfg)); !slices.Equal(got, want) {
				t.Errorf("registered collectors = %v; want legacy default %v", got, want)
			}
		})
	}
}

func TestProfileEnvironmentLayersAtStartup(t *testing.T) {
	t.Setenv("G2O_PROFILES", "graph, teams")
	t.Setenv("G2O_TENANTS__0__PROFILES", "teams")
	cfg := loadProfileTestConfig(t, `profiles: [teams]
tenants:
  - tenant_id: "`+profileTestTenant+`"
    client_id: "00000000-0000-0000-0000-000000000002"
    profiles: [graph]
  - tenant_id: "00000000-0000-0000-0000-000000000003"
`)
	if len(cfg.Tenants) != 2 || cfg.Tenants[0].ClientID != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("indexed env replaced unrelated YAML tenant configuration: %+v", cfg.Tenants)
	}
	want := []string{"m365.collaboration_activity", "m365.servicehealth", "m365.teams"}
	if got := profileTestRegistryNames(setupProfileTestTenant(t, cfg)); !slices.Equal(got, want) {
		t.Errorf("registered collectors = %v, want %v", got, want)
	}
	if got := cfg.SelectedProfiles(cfg.Tenants[1].TenantID).Names(); !slices.Equal(got, []string{"graph", "teams"}) {
		t.Errorf("tenant without a local list inherited %v, want global env [graph teams]", got)
	}
}

func loadProfileTestConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadValidatedConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CheckpointDir = t.TempDir()
	return cfg
}

func setupProfileTestTenant(t *testing.T, cfg *config.Config) admin.CollectorSource {
	t.Helper()
	provider, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		Protocol: "stdout", StdoutWriter: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})

	// Run the real startup wiring without starting any network polls.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx, startupTenantAuth(profileTestTenant), cfg, provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)), graphclient.NewWorkloadLimiter(), map[admin.SkipKey]string{}, &wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: profileTestTenant}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return allAvailabilityTestCapabilities(), nil
		},
	)
	wg.Wait()
	if err != nil || source.StartupFailure != "" || source.Registry == nil || source.Availability == nil {
		t.Fatalf("tenant startup failed: %v, source %+v", err, source)
	}
	return source
}

func profileTestRegistryNames(source admin.CollectorSource) []string {
	var names []string
	for _, entry := range source.Registry.Entries() {
		names = append(names, entry.Collector.Name())
	}
	slices.Sort(names)
	return names
}
