package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/startupevent"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const vaacTenantFixture = "00000000-0000-0000-0000-000000000001"
const vaacOtherTenantFixture = "00000000-0000-0000-0000-000000000002"
const vaacCollectorName = "teams.voice_apps"

func TestVAACOptInDiscoveredAcrossWindowPathAndPreflight(t *testing.T) {
	var c collector.Collector
	var paths preflightFactoryVisitor
	visitRegisteredCollectorFactories(&paths)
	for _, factory := range paths.window {
		rw := factory(snapshotWindowDeps())
		if rw.Collector != nil && rw.Collector.Name() == vaacCollectorName {
			c = rw.Collector
		}
	}
	if c == nil || collector.TransportOf(c) != telemetry.TransportVAAC {
		t.Fatal("VAAC was not exposed by the existing window registration path")
	}

	const yes = true
	for _, mode := range []struct {
		name                             string
		profiles                         []string
		collectorOverride, enabled, want bool
	}{
		{"graph-default", []string{"graph"}, false, false, false},
		{"teams-default", []string{"teams"}, false, false, false},
		{"explicit-collector-is-not-consent", []string{"teams"}, true, false, false},
		{"enabled-in-other-profile", []string{"graph"}, false, true, false},
		{"opted-in", []string{"teams"}, false, true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			cfg := &config.Config{Profiles: mode.profiles, Tenants: []config.TenantConfig{
				{TenantID: vaacTenantFixture}, {TenantID: vaacOtherTenantFixture},
			}}
			if mode.collectorOverride {
				override := yes
				cfg.Collectors = map[string]config.CollectorConfig{vaacCollectorName: {Enabled: &override}}
			}
			// These paths must not be opened during preflight. They do not exist.
			cfg.Tenants[0].Teams = &config.TeamsConfig{VAAC: &config.VAACConfig{Enabled: mode.enabled, UsernameFile: "/synthetic/no-such-username", PasswordFile: "/synthetic/no-such-password"}}
			caps := license.Capabilities{}
			if _, enabled, _ := collectorGate(c, cfg, vaacTenantFixture, caps); enabled != mode.want {
				t.Fatalf("runtime gate = %t, want %t", enabled, mode.want)
			}
			reqs, err := requiredCollectorPermissions(cfg, vaacTenantFixture, caps)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, req := range reqs {
				if req.Name != vaacCollectorName {
					continue
				}
				found = true
				if len(req.Permissions)+len(req.PermissionAlternatives) != 0 || len(req.UnverifiablePrereqs) != 1 || !strings.Contains(req.UnverifiablePrereqs[0], "cannot be proven from a Graph token") {
					t.Fatal("VAAC preflight must declare only a manual user access prerequisite")
				}
			}
			if found != mode.want {
				t.Fatalf("preflight VAAC = %t, want %t", found, mode.want)
			}
			if _, enabled, _ := collectorGate(c, cfg, vaacOtherTenantFixture, caps); enabled {
				t.Fatal("one tenant's consent enabled VAAC for another tenant")
			}
			inv := resolveAvailabilityInventory(cfg, vaacTenantFixture, caps, true)
			for _, s := range inv {
				if s.Collector != vaacCollectorName {
					continue
				}
				if (s.State == availability.StateStarting) != mode.want || s.Transport != telemetry.TransportVAAC {
					t.Fatalf("VAAC availability = %+v", s)
				}
				return
			}
			t.Fatal("VAAC missing from availability inventory")
		})
	}
}

func TestVAACStartupRegistersAndWarnsOnlyAfterOptIn(t *testing.T) {
	provider, err := telemetry.NewProvider(t.Context(), telemetry.Options{Protocol: "stdout", StdoutWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			cfg := &config.Config{Profiles: []string{"teams"}, CheckpointDir: t.TempDir(), Tenants: []config.TenantConfig{{TenantID: vaacTenantFixture}}}
			cfg.Tenants[0].Teams = &config.TeamsConfig{VAAC: &config.VAACConfig{
				Enabled: enabled, UsernameFile: "/synthetic/username-path", PasswordFile: "/synthetic/password-path",
			}}
			// Exercise the real registry assembly but prevent the scheduler from
			// making any polls. No Graph or VAAC request leaves this test.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var wg sync.WaitGroup
			var logs bytes.Buffer
			source, err := tenantGeoIPReaders(nil).setupTenantWithGraphAndLicenseBuilders(ctx, startupTenantAuth(vaacTenantFixture), cfg, provider,
				slog.New(slog.NewTextHandler(&logs, nil)), graphclient.NewWorkloadLimiter(), map[admin.SkipKey]string{}, &wg,
				func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
					return &graphclient.Client{TenantID: vaacTenantFixture}, nil
				},
				func(context.Context, *graphclient.Client) (license.Capabilities, error) {
					return allAvailabilityTestCapabilities(), nil
				},
			)
			wg.Wait()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, entry := range source.Registry.Entries() {
				found = found || entry.Collector.Name() == vaacCollectorName
			}
			logged := logs.String()
			if found != enabled || strings.Contains(logged, "ROPC") != enabled || strings.Contains(logged, "end-user identities") != enabled || strings.Contains(logged, "/synthetic/") {
				t.Fatal("VAAC registration or risk warning did not match opt-in, or exposed a secret path")
			}
		})
	}
}

func TestVAACConfigRejectsMalformedInputWithoutDisclosure(t *testing.T) {
	const marker = "synthetic-pasted-credential-marker"
	for _, tc := range []struct{ name, yaml string }{
		{"plaintext", "vaac: {enabled: true, username: '" + marker + "', password: '" + marker + "'}"},
		{"invalid-file-shape", "vaac: {enabled: true, username_file: ['" + marker + "']}"},
		{"invalid-path", "vaac: {enabled: true, username_file: '" + marker + "', password_file: '/synthetic/file'}"},
		{"untyped-opt-in", "vaac: {enabled: '" + marker + "'}"},
		{"quoted-opt-in", "vaac: {enabled: 'true', username_file: '/synthetic/username', password_file: '/synthetic/password'}"},
		{"invalid-vaac-shape", "vaac: '" + marker + "'"},
		{"missing-file", "vaac: {enabled: true, username_file: '/synthetic/file'}"},
	} {
		for _, shape := range []struct{ name, yaml string }{
			{"list", "  - tenant_id: %s\n    teams:\n      %s\n"},
			{"singleton", "  tenant_id: %s\n  teams:\n    %s\n"},
		} {
			t.Run(tc.name+"/"+shape.name, func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "config.yaml")
				yaml := "profiles: [teams]\notlp: {protocol: stdout}\ntenants:\n" + fmt.Sprintf(shape.yaml, vaacTenantFixture, tc.yaml)
				if err := os.WriteFile(file, []byte(yaml), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := config.Load(file)
				if err == nil {
					err = cfg.Validate()
				}
				if err == nil || !strings.Contains(err.Error(), "teams.vaac") || strings.Contains(err.Error(), marker) {
					t.Fatal("VAAC config must reject malformed input without exposing its value")
				}
			})
		}
	}
}

func TestVAACStartupFingerprintIncludesConsentNotSecretPaths(t *testing.T) {
	v := &config.VAACConfig{UsernameFile: "/synthetic/marker-one", PasswordFile: "/synthetic/marker-two"}
	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: vaacTenantFixture, Teams: &config.TeamsConfig{VAAC: v}}}}
	original, err := startupevent.Fingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	v.Enabled = true
	enabled, err := startupevent.Fingerprint(cfg)
	if err != nil || enabled == original {
		t.Fatalf("VAAC opt-in did not change startup fingerprint: %v", err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encoded), "synthetic/marker-") {
		t.Fatal("JSON config dump exposed a VAAC secret path")
	}
	v.UsernameFile, v.PasswordFile = "/not-opened/other-one", "/not-opened/other-two"
	if moved, err := startupevent.Fingerprint(cfg); err != nil || moved != enabled {
		t.Fatal("secret path affected the startup fingerprint")
	}
}
