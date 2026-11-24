package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/teams/geoip"
	"github.com/rknightion/graph2otel/internal/teams/geoiptest"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestTeamsGeoIPReaderOwnership(t *testing.T) {
	asn, city := geoiptest.ASN(t), geoiptest.City(t)
	cfg := &config.Config{Tenants: []config.TenantConfig{
		{TenantID: "asn", Teams: &config.TeamsConfig{GeoIP: config.TeamsGeoIPConfig{ASNDB: asn}}},
		{TenantID: "city", Teams: &config.TeamsConfig{GeoIP: config.TeamsGeoIPConfig{CityDB: city}}},
		{TenantID: "disabled", Teams: &config.TeamsConfig{}},
	}}
	assertClosed := func(t *testing.T, reader *geoip.Reader) {
		t.Helper()
		if result, err := reader.Lookup("2fff::661", ""); err == nil || !strings.Contains(err.Error(), "closed database") {
			t.Errorf("reader still usable after cleanup: result=%+v err=%v", result, err)
		}
	}
	t.Run("close all", func(t *testing.T) {
		readers, err := openTeamsGeoIP(cfg, geoip.Open)
		if err != nil {
			t.Fatal(err)
		}
		if len(readers) != 2 || readers["asn"] == nil || readers["city"] == nil || readers["disabled"] != nil {
			t.Errorf("readers not isolated by tenant: %v", readers)
		}
		if got, err := readers["asn"].Lookup("2fff::661", ""); err != nil || got.ASN != 64512 || got.City != "" {
			t.Errorf("ASN-only reader: %+v, %v", got, err)
		}
		if got, err := readers["city"].Lookup("2fff::661", ""); err != nil || got.City != "Example City" || got.ASN != 0 {
			t.Errorf("city-only reader: %+v, %v", got, err)
		}
		if err := readers.close(); err != nil {
			t.Fatal(err)
		}
		assertClosed(t, readers["asn"])
		assertClosed(t, readers["city"])
	})
	t.Run("roll back on later tenant failure", func(t *testing.T) {
		cfg.Tenants[1].Teams.GeoIP.CityDB = filepath.Join(t.TempDir(), "missing.mmdb")
		var opened *geoip.Reader
		readers, err := openTeamsGeoIP(cfg, func(a, c string) (*geoip.Reader, error) {
			r, err := geoip.Open(a, c)
			if r != nil {
				opened = r
			}
			return r, err
		})
		if err == nil || readers != nil || opened == nil {
			t.Fatalf("want startup failure with no readers returned after opening the first tenant; got %v, %v", readers, err)
		}
		assertClosed(t, opened)
	})
}

func TestTeamsGeoIPStartupValidation(t *testing.T) {
	originalTelemetry, originalAuth := buildTelemetryProvider, buildTenantAuths
	buildTelemetryProvider = func(context.Context, *config.Config, io.Writer) (*telemetry.Provider, error) {
		return nil, errors.New("unexpected telemetry constructor")
	}
	buildTenantAuths = func([]config.TenantConfig) ([]*auth.TenantAuth, error) {
		return nil, errors.New("unexpected credential constructor")
	}
	t.Cleanup(func() { buildTelemetryProvider, buildTenantAuths = originalTelemetry, originalAuth })
	dir := t.TempDir()
	invalid := filepath.Join(dir, "not-a-database.mmdb")
	if err := os.WriteFile(invalid, []byte("invalid MMDB"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, db, reason string }{
		{"asn_db", filepath.Join(dir, "missing.mmdb"), "no such file"},
		{"city_db", invalid, "invalid MaxMind DB"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			path := writeTempConfig(t, fmt.Sprintf(`otlp:
  protocol: stdout
checkpoint_dir: %q
tenants:
  - tenant_id: 00000000-0000-0000-0000-000000000001
  - tenant_id: 00000000-0000-0000-0000-000000000002
    teams:
      geoip:
        %s: %q
`, dir, tc.key, tc.db))
			for _, prefix := range [][]string{nil, {"check"}} {
				var stdout, stderr bytes.Buffer
				code := dispatch(t.Context(), append(prefix, "-config", path), &stdout, &stderr)
				if code != 1 || !strings.Contains(stderr.String(), "tenants[1].teams.geoip."+tc.key+": open") ||
					!strings.Contains(stderr.String(), tc.db) || !strings.Contains(stderr.String(), tc.reason) ||
					stdout.Len() != 0 || strings.Contains(stderr.String(), "graph2otel starting") {
					t.Errorf("dispatch(%v) = %d, stdout=%q, stderr=%q; want database error before startup", prefix, code, stdout.String(), stderr.String())
				}
			}
		})
	}
}
