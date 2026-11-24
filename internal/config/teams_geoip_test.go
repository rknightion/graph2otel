package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTeamsGeoIPConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`otlp:
  protocol: stdout
tenants:
  - tenant_id: 00000000-0000-0000-0000-000000000001
    teams:
      geoip:
        asn_db: asn.mmdb
        city_db: city.mmdb
  - tenant_id: 00000000-0000-0000-0000-000000000002
  - tenant_id: 00000000-0000-0000-0000-000000000003
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("G2O_TENANTS__0__TEAMS__GEOIP__ASN_DB", "")
	t.Setenv("G2O_TENANTS__1__TEAMS__GEOIP__ASN_DB", "different.mmdb")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Tenants[0].Teams.GeoIP; got != (TeamsGeoIPConfig{CityDB: "city.mmdb"}) {
		t.Errorf("first tenant = %+v, want only YAML city path after clearing ASN", got)
	}
	if got := cfg.Tenants[1].Teams; got == nil || got.GeoIP != (TeamsGeoIPConfig{ASNDB: "different.mmdb"}) {
		t.Errorf("second tenant = %+v, want only environment ASN path", got)
	}
	if cfg.Tenants[2].Teams != nil {
		t.Error("unconfigured tenant inherited settings")
	}
	t.Setenv("G2O_TENANTS__3__TEAMS__GEOIP__CITY_DB", "out-of-range.mmdb")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "G2O_TENANTS__3__TEAMS__GEOIP__CITY_DB: tenant index out of range") {
		t.Fatalf("out-of-range override error = %v", err)
	}
}
