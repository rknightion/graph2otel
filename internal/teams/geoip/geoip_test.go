package geoip_test

import (
	"errors"
	"io/fs"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/teams/geoip"
	"github.com/rknightion/graph2otel/internal/teams/geoiptest"
)

// Made-up addresses in the IPv6 global unicast range, used only as lookup keys.
const (
	reflexive = "2fff::661"
	relay     = "2fff::662"
)

func TestLookup(t *testing.T) {
	reader, err := geoip.Open(geoiptest.ASN(t), geoiptest.City(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	got, err := reader.Lookup(reflexive, relay)
	if err != nil {
		t.Fatal(err)
	}
	if got.ASN != 64512 || got.Organization != "Example Network" || got.CountryCode != "ZZ" || got.City != "Example City" {
		t.Errorf("unexpected enrichment: %+v", got)
	}
	if got.Latitude == nil || *got.Latitude != 0 || got.Longitude == nil || *got.Longitude != 12.5 {
		t.Errorf("unexpected coordinates: %+v", got)
	}
}

func TestLookupSkipsNonPublicAndRelay(t *testing.T) {
	reader, err := geoip.Open(geoiptest.ASN(t), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})

	// Construct test-only addresses from the standard reserved ranges.
	private := netip.AddrFrom4([4]byte{10, 8, 7, 6})
	for _, tt := range []struct{ name, ip, relayIP string }{
		{"relay only", "", relay},
		{"reflexive also marked as relay", relay, "2fff:0:0:0:0:0:0:662"},
		{"private IPv4", private.String(), relay},
		{"mapped private IPv4", netip.AddrFrom16(private.As16()).String(), relay},
		{"private IPv6", "fd00::1", ""},
		{"carrier NAT", netip.AddrFrom4([4]byte{100, 64, 0, 1}).String(), ""},
		{"link local", netip.AddrFrom4([4]byte{169, 254, 1, 2}).String(), ""},
		{"documentation IPv4", "192.0.2.1", ""},
		{"documentation IPv6", "2001:db8::1", ""},
		{"zoned address", reflexive + "%eth0", ""},
		{"invalid address", "not-an-address", relay},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reader.Lookup(tt.ip, tt.relayIP)
			if err != nil || got != (geoip.Result{}) {
				t.Fatalf("want no enrichment, got %+v, %v", got, err)
			}
		})
	}
}

func TestOpenDisabled(t *testing.T) {
	reader, err := geoip.Open("", "")
	if reader != nil || err != nil {
		t.Fatalf("want enrichment disabled without a reader, got %v, %v", reader, err)
	}
	if got, err := reader.Lookup(reflexive, ""); err != nil || got != (geoip.Result{}) {
		t.Fatalf("disabled lookup: got %+v, %v", got, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("disabled close: %v", err)
	}
}

func TestOpenMissingConfiguredDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.mmdb")
	asn := geoiptest.ASN(t)
	for _, tt := range []struct{ key, asnPath, cityPath string }{
		{"asn_db", missing, ""},
		{"city_db", asn, missing},
	} {
		t.Run(tt.key, func(t *testing.T) {
			reader, err := geoip.Open(tt.asnPath, tt.cityPath)
			if reader != nil {
				if closeErr := reader.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Error("a startup error must not return a usable reader")
			}
			if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "teams.geoip."+tt.key) ||
				!strings.Contains(err.Error(), missing) {
				t.Fatalf("want missing-file error with config key and path, got %v", err)
			}
		})
	}
}
