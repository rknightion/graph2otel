package sites_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/teams/sites"
)

const header = "subnet,location,country,latitude,longitude\n"

func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.csv")
	writeCSV(t, path, header+
		"192.0.2.128/25,West,GB,0,-12.25\n"+
		"192.0.2.0/24,Campus,GB,1,2\n"+
		"2001:db8:1::/48,Annex,AU,-12,90\n"+
		"2001:db8::/32,Region,AU,-90,180\n"+
		"10.0.0.0/8,Corporate,GB,3,4\n"+
		"203.0.113.0/25,Narrow,GB,5,6\n"+
		"203.0.113.0/24,Wide,GB,7,8\n")
	file, err := sites.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	table := file.Snapshot()
	west := sites.Site{Name: "West", Country: "GB", Latitude: 0, Longitude: -12.25}
	campus := sites.Site{Name: "Campus", Country: "GB", Latitude: 1, Longitude: 2}
	annex := sites.Site{Name: "Annex", Country: "AU", Latitude: -12, Longitude: 90}
	region := sites.Site{Name: "Region", Country: "AU", Latitude: -90, Longitude: 180}
	narrow := sites.Site{Name: "Narrow", Country: "GB", Latitude: 5, Longitude: 6}
	wide := sites.Site{Name: "Wide", Country: "GB", Latitude: 7, Longitude: 8}
	unmapped := sites.Site{Name: "unmapped"}
	for _, tc := range []struct {
		name, subnet, ip, reflexive string
		want                        sites.Site
		match                       sites.MatchSource
	}{
		{"v4 overlap", "", "192.0.2.128", "", west, sites.MatchIP},
		{"v4 outside narrower range", "", "192.0.2.127", "", campus, sites.MatchIP},
		{"mapped v4", "", "::ffff:192.0.2.128", "", west, sites.MatchIP},
		{"v6 overlap", "", "2001:db8:1::7", "", annex, sites.MatchIP},
		{"v6 outside narrower range", "", "2001:db8:2::7", "", region, sites.MatchIP},
		{"subnet wins over address", "2001:db8:1:42::/64", "192.0.2.1", "", annex, sites.MatchSubnet},
		{"prefix must cover entire subnet", "192.0.2.128/24", "", "", campus, sites.MatchSubnet},
		{"bare subnet address", "192.0.2.128", "", "", west, sites.MatchSubnet},
		{"IP fallback on subnet miss", "198.51.100.0/24", "2001:db8:1::7", "", annex, sites.MatchIP},
		{"IP fallback on malformed subnet", "not-a-subnet", "192.0.2.1", "", campus, sites.MatchIP},
		{"unmapped", "", "198.51.100.1", "", unmapped, sites.MatchNone},
		{"no inputs", "", "", "", unmapped, sites.MatchNone},
		{"reflexive fallback when local fields miss", "", "198.51.100.1", "192.0.2.130", west, sites.MatchReflexive},
		{"reflexive fallback with no local fields", "", "", "2001:db8:1::9", annex, sites.MatchReflexive},
		{"local IP wins over reflexive", "", "192.0.2.1", "192.0.2.130", campus, sites.MatchIP},
		{"masked reflexive matches its /24", "", "", "192.0.2.x", campus, sites.MatchReflexive},
		{"masked reflexive never matches a narrower prefix", "", "", "203.0.113.x", wide, sites.MatchReflexive},
		{"full reflexive matches the narrower prefix", "", "", "203.0.113.9", narrow, sites.MatchReflexive},
		{"private reflexive is a provider hop", "", "", "10.0.17.160", unmapped, sites.MatchNone},
		{"malformed masked reflexive", "", "", "192.0.x", unmapped, sites.MatchNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, match := table.Lookup(tc.subnet, tc.ip, tc.reflexive)
			if got != tc.want || match != tc.match {
				t.Errorf("Lookup() = %+v, %q, want %+v, %q", got, match, tc.want, tc.match)
			}
		})
	}
}

func TestInternalDomains(t *testing.T) {
	domains, err := sites.NewDomains([]string{" Example.COM ", "*.staff.example.com."})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		upn  string
		want bool
	}{
		{" user@eXample.com. ", true},
		{"user@sub.example.com", false},
		{"user@notexample.example", false},
		{"user@example.com.invalid.example", false},
		{"user@staff.example.com", false},
		{"user@region.staff.example.com", true},
		{"user@dept.region.STAFF.EXAMPLE.COM", true},
		{"user@notstaff.example.com", false},
		{"user@.staff.example.com", false},
		{"user@dept..staff.example.com", false},
		{"user@ext@region.staff.example.com", false},
		{"@example.com", false},
		{"user name@example.com", false},
		{"example.com", false},
		{"", false},
	} {
		if got := domains.IsInternal(tc.upn); got != tc.want {
			t.Errorf("IsInternal(%q) = %t, want %t", tc.upn, got, tc.want)
		}
	}
	empty, err := sites.NewDomains(nil)
	if err != nil || empty.IsInternal("user@example.com") {
		t.Fatalf("no configured domains should not mark a participant internal; error = %v", err)
	}
	for _, invalid := range []string{"", "*", "example.*.com", "-example.com", "example..com", "name@example.com"} {
		if _, err := sites.NewDomains([]string{"example.com", invalid}); err == nil || !strings.Contains(err.Error(), "entry 2") {
			t.Errorf("NewDomains accepted %q or did not identify its position: %v", invalid, err)
		}
	}
}

func TestIPAndRelayFacts(t *testing.T) {
	for _, tc := range []struct {
		ip    string
		class sites.IPClass
		relay bool
	}{
		{"", sites.IPUnknown, false},
		{"invalid", sites.IPUnknown, false},
		{"0.0.0.0", sites.IPUnknown, false},
		{"::", sites.IPUnknown, false},
		{"127.0.0.1", sites.IPUnknown, false},
		{"fe80::1%local", sites.IPUnknown, false},
		{"ff02::1", sites.IPUnknown, false},
		{"192.0.2.1", sites.IPPublic, true},
		{"2001:db8::1", sites.IPPublic, true},
		{"192.168.0.1", sites.IPPrivate, true},
		{"::ffff:192.168.0.1", sites.IPPrivate, true},
		{"fd00::1", sites.IPPrivate, true},
		{"100.64.0.0", sites.IPCGNAT, true},
		{"::ffff:100.127.255.255", sites.IPCGNAT, true},
		{netip.MustParseAddr("100.127.255.255").Next().String(), sites.IPPublic, true},
	} {
		if got := sites.ClassifyIP(tc.ip); got != tc.class {
			t.Errorf("ClassifyIP(%q) = %q, want %q", tc.ip, got, tc.class)
		}
		if got := sites.RelayUsed(tc.ip); got != tc.relay {
			t.Errorf("RelayUsed(%q) = %t, want %t", tc.ip, got, tc.relay)
		}
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.csv")
	if file, err := sites.Open(path); file != nil || err == nil {
		t.Fatalf("Open(missing) = (%v, %v), want a startup error", file, err)
	}
	writeCSV(t, path, header+"192.0.2.0/24,West,GB,0,0\n")
	file, err := sites.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	before := file.Snapshot()
	if err := file.Reload(); err != nil || file.Snapshot() != before {
		t.Fatalf("unchanged file should keep its snapshot; error = %v", err)
	}

	t.Run("invalid replacement keeps all of previous snapshot", func(t *testing.T) {
		writeCSV(t, path, header+"192.0.2.0/24,East,GB,0,0\n"+"2001:db8::/32,Annex,AU,0,181\n")
		if err := file.Reload(); err == nil || !strings.Contains(err.Error(), "line 3") {
			t.Fatalf("Reload() = %v, want validation error on line 3", err)
		}
		if got, _ := file.Snapshot().Lookup("", "192.0.2.1", ""); got.Name != "West" {
			t.Errorf("after invalid reload = %q, want West", got.Name)
		}
	})

	t.Run("same size and mtime replacement is detected", func(t *testing.T) {
		writeCSV(t, path, header+"192.0.2.0/24,West,GB,0,0\n")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		replacement := path + ".new"
		writeCSV(t, replacement, header+"192.0.2.0/24,East,GB,0,0\n")
		if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		if err := file.Reload(); err != nil {
			t.Fatal(err)
		}
		if got, _ := file.Snapshot().Lookup("", "192.0.2.1", ""); got.Name != "East" {
			t.Errorf("after valid reload = %q, want East", got.Name)
		}
		if got, _ := before.Lookup("", "192.0.2.1", ""); got.Name != "West" {
			t.Errorf("old snapshot changed to %q, want West", got.Name)
		}
	})

	t.Run("missing replacement retains current table", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		current := file.Snapshot()
		if err := file.Reload(); err == nil || current != file.Snapshot() {
			t.Fatalf("missing file should fail and keep the current table; error = %v", err)
		}
		writeCSV(t, path, "\ufeff"+header) // a header-only table intentionally clears all mappings
		if err := file.Reload(); err != nil {
			t.Fatal(err)
		}
		if got, _ := file.Snapshot().Lookup("", "192.0.2.1", ""); got.Name != "unmapped" {
			t.Errorf("after clearing sites = %q, want unmapped", got.Name)
		}
	})

	t.Run("unconfigured file", func(t *testing.T) {
		file, err := sites.Open("")
		if err != nil {
			t.Fatal(err)
		}
		if err = file.Reload(); err != nil {
			t.Fatal(err)
		}
		if got, _ := file.Snapshot().Lookup("", "192.0.2.1", ""); got.Name != "unmapped" {
			t.Errorf("without a configured file = %q, want unmapped", got.Name)
		}
	})
}

func TestSampleFile(t *testing.T) {
	file, err := sites.Open(filepath.Join("..", "..", "..", "docs", "teams-sites.example.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := file.Snapshot().Lookup("", "192.0.2.130", ""); got.Name != "Example Annex" {
		t.Errorf("sample lookup = %q, want Example Annex", got.Name)
	}
	if got, _ := file.Snapshot().Lookup("", "2001:db8:200::1", ""); got.Name != "Example IPv6 Site" {
		t.Errorf("sample lookup = %q, want Example IPv6 Site", got.Name)
	}
}

func TestCSVValidation(t *testing.T) {
	for _, tc := range []struct {
		name, csv, line, reason string
	}{
		{"missing header", "", "1", "header"},
		{"wrong header", "location,subnet,country,latitude,longitude\n", "1", "header"},
		{"extra column", header + "192.0.2.0/24,Campus,GB,0,0,extra\n", "2", "field"},
		{"invalid CIDR", header + "192.0.2.0/33,Campus,GB,0,0\n", "2", "subnet"},
		{"duplicate masked CIDR", header + "192.0.2.0/24,Campus,GB,0,0\n\n192.0.2.8/24,Annex,GB,0,0\n", "4", "duplicate"},
		{"duplicate mapped CIDR", header + "192.0.2.0/24,Campus,GB,0,0\n::ffff:192.0.2.0/120,Annex,GB,0,0\n", "3", "duplicate"},
		{"empty location", header + "192.0.2.0/24,  ,GB,0,0\n", "2", "location"},
		{"reserved location", header + "192.0.2.0/24,unmapped,GB,0,0\n", "2", "location"},
		{"empty country", header + "192.0.2.0/24,Campus,,0,0\n", "2", "country"},
		{"non-finite latitude", header + "192.0.2.0/24,Campus,GB,NaN,0\n", "2", "latitude"},
		{"latitude out of range", header + "192.0.2.0/24,Campus,GB,-91,0\n", "2", "latitude"},
		{"longitude out of range", header + "192.0.2.0/24,Campus,GB,0,181\n", "2", "longitude"},
		{"broken quote", header + "192.0.2.0/24,\"Campus,GB,0,0\n", "2", "CSV"},
		{"multiline row", header + "192.0.2.0/24,\"Campus\nAnnex\",GB,0,invalid\n", "3", "longitude"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.csv")
			writeCSV(t, path, tc.csv)
			file, err := sites.Open(path)
			if file != nil || err == nil || !strings.Contains(err.Error(), "line "+tc.line) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Open() = (%v, %v), want no file and a %s error on line %s", file, err, tc.reason, tc.line)
			}
		})
	}
}
