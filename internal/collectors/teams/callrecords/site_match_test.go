package callrecords

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// A browser leg carries only a reflexive address. The site and the field that
// matched must both reach the stream log, so an egress-inferred site is never
// mistaken for one matched on the client's own subnet.
func TestSideSiteMatchReachesLog(t *testing.T) {
	csv := filepath.Join(t.TempDir(), "sites.csv")
	rows := "subnet,location,country,latitude,longitude\n" +
		"203.0.113.0/25,Narrow,GB,5,6\n" +
		"203.0.113.0/24,Egress,GB,1,2\n" +
		"198.51.100.0/24,Office,GB,3,4\n"
	if err := os.WriteFile(csv, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := sites.Open(csv)
	if err != nil {
		t.Fatal(err)
	}
	table := file.Snapshot()
	for _, tc := range []struct {
		name        string
		network     Network
		site, match string
	}{
		{"browser with masked egress", Network{ReflexiveIP: "203.0.113.x"}, "Egress", "reflexive_ip_address"},
		{"browser with full egress", Network{ReflexiveIP: "203.0.113.9"}, "Narrow", "reflexive_ip_address"},
		{"client subnet", Network{Subnet: "198.51.100.0", IP: "198.51.100.7", ReflexiveIP: "203.0.113.9"}, "Office", "subnet"},
		{"endpoint IP", Network{IP: "198.51.100.7", ReflexiveIP: "203.0.113.9"}, "Office", "ip_address"},
		{"no match", Network{ReflexiveIP: "192.0.2.1"}, "unmapped", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			side := mapSide(endpoint{}, endpoint{}, tc.network, Device{}, nil, table, sites.Domains{})
			a := telemetry.Attrs{}
			setSide(a, "caller_", side)
			if got := a["caller_site"]; got != tc.site {
				t.Errorf("caller_site = %v, want %q", got, tc.site)
			}
			got, ok := a["caller_site_match"]
			if tc.match == "" && ok {
				t.Errorf("caller_site_match = %v on an unmapped side, want absent", got)
			}
			if tc.match != "" && got != tc.match {
				t.Errorf("caller_site_match = %v, want %q", got, tc.match)
			}
		})
	}
}
