package networktopology

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/teams/adminmap"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/teamsadminclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeAdmin returns decoded configurations by name, like the real client.
type fakeAdmin struct {
	data  map[string][]map[string]any
	errOn string
	err   error
	calls []string
}

func (f *fakeAdmin) Configurations(_ context.Context, name string) ([]map[string]any, error) {
	f.calls = append(f.calls, name)
	if f.err != nil && (f.errOn == "" || f.errOn == name) {
		return nil, f.err
	}
	return f.data[name], nil
}

func (*fakeAdmin) VoiceApps(context.Context, teamsadminclient.VoiceAppKind) (teamsadminclient.VoiceAppsResult, error) {
	return teamsadminclient.VoiceAppsResult{}, errors.New("network topology never reads voice apps")
}

// loadFixtures decodes the committed lab fixtures. Calling it twice gives two
// independent decodes.
func loadFixtures(t *testing.T) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{}
	for _, name := range []string{configRegion, configSite, configSubnet} {
		raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var recs []map[string]any
		if err := json.Unmarshal(raw, &recs); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		out[name] = recs
	}
	return out
}

func writeSites(t *testing.T, rows string) *sites.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sites.csv")
	if err := os.WriteFile(path, []byte("subnet,location,country,latitude,longitude\n"+rows), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := sites.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func run(t *testing.T, data map[string][]map[string]any, files *sites.File) (*telemetrytest.Recorder, *recordoutcome.Recorder) {
	t.Helper()
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	c := New(collectors.Deps{TeamsAdmin: &fakeAdmin{data: data}, TeamsSites: files})
	if err := c.Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec, outcomes
}

// twins returns the attributes of every twin of one event, in emission order,
// with the stamps the emitter adds removed.
func twins(rec *telemetrytest.Recorder, event string) []map[string]string {
	var out []map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == event {
			a := maps.Clone(l.Attrs)
			delete(a, semconv.AttrTenantID)
			delete(a, semconv.AttrIngestTransport)
			out = append(out, a)
		}
	}
	return out
}

func coverageGauge(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCoverage) {
		out[p.Attrs[semconv.AttrCoverage]] = p.Value
	}
	return out
}

var sha256Hex = regexp.MustCompile("^[0-9a-f]{64}$")

// checkHash asserts the hash attributes are present and returns the hash,
// removing both from attrs so the rest can be compared exactly.
func checkHash(t *testing.T, attrs map[string]string) string {
	t.Helper()
	h := attrs[semconv.AttrConfigSHA256]
	if !sha256Hex.MatchString(h) {
		t.Errorf("config_sha256 = %q, want 64 hex characters", h)
	}
	if v := attrs[semconv.AttrConfigHashVersion]; v != strconv.Itoa(adminmap.HashVersion) {
		t.Errorf("config_hash_version = %q, want %d", v, adminmap.HashVersion)
	}
	delete(attrs, semconv.AttrConfigSHA256)
	delete(attrs, semconv.AttrConfigHashVersion)
	return h
}

func equalAttrs(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Errorf("%s attributes:\n got  %v\n want %v", what, got, want)
	}
}

func TestRegionTwins_EveryAttribute(t *testing.T) {
	rec, _ := run(t, loadFixtures(t), nil)
	got := twins(rec, eventRegion)
	if len(got) != 2 {
		t.Fatalf("region twins = %d, want 2", len(got))
	}
	checkHash(t, got[0])
	equalAttrs(t, "region 0", got[0], map[string]string{
		semconv.AttrNetworkRegionIdentity:    "TeamsLab_UK",
		semconv.AttrNetworkRegionDescription: "Teams lab 2026-11",
		semconv.AttrNetworkRegionCentralSite: "TeamsLab_UK",
		semconv.AttrNetworkRegionAuthority:   "Tenant",
	})
	checkHash(t, got[1])
	if got[1][semconv.AttrNetworkRegionIdentity] != "TeamsLab_Cloud" {
		t.Errorf("region 1 identity = %q", got[1][semconv.AttrNetworkRegionIdentity])
	}
}

// TestSiteTwins_EveryAttributeAndNullOmission: the fixture site carries nine
// null fields. None may appear, and EnableLocationBasedRouting false (a real
// value) must.
func TestSiteTwins_EveryAttributeAndNullOmission(t *testing.T) {
	rec, _ := run(t, loadFixtures(t), nil)
	got := twins(rec, eventSite)
	if len(got) != 5 {
		t.Fatalf("site twins = %d, want 5", len(got))
	}
	checkHash(t, got[0])
	equalAttrs(t, "site 0", got[0], map[string]string{
		semconv.AttrNetworkSiteIdentity:                   "TeamsLab_Home_LAN",
		semconv.AttrNetworkSiteNetworkRegionId:            "TeamsLab_UK",
		semconv.AttrNetworkSiteDescription:                "Teams lab 2026-11",
		semconv.AttrNetworkSiteEnableLocationBasedRouting: "false",
		semconv.AttrNetworkSiteAuthority:                  "Tenant",
	})
}

// TestSiteTwin_PopulatedOptionalFields covers the fields the lab leaves null, on
// a record built in the test.
func TestSiteTwin_PopulatedOptionalFields(t *testing.T) {
	data := loadFixtures(t)
	site := data[configSite][0]
	site["LocationPolicy"] = "lp"
	site["EmergencyCallRoutingPolicy"] = "ecrp"
	site["EmergencyCallingPolicy"] = "ecp"
	site["NetworkRoamingPolicy"] = "nrp"
	site["SiteAddress"] = "addr"
	site["EnableLocationBasedRouting"] = true
	data[configSite] = data[configSite][:1]
	rec, _ := run(t, data, nil)
	got := twins(rec, eventSite)[0]
	checkHash(t, got)
	equalAttrs(t, "site", got, map[string]string{
		semconv.AttrNetworkSiteIdentity:                   "TeamsLab_Home_LAN",
		semconv.AttrNetworkSiteNetworkRegionId:            "TeamsLab_UK",
		semconv.AttrNetworkSiteDescription:                "Teams lab 2026-11",
		semconv.AttrNetworkSiteEnableLocationBasedRouting: "true",
		semconv.AttrNetworkSiteLocationPolicy:             "lp",
		semconv.AttrNetworkSiteEmergencyCallRoutingPolicy: "ecrp",
		semconv.AttrNetworkSiteEmergencyCallingPolicy:     "ecp",
		semconv.AttrNetworkSiteNetworkRoamingPolicy:       "nrp",
		semconv.AttrNetworkSiteSiteAddress:                "addr",
		semconv.AttrNetworkSiteAuthority:                  "Tenant",
	})
}

// TestSiteTwin_AbsentAndNullBooleanOmitted: a null or absent
// EnableLocationBasedRouting is "not configured", not false.
func TestSiteTwin_AbsentAndNullBooleanOmitted(t *testing.T) {
	for _, set := range []func(map[string]any){
		func(m map[string]any) { delete(m, "EnableLocationBasedRouting") },
		func(m map[string]any) { m["EnableLocationBasedRouting"] = nil },
	} {
		data := loadFixtures(t)
		set(data[configSite][0])
		rec, _ := run(t, data, nil)
		if _, present := twins(rec, eventSite)[0][semconv.AttrNetworkSiteEnableLocationBasedRouting]; present {
			t.Error("a null or absent EnableLocationBasedRouting must be omitted, not defaulted to false")
		}
	}
}

func TestSubnetTwins_EveryAttributeAndNullOmission(t *testing.T) {
	rec, _ := run(t, loadFixtures(t), nil)
	got := twins(rec, eventSubnet)
	if len(got) != 5 {
		t.Fatalf("subnet twins = %d, want 5", len(got))
	}
	checkHash(t, got[0])
	equalAttrs(t, "subnet 0", got[0], map[string]string{
		semconv.AttrNetworkSubnetIdentity:      "10.0.0.0",
		semconv.AttrNetworkSubnetSubnetId:      "10.0.0.0",
		semconv.AttrNetworkSubnetMaskBits:      "24",
		semconv.AttrNetworkSubnetNetworkSiteId: "TeamsLab_Home_LAN",
		semconv.AttrNetworkSubnetDescription:   "Teams lab 2026-11",
		semconv.AttrNetworkSubnetAuthority:     "Tenant",
		semconv.AttrNetworkSubnetCidr:          "10.0.0.0/24",
		semconv.AttrNetworkSubnetCsvCoverage:   coverageNoCSV,
	})
	// Subnet 2 has a null Description: omitted, not empty.
	checkHash(t, got[2])
	if _, present := got[2][semconv.AttrNetworkSubnetDescription]; present {
		t.Error("null Description must be omitted")
	}
	if got[2][semconv.AttrNetworkSubnetCidr] != "172.31.16.0/20" {
		t.Errorf("cidr = %q", got[2][semconv.AttrNetworkSubnetCidr])
	}
}

func TestCollect_AccountsEveryObject(t *testing.T) {
	_, outcomes := run(t, loadFixtures(t), nil)
	got := outcomes.Snapshot().Summarize(nil, false)
	want := recordoutcome.Counts{Fetched: 12, Mapped: 12, Emitted: 12}
	if got.Result != recordoutcome.ResultSuccess || got.Counts != want {
		t.Errorf("outcome = %#v, want success/%#v", got, want)
	}
}

// TestHash_StableAndSensitive: the hash is the same across two independent
// decodes, changes when an exported field changes, and ignores a wire field the
// twin does not export.
func TestHash_StableAndSensitive(t *testing.T) {
	hashes := func(data map[string][]map[string]any) map[string][]string {
		rec, _ := run(t, data, nil)
		out := map[string][]string{}
		for _, ev := range []string{eventRegion, eventSite, eventSubnet} {
			for _, a := range twins(rec, ev) {
				out[ev] = append(out[ev], a[semconv.AttrConfigSHA256])
			}
		}
		return out
	}
	a, b := hashes(loadFixtures(t)), hashes(loadFixtures(t))
	for ev := range a {
		if !slices.Equal(a[ev], b[ev]) {
			t.Errorf("%s hashes differ across two decodes of the same fixture", ev)
		}
	}

	changed := loadFixtures(t)
	changed[configSubnet][0]["MaskBits"] = float64(23)
	changed[configSite][0]["Description"] = "edited"
	changed[configRegion][0]["CentralSite"] = "elsewhere"
	c := hashes(changed)
	for _, ev := range []string{eventRegion, eventSite, eventSubnet} {
		if c[ev][0] == a[ev][0] {
			t.Errorf("%s hash did not change when an exported field changed", ev)
		}
		if !slices.Equal(c[ev][1:], a[ev][1:]) {
			t.Errorf("%s hashes of untouched objects changed", ev)
		}
	}

	unexported := loadFixtures(t)
	unexported[configSite][0]["Subnets"] = []any{"10.9.9.0"}
	if d := hashes(unexported); !slices.Equal(d[eventSite], a[eventSite]) {
		t.Error("a wire field the twin does not export changed the hash")
	}
}

func TestCollect_NilClientErrors(t *testing.T) {
	c := New(collectors.Deps{})
	if err := c.Collect(context.Background(), telemetrytest.New().Emitter(), recordoutcome.NewRecorder()); err == nil {
		t.Fatal("a nil Teams admin client must be an error")
	}
}

func TestCollect_PermissionDenied(t *testing.T) {
	fake := &fakeAdmin{data: loadFixtures(t), err: &teamsadminclient.APIError{StatusCode: http.StatusForbidden, Path: "/Skype.Policy/configurations/TenantNetworkSite"}, errOn: configSite}
	outcomes := recordoutcome.NewRecorder()
	rec := telemetrytest.New()
	err := New(collectors.Deps{TeamsAdmin: fake}).Collect(context.Background(), rec.Emitter(), outcomes)
	if err == nil {
		t.Fatal("a 403 must return a non-nil error")
	}
	if snap := outcomes.Snapshot(); !slices.Contains(snap.Causes, recordoutcome.CausePermissionDenied) {
		t.Errorf("causes = %v, want %s", snap.Causes, recordoutcome.CausePermissionDenied)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("a failed tick emitted %d records, want none", n)
	}
}

func TestCollect_OtherErrorIsSourceError(t *testing.T) {
	fake := &fakeAdmin{data: loadFixtures(t), err: &teamsadminclient.APIError{StatusCode: http.StatusBadGateway}}
	outcomes := recordoutcome.NewRecorder()
	if err := New(collectors.Deps{TeamsAdmin: fake}).Collect(context.Background(), telemetrytest.New().Emitter(), outcomes); err == nil {
		t.Fatal("want error")
	}
	if snap := outcomes.Snapshot(); !slices.Contains(snap.Causes, recordoutcome.CauseSourceError) || slices.Contains(snap.Causes, recordoutcome.CausePermissionDenied) {
		t.Errorf("causes = %v, want only %s", snap.Causes, recordoutcome.CauseSourceError)
	}
}

func TestCoverage_NoCSV(t *testing.T) {
	rec, _ := run(t, loadFixtures(t), nil)
	want := map[string]float64{coverageCovered: 0, coverageUncovered: 0, coverageNoCSV: 5}
	if got := coverageGauge(rec); !maps.Equal(got, want) {
		t.Errorf("gauge = %v, want %v", got, want)
	}
	// A configured-but-disabled file (empty path) has no snapshot: also no_csv.
	disabled, err := sites.Open("")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = run(t, loadFixtures(t), disabled)
	if got := coverageGauge(rec); !maps.Equal(got, want) {
		t.Errorf("disabled file: gauge = %v, want %v", got, want)
	}
}

// TestCoverage_CoveredUncovered drives every class against the five fixture
// subnets plus two built here (an IPv6 subnet, which the lab does not have, and
// a subnet wider than the CSV prefix):
//
//	10.0.0.0/24      CSV 10.0.0.0/24      covered, exact
//	10.0.50.0/24     CSV 10.0.0.0/16      covered, CSV wider than the subnet
//	172.31.16.0/20   CSV 172.31.16.0/24   uncovered, Teams subnet wider than the CSV prefix
//	10.250.1.0/30    no CSV row           uncovered
//	10.250.2.0/30    no CSV row           uncovered
//	2001:db8:1::/48  CSV 2001:db8::/32    covered, IPv6
//	2001:db9::/48    no CSV row           uncovered, IPv6
func TestCoverage_CoveredUncovered(t *testing.T) {
	data := loadFixtures(t)
	data[configSubnet] = append(data[configSubnet],
		map[string]any{"Identity": "2001:db8:1::", "SubnetID": "2001:db8:1::", "MaskBits": float64(48), "NetworkSiteID": "v6"},
		map[string]any{"Identity": "2001:db9::", "SubnetID": "2001:db9::", "MaskBits": float64(48), "NetworkSiteID": "v6b"},
	)
	files := writeSites(t, "10.0.0.0/24,Exact,GB,1,2\n"+
		"10.0.0.0/16,Wide,GB,1,2\n"+
		"172.31.16.0/24,Narrow,GB,1,2\n"+
		"2001:db8::/32,V6,GB,1,2\n")
	rec, _ := run(t, data, files)

	if got, want := coverageGauge(rec), map[string]float64{coverageCovered: 3, coverageUncovered: 4, coverageNoCSV: 0}; !maps.Equal(got, want) {
		t.Errorf("gauge = %v, want %v", got, want)
	}

	type verdict struct{ coverage, site string }
	want := map[string]verdict{
		"10.0.0.0/24":     {coverageCovered, "Exact"},
		"10.0.50.0/24":    {coverageCovered, "Wide"},
		"172.31.16.0/20":  {coverageUncovered, ""},
		"10.250.1.0/30":   {coverageUncovered, ""},
		"10.250.2.0/30":   {coverageUncovered, ""},
		"2001:db8:1::/48": {coverageCovered, "V6"},
		"2001:db9::/48":   {coverageUncovered, ""},
	}
	got := map[string]verdict{}
	for _, a := range twins(rec, eventSubnet) {
		got[a[semconv.AttrNetworkSubnetCidr]] = verdict{a[semconv.AttrNetworkSubnetCsvCoverage], a[semconv.AttrNetworkSubnetCsvSite]}
		if a[semconv.AttrNetworkSubnetCsvCoverage] != coverageCovered {
			if _, present := a[semconv.AttrNetworkSubnetCsvSite]; present {
				t.Errorf("%s: an uncovered subnet must carry no csv site", a[semconv.AttrNetworkSubnetCidr])
			}
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("verdicts:\n got  %v\n want %v", got, want)
	}
}

// TestCoverage_DoesNotMoveTheConfigHash: coverage comes from the operator's
// sites CSV, not from Teams, so adding or changing the CSV must not look like a
// Teams configuration change in config_sha256.
func TestCoverage_DoesNotMoveTheConfigHash(t *testing.T) {
	hashes := func(files *sites.File) map[string]string {
		rec, _ := run(t, loadFixtures(t), files)
		out := map[string]string{}
		for _, a := range twins(rec, eventSubnet) {
			out[a[semconv.AttrNetworkSubnetCidr]] = a[semconv.AttrConfigSHA256]
		}
		return out
	}
	noCSV := hashes(nil)
	withCSV := hashes(writeSites(t, "10.0.0.0/16,Wide,GB,1,2\n"))
	renamed := hashes(writeSites(t, "10.0.0.0/16,Renamed,GB,1,2\n"))
	if len(noCSV) == 0 || !maps.Equal(noCSV, withCSV) || !maps.Equal(withCSV, renamed) {
		t.Errorf("subnet hashes moved with the CSV:\n none    %v\n csv     %v\n renamed %v", noCSV, withCSV, renamed)
	}
}

// TestCoverage_SubnetWithoutCIDR: a subnet missing its address or mask cannot be
// matched, so with a CSV configured it is uncovered; without one, no_csv.
func TestCoverage_SubnetWithoutCIDR(t *testing.T) {
	data := loadFixtures(t)
	data[configSubnet] = []map[string]any{
		{"Identity": "10.0.0.0", "SubnetID": "10.0.0.0", "NetworkSiteID": "x"},
		{"Identity": "10.0.1.0", "MaskBits": float64(24), "NetworkSiteID": "y"},
		{"Identity": "10.0.2.0", "SubnetID": "10.0.2.0", "MaskBits": 24.5},
	}
	files := writeSites(t, "10.0.0.0/8,Big,GB,1,2\n")
	rec, _ := run(t, data, files)
	if got, want := coverageGauge(rec), map[string]float64{coverageCovered: 0, coverageUncovered: 3, coverageNoCSV: 0}; !maps.Equal(got, want) {
		t.Errorf("gauge = %v, want %v", got, want)
	}
	for _, a := range twins(rec, eventSubnet) {
		if _, present := a[semconv.AttrNetworkSubnetCidr]; present {
			t.Errorf("cidr set without both address and mask: %v", a)
		}
	}
	rec, _ = run(t, data, nil)
	if got := coverageGauge(rec)[coverageNoCSV]; got != 3 {
		t.Errorf("no_csv = %v, want 3", got)
	}
}

func TestCollect_EmptyTenantEmitsZeroGauge(t *testing.T) {
	rec, _ := run(t, map[string][]map[string]any{configRegion: {}, configSite: {}, configSubnet: {}}, nil)
	if got, want := coverageGauge(rec), map[string]float64{coverageCovered: 0, coverageUncovered: 0, coverageNoCSV: 0}; !maps.Equal(got, want) {
		t.Errorf("gauge = %v, want all-zero", got)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("empty tenant emitted %d twins", n)
	}
}

// TestAttrKeys_FollowTheNamingRule: every constant that maps one wire field
// equals adminmap.SnakeKey of it. The derived keys are the listed exceptions.
func TestAttrKeys_FollowTheNamingRule(t *testing.T) {
	direct := []struct{ key, prefix, field string }{
		{semconv.AttrNetworkRegionIdentity, "network_region_", "Identity"},
		{semconv.AttrNetworkRegionDescription, "network_region_", "Description"},
		{semconv.AttrNetworkRegionCentralSite, "network_region_", "CentralSite"},
		{semconv.AttrNetworkRegionAuthority, "network_region_", "authority"},
		{semconv.AttrNetworkSiteIdentity, "network_site_", "Identity"},
		{semconv.AttrNetworkSiteNetworkRegionId, "network_site_", "NetworkRegionID"},
		{semconv.AttrNetworkSiteDescription, "network_site_", "Description"},
		{semconv.AttrNetworkSiteEnableLocationBasedRouting, "network_site_", "EnableLocationBasedRouting"},
		{semconv.AttrNetworkSiteLocationPolicy, "network_site_", "LocationPolicy"},
		{semconv.AttrNetworkSiteEmergencyCallRoutingPolicy, "network_site_", "EmergencyCallRoutingPolicy"},
		{semconv.AttrNetworkSiteEmergencyCallingPolicy, "network_site_", "EmergencyCallingPolicy"},
		{semconv.AttrNetworkSiteNetworkRoamingPolicy, "network_site_", "NetworkRoamingPolicy"},
		{semconv.AttrNetworkSiteSiteAddress, "network_site_", "SiteAddress"},
		{semconv.AttrNetworkSiteAuthority, "network_site_", "authority"},
		{semconv.AttrNetworkSubnetIdentity, "network_subnet_", "Identity"},
		{semconv.AttrNetworkSubnetSubnetId, "network_subnet_", "SubnetID"},
		{semconv.AttrNetworkSubnetMaskBits, "network_subnet_", "MaskBits"},
		{semconv.AttrNetworkSubnetNetworkSiteId, "network_subnet_", "NetworkSiteID"},
		{semconv.AttrNetworkSubnetDescription, "network_subnet_", "Description"},
		{semconv.AttrNetworkSubnetAuthority, "network_subnet_", "authority"},
	}
	for _, d := range direct {
		if want := adminmap.SnakeKey(d.prefix, d.field); d.key != want {
			t.Errorf("key %q, SnakeKey(%q, %q) = %q", d.key, d.prefix, d.field, want)
		}
	}
	// Exceptions: derived keys with no single wire field.
	for key, want := range map[string]string{
		semconv.AttrNetworkSubnetCidr:        "network_subnet_cidr",
		semconv.AttrNetworkSubnetCsvCoverage: "network_subnet_csv_coverage",
		semconv.AttrNetworkSubnetCsvSite:     "network_subnet_csv_site",
	} {
		if key != want {
			t.Errorf("derived key %q, want %q", key, want)
		}
	}
}
