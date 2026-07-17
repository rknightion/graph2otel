package riskdetections

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveRiskDetection is a VERBATIM GET /identityProtection/riskDetections record
// from the m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #129]`. It is the risk event #129 synthesized (a
// Tor sign-in), and it is the only real risk record this project has ever seen —
// the collection is empty on a healthy tenant, which is exactly why two mapping
// defects survived to #153.
//
// It is pinned, not hand-written, because a hand-written fixture is what caused
// the bug it now guards: the previous version of this test INVENTED a "riskType"
// key, which made the dead `risk_type` mapper line look tested and green for the
// life of the project. Same failure as #142's `"platform": "windows"`.
//
// Trimmed of nothing, so it stays a faithful record of what the endpoint
// actually returns. Every field on it is now mapped (#159 landed the last five:
// tokenIssuerType, userDisplayName, location.state, location.geoCoordinates and
// additionalInfo's userAgent); the timestamps the engine consumes rather than the
// mapper — activityDateTime, detectedDateTime, lastUpdatedDateTime — are the only
// keys with no attribute of their own.
//
// Note `additionalInfo`: it is a JSON-encoded STRING holding an array of
// {"Key","Value"} pairs — NOT a JSON object. A mapper written against the
// intuitive object shape parses nothing and reports success forever.
const liveRiskDetection = `{
  "id": "661b3630a381bc220d8b84c965daa092f4113dbff677c21450582fd5ca322a19",
  "requestId": "c0ee37b3-2cd2-43c0-a7d9-d36e31425600",
  "correlationId": "39e1e8c0-a497-4e5b-b8a5-354d297c68a9",
  "riskEventType": "anonymizedIPAddress",
  "riskState": "atRisk",
  "riskLevel": "medium",
  "riskDetail": "none",
  "source": "IdentityProtection",
  "detectionTimingType": "realtime",
  "activity": "signin",
  "tokenIssuerType": "AzureAD",
  "ipAddress": "2001:67c:e60:c0c:192:42:116:55",
  "activityDateTime": "2026-07-17T10:07:37.5365166Z",
  "detectedDateTime": "2026-07-17T10:07:37.5365166Z",
  "lastUpdatedDateTime": "2026-07-17T10:09:47.256866Z",
  "userId": "5289e9c7-3945-4ffd-8fd3-d56124baf45d",
  "userDisplayName": "RISK SYNTH - DELETE ME (graph2otel #129)",
  "userPrincipalName": "risk-synth-DELETE-ME@m7kni.io",
  "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0\"},{\"Key\":\"mitreTechniques\",\"Value\":\"T1090.003,T1078\"}]",
  "location": {
    "city": "Camperduin",
    "state": "Noord-Holland",
    "countryOrRegion": "NL",
    "geoCoordinates": {
      "latitude": 52.733,
      "longitude": 4.65
    }
  }
}`

// decodeLive unmarshals a pinned live record into the untyped shape the
// logpipeline engine hands to the mapper.
func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return rec
}

// TestLiveRiskDetectionCarriesNoRiskTypeField pins the WIRE fact behind #153's
// first defect, independent of any mapper behavior: the Graph v1.0 riskDetection
// resource has no `riskType` key. Only `riskEventType` exists.
//
// This is the test to read before re-adding a `risk_type` mapping. The value
// such a line would carry already ships as `risk_event_type` (both are
// "anonymizedIPAddress" on the blob path, where riskType does exist), so
// reintroducing it would emit a duplicate attribute that is present ONLY on
// blob-sourced records — an accidental provenance signal, which #141 owns and
// which must not be smuggled in via an attribute's presence.
func TestLiveRiskDetectionCarriesNoRiskTypeField(t *testing.T) {
	rec := decodeLive(t, liveRiskDetection)
	if v, present := rec["riskType"]; present {
		t.Fatalf("live riskDetection carries riskType = %v; #153's premise (and this package's mapper) assumes it does not", v)
	}
	if got := str(rec, "riskEventType"); got != "anonymizedIPAddress" {
		t.Errorf("riskEventType = %q, want anonymizedIPAddress (the value a risk_type line would have duplicated)", got)
	}
}

// TestMapRiskDetectionAgainstLiveRecord pins the EXACT attribute set the mapper
// produces from the one real record this project has. Exact-set equality is the
// point: it fails on a missing attribute (a dropped field) AND on an unexpected
// one (a fabricated field), which is the pair of mistakes #153 and #142 are made
// of.
func TestMapRiskDetectionAgainstLiveRecord(t *testing.T) {
	id, ev := mapRiskDetection(decodeLive(t, liveRiskDetection))

	if id != "661b3630a381bc220d8b84c965daa092f4113dbff677c21450582fd5ca322a19" {
		t.Errorf("dedupe id = %q, want the record's immutable detection id", id)
	}

	wantKeys := []string{
		"activity",
		"correlation_id",
		"detection_timing_type",
		"id",
		"ip_address",
		"location_city",
		"location_country_or_region",
		"location_latitude",
		"location_longitude",
		"location_state",
		"mitre_techniques",
		"request_id",
		"risk_detail",
		"risk_event_type",
		"risk_level",
		"risk_state",
		"source",
		"token_issuer_type",
		"user_agent",
		"user_display_name",
		"user_id",
		"user_principal_name",
	}
	gotKeys := make([]string, 0, len(ev.Attrs))
	for k := range ev.Attrs {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("attribute key set mismatch\n got: %v\nwant: %v", gotKeys, wantKeys)
	}

	wantScalars := map[string]any{
		"id":                         "661b3630a381bc220d8b84c965daa092f4113dbff677c21450582fd5ca322a19",
		"risk_event_type":            "anonymizedIPAddress",
		"risk_level":                 "medium",
		"risk_state":                 "atRisk",
		"risk_detail":                "none",
		"detection_timing_type":      "realtime",
		"source":                     "IdentityProtection",
		"ip_address":                 "2001:67c:e60:c0c:192:42:116:55",
		"user_principal_name":        "risk-synth-DELETE-ME@m7kni.io",
		"user_id":                    "5289e9c7-3945-4ffd-8fd3-d56124baf45d",
		"correlation_id":             "39e1e8c0-a497-4e5b-b8a5-354d297c68a9",
		"request_id":                 "c0ee37b3-2cd2-43c0-a7d9-d36e31425600",
		"activity":                   "signin",
		"token_issuer_type":          "AzureAD",
		"user_display_name":          "RISK SYNTH - DELETE ME (graph2otel #129)",
		"user_agent":                 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
		"location_city":              "Camperduin",
		"location_state":             "Noord-Holland",
		"location_country_or_region": "NL",
		"location_latitude":          52.733,
		"location_longitude":         4.65,
	}
	for k, want := range wantScalars {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

// TestMapRiskDetectionEmitsMitreTechniques pins #153's third finding: the MITRE
// ATT&CK technique ids Identity Protection buries inside additionalInfo reach the
// log record.
//
// T1090.003 is Multi-hop Proxy — it correctly named the Tor sign-in #129
// synthesized — and T1078 is Valid Accounts. This is the highest-value SIEM
// field on the record and it was being discarded on both transports.
//
// It is a LOG attribute and must never become a metric label (#112): the value
// is per-detection and its combinations are unbounded. This package emits no
// metrics at all, so the boundary holds by construction.
func TestMapRiskDetectionEmitsMitreTechniques(t *testing.T) {
	_, ev := mapRiskDetection(decodeLive(t, liveRiskDetection))

	got, ok := ev.Attrs["mitre_techniques"].([]string)
	if !ok {
		t.Fatalf("mitre_techniques = %#v, want []string parsed out of additionalInfo", ev.Attrs["mitre_techniques"])
	}
	want := []string{"T1090.003", "T1078"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mitre_techniques = %v, want %v", got, want)
	}
}

// TestMapRiskDetectionEmitsUserAgent pins #159's headline field: the client
// string behind a risk detection, which Identity Protection buries in the same
// double-encoded additionalInfo payload as mitreTechniques.
//
// It is a first-order SIEM pivot — "what was the client behind this Tor
// sign-in" — and it was being read past on both transports. The attribute name
// matches entra.graph_activity's existing user_agent.
func TestMapRiskDetectionEmitsUserAgent(t *testing.T) {
	_, ev := mapRiskDetection(decodeLive(t, liveRiskDetection))

	want := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
	if got := ev.Attrs["user_agent"]; got != want {
		t.Errorf("user_agent = %v, want %v (parsed out of additionalInfo)", got, want)
	}
}

// TestAdditionalInfoToleratedShapes pins that the shared additionalInfo parser
// never emits a junk attribute and never panics on a record whose additionalInfo
// is missing, malformed, or simply carries none of the pairs we want. Every case
// must omit the attribute rather than emit an empty one.
//
// This matters more than usual here: additionalInfo's contents are undocumented
// and vary by riskEventType, so most records will legitimately lack a given key.
//
// Both consumers (mitre_techniques and user_agent, #153/#159) are asserted on
// every case because they share one parser: a tolerance bug found via one key
// would otherwise be re-found via the other.
func TestAdditionalInfoToleratedShapes(t *testing.T) {
	cases := []struct {
		name           string
		additionalInfo any
		wantUserAgent  string // "" means the attribute must be omitted
	}{
		{name: "absent", additionalInfo: nil},
		{name: "empty string", additionalInfo: ""},
		{name: "malformed json", additionalInfo: `[{"Key":`},
		{name: "json object rather than the real array shape", additionalInfo: `{"mitreTechniques":"T1078","userAgent":"curl/8.0"}`},
		{name: "array without a mitreTechniques pair", additionalInfo: `[{"Key":"userAgent","Value":"curl/8.0"}]`, wantUserAgent: "curl/8.0"},
		{name: "mitreTechniques present but empty", additionalInfo: `[{"Key":"mitreTechniques","Value":""}]`},
		{name: "userAgent present but empty", additionalInfo: `[{"Key":"userAgent","Value":""}]`},
		{name: "wrong json type entirely", additionalInfo: float64(42)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := map[string]any{"id": "rd-x", "riskLevel": "low"}
			if tc.additionalInfo != nil {
				rec["additionalInfo"] = tc.additionalInfo
			}
			_, ev := mapRiskDetection(rec)
			if v, present := ev.Attrs["mitre_techniques"]; present {
				t.Errorf("mitre_techniques = %#v, want the attribute omitted entirely", v)
			}
			got, present := ev.Attrs["user_agent"]
			switch {
			case tc.wantUserAgent == "" && present:
				t.Errorf("user_agent = %#v, want the attribute omitted entirely", got)
			case tc.wantUserAgent != "" && got != tc.wantUserAgent:
				t.Errorf("user_agent = %#v, want %q", got, tc.wantUserAgent)
			}
		})
	}
}

// TestMapRiskDetectionGeoCoordinatesArePresenceGated pins the one trap in
// mapping geoCoordinates: latitude/longitude are numbers, so presence — not
// truthiness — decides whether the attribute is emitted.
//
// 0,0 is a real coordinate (the Gulf of Guinea, and the classic value of a
// broken geo-IP lookup — precisely the thing a SIEM rule wants to see), but it
// is also float64's zero value. A setStr-style "skip the empty value" guard
// would silently drop it, so the coordinate accessors gate on the type
// assertion instead.
func TestMapRiskDetectionGeoCoordinatesArePresenceGated(t *testing.T) {
	t.Run("zero coordinates are emitted, not treated as absent", func(t *testing.T) {
		rec := map[string]any{
			"id":       "rd-geo-zero",
			"location": map[string]any{"geoCoordinates": map[string]any{"latitude": float64(0), "longitude": float64(0)}},
		}
		_, ev := mapRiskDetection(rec)
		for _, k := range []string{"location_latitude", "location_longitude"} {
			got, present := ev.Attrs[k]
			if !present {
				t.Fatalf("attr %q missing; 0 is a real coordinate, not an absent one", k)
			}
			if got != float64(0) {
				t.Errorf("attr %q = %#v, want float64(0)", k, got)
			}
		}
	})

	t.Run("absent or non-numeric coordinates omit the attributes", func(t *testing.T) {
		cases := []struct {
			name     string
			location map[string]any
		}{
			{"no geoCoordinates", map[string]any{"city": "London"}},
			{"geoCoordinates is not an object", map[string]any{"geoCoordinates": "52.733,4.65"}},
			{"coordinates are strings", map[string]any{"geoCoordinates": map[string]any{"latitude": "52.733", "longitude": "4.65"}}},
			{"latitude only", map[string]any{"geoCoordinates": map[string]any{"latitude": 52.733}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, ev := mapRiskDetection(map[string]any{"id": "rd-geo", "location": tc.location})
				if v, present := ev.Attrs["location_longitude"]; present {
					t.Errorf("location_longitude = %#v, want the attribute omitted entirely", v)
				}
				if tc.name == "latitude only" {
					return // latitude legitimately present; only longitude must be absent
				}
				if v, present := ev.Attrs["location_latitude"]; present {
					t.Errorf("location_latitude = %#v, want the attribute omitted entirely", v)
				}
			})
		}
	})
}

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

// TestMapRiskDetection covers the mapper's plumbing on a synthetic record.
//
// It deliberately carries NO "riskType" key: this fixture used to invent one, and
// asserted a "risk_type" attribute that the live endpoint can never produce. That
// fabrication is what kept the dead mapper line green for the life of the project
// (#153). The authority on this record's shape is liveRiskDetection above; keep
// this fixture a subset of those keys.
func TestMapRiskDetection(t *testing.T) {
	rec := map[string]any{
		"id":                  "rd-1",
		"riskEventType":       "anonymizedIPAddress",
		"riskLevel":           "medium",
		"riskState":           "atRisk",
		"riskDetail":          "none",
		"detectionTimingType": "realtime",
		"source":              "IdentityProtection",
		"ipAddress":           "203.0.113.9",
		"userPrincipalName":   "alice@contoso.com",
		"userId":              "user-guid",
		"correlationId":       "corr-1",
		"requestId":           "req-1",
		"activity":            "signin",
		"detectedDateTime":    "2026-07-01T10:00:00Z",
		"location": map[string]any{
			"city":            "London",
			"countryOrRegion": "GB",
		},
	}

	id, ev := mapRiskDetection(rec)
	if id != "rd-1" {
		t.Fatalf("dedupe id = %q, want rd-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("medium risk severity = %v, want Warn", ev.Severity)
	}

	wantAttrs := map[string]any{
		"id":                         "rd-1",
		"risk_event_type":            "anonymizedIPAddress",
		"risk_level":                 "medium",
		"risk_state":                 "atRisk",
		"risk_detail":                "none",
		"detection_timing_type":      "realtime",
		"source":                     "IdentityProtection",
		"ip_address":                 "203.0.113.9",
		"user_principal_name":        "alice@contoso.com",
		"user_id":                    "user-guid",
		"correlation_id":             "corr-1",
		"request_id":                 "req-1",
		"activity":                   "signin",
		"location_city":              "London",
		"location_country_or_region": "GB",
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

func TestMapRiskDetectionSeverityByRiskLevel(t *testing.T) {
	cases := []struct {
		riskLevel string
		want      telemetry.Severity
	}{
		{"high", telemetry.SeverityError},
		{"medium", telemetry.SeverityWarn},
		{"low", telemetry.SeverityInfo},
		{"hidden", telemetry.SeverityInfo},
		{"", telemetry.SeverityInfo},
	}
	for _, tc := range cases {
		rec := map[string]any{"id": "x", "riskLevel": tc.riskLevel}
		_, ev := mapRiskDetection(rec)
		if ev.Severity != tc.want {
			t.Errorf("riskLevel=%q severity = %v, want %v", tc.riskLevel, ev.Severity, tc.want)
		}
	}
}

func TestMapRiskDetectionOmitsAbsentOptionalFields(t *testing.T) {
	rec := map[string]any{
		"id":        "rd-2",
		"riskLevel": "low",
	}
	_, ev := mapRiskDetection(rec)
	for _, k := range []string{
		"request_id", "activity", "location_city", "location_country_or_region", "ip_address", "correlation_id",
		"location_state", "location_latitude", "location_longitude", "token_issuer_type", "user_agent", "user_display_name",
	} {
		if _, present := ev.Attrs[k]; present {
			t.Errorf("attr %q must be omitted when absent from the record, attrs=%v", k, ev.Attrs)
		}
	}
}

func TestRequiredCapabilityIsEntraP2(t *testing.T) {
	d := collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  &recordingFetcher{},
		Store:    checkpoint.NewStore(t.TempDir()),
	}
	c := newCollector(d)
	if got := c.RequiredCapability(); got != license.CapEntraP2 {
		t.Errorf("RequiredCapability = %q, want %q", got, license.CapEntraP2)
	}
}

func TestRequiredPermissions(t *testing.T) {
	d := collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  &recordingFetcher{},
		Store:    checkpoint.NewStore(t.TempDir()),
	}
	c := newCollector(d)
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "IdentityRiskEvent.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [IdentityRiskEvent.Read.All]", perms)
	}
}

// TestClassifyWorkloadRoutesThroughIPC documents (and guards against
// regression of) the load-bearing fact this collector's schedule tuning
// depends on: the transport classifies this endpoint's path onto the
// Identity Protection workload, not the reporting bucket, so it is
// serialized through the shared 1-req/s-per-tenant IPC limiter alongside
// risky users/SPs and Conditional Access.
func TestClassifyWorkloadRoutesThroughIPC(t *testing.T) {
	if got := graphclient.ClassifyWorkload(riskDetectionsPath); got != graphclient.WorkloadIPC {
		t.Errorf("ClassifyWorkload(%q) = %q, want %q", riskDetectionsPath, got, graphclient.WorkloadIPC)
	}
}

// TestPageSizeIsCappedAt500 guards the live-verified constraint that the
// Identity Protection endpoint rejects $top=1000 with HTTP 400 ("Must be
// between 1 and 500 inclusive"); this collector must request $top=500, not the
// engine's 1000 default.
func TestPageSizeIsCappedAt500(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "detectedDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	if !strings.Contains(f.seenURLs[0], "%24top=500") && !strings.Contains(f.seenURLs[0], "$top=500") {
		t.Errorf("first-page URL = %q, want $top=500 (Identity Protection caps page size at 500)", f.seenURLs[0])
	}
}

// TestCollectorEmitsLiveRecordEndToEnd drives the one real record this project
// has through the engine into an emitter, rather than calling the mapper
// directly like the tests above.
//
// Two things depend on it. First, it proves the #159 fields survive the whole
// path, not just mapRiskDetection. Second, it is what makes testdata/signals.json
// honest: the signal gate goldens the union of what a package's tests EMIT, so
// with only minimal synthetic fixtures reaching the emitter, the golden recorded
// a 4-attribute surface for a collector that really ships 22 — understating the
// exact thing the golden exists to make reviewable.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveRiskDetection)}}
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: checkpoint.NewStore(t.TempDir())})

	from := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(logs))
	}
	got := logs[0]
	if got.EventName != eventName {
		t.Errorf("event name = %q, want %q", got.EventName, eventName)
	}

	// The #159 fields specifically, checked at the emitter rather than the
	// mapper: these are the ones that were on the wire and being dropped.
	wantAttrs := map[string]string{
		"user_agent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
		"token_issuer_type": "AzureAD",
		"user_display_name": "RISK SYNTH - DELETE ME (graph2otel #129)",
		"location_state":    "Noord-Holland",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}

	// The geo coordinates are checked for PRESENCE only, and their values are
	// pinned at the mapper instead (TestMapRiskDetectionAgainstLiveRecord).
	//
	// Not an oversight, and do not "fix" it by asserting values here: they are
	// emitted as OTLP doubles (telemetry.toLogKV maps float64 → log.Float64,
	// which is correct on the wire), but telemetrytest.Recorder flattens every
	// log attribute through log.Value.AsString(), which yields "" for any
	// non-string Kind. So the recorder cannot represent a float attribute's
	// value — a limitation of the test harness, not of the emission. The
	// "AsString / invalid Kind Float64" lines in this package's test output are
	// that same limitation talking.
	for _, k := range []string{"location_latitude", "location_longitude"} {
		if _, present := got.Attrs[k]; !present {
			t.Errorf("emitted attrs missing %q", k)
		}
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "rd-a", "detectedDateTime": "2026-07-01T09:10:00Z", "riskLevel": "low", "userPrincipalName": "a@x.com"},
		{"id": "rd-b", "detectedDateTime": newest, "riskLevel": "high", "userPrincipalName": "b@x.com"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}

	cp, err := store.Load("t1", riskDetectionsPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipeline.DefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag(%v) = %v", cp.Watermark, newest, logpipeline.DefaultSafetyLag, wantHW)
	}
}
