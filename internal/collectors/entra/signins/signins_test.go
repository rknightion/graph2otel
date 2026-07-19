package signins

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
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveInteractiveSignIn is a VERBATIM GET /auditLogs/signIns record from the
// m7kni tenant's v1.0 interactive stream, read as graph2otel-poller on
// 2026-07-17 `[live-measured 2026-07-17, #165]`. It is the first of five records
// returned by GET /auditLogs/signIns?$top=5 (v1.0, no filter — the default
// collection is the interactive user slice this package's `entra.signins.interactive`
// stream polls; the other three streams are beta-only via BaseURLOverride).
//
// It is the POLLED envelope's native wire shape, which is distinct from the blob
// envelope pinned in realBlobFailure (the polled record has no diagnostic-settings
// wrapper — the sign-in fields sit at the top level, not under a `properties`
// object). Pinning it separately is the point: the inner sign-in fields overlap
// the blob record but the surrounding shape does not, and the polled path is what
// mapSignIn is fed by the logpipeline engine.
//
// The fields graph2otel does not map (appliedConditionalAccessPolicies,
// deviceDetail, isInteractive, location.city/state/geoCoordinates, riskDetail,
// riskEventTypes, riskLevelAggregated, userDisplayName, status.additionalDetails)
// are left in on purpose so this stays a faithful sample of what the endpoint
// returns. UPN and corporate identity are retained (SIEM by design).
//
// REDACTED for a public repo (the mapper reads none of these, so it is
// shape-only): ipAddress, location.city/state, and geoCoordinates were the
// tenant owner's home address in effect — replaced with documentation values
// (2001:db8::/32, London city-center coordinates). Everything else is verbatim.
//
// WIRE FACT worth its own guard (TestLiveInteractiveRecordCarriesNoSignInEventTypes):
// the v1.0 default collection returns NO `signInEventTypes` key. The synthetic
// fixture in TestMapSignInUserSignInSuccess invents one; the interactive stream
// never sees it (isInteractive:true is what the wire carries instead).
const liveInteractiveSignIn = `{
  "appDisplayName": "One Outlook Web",
  "appId": "9199bf20-a13f-4107-85dc-02114787ef48",
  "appliedConditionalAccessPolicies": [
    {
      "displayName": "Reduced reauth frequency at home",
      "enforcedGrantControls": [],
      "enforcedSessionControls": ["SignInFrequency"],
      "id": "3fa9321f-1213-47c8-87be-eeb71bb4e6fc",
      "result": "success"
    },
    {
      "displayName": "Require multifactor authentication for all users",
      "enforcedGrantControls": ["Mfa"],
      "enforcedSessionControls": [],
      "id": "013f1d6b-785b-4520-b0f9-31bfaefb8e2b",
      "result": "success"
    },
    {
      "displayName": "Block legacy authentication",
      "enforcedGrantControls": ["Block"],
      "enforcedSessionControls": [],
      "id": "738ad89e-6820-4164-84f1-53d295360d42",
      "result": "notApplied"
    }
  ],
  "clientAppUsed": "Browser",
  "conditionalAccessStatus": "success",
  "correlationId": "845e7924-e581-7853-4d9d-56a508b211b9",
  "createdDateTime": "2026-07-17T14:10:02Z",
  "deviceDetail": {
    "browser": "Chrome 151.0.0",
    "deviceId": "",
    "displayName": "",
    "isCompliant": false,
    "isManaged": false,
    "operatingSystem": "MacOs",
    "trustType": null
  },
  "id": "d70d10b6-221a-4840-899d-87ee20ff5900",
  "ipAddress": "2001:db8::1038",
  "isInteractive": true,
  "location": {
    "city": "London",
    "countryOrRegion": "GB",
    "geoCoordinates": {
      "altitude": null,
      "latitude": 51.5074,
      "longitude": -0.1278
    },
    "state": "England"
  },
  "resourceDisplayName": "Office 365 Exchange Online",
  "resourceId": "00000002-0000-0ff1-ce00-000000000000",
  "riskDetail": "none",
  "riskEventTypes": [],
  "riskEventTypes_v2": [],
  "riskLevelAggregated": "none",
  "riskLevelDuringSignIn": "none",
  "riskState": "none",
  "status": {
    "additionalDetails": "MFA requirement satisfied by claim in the token",
    "errorCode": 0,
    "failureReason": "Other."
  },
  "userDisplayName": "Rob Knight",
  "userId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "userPrincipalName": "rob@m7kni.io"
}`

// decodeLive unmarshals a pinned live record into the untyped shape the
// logpipeline engine hands to mapSignIn.
func decodeLive(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decode live record: %v", err)
	}
	return rec
}

// TestLiveInteractiveRecordCarriesNoSignInEventTypes pins the wire fact behind
// this package's one fabrication risk: the v1.0 default /auditLogs/signIns
// collection returns NO `signInEventTypes` property (0 of 5 records in the
// $top=5 capture carried it). The mapper reads that key, so on the interactive
// v1.0 stream the `sign_in_event_types` attribute is never emitted — it exists
// only on the three beta signInEventTypes-filtered streams, whose responses do
// echo the filtered value.
//
// The synthetic TestMapSignInUserSignInSuccess fixture invents
// signInEventTypes:["interactiveUser"] on what it labels a user sign-in; the
// real interactive record carries isInteractive:true instead. This is the same
// class of hand-written fabrication as #142's "platform":"windows" — read this
// test before trusting the synthetic fixture's shape.
func TestLiveInteractiveRecordCarriesNoSignInEventTypes(t *testing.T) {
	rec := decodeLive(t, liveInteractiveSignIn)
	if v, present := rec["signInEventTypes"]; present {
		t.Fatalf("live v1.0 interactive signIn carries signInEventTypes = %v; the interactive stream's mapper assumes it does not", v)
	}
	if v, present := rec["isInteractive"]; !present || v != true {
		t.Errorf("isInteractive = %v (present=%v), want true — the field the v1.0 collection actually uses to mark an interactive sign-in", v, present)
	}
}

// TestMapSignInAgainstLiveInteractiveRecord pins the EXACT attribute set
// mapSignIn produces from a real polled record. Exact-set equality fails on a
// dropped field AND on a fabricated one — the pair of mistakes #142/#153 are
// made of.
//
// Note status_failure_reason = "Other." is emitted on a SUCCESSFUL sign-in
// (errorCode 0): Graph populates failureReason with the placeholder "Other." on
// every success, and the mapper sets the attribute whenever the field is present
// regardless of errorCode. That is faithful to the wire (all 5 captured records
// carry it), so it is pinned here rather than "fixed".
func TestMapSignInAgainstLiveInteractiveRecord(t *testing.T) {
	id, ev := mapSignIn(decodeLive(t, liveInteractiveSignIn))

	if id != "d70d10b6-221a-4840-899d-87ee20ff5900" {
		t.Errorf("dedupe id = %q, want the record's immutable sign-in id", id)
	}
	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != 0 { // SeverityInfo — errorCode 0
		t.Errorf("severity = %v, want Info for a successful sign-in", ev.Severity)
	}

	wantKeys := []string{
		"app_display_name",
		"app_id",
		"client_app_used",
		"conditional_access_status",
		"correlation_id",
		"id",
		"ip_address",
		"location_country_or_region",
		"resource_display_name",
		"resource_id",
		"risk_level_during_sign_in",
		"risk_state",
		"status_error_code",
		"status_failure_reason",
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
		"id":                         "d70d10b6-221a-4840-899d-87ee20ff5900",
		"correlation_id":             "845e7924-e581-7853-4d9d-56a508b211b9",
		"user_principal_name":        "rob@m7kni.io",
		"user_id":                    "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"app_id":                     "9199bf20-a13f-4107-85dc-02114787ef48",
		"app_display_name":           "One Outlook Web",
		"resource_display_name":      "Office 365 Exchange Online",
		"resource_id":                "00000002-0000-0ff1-ce00-000000000000",
		"ip_address":                 "2001:db8::1038",
		"client_app_used":            "Browser",
		"conditional_access_status":  "success",
		"risk_level_during_sign_in":  "none",
		"risk_state":                 "none",
		"location_country_or_region": "GB",
		"status_error_code":          0,
		"status_failure_reason":      "Other.",
	}
	for k, want := range wantScalars {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

// TestCollectorEmitsLiveInteractiveRecordEndToEnd drives the real polled record
// through the logpipeline engine into an emitter, rather than calling mapSignIn
// directly, so the #112 signal gate (testdata/signals.json) goldens the true
// emitted surface of a real interactive sign-in — not the thinner set the
// minimal {id, createdDateTime} fixtures reach the emitter with.
func TestCollectorEmitsLiveInteractiveRecordEndToEnd(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{decodeLive(t, liveInteractiveSignIn)}}
	rec := telemetrytest.New()
	c := newCollector(specByName(t, "entra.signins.interactive"), depsWith(t, f))

	from := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
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
	wantAttrs := map[string]string{
		"user_principal_name":        "rob@m7kni.io",
		"user_id":                    "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
		"app_display_name":           "One Outlook Web",
		"ip_address":                 "2001:db8::1038",
		"conditional_access_status":  "success",
		"location_country_or_region": "GB",
	}
	for k, want := range wantAttrs {
		if v := got.Attrs[k]; v != want {
			t.Errorf("emitted attr %q = %q, want %q", k, v, want)
		}
	}
}

// recordingFetcher is a logpipeline.PageFetcher that returns a fixed set of
// records once and records every requested page URL, so a test can both drain
// records and assert the exact first-page URL the collector built.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func depsWith(t *testing.T, f *recordingFetcher) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  f,
		Store:    checkpoint.NewStore(t.TempDir()),
	}
}

// depsSelf is depsWith plus the exclude_self wiring (#176).
func depsSelf(t *testing.T, f *recordingFetcher, excludeSelf bool, selfClientID string) collectors.WindowDeps {
	t.Helper()
	d := depsWith(t, f)
	d.ExcludeSelf = excludeSelf
	d.SelfClientID = selfClientID
	return d
}

// signInWithApp is a minimal sign-in record carrying an appId, the field the
// service-principal self filter reads.
func signInWithApp(id, appID string) map[string]any {
	return map[string]any{"id": id, "appId": appID, "createdDateTime": "2026-07-01T10:00:00Z"}
}

// TestServicePrincipalStreamExcludesSelfWhenEnabled is the #176 wiring guard: the
// service-principal stream drops the poller's own sign-in (appId == self client
// id) and passes a third party through when exclude_self is on.
func TestServicePrincipalStreamExcludesSelfWhenEnabled(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{
		signInWithApp("self", "POLLER"), signInWithApp("other", "THIRDPARTY"),
	}}
	rec := telemetrytest.New()
	c := newCollector(specByName(t, "entra.signins.service_principal"), depsSelf(t, f, true, "POLLER"))

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].Attrs["id"] != "other" {
		t.Fatalf("emitted %+v, want only the third-party sign-in [other]", logs)
	}
}

// TestServicePrincipalStreamKeepsSelfWhenDisabled is the default-off guard: with
// exclude_self off, the poller's own sign-in ships exactly as before.
func TestServicePrincipalStreamKeepsSelfWhenDisabled(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{
		signInWithApp("self", "POLLER"), signInWithApp("other", "THIRDPARTY"),
	}}
	rec := telemetrytest.New()
	c := newCollector(specByName(t, "entra.signins.service_principal"), depsSelf(t, f, false, "POLLER"))

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if logs := rec.LogRecords(); len(logs) != 2 {
		t.Fatalf("emitted %d, want both sign-ins (filter off)", len(logs))
	}
}

// TestNonServicePrincipalStreamsIgnoreExcludeSelf guards that a user/managed
// stream never filters — a record whose appId matches the poller id is NOT the
// poller and must pass, because only the service-principal stream is
// self-excludable (#176).
func TestNonServicePrincipalStreamsIgnoreExcludeSelf(t *testing.T) {
	for _, name := range []string{"entra.signins.interactive", "entra.signins.non_interactive", "entra.signins.managed_identity"} {
		t.Run(name, func(t *testing.T) {
			f := &recordingFetcher{records: []map[string]any{signInWithApp("a", "POLLER")}}
			rec := telemetrytest.New()
			c := newCollector(specByName(t, name), depsSelf(t, f, true, "POLLER"))

			from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
			if _, err := c.CollectWindow(context.Background(), from, from.Add(2*time.Hour), rec.Emitter()); err != nil {
				t.Fatalf("CollectWindow: %v", err)
			}
			if logs := rec.LogRecords(); len(logs) != 1 {
				t.Fatalf("%s emitted %d, want 1 (non-SP stream never self-filters)", name, len(logs))
			}
		})
	}
}

func specByName(t *testing.T, name string) spec {
	t.Helper()
	for _, s := range specs {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no spec named %q", name)
	return spec{}
}

func TestMapSignInUserSignInSuccess(t *testing.T) {
	rec := map[string]any{
		"id":                      "sign-in-1",
		"correlationId":           "corr-1",
		"createdDateTime":         "2026-07-01T10:00:00Z",
		"userPrincipalName":       "alice@contoso.com",
		"appId":                   "app-guid",
		"appDisplayName":          "Graph Explorer",
		"ipAddress":               "203.0.113.7",
		"clientAppUsed":           "Browser",
		"conditionalAccessStatus": "success",
		"location":                map[string]any{"countryOrRegion": "GB"},
		"signInEventTypes":        []any{"interactiveUser"},
		"status":                  map[string]any{"errorCode": float64(0)},
	}
	id, ev := mapSignIn(rec)
	if id != "sign-in-1" {
		t.Fatalf("dedupe id = %q, want sign-in-1", id)
	}
	if ev.Name != eventName {
		t.Fatalf("event name = %q, want %q", ev.Name, eventName)
	}
	if ev.Severity != 0 { // SeverityInfo
		t.Errorf("successful sign-in severity = %v, want Info", ev.Severity)
	}
	wantAttrs := map[string]any{
		"id":                         "sign-in-1",
		"correlation_id":             "corr-1",
		"user_principal_name":        "alice@contoso.com",
		"ip_address":                 "203.0.113.7",
		"conditional_access_status":  "success",
		"location_country_or_region": "GB",
		"status_error_code":          0,
	}
	for k, want := range wantAttrs {
		if got := ev.Attrs[k]; got != want {
			t.Errorf("attr %q = %v, want %v", k, got, want)
		}
	}
}

func TestMapSignInFailureIsWarn(t *testing.T) {
	rec := map[string]any{
		"id":                "s2",
		"userPrincipalName": "bob@contoso.com",
		"appDisplayName":    "Office",
		"status":            map[string]any{"errorCode": float64(50126), "failureReason": "Invalid credentials"},
	}
	_, ev := mapSignIn(rec)
	if ev.Severity != 1 { // SeverityWarn
		t.Errorf("failed sign-in severity = %v, want Warn", ev.Severity)
	}
	if ev.Attrs["status_error_code"] != 50126 {
		t.Errorf("status_error_code = %v, want 50126", ev.Attrs["status_error_code"])
	}
	if ev.Attrs["status_failure_reason"] != "Invalid credentials" {
		t.Errorf("status_failure_reason = %v", ev.Attrs["status_failure_reason"])
	}
	if !strings.Contains(ev.Body, "failure (50126)") {
		t.Errorf("body = %q, want it to mention the failure code", ev.Body)
	}
}

// #20 acceptance: a service-principal sign-in has no userPrincipalName — the
// attribute must be OMITTED, not emitted empty.
func TestMapSignInServicePrincipalOmitsUserPrincipalName(t *testing.T) {
	rec := map[string]any{
		"id":                   "sp1",
		"servicePrincipalId":   "sp-guid",
		"servicePrincipalName": "my-automation",
		"appId":                "app-guid",
		"resourceDisplayName":  "Microsoft Graph",
		"status":               map[string]any{"errorCode": float64(0)},
	}
	_, ev := mapSignIn(rec)
	if _, present := ev.Attrs["user_principal_name"]; present {
		t.Errorf("service-principal sign-in must not carry user_principal_name, attrs=%v", ev.Attrs)
	}
	if ev.Attrs["service_principal_id"] != "sp-guid" {
		t.Errorf("service_principal_id = %v, want sp-guid", ev.Attrs["service_principal_id"])
	}
	if ev.Attrs["service_principal_name"] != "my-automation" {
		t.Errorf("service_principal_name = %v", ev.Attrs["service_principal_name"])
	}
}

func TestInteractiveIsV1AndDefaultOn(t *testing.T) {
	f := &recordingFetcher{records: []map[string]any{{"id": "a", "createdDateTime": "2026-07-01T10:00:00Z"}}}
	c := newCollector(specByName(t, "entra.signins.interactive"), depsWith(t, f))

	if c.Experimental() {
		t.Error("interactive stream must not be Experimental (it is the v1.0 default slice)")
	}
	if c.RequiredCapability() != license.CapEntraP1 {
		t.Errorf("RequiredCapability = %q, want entra_p1", c.RequiredCapability())
	}

	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if len(f.seenURLs) == 0 {
		t.Fatal("no page fetched")
	}
	u := f.seenURLs[0]
	if !strings.HasPrefix(u, "https://graph.microsoft.com/v1.0/auditLogs/signIns?") {
		t.Errorf("interactive first-page URL = %q, want the v1.0 signIns endpoint", u)
	}
	if strings.Contains(u, "signInEventTypes") {
		t.Errorf("interactive stream must not carry a signInEventTypes filter, URL=%q", u)
	}
}

func TestBetaStreamsUseBetaEndpointAndEventTypeFilter(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
	}{
		{"entra.signins.non_interactive", "nonInteractiveUser"},
		{"entra.signins.service_principal", "servicePrincipal"},
		{"entra.signins.managed_identity", "managedIdentity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &recordingFetcher{records: []map[string]any{{"id": "a", "createdDateTime": "2026-07-01T10:00:00Z"}}}
			c := newCollector(specByName(t, tc.name), depsWith(t, f))
			if !c.Experimental() {
				t.Error("beta signInEventTypes stream must be Experimental (opt-in)")
			}
			from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
			if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), telemetrytest.New().Emitter()); err != nil {
				t.Fatalf("CollectWindow: %v", err)
			}
			u := f.seenURLs[0]
			if !strings.HasPrefix(u, "https://graph.microsoft.com/beta/auditLogs/signIns?") {
				t.Errorf("first-page URL = %q, want the BETA signIns endpoint", u)
			}
			if !strings.Contains(u, "signInEventTypes") || !strings.Contains(u, tc.eventType) {
				t.Errorf("first-page URL = %q, want it to filter signInEventTypes for %q", u, tc.eventType)
			}
		})
	}
}

// The four streams share /auditLogs/signIns but must keep independent
// checkpoints: the same sign-in id in each stream is a distinct event and all
// four must emit it (no cross-stream dedupe collision).
func TestStreamsHaveIndependentCheckpoints(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

	for _, s := range specs {
		f := &recordingFetcher{records: []map[string]any{{"id": "shared", "createdDateTime": "2026-07-01T09:30:00Z"}}}
		d := collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store}
		c := newCollector(s, d)
		if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
			t.Fatalf("%s CollectWindow: %v", s.name, err)
		}
	}

	if got := len(rec.LogRecords()); got != len(specs) {
		t.Fatalf("expected %d emitted records (one per independent stream), got %d — streams collided on a shared checkpoint", len(specs), got)
	}
}

func TestCollectorDrainsEmitsAndPersistsWatermark(t *testing.T) {
	dir := t.TempDir()
	from := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	newest := "2026-07-01T09:45:00Z"

	f := &recordingFetcher{records: []map[string]any{
		{"id": "a", "createdDateTime": "2026-07-01T09:10:00Z", "userPrincipalName": "a@x.com"},
		{"id": "b", "createdDateTime": newest, "userPrincipalName": "b@x.com"},
	}}
	store := checkpoint.NewStore(dir)
	rec := telemetrytest.New()
	c := newCollector(specByName(t, "entra.signins.interactive"), collectors.WindowDeps{TenantID: "t1", Fetcher: f, Store: store})

	if _, err := c.CollectWindow(context.Background(), from, from.Add(time.Hour), rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	if got := len(rec.LogRecords()); got != 2 {
		t.Fatalf("emitted %d records, want 2", got)
	}
	// Checkpoint persisted under the interactive namespace.
	cp, err := store.Load("t1", signInsPath+"#interactive")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Fatal("watermark was not persisted")
	}
	wantHW := time.Date(2026, 7, 1, 9, 45, 0, 0, time.UTC).Add(-logpipelineDefaultSafetyLag)
	if !cp.Watermark.Equal(wantHW) {
		t.Errorf("watermark = %v, want newest(%s) - safetyLag = %v", cp.Watermark, newest, wantHW)
	}
}

// logpipelineDefaultSafetyLag mirrors logpipeline.DefaultSafetyLag (15m), the
// margin the engine trails the watermark by when EndpointConfig.SafetyLag is
// left at its default.
const logpipelineDefaultSafetyLag = 15 * time.Minute
