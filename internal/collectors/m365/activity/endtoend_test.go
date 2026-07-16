package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// endtoend_test.go drives the collector through the REAL o365pipeline engine and
// the REAL o365activityclient against an httptest server, rather than against a
// fake of either. The unit tests above cover the mapper in isolation; these
// cover the thing the mapper tests structurally cannot — that the EndpointConfig
// is wired correctly, so the mapper is actually REACHED and its output actually
// ships. A collector whose Map is never called passes every mapper test.
//
// No live tenant is touched.

const testTenantID = "11111111-2222-3333-4444-555555555555"

// fakeCred is a canned azcore.TokenCredential. The client only needs a token to
// put in a header; the httptest server does not check it.
type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeAPI is a minimal Office 365 Management Activity API: it accepts
// subscription starts, lists one content blob per content type, and serves that
// blob's records.
//
// Each content type's blob serves records with DISTINCT ids (the record id is
// suffixed with the content type). That is both realistic — a record belongs to
// one content type — and necessary: the engine dedupes by record id ACROSS
// content types, so a fake serving identical ids in both blobs would have the
// second blob's records silently deduped away, and every count assertion here
// would be measuring the dedupe rather than the mapper.
type fakeAPI struct {
	mu sync.Mutex
	// started records which content types had /subscriptions/start called.
	started []string
	// records is the per-content-type record set, before id suffixing.
	records []map[string]any
	// listed counts /subscriptions/content calls per content type.
	listed map[string]int
	// blobCreated is the listed blob's contentCreated. It must sit inside the
	// collection window, which the engine derives from the real clock.
	blobCreated time.Time
}

func (f *fakeAPI) handler(t *testing.T, baseURL func() string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ct := r.URL.Query().Get("contentType")
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/start"):
			f.started = append(f.started, ct)
			_, _ = fmt.Fprintf(w, `{"contentType":%q,"status":"enabled"}`, ct)

		case strings.HasSuffix(r.URL.Path, "/subscriptions/content"):
			f.listed[ct]++
			// One blob per content type, whose contentUri points back here.
			_, _ = fmt.Fprintf(w, `[{"contentType":%q,"contentId":"blob-%s","contentUri":"%s/api/v1.0/%s/activity/feed/audit/blob-%s","contentCreated":%q,"contentExpiration":%q}]`,
				ct, ct, baseURL(), testTenantID, ct,
				f.blobCreated.Format(time.RFC3339), f.blobCreated.Add(20*24*time.Hour).Format(time.RFC3339))

		case strings.Contains(r.URL.Path, "/activity/feed/audit/blob-"):
			_, blobCT, _ := strings.Cut(r.URL.Path, "/activity/feed/audit/blob-")
			out := make([]map[string]any, 0, len(f.records))
			for _, rec := range f.records {
				clone := maps.Clone(rec)
				clone["Id"] = fmt.Sprintf("%v@%s", rec["Id"], blobCT)
				out = append(out, clone)
			}
			_ = json.NewEncoder(w).Encode(out)

		default:
			t.Errorf("fakeAPI: unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// window returns a collection window the engine will accept. The engine resumes
// a cold start from now-InitialLookback and ignores the caller's `from`, so a
// fixed historical window would produce endTime-before-startTime. Everything
// here is anchored to the real clock for that reason.
func window() (from, to time.Time) {
	now := time.Now().UTC()
	return now.Add(-2 * time.Hour), now.Add(-30 * time.Minute)
}

// newTestCollector wires a real client + real engine at a fakeAPI. Passing
// contentTypes exercises the configured-content-types path; passing none
// exercises the default fallback.
func newTestCollector(t *testing.T, api *fakeAPI, contentTypes ...o365activityclient.ContentType) *collectorImpl {
	t.Helper()
	api.listed = map[string]int{}
	if api.blobCreated.IsZero() {
		api.blobCreated = time.Now().UTC().Add(-time.Hour)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(api.handler(t, func() string { return srv.URL }))
	t.Cleanup(srv.Close)

	client, err := o365activityclient.NewClient(
		&auth.TenantAuth{TenantID: testTenantID, Cred: fakeCred{}},
		o365activityclient.Options{BaseURL: srv.URL},
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return newCollector(collectors.O365Deps{
		Client:       client,
		TenantID:     testTenantID,
		Store:        checkpoint.NewStore(t.TempDir()),
		ContentTypes: contentTypes,
	})
}

// TestConfiguredContentTypesOverrideTheDefault asserts the per-tenant config
// actually reaches the subscription, and does so BEHAVIORALLY — by observing
// which content types are subscribed and listed on the wire, not by reading the
// EndpointConfig back (which is unexported, and which would only prove the
// struct was populated rather than honored).
//
// It deliberately configures Audit.General — a content type the default
// EXCLUDES — so the test cannot pass by accident on the fallback path.
func TestConfiguredContentTypesOverrideTheDefault(t *testing.T) {
	api := &fakeAPI{records: []map[string]any{liveRecord()}}
	c := newTestCollector(t, api, o365activityclient.ContentGeneral)

	from, to := window()
	if _, err := c.CollectWindow(context.Background(), from, to, telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	if got := api.listed[string(o365activityclient.ContentGeneral)]; got == 0 {
		t.Errorf("configured content type Audit.General was never listed; listed = %v", api.listed)
	}
	// The default must NOT also be drained — config REPLACES the default rather
	// than adding to it. Draining both would silently double an operator's bill
	// on an API with no server-side filtering.
	for _, ct := range defaultContentTypes {
		if api.listed[string(ct)] != 0 {
			t.Errorf("default content type %q was listed despite an explicit config; config must replace the default, not extend it", ct)
		}
	}
}

// TestEmptyContentTypesFallsBackToTheDefault pins the other half of the
// contract O365Deps.ContentTypes documents: empty means "use the collector's
// own default", not "subscribe to nothing".
//
// The failure this prevents is silent: a collector that subscribed to nothing
// would report success forever while shipping zero records — indistinguishable
// from a quiet tenant.
func TestEmptyContentTypesFallsBackToTheDefault(t *testing.T) {
	api := &fakeAPI{records: []map[string]any{liveRecord()}}
	c := newTestCollector(t, api) // no content types configured

	from, to := window()
	if _, err := c.CollectWindow(context.Background(), from, to, telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	if len(api.listed) == 0 {
		t.Fatal("no content types were listed at all; an empty O365Deps.ContentTypes must fall back to the default, not subscribe to nothing")
	}
	for _, ct := range defaultContentTypes {
		if api.listed[string(ct)] == 0 {
			t.Errorf("default content type %q was not listed; listed = %v", ct, api.listed)
		}
	}
}

// TestCollectWindowEndToEnd drives a full subscribe -> list -> fetch -> map ->
// emit cycle, proving the EndpointConfig reaches the engine: the mapper is
// called, its event name and attributes ship, and the default content types are
// the ones subscribed and drained.
func TestCollectWindowEndToEnd(t *testing.T) {
	api := &fakeAPI{records: []map[string]any{
		liveRecord(),
		func() map[string]any {
			r := liveRecord()
			r["Id"] = "rec-def-456"
			r["RecordType"] = float64(63) // DLPEndpoint
			r["Workload"] = "Endpoint"
			r["ResultStatus"] = "Failed"
			return r
		}(),
	}}
	c := newTestCollector(t, api)
	rec := telemetrytest.New()

	from, to := window()
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	logs := rec.LogRecords()
	// Two records per content blob, one blob per default content type.
	if want := 2 * len(defaultContentTypes); len(logs) != want {
		t.Fatalf("emitted %d logs, want %d (%d records x %d content types)", len(logs), want, 2, len(defaultContentTypes))
	}

	for _, l := range logs {
		if l.EventName != "m365.audit" {
			t.Errorf("EventName = %q, want m365.audit", l.EventName)
		}
		// The mapper's timestamp must survive the engine — not be replaced with
		// the poll time or the blob's contentCreated (#135).
		if want := time.Date(2026, 7, 16, 9, 15, 0, 0, time.UTC); !l.Timestamp.Equal(want) {
			t.Errorf("Timestamp = %s, want %s (the record's own CreationTime, not the blob's contentCreated 09:20 nor now)",
				l.Timestamp.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	}

	// Every default content type was subscribed and listed — the config's
	// ContentTypes actually reached the engine.
	for _, ct := range defaultContentTypes {
		if api.listed[string(ct)] == 0 {
			t.Errorf("content type %q was never listed", ct)
		}
	}
}

// TestEndToEndEmitsNoMetrics is the #112 guard at the pipeline level, and the
// half the mapper tests cannot reach: it asserts against the real Emitter that
// a full collection cycle over records dense with unbounded per-entity detail
// (UPN, client IP, record id, object id) produces ZERO metric series.
//
// This is the collector's cardinality contract stated positively. Every field
// here is unbounded — a metric keyed by any of them would be one series per
// sign-in, the pathological TSDB case CLAUDE.md calls out. The detail belongs in
// the logs, and this proves that is where all of it goes.
func TestEndToEndEmitsNoMetrics(t *testing.T) {
	// 50 records with 50 distinct users, IPs and record ids: under any mapper
	// that leaked per-entity data into a metric label, this is 50+ series.
	records := make([]map[string]any, 0, 50)
	for i := range 50 {
		r := liveRecord()
		r["Id"] = fmt.Sprintf("rec-%d", i)
		r["UserId"] = fmt.Sprintf("user-%d@contoso.com", i)
		r["ClientIP"] = fmt.Sprintf("203.0.113.%d", i)
		r["ObjectId"] = fmt.Sprintf("obj-%d", i)
		records = append(records, r)
	}
	c := newTestCollector(t, &fakeAPI{records: records})
	rec := telemetrytest.New()

	from, to := window()
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	if got := len(rec.LogRecords()); got != 50*len(defaultContentTypes) {
		t.Fatalf("emitted %d logs, want %d — the fixture must actually flow for this guard to mean anything", got, 50*len(defaultContentTypes))
	}
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("m365.activity emitted metrics %v, want none — every field on an audit record is per-entity and unbounded, so it is a logs-only collector; a count belongs in a LogQL `count by` over the log twin, never a metric series keyed by UPN/IP/record id (#112)", names)
	}
}

// TestSubscriptionIsStartedLazily pins the WRITE. POST /subscriptions/start is
// graph2otel's second read-only break, so it must happen only as part of a real
// collection and only for the content types configured — never as a side effect
// of constructing the collector.
func TestSubscriptionIsStartedLazily(t *testing.T) {
	api := &fakeAPI{records: []map[string]any{liveRecord()}}
	c := newTestCollector(t, api)

	if len(api.started) != 0 {
		t.Errorf("constructing the collector already started subscriptions %v; the write must not happen until Collect", api.started)
	}

	from, to := window()
	if _, err := c.CollectWindow(context.Background(), from, to, telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}

	for _, ct := range defaultContentTypes {
		if !slices.Contains(api.started, string(ct)) {
			t.Errorf("content type %q was never subscribed; started = %v", ct, api.started)
		}
	}
	// Nothing outside the configured set may be subscribed — subscribing to
	// Audit.General or DLP.All by accident is a real cost and a scope problem.
	for _, got := range api.started {
		if !slices.Contains(defaultContentTypes, o365activityclient.ContentType(got)) {
			t.Errorf("subscribed to unconfigured content type %q", got)
		}
	}
}
