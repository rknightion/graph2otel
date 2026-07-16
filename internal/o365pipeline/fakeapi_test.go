package o365pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const testTenantID = "41463f53-8812-40f4-890f-865bf6e35190"

// apiTimeFormat mirrors the client's documented YYYY-MM-DDTHH:MM:SS form for
// startTime/endTime QUERY PARAMETERS, so the fake filters a listing the way the
// real service does.
const apiTimeFormat = "2006-01-02T15:04:05"

// recordTimeFormat is how CreationTime appears INSIDE an audit record. It
// happens to coincide with apiTimeFormat but is a separately-owned wire format,
// so it gets its own name rather than sharing the constant.
//
// It is deliberately NOT RFC3339: the Common Schema's CreationTime carries no
// zone and no 'Z' (Microsoft's own reference sample, mirrored in this repo at
// internal/o365activityclient/content_test.go:421, reads
// "2015-06-29T20:03:19"). It is documented UTC but zone-less, so
// time.Parse(time.RFC3339, ...) FAILS on it and a mapper that reaches for the
// obvious constant silently drops every record.
//
// This engine parses no record times at all — EndpointConfig.Map owns the
// Event's Timestamp — so nothing here depends on it. The fixture uses the real
// shape anyway, so that if engine-side parsing is ever added, these tests break
// loudly rather than passing against a format the service never sends.
const recordTimeFormat = "2006-01-02T15:04:05"

// fakeCredential is a credential that mints a static token. The client requires
// one; nothing in this package's behavior depends on its contents.
type fakeCredential struct{}

func (fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// blobSpec is one content blob the fake serves: its listing entry plus the
// records a fetch of it returns.
type blobSpec struct {
	contentType o365activityclient.ContentType
	contentID   string
	created     time.Time
	records     []map[string]any
	// errCode, when non-empty, makes a FETCH of this blob fail with that
	// documented AF code (e.g. o365activityclient.CodeContentExpired) rather
	// than return records.
	errCode string
	// errStatus is the HTTP status paired with errCode; defaults to 400.
	errStatus int
}

// fakeAPI is an httptest-backed stand-in for the Management Activity API,
// implementing the three operations this engine drives: subscriptions/start,
// subscriptions/content (with real startTime/endTime filtering, so the client's
// 24h chunking is genuinely exercised), and a per-blob content fetch.
type fakeAPI struct {
	mu sync.Mutex

	blobs []blobSpec

	// starts records every contentType passed to subscriptions/start, in order.
	starts []string
	// fetches records every contentId fetched, in order — the observable that
	// proves blob-level dedupe skipped a fetch entirely.
	fetches []string
	// listRanges records the [startTime, endTime] of every listing request.
	listRanges [][2]string

	// noSubscriptionFor makes subscriptions/content fail with AF20022 for these
	// content types until subscriptions/start is called for them.
	noSubscriptionFor map[string]bool
	// alreadyEnabledFor makes subscriptions/start fail with AF20024 for these
	// content types — the real API's response when the subscription is already
	// on, which is the steady state on any tenant whose subscriptions were
	// started by a previous deployment, another tool, or an operator.
	alreadyEnabledFor map[string]bool

	srv *httptest.Server
}

func newFakeAPI(t *testing.T, blobs ...blobSpec) *fakeAPI {
	t.Helper()
	f := &fakeAPI{blobs: blobs, noSubscriptionFor: map[string]bool{}, alreadyEnabledFor: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/subscriptions/start"):
		f.handleStart(w, r)
	case strings.HasSuffix(r.URL.Path, "/subscriptions/content"):
		f.handleContent(w, r)
	case strings.HasPrefix(r.URL.Path, "/blob/"):
		f.handleBlob(w, r)
	default:
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}
}

func (f *fakeAPI) handleStart(w http.ResponseWriter, r *http.Request) {
	ct := r.URL.Query().Get("contentType")
	f.mu.Lock()
	f.starts = append(f.starts, ct)
	delete(f.noSubscriptionFor, ct)
	already := f.alreadyEnabledFor[ct]
	f.mu.Unlock()

	// AF20024 is what the REAL API returns when the content type is already
	// enabled — an undocumented 400 for an operation the reference describes as a
	// safe update. This fake returned 200 unconditionally until 2026-07-16, which
	// is precisely why the engine shipped without tolerating it and failed on
	// every tick against a live tenant. A fake that is kinder than the wire tests
	// nothing about the wire.
	if already {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": map[string]any{
			"code":    o365activityclient.CodeAlreadyEnabled,
			"message": "The subscription is already enabled. No property change.",
		}})
		return
	}
	writeJSON(w, o365activityclient.Subscription{ContentType: ct, Status: o365activityclient.StatusEnabled})
}

func (f *fakeAPI) handleContent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ct := q.Get("contentType")

	f.mu.Lock()
	blocked := f.noSubscriptionFor[ct]
	f.listRanges = append(f.listRanges, [2]string{q.Get("startTime"), q.Get("endTime")})
	f.mu.Unlock()

	if blocked {
		writeAPIError(w, http.StatusBadRequest, o365activityclient.CodeNoSubscription,
			"There is no subscription for the specified content type.")
		return
	}

	start, end, err := parseRange(q)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, o365activityclient.CodeInvalidTimeRange, err.Error())
		return
	}

	out := []o365activityclient.ContentBlob{}
	f.mu.Lock()
	for _, b := range f.blobs {
		if string(b.contentType) != ct {
			continue
		}
		// The API filters on contentCreated, inclusive of start, exclusive of
		// end — the semantics ListContent relies on to tile chunks cleanly.
		if !start.IsZero() && (b.created.Before(start) || !b.created.Before(end)) {
			continue
		}
		out = append(out, o365activityclient.ContentBlob{
			ContentType:       string(b.contentType),
			ContentID:         b.contentID,
			ContentURI:        f.srv.URL + "/blob/" + b.contentID,
			ContentCreated:    b.created,
			ContentExpiration: b.created.Add(20 * 24 * time.Hour),
		})
	}
	f.mu.Unlock()
	writeJSON(w, out)
}

func (f *fakeAPI) handleBlob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/blob/")
	f.mu.Lock()
	f.fetches = append(f.fetches, id)
	var spec *blobSpec
	for i := range f.blobs {
		if f.blobs[i].contentID == id {
			spec = &f.blobs[i]
			break
		}
	}
	f.mu.Unlock()

	if spec == nil {
		writeAPIError(w, http.StatusNotFound, o365activityclient.CodeContentNotFound, "not found")
		return
	}
	if spec.errCode != "" {
		status := spec.errStatus
		if status == 0 {
			status = http.StatusBadRequest
		}
		writeAPIError(w, status, spec.errCode, "injected "+spec.errCode)
		return
	}
	writeJSON(w, spec.records)
}

func parseRange(q url.Values) (start, end time.Time, err error) {
	s, e := q.Get("startTime"), q.Get("endTime")
	if s == "" && e == "" {
		return time.Time{}, time.Time{}, nil
	}
	if s == "" || e == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("startTime and endTime must both be set")
	}
	if start, err = time.Parse(apiTimeFormat, s); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bad startTime %q", s)
	}
	if end, err = time.Parse(apiTimeFormat, e); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bad endTime %q", e)
	}
	if end.Sub(start) > o365activityclient.MaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("range %s..%s exceeds 24h", s, e)
	}
	return start.UTC(), end.UTC(), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

// recordedStarts returns the content types subscriptions/start was called for.
func (f *fakeAPI) recordedStarts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.starts...)
}

// recordedFetches returns the content ids that were actually fetched.
func (f *fakeAPI) recordedFetches() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.fetches...)
}

// lastListRange returns the [startTime, endTime] of the most recent listing
// request, as the wire saw them.
func (f *fakeAPI) lastListRange() [2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.listRanges) == 0 {
		return [2]string{}
	}
	return f.listRanges[len(f.listRanges)-1]
}

// blockSubscription makes subscriptions/content return AF20022 for ct until
// subscriptions/start is called.
func (f *fakeAPI) blockSubscription(ct o365activityclient.ContentType) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noSubscriptionFor[string(ct)] = true
}

// client builds a real o365activityclient pointed at the fake, so these tests
// exercise the client's genuine chunking, paging and AF-code parsing rather
// than a mock's idea of them.
func (f *fakeAPI) client(t *testing.T, mutate ...func(*o365activityclient.Options)) *o365activityclient.Client {
	t.Helper()
	opts := o365activityclient.Options{BaseURL: f.srv.URL}
	for _, m := range mutate {
		m(&opts)
	}
	c, err := o365activityclient.NewClient(
		&auth.TenantAuth{TenantID: testTenantID, Cred: fakeCredential{}},
		opts,
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// NOTE ON SPEED. The client's retry transport cannot be switched off from
// outside its package: retryTransport.RoundTrip coerces any maxRetries <= 0 to
// its default of 3, and the backoff base is an unexported Options field. So a
// test that serves a RETRYABLE status (429, or any 5xx) pays several seconds of
// real backoff. Only TestCollectSurfacesThrottling does, deliberately; every
// other failure test uses a non-retryable 4xx and runs instantly.

// newStore returns a checkpoint store rooted at a temp dir.
func newStore(t *testing.T) *checkpoint.Store {
	t.Helper()
	return checkpoint.NewStore(t.TempDir())
}

// mapAll accepts every record, taking its dedupe id from "Id" and its event
// time from "CreationTime". It stands in for a real collector's mapper, and
// like a real one it owns the Event's Timestamp — the engine never sets it.
func mapAll(rec map[string]any) (string, telemetry.Event, bool) {
	id, _ := rec["Id"].(string)
	ev := telemetry.Event{Body: id, Severity: telemetry.SeverityInfo}
	if s, ok := rec["CreationTime"].(string); ok {
		if t, err := time.Parse(recordTimeFormat, s); err == nil {
			ev.Timestamp = t.UTC()
		}
	}
	return id, ev, true
}

// rec builds one raw audit record with the given id and creation time, in the
// shapes the real API sends: a zone-less CreationTime (see recordTimeFormat) and
// a NUMERIC RecordType, which arrives through encoding/json into a
// map[string]any as a float64 — never an int, so a `.(int)` assertion on it
// always fails.
func rec(id string, created time.Time) map[string]any {
	return map[string]any{
		"Id":           id,
		"CreationTime": created.UTC().Format(recordTimeFormat),
		"RecordType":   float64(15),
		"Workload":     "AzureActiveDirectory",
	}
}

// bodies returns the Body of every emitted log record, in emission order.
func bodies(recs []telemetrytest.LogRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Body)
	}
	return out
}
