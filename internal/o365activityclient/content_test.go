package o365activityclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recordedQuery is one /subscriptions/content request the fake server saw.
type recordedQuery struct {
	contentType string
	startTime   string
	endTime     string
	nextPage    string
}

func (r recordedQuery) window(t *testing.T) (time.Time, time.Time) {
	t.Helper()
	start, err := time.Parse(apiTimeFormat, r.startTime)
	if err != nil {
		t.Fatalf("parse startTime %q: %v", r.startTime, err)
	}
	end, err := time.Parse(apiTimeFormat, r.endTime)
	if err != nil {
		t.Fatalf("parse endTime %q: %v", r.endTime, err)
	}
	return start, end
}

// contentServer serves an empty listing and records every query it saw.
func contentServer(t *testing.T, queries *[]recordedQuery) *httptest.Server {
	t.Helper()
	return jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		*queries = append(*queries, recordedQuery{
			contentType: q.Get("contentType"),
			startTime:   q.Get("startTime"),
			endTime:     q.Get("endTime"),
			nextPage:    q.Get("nextPage"),
		})
		_, _ = w.Write([]byte(`[]`))
	})
}

// TestListContentOmitsTimeWhenZero checks two zero times send NO time
// parameters, which the API defines as "the last 24 hours". Sending a computed
// range instead would silently change the semantics.
func TestListContentOmitsTimeWhenZero(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{}); err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(queries) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(queries))
	}
	if queries[0].startTime != "" || queries[0].endTime != "" {
		t.Errorf("startTime=%q endTime=%q, want both omitted",
			queries[0].startTime, queries[0].endTime)
	}
	if queries[0].contentType != string(ContentAzureActiveDirectory) {
		t.Errorf("contentType = %q, want %q", queries[0].contentType, ContentAzureActiveDirectory)
	}
}

// TestListContentRejectsHalfOpenRange guards the API's both-or-neither rule at
// the call site rather than letting it become an AF20030.
func TestListContentRejectsHalfOpenRange(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	_, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Now().Add(-time.Hour), time.Time{})
	if err == nil {
		t.Error("ListContent(start set, end zero) = nil error, want an error")
	}
	if len(queries) != 0 {
		t.Errorf("server saw %d requests, want 0 — the range should be rejected locally", len(queries))
	}
}

// TestListContentRejectsInvertedRange checks an end-before-start range is a
// local error rather than a wasted round trip.
func TestListContentRejectsInvertedRange(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	now := time.Now()
	_, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, now, now.Add(-time.Hour))
	if err == nil {
		t.Error("ListContent(end before start) = nil error, want an error")
	}
	if len(queries) != 0 {
		t.Errorf("server saw %d requests, want 0", len(queries))
	}
}

// TestListContentSingleWindowUnder24h checks a range inside the limit is one
// request, not needlessly chunked.
func TestListContentSingleWindowUnder24h(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	end := time.Now().UTC().Truncate(time.Second)
	start := end.Add(-6 * time.Hour)
	if _, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, start, end); err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(queries) != 1 {
		t.Fatalf("server saw %d requests, want 1 for a 6h window", len(queries))
	}
	gotStart, gotEnd := queries[0].window(t)
	if !gotStart.Equal(start) || !gotEnd.Equal(end) {
		t.Errorf("window = [%s, %s), want [%s, %s)", gotStart, gotEnd, start, end)
	}
}

// TestListContentChunksOver24Hours is the load-bearing one. The API does not
// reliably reject a >24h window — it may return PARTIAL results — so a client
// that passed the range through would lose data silently. Every emitted window
// must be <=24h, and together they must tile [start, end) with no gap and no
// overlap.
func TestListContentChunksOver24Hours(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	end := time.Now().UTC().Truncate(time.Second)
	start := end.Add(-50 * time.Hour) // 24 + 24 + 2
	if _, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, start, end); err != nil {
		t.Fatalf("ListContent: %v", err)
	}

	if len(queries) != 3 {
		t.Fatalf("server saw %d requests, want 3 for a 50h range (24+24+2)", len(queries))
	}

	var prevEnd time.Time
	for i, q := range queries {
		gotStart, gotEnd := q.window(t)
		if d := gotEnd.Sub(gotStart); d > MaxWindow {
			t.Errorf("chunk %d spans %v, want <= %v — the API may return partial results beyond this", i, d, MaxWindow)
		}
		if i == 0 {
			if !gotStart.Equal(start) {
				t.Errorf("chunk 0 starts at %s, want %s", gotStart, start)
			}
		} else if !gotStart.Equal(prevEnd) {
			t.Errorf("chunk %d starts at %s, want %s — chunks must tile with no gap or overlap",
				i, gotStart, prevEnd)
		}
		prevEnd = gotEnd
	}
	if !prevEnd.Equal(end) {
		t.Errorf("last chunk ends at %s, want %s", prevEnd, end)
	}
}

// TestListContentClampsBeyondSevenDays checks a start older than the retention
// window is moved forward rather than 400ing. Erroring would permanently wedge
// a collector resuming after a long outage; the data is genuinely gone either
// way, so resuming from the oldest retrievable point is the only useful move.
func TestListContentClampsBeyondSevenDays(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	end := time.Now().UTC().Truncate(time.Second)
	start := end.Add(-30 * 24 * time.Hour)
	if _, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, start, end); err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(queries) == 0 {
		t.Fatal("server saw no requests")
	}

	oldest, _ := queries[0].window(t)
	limit := time.Now().UTC().Add(-MaxLookback)
	if oldest.Before(limit) {
		t.Errorf("oldest startTime = %s, which is beyond the %v retention limit (%s) — the API would reject it",
			oldest, MaxLookback, limit)
	}
	// 7 days of 24h chunks, not 30.
	if len(queries) > 8 {
		t.Errorf("server saw %d requests, want <= 8 — the pre-retention window should be clamped away, not chunked through",
			len(queries))
	}
}

// TestListContentFullyExpiredWindowIsEmpty checks a window that has entirely
// aged out returns nothing without calling the API at all.
func TestListContentFullyExpiredWindowIsEmpty(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	end := time.Now().UTC().Add(-14 * 24 * time.Hour)
	start := end.Add(-24 * time.Hour)
	blobs, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, start, end)
	if err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(blobs) != 0 {
		t.Errorf("len(blobs) = %d, want 0", len(blobs))
	}
	if len(queries) != 0 {
		t.Errorf("server saw %d requests, want 0 — the whole window is past retention", len(queries))
	}
}

// TestListContentFollowsNextPageUri checks pagination works off the RESPONSE
// HEADER. This API does not use a body field like Graph's @odata.nextLink, so a
// client looking in the body silently truncates every large listing.
func TestListContentFollowsNextPageUri(t *testing.T) {
	var srv *httptest.Server
	var pages int
	srv = jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		switch r.URL.Query().Get("nextPage") {
		case "":
			w.Header().Set(headerNextPage, srv.URL+"/api/v1.0/"+testTenantID+
				"/activity/feed/subscriptions/content?contentType=Audit.AzureActiveDirectory&nextPage=2")
			_, _ = w.Write([]byte(`[{"contentId":"a","contentUri":"https://x/1"}]`))
		case "2":
			w.Header().Set(headerNextPage, srv.URL+"/api/v1.0/"+testTenantID+
				"/activity/feed/subscriptions/content?contentType=Audit.AzureActiveDirectory&nextPage=3")
			_, _ = w.Write([]byte(`[{"contentId":"b","contentUri":"https://x/2"}]`))
		default:
			_, _ = w.Write([]byte(`[{"contentId":"c","contentUri":"https://x/3"}]`))
		}
	})
	c, _ := newTestClient(t, srv, nil)

	blobs, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if pages != 3 {
		t.Errorf("fetched %d pages, want 3", pages)
	}
	var ids []string
	for _, b := range blobs {
		ids = append(ids, b.ContentID)
	}
	if strings.Join(ids, ",") != "a,b,c" {
		t.Errorf("contentIds = %v, want [a b c]", ids)
	}
}

// foreignHost stands in for an attacker-controlled endpoint. It is a REAL
// server that records the tokens it receives, because the property under test
// is "the bearer token never reaches this host" — not merely "an error
// happened". Pointing at an unroutable name instead would let a DNS failure
// masquerade as a passing test even with the guard removed.
func foreignHost(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	return srv, &received
}

// TestListContentRejectsForeignNextPageHost checks a NextPageUri pointing off
// our own host is refused. The next request carries a bearer token, so
// following an attacker-supplied URL would hand over the credential.
func TestListContentRejectsForeignNextPageHost(t *testing.T) {
	evil, evilAuths := foreignHost(t)
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerNextPage, evil.URL+"/steal?nextPage=2")
		_, _ = w.Write([]byte(`[{"contentId":"a"}]`))
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})

	// The decisive assertion: the token never reached the foreign host.
	if len(*evilAuths) != 0 {
		t.Fatalf("the foreign host received %d request(s) carrying %v — the bearer token leaked",
			len(*evilAuths), *evilAuths)
	}
	if err == nil {
		t.Fatal("ListContent = nil error, want a refusal to follow NextPageUri to a foreign host")
	}
	if !strings.Contains(err.Error(), "refusing to send a token") {
		t.Errorf("error = %v, want the host-allow-list refusal (a network error would not prove the guard ran)", err)
	}
}

// TestListContentDedupesWithinCall checks a contentId repeated across pages is
// returned once. This is a defensive guard only — cross-tick dedupe is the
// caller's checkpoint's job.
func TestListContentDedupesWithinCall(t *testing.T) {
	var srv *httptest.Server
	srv = jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("nextPage") == "" {
			w.Header().Set(headerNextPage, srv.URL+"/api/v1.0/"+testTenantID+
				"/activity/feed/subscriptions/content?contentType=Audit.AzureActiveDirectory&nextPage=2")
		}
		_, _ = w.Write([]byte(`[{"contentId":"dupe","contentUri":"https://x/1"}]`))
	})
	c, _ := newTestClient(t, srv, nil)

	end := time.Now().UTC()
	blobs, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, end.Add(-time.Hour), end)
	if err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(blobs) != 1 {
		t.Errorf("len(blobs) = %d, want 1 — the repeated contentId should be deduped", len(blobs))
	}
}

// TestListContentDecodesBlobFields pins the documented response shape.
func TestListContentDecodesBlobFields(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{
			"contentType": "Audit.AzureActiveDirectory",
			"contentId": "492638008028$492638008028$abc",
			"contentUri": "https://manage.office.com/api/v1.0/t/activity/feed/audit/492638008028$abc",
			"contentCreated": "2015-05-23T17:35:00.000Z",
			"contentExpiration": "2015-05-30T17:35:00.000Z"
		}]`))
	})
	c, _ := newTestClient(t, srv, nil)

	blobs, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("len(blobs) = %d, want 1", len(blobs))
	}
	b := blobs[0]
	if b.ContentID != "492638008028$492638008028$abc" {
		t.Errorf("ContentID = %q", b.ContentID)
	}
	if b.ContentType != string(ContentAzureActiveDirectory) {
		t.Errorf("ContentType = %q", b.ContentType)
	}
	wantCreated := time.Date(2015, 5, 23, 17, 35, 0, 0, time.UTC)
	if !b.ContentCreated.Equal(wantCreated) {
		t.Errorf("ContentCreated = %s, want %s", b.ContentCreated, wantCreated)
	}
	wantExpiry := time.Date(2015, 5, 30, 17, 35, 0, 0, time.UTC)
	if !b.ContentExpiration.Equal(wantExpiry) {
		t.Errorf("ContentExpiration = %s, want %s", b.ContentExpiration, wantExpiry)
	}
}

// TestContentExpirationIsReadNotDerived pins that expiry comes off the wire and
// is never computed from MaxLookback.
//
// The reference's AF20051 text says content older than 7 days cannot be
// retrieved, but a live blob (2026-07-16) reported a ~20-day gap between
// contentCreated and contentExpiration. Deriving expiry from the 7-day
// lookback constant would silently discard ~13 days of retrievable blobs. This
// serves a listing whose lifetime matches NEITHER figure, so only a decoder
// that reads the field passes.
func TestContentExpirationIsReadNotDerived(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{
			"contentType": "Audit.AzureActiveDirectory",
			"contentId": "abc",
			"contentCreated": "2026-07-15T20:45:11.875Z",
			"contentExpiration": "2026-08-05T19:44:14.638Z"
		}]`))
	})
	c, _ := newTestClient(t, srv, nil)

	blobs, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("ListContent: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("len(blobs) = %d, want 1", len(blobs))
	}

	want := time.Date(2026, 8, 5, 19, 44, 14, 638000000, time.UTC)
	if !blobs[0].ContentExpiration.Equal(want) {
		t.Errorf("ContentExpiration = %s, want %s (read off the wire)", blobs[0].ContentExpiration, want)
	}
	if derived := blobs[0].ContentCreated.Add(MaxLookback); blobs[0].ContentExpiration.Equal(derived) {
		t.Errorf("ContentExpiration equals contentCreated+MaxLookback (%s) — expiry is being derived from the 7-day constant, not read", derived)
	}
	// The live-observed lifetime is roughly 20 days, well beyond MaxLookback.
	if d := blobs[0].ContentExpiration.Sub(blobs[0].ContentCreated); d <= MaxLookback {
		t.Errorf("blob lifetime = %v, want > %v — the wire reports a longer lifetime than the docs' 7 days", d, MaxLookback)
	}
}

// TestListContentRejectsInvalidContentType turns an AF20020 into a local error.
func TestListContentRejectsInvalidContentType(t *testing.T) {
	var queries []recordedQuery
	srv := contentServer(t, &queries)
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.ListContent(context.Background(), ContentType("Audit.Nonsense"), time.Time{}, time.Time{}); err == nil {
		t.Error("ListContent(invalid content type) = nil error, want an error")
	}
	if len(queries) != 0 {
		t.Errorf("server saw %d requests, want 0", len(queries))
	}
}

// TestFetchContentReturnsRecords checks a blob decodes into raw records, using
// the reference's own sample shape.
func TestFetchContentReturnsRecords(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"CreationTime":"2015-06-29T20:03:19","Id":"80c76bd2","Operation":"PasswordLogonInitialAuthUsingPassword","RecordType":9,"Workload":"AzureActiveDirectory","ClientIP":"134.170.188.221","UserId":"admin@contoso.onmicrosoft.com"},
			{"CreationTime":"2015-06-29T20:04:55","Id":"b567caf0","Operation":"Add User.","RecordType":8,"Workload":"AzureActiveDirectory"}
		]`))
	})
	c, _ := newTestClient(t, srv, nil)

	uri := srv.URL + "/api/v1.0/" + testTenantID + "/activity/feed/audit/492638008028$abc"
	records, err := c.FetchContent(context.Background(), uri)
	if err != nil {
		t.Fatalf("FetchContent: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if records[0]["Operation"] != "PasswordLogonInitialAuthUsingPassword" {
		t.Errorf("records[0][Operation] = %v", records[0]["Operation"])
	}
	if records[0]["UserId"] != "admin@contoso.onmicrosoft.com" {
		t.Errorf("records[0][UserId] = %v", records[0]["UserId"])
	}
}

// TestFetchContentRejectsForeignHost is the same token-exfiltration guard as
// the NextPageUri one: contentUri arrives in a response body and is then
// requested WITH the bearer token.
func TestFetchContentRejectsForeignHost(t *testing.T) {
	evil, evilAuths := foreignHost(t)
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.FetchContent(context.Background(), evil.URL+"/api/v1.0/t/activity/feed/audit/abc")

	if len(*evilAuths) != 0 {
		t.Fatalf("the foreign host received %d request(s) carrying %v — the bearer token leaked",
			len(*evilAuths), *evilAuths)
	}
	if err == nil {
		t.Fatal("FetchContent(foreign host) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "refusing to send a token") {
		t.Errorf("error = %v, want the host-allow-list refusal", err)
	}
}

// TestFetchContentExpiredBlobIsTyped checks the 7-day expiry race surfaces as a
// recognizable AF20051 — a blob listed shortly before expiry can vanish before
// it is fetched, and the caller must be able to tell that apart from a real
// failure so it can drop the blob and continue.
func TestFetchContentExpiredBlobIsTyped(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"AF20051","message":"Content requested with the key abc has already expired. Content older than 7 days cannot be retrieved."}}`))
	})
	c, _ := newTestClient(t, srv, nil)

	uri := srv.URL + "/api/v1.0/" + testTenantID + "/activity/feed/audit/abc"
	_, err := c.FetchContent(context.Background(), uri)
	if !IsContentExpired(err) {
		t.Errorf("IsContentExpired(%v) = false, want true", err)
	}
}

// TestListContentPageCapStopsRunaway checks a service returning a
// self-referential NextPageUri terminates instead of spinning forever.
func TestListContentPageCapStopsRunaway(t *testing.T) {
	var srv *httptest.Server
	var pages int
	srv = jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		pages++
		w.Header().Set(headerNextPage, srv.URL+"/api/v1.0/"+testTenantID+
			"/activity/feed/subscriptions/content?contentType=Audit.AzureActiveDirectory&nextPage=always")
		_, _ = fmt.Fprintf(w, `[{"contentId":"id-%d"}]`, pages)
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})
	if err == nil {
		t.Fatal("ListContent = nil error, want the page cap to stop an endless listing")
	}
	if pages > maxContentPages+1 {
		t.Errorf("fetched %d pages, want the cap to stop at %d", pages, maxContentPages)
	}
}
