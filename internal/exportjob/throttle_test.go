package exportjob

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// staticCredential is an offline azcore.TokenCredential for the real
// graphclient used by the throttle tests.
type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "tok", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeGraphExport is an httptest stand-in for the Intune export-job endpoints.
// throttleCreates / throttlePolls are how many leading POST / GET requests answer
// 429 (counted per physical attempt, so Kiota's own transport-level retries
// consume them too). retryAfter, when non-empty, is sent on every 429.
type fakeGraphExport struct {
	throttleCreates int32
	throttlePolls   int32
	retryAfter      string

	creates atomic.Int32
	polls   atomic.Int32
	srv     *httptest.Server
	zip     []byte
}

func (f *fakeGraphExport) handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/deviceManagement/reports/exportJobs"):
		if f.creates.Add(1) <= f.throttleCreates {
			f.tooMany(w)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"job1","status":"notStarted"}`))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/deviceManagement/reports/exportJobs/job1"):
		if f.polls.Add(1) <= f.throttlePolls {
			f.tooMany(w)
			return
		}
		expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, _ = fmt.Fprintf(w, `{"id":"job1","status":"completed","url":%q,"expirationDateTime":%q}`,
			f.srv.URL+"/sas/export.zip", expiry)
	case r.Method == http.MethodGet && r.URL.Path == "/sas/export.zip":
		_, _ = w.Write(f.zip)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func (f *fakeGraphExport) tooMany(w http.ResponseWriter) {
	if f.retryAfter != "" {
		w.Header().Set("Retry-After", f.retryAfter)
	}
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"throttled"}}`))
}

// newThrottleHarness wires a REAL graphclient.Client (Kiota retry pipeline and
// all) to the fake Graph server, so the only fake is at the HTTP edge. Kiota is
// held to one 1s retry so the test exercises what happens once the transport's
// own retries are exhausted — the live failure shape.
func newThrottleHarness(t *testing.T, f *fakeGraphExport) (*graphclient.Client, string) {
	t.Helper()
	f.zip = buildZip(t, "export.csv", []byte("name\ndevice1\n"))
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(f.srv.Close)

	prev := http.DefaultTransport
	http.DefaultTransport = f.srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = prev })

	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	gc, err := graphclient.NewClient(context.Background(),
		&auth.TenantAuth{TenantID: "t1", Cred: staticCredential{}},
		graphclient.Options{ValidHosts: []string{u.Hostname()}, MaxRetries: 1, RetryDelaySeconds: 1})
	if err != nil {
		t.Fatalf("graphclient.NewClient: %v", err)
	}
	return gc, f.srv.URL + "/v1.0"
}

// TestExportRetriesThrottledCreateWithinTick reproduces the live failure: the
// create POST is still 429 after the transport's own retries are spent. Export
// must back off and retry inside the same call instead of failing the whole
// 6-hour cycle.
func TestExportRetriesThrottledCreateWithinTick(t *testing.T) {
	// 2 = the original attempt + Kiota's one retry, i.e. one whole RawPost fails.
	f := &fakeGraphExport{throttleCreates: 2}
	gc, base := newThrottleHarness(t, f)

	var delays []time.Duration
	c := New(gc, DefaultDownloader(), Options{BaseURL: base, Sleep: noSleep(&delays)})

	rows, err := c.Export(context.Background(), Request{ReportName: "R", Select: []string{"name"}}, telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("Export: %v (throttled create must be retried within the tick)", err)
	}
	if len(rows) != 1 || rows[0]["name"] != "device1" {
		t.Fatalf("rows = %+v, want one device1 row", rows)
	}
	if got := f.creates.Load(); got != 3 {
		t.Fatalf("create attempts = %d, want 3 (two throttled, one accepted)", got)
	}
	if len(delays) != 1 || delays[0] <= 0 {
		t.Fatalf("throttle waits = %v, want exactly one positive backoff before the retried create", delays)
	}
}

// TestExportHonoursRetryAfterOnThrottledCreateAndPoll: when Graph names a
// Retry-After, the in-tick retry waits exactly that long — on the create and on
// a poll alike — rather than its own computed backoff.
func TestExportHonoursRetryAfterOnThrottledCreateAndPoll(t *testing.T) {
	f := &fakeGraphExport{throttleCreates: 2, throttlePolls: 2, retryAfter: "1"}
	gc, base := newThrottleHarness(t, f)

	var delays []time.Duration
	c := New(gc, DefaultDownloader(), Options{BaseURL: base, Sleep: noSleep(&delays)})

	rows, err := c.Export(context.Background(), Request{ReportName: "R", Select: []string{"name"}}, telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one row", rows)
	}
	want := []time.Duration{time.Second, time.Second}
	if len(delays) != len(want) || delays[0] != want[0] || delays[1] != want[1] {
		t.Fatalf("waits = %v, want %v (Retry-After on the create, then on the poll)", delays, want)
	}
}

// TestExportThrottleRetryIsBounded: a create that is throttled forever must give
// up within the retry budget rather than spin for the rest of the tick.
func TestExportThrottleRetryIsBounded(t *testing.T) {
	var posts atomic.Int32
	poster := &fakePoster{
		post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
			posts.Add(1)
			return nil, &graphclient.HTTPStatusError{Method: http.MethodPost, URL: "u", StatusCode: http.StatusTooManyRequests}
		},
		get: func(context.Context, string, map[string]string) ([]byte, error) {
			t.Fatal("must not poll a job that was never created")
			return nil, nil
		},
	}
	var delays []time.Duration
	c := New(poster, &fakeDownloader{}, Options{Sleep: noSleep(&delays)})

	_, err := c.Export(context.Background(), Request{ReportName: "R"}, telemetrytest.New().Emitter())
	if err == nil {
		t.Fatal("Export succeeded against a permanently throttled create")
	}
	var total time.Duration
	for _, d := range delays {
		total += d
	}
	if int(posts.Load()) != defaultThrottleRetries+1 {
		t.Fatalf("create attempts = %d, want %d", posts.Load(), defaultThrottleRetries+1)
	}
	if total > defaultThrottleBudget {
		t.Fatalf("total throttle wait %v exceeds budget %v", total, defaultThrottleBudget)
	}
}

// TestExportCapsConcurrentJobs: many export collectors ticking at the same
// instant must not all create jobs at once — that burst is what Graph 429s.
func TestExportCapsConcurrentJobs(t *testing.T) {
	var inFlight, maxSeen atomic.Int32
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	poster := &fakePoster{
		post: func(context.Context, string, []byte, map[string]string) ([]byte, error) {
			n := inFlight.Add(1)
			for {
				m := maxSeen.Load()
				if n <= m || maxSeen.CompareAndSwap(m, n) {
					break
				}
			}
			return []byte(`{"id":"j"}`), nil
		},
		get: func(context.Context, string, map[string]string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"id":"j","status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`, expiry)), nil
		},
	}
	zipBytes := buildZip(t, "export.csv", []byte("name\nd\n"))
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) {
		time.Sleep(20 * time.Millisecond) // hold the slot so overlap is observable
		inFlight.Add(-1)
		return zipBytes, nil
	}}
	c := New(poster, dl, Options{MaxConcurrent: 2})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Export(context.Background(), Request{ReportName: "R"}, telemetrytest.New().Emitter()); err != nil {
				t.Errorf("Export: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := maxSeen.Load(); got != 2 {
		t.Fatalf("max concurrent export jobs = %d, want exactly the cap of 2", got)
	}
}
