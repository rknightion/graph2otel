package logpipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeCredential is a stand-in azcore.TokenCredential for offline tests,
// mirroring the same seam graphclient's own tests use.
type fakeCredential struct{}

func (fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token"}, nil
}

type graphAdapterRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f graphAdapterRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func routeTestRequest(req *http.Request, target *url.URL, transport http.RoundTripper) (*http.Response, error) {
	routed := req.Clone(req.Context())
	routedURL := *req.URL
	routedURL.Scheme = target.Scheme
	routedURL.Host = target.Host
	routed.URL = &routedURL
	return transport.RoundTrip(routed)
}

// TestGraphPageFetcherDecodesValueAndNextLink verifies the real PageFetcher
// adapter fetches through (*graphclient.Client).RawGet and decodes the
// Graph collection response shape ("value" + "@odata.nextLink") into
// PageFetcher's return values.
func TestGraphPageFetcherDecodesValueAndNextLink(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := graphPage{
			Value: []map[string]any{
				{"id": "a", "createdDateTime": "2026-01-01T00:00:00Z"},
			},
			NextLink: "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	testURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	previousTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	ta := &auth.TenantAuth{TenantID: "t1", Cred: fakeCredential{}}
	client, err := graphclient.NewClient(context.Background(), ta, graphclient.Options{ValidHosts: []string{testURL.Hostname()}})
	if err != nil {
		t.Fatalf("graphclient.NewClient: %v", err)
	}

	fetcher := NewGraphPageFetcher(client)
	records, next, err := fetcher.FetchPage(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if len(records) != 1 || records[0]["id"] != "a" {
		t.Fatalf("records = %+v, want a single record with id=a", records)
	}
	if next != "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc" {
		t.Fatalf("nextLink = %q", next)
	}
}

// TestPollRejectsForeignNextLinkAfterReliablePrefix preserves the adapter's
// SSRF boundary across the complete Poll -> graphPageFetcher ->
// graphclient.RawGet path under ordered streaming. If raw host validation is
// weakened, the routing transport below delivers the foreign next-link request
// to foreignSrv and this test observes the leak. The successful first page is
// visible, while the rejected foreign suffix cannot be fetched and the caller
// checkpoint remains unchanged so retry replays that prefix.
func TestPollRejectsForeignNextLinkAfterReliablePrefix(t *testing.T) {
	var foreignRequests atomic.Int32
	foreignSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer foreignSrv.Close()

	firstSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(graphPage{
			Value: []map[string]any{
				{"id": "first-page-record", "createdDateTime": "2026-01-01T00:30:00Z"},
			},
			NextLink: "https://foreign.example/v1.0/auditLogs/signIns?$skiptoken=hostile",
		})
	}))
	defer firstSrv.Close()

	firstURL, err := url.Parse(firstSrv.URL)
	if err != nil {
		t.Fatalf("parse first server URL: %v", err)
	}
	foreignURL, err := url.Parse(foreignSrv.URL)
	if err != nil {
		t.Fatalf("parse foreign server URL: %v", err)
	}
	router := graphAdapterRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Hostname() {
		case "graph.microsoft.com":
			return routeTestRequest(req, firstURL, firstSrv.Client().Transport)
		case "foreign.example":
			return routeTestRequest(req, foreignURL, foreignSrv.Client().Transport)
		default:
			return nil, fmt.Errorf("unexpected test request host %q", req.URL.Hostname())
		}
	})
	previousTransport := http.DefaultTransport
	http.DefaultTransport = router
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	client, err := graphclient.NewClient(
		context.Background(),
		&auth.TenantAuth{TenantID: "t1", Cred: fakeCredential{}},
		graphclient.Options{},
	)
	if err != nil {
		t.Fatalf("graphclient.NewClient: %v", err)
	}

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	existingSeenAt := from.Add(-30 * time.Minute)
	cp := &checkpoint.Checkpoint{
		TenantID:      "t1",
		Endpoint:      "/auditLogs/signIns",
		Watermark:     from.Add(-time.Hour),
		OverlapWindow: 2 * time.Hour,
		SeenIDs:       checkpoint.SeenIDs{"existing": existingSeenAt},
	}
	wantCheckpoint := &checkpoint.Checkpoint{
		TenantID:      "t1",
		Endpoint:      "/auditLogs/signIns",
		Watermark:     from.Add(-time.Hour),
		OverlapWindow: 2 * time.Hour,
		SeenIDs:       checkpoint.SeenIDs{"existing": existingSeenAt},
	}
	recorder := telemetrytest.New()
	cfg := EndpointConfig{
		Path:            "/auditLogs/signIns",
		TimeField:       "createdDateTime",
		OrderByReliable: true,
		Map:             mapByID,
	}

	highWater, err := Poll(context.Background(), cfg, cp, from, to, NewGraphPageFetcher(client), recorder.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Poll to reject a foreign @odata.nextLink")
	}
	if !strings.Contains(err.Error(), "foreign.example") {
		t.Errorf("Poll error = %v, want foreign hostname context", err)
	}
	if got := foreignRequests.Load(); got != 0 {
		t.Errorf("foreign server requests = %d, want 0", got)
	}
	if got := emittedIDSet(recorder); len(got) != 1 || got[0] != "first-page-record" {
		t.Errorf("emitted ids = %v, want reliable first-page prefix [first-page-record]", got)
	}
	if !highWater.Equal(wantCheckpoint.Watermark) {
		t.Errorf("returned high water = %s, want unchanged %s", highWater, wantCheckpoint.Watermark)
	}
	if !reflect.DeepEqual(cp, wantCheckpoint) {
		t.Errorf("checkpoint changed after rejected next link:\n got: %+v\nwant: %+v", cp, wantCheckpoint)
	}
}
