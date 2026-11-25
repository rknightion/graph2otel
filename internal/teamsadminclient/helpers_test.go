package teamsadminclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
)

const testTenantID = "11111111-2222-4333-8444-555555555555"

// fakeCredential records every scope set it is asked for.
type fakeCredential struct {
	mu     sync.Mutex
	token  string
	err    error
	scopes [][]string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, opts.Scopes)
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (f *fakeCredential) requestedScopes() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.scopes...)
}

func newTestClient(t *testing.T, srv *httptest.Server, mutate func(*Options)) (*Client, *fakeCredential) {
	t.Helper()
	cred := &fakeCredential{token: "test-token"}
	opts := Options{BaseURL: srv.URL, Limiter: rate.NewLimiter(rate.Inf, 1)}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: cred}, opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, cred
}

func newServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// queueObjects builds n queue objects with IDs id-<from>..id-<from+n-1>.
func queueObjects(from, n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = map[string]any{"Identity": "id-" + strconv.Itoa(from+i), "Name": "q"}
	}
	return out
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// pagingServer serves callqueues from a slice of total objects, honoring Skip
// and capping each page at serverCap (First is honored up to that cap). It
// records the raw query of every request.
type pagingServer struct {
	mu      sync.Mutex
	queries []string
}

func (p *pagingServer) handler(t *testing.T, total, serverCap int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.queries = append(p.queries, r.URL.RawQuery)
		p.mu.Unlock()
		skip, _ := strconv.Atoi(r.URL.Query().Get("Skip"))
		first, _ := strconv.Atoi(r.URL.Query().Get("First"))
		n := min(first, serverCap, max(total-skip, 0))
		writeJSON(t, w, map[string]any{"CallQueues": queueObjects(skip, n), "Diagnostics": []any{}})
	}
}
