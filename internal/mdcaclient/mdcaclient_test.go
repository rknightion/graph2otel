package mdcaclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient("tenant-1", Options{BaseURL: srv.URL, Token: "sekret"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{"empty base URL", Options{Token: "t"}, "empty base URL"},
		{"base URL no host", Options{BaseURL: "not-a-url", Token: "t"}, "no host"},
		{"empty token", Options{BaseURL: "https://x.eu2.portal.cloudappsecurity.com"}, "empty token"},
		{"valid", Options{BaseURL: "https://x.eu2.portal.cloudappsecurity.com", Token: "t"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient("t1", tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewClient = %v, want nil", err)
				}
				return
			}
			if err == nil || !contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewClient = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestGovernanceSinglePageSendsTokenAndDecodes(t *testing.T) {
	var gotAuth, gotContentType string
	var gotBody governanceBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/governance/" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"total":2,"data":[{"_id":"a","taskName":"DiscoveryParseLogTask"},{"_id":"b"}]}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	page, err := c.Governance(context.Background(), GovernanceQuery{})
	if err != nil {
		t.Fatalf("Governance: %v", err)
	}
	if gotAuth != "Token sekret" {
		t.Errorf("Authorization = %q, want %q (the scheme is 'Token', not 'Bearer')", gotAuth, "Token sekret")
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody.Limit != defaultPageLimit || gotBody.Skip != 0 {
		t.Errorf("body limit/skip = %d/%d, want %d/0", gotBody.Limit, gotBody.Skip, defaultPageLimit)
	}
	if gotBody.Filters != nil {
		t.Errorf("body filters = %v, want nil (no SinceMillis)", gotBody.Filters)
	}
	if page.Total != 2 || len(page.Records) != 2 {
		t.Fatalf("page total/len = %d/%d, want 2/2", page.Total, len(page.Records))
	}
	if page.Records[0]["_id"] != "a" {
		t.Errorf("records[0]._id = %v, want a", page.Records[0]["_id"])
	}
}

func TestGovernanceSinceMillisSetsServerSideFilter(t *testing.T) {
	var gotBody governanceBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"total":0,"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	if _, err := c.Governance(context.Background(), GovernanceQuery{SinceMillis: 1784242829127}); err != nil {
		t.Fatalf("Governance: %v", err)
	}
	ts, ok := gotBody.Filters["timestamp"].(map[string]any)
	if !ok {
		t.Fatalf("filters.timestamp missing/wrong type: %v", gotBody.Filters)
	}
	// JSON numbers decode to float64.
	if gte, _ := ts["gte"].(float64); int64(gte) != 1784242829127 {
		t.Errorf("filters.timestamp.gte = %v, want 1784242829127", ts["gte"])
	}
}

func TestGovernancePaginatesBySkip(t *testing.T) {
	// total=250 across three pages (100,100,50). Assert skip advances and all
	// records are collected in order.
	var skips []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b governanceBody
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &b)
		skips = append(skips, b.Skip)
		n := 100
		if b.Skip >= 200 {
			n = 50
		}
		recs := make([]map[string]any, n)
		for i := range recs {
			recs[i] = map[string]any{"_id": fmt.Sprintf("id-%d", b.Skip+i)}
		}
		resp, _ := json.Marshal(governanceResponse{Total: 250, Data: recs})
		_, _ = w.Write(resp)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	page, err := c.Governance(context.Background(), GovernanceQuery{})
	if err != nil {
		t.Fatalf("Governance: %v", err)
	}
	if len(page.Records) != 250 {
		t.Fatalf("collected %d records, want 250", len(page.Records))
	}
	if want := []int{0, 100, 200}; !equalInts(skips, want) {
		t.Errorf("skips = %v, want %v", skips, want)
	}
	if page.Records[0]["_id"] != "id-0" || page.Records[249]["_id"] != "id-249" {
		t.Errorf("record order wrong: first=%v last=%v", page.Records[0]["_id"], page.Records[249]["_id"])
	}
}

func TestGovernanceAPIErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"invalid token"}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.Governance(context.Background(), GovernanceQuery{})
	if err == nil {
		t.Fatal("Governance = nil error, want APIError")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err type = %T, want *APIError", err)
	}
	if apiErr.Status != http.StatusForbidden || !contains(apiErr.Body, "invalid token") {
		t.Errorf("APIError = %+v, want status 403 with body", apiErr)
	}
}

func TestCheckHostRefusesForeignHost(t *testing.T) {
	c, err := NewClient("t1", Options{BaseURL: "https://m7knio.eu2.portal.cloudappsecurity.com", Token: "t"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.checkHost("https://m7knio.eu2.portal.cloudappsecurity.com/api/v1/governance/"); err != nil {
		t.Errorf("checkHost(own host) = %v, want nil", err)
	}
	if err := c.checkHost("https://evil.example.com/api/v1/governance/"); err == nil {
		t.Error("checkHost(foreign host) = nil, want refusal — a token must never leave the configured host")
	}
}

func TestLimiterGatesPerTenant(t *testing.T) {
	// A 2-token bucket that refills slowly: the third immediate Wait must block
	// until the (short) context deadline, proving the gate is live.
	lim := newLimiterWithRate(rate.Limit(1), 2)
	ctx := context.Background()
	if err := lim.Wait(ctx, "t"); err != nil {
		t.Fatalf("Wait 1: %v", err)
	}
	if err := lim.Wait(ctx, "t"); err != nil {
		t.Fatalf("Wait 2: %v", err)
	}
	tight, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if err := lim.Wait(tight, "t"); err == nil {
		t.Error("Wait 3 within a drained bucket returned nil, want deadline error (limiter not gating)")
	}
	// A nil limiter never gates.
	var nilLim *Limiter
	if err := nilLim.Wait(ctx, "t"); err != nil {
		t.Errorf("nil Limiter.Wait = %v, want nil", err)
	}
}

// --- helpers ---

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
