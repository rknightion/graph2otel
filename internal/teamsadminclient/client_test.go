package teamsadminclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
)

func TestNewClientValidation(t *testing.T) {
	cred := &fakeCredential{}
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Error("nil TenantAuth accepted")
	}
	if _, err := NewClient(&auth.TenantAuth{Cred: cred}, Options{}); err == nil {
		t.Error("empty tenant ID accepted")
	}
	for _, bad := range []string{"://x", "no-scheme-or-host", "https://", "ftp://host"} {
		if _, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: cred}, Options{BaseURL: bad}); err == nil {
			t.Errorf("BaseURL %q accepted", bad)
		}
	}
}

func TestNewClientMakesNoRequestAndDefaults(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	_, cred := newTestClient(t, srv, nil)
	if hits.Load() != 0 || len(cred.requestedScopes()) != 0 {
		t.Errorf("NewClient did I/O: %d requests, %d token calls", hits.Load(), len(cred.requestedScopes()))
	}
	zero, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: cred}, Options{})
	if err != nil {
		t.Fatalf("NewClient zero options: %v", err)
	}
	impl := zero.impl
	if impl.baseURL != DefaultBaseURL || impl.scope != DefaultScope {
		t.Errorf("defaults: base %q scope %q", impl.baseURL, impl.scope)
	}
	if impl.httpClient.Timeout != 30*time.Second || impl.callDeadline != 5*time.Minute {
		t.Errorf("defaults: timeout %v callDeadline %v", impl.httpClient.Timeout, impl.callDeadline)
	}
}

func TestRequestShapeAndScope(t *testing.T) {
	var method, authz, accept, path, rawQuery string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		method, authz, accept, path, rawQuery = r.Method, r.Header.Get("Authorization"), r.Header.Get("Accept"), r.URL.Path, r.URL.RawQuery
		_, _ = io.WriteString(w, `[{"Identity":"Global"}]`)
	})
	c, cred := newTestClient(t, srv, nil)
	recs, err := c.Configurations(context.Background(), "TenantNetworkSite")
	if err != nil {
		t.Fatalf("Configurations: %v", err)
	}
	if len(recs) != 1 || recs[0]["Identity"] != "Global" {
		t.Errorf("records = %v", recs)
	}
	if method != "GET" || authz != "Bearer test-token" || accept != "application/json" {
		t.Errorf("method %q authz %q accept %q", method, authz, accept)
	}
	if path != "/Skype.Policy/configurations/TenantNetworkSite" || rawQuery != "" {
		t.Errorf("path %q query %q", path, rawQuery)
	}
	scopes := cred.requestedScopes()
	if len(scopes) != 1 || len(scopes[0]) != 1 || scopes[0][0] != DefaultScope {
		t.Errorf("requested scopes = %v, want [[%s]]", scopes, DefaultScope)
	}
	if DefaultScope != "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default" {
		t.Errorf("DefaultScope = %q", DefaultScope)
	}
}

func TestScopeOverrideIsNotDerivedFromBaseURL(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "[]") })
	c, cred := newTestClient(t, srv, func(o *Options) { o.Scope = "custom/.default" })
	if _, err := c.Configurations(context.Background(), "X"); err != nil {
		t.Fatal(err)
	}
	if s := cred.requestedScopes(); len(s) != 1 || s[0][0] != "custom/.default" {
		t.Errorf("scopes = %v", s)
	}
}

func TestTokenFailureIsErrToken(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	c, cred := newTestClient(t, srv, nil)
	cause := errors.New("AADSTS500011: resource principal not found")
	cred.err = cause
	_, err := c.Configurations(context.Background(), "X")
	if !errors.Is(err, ErrToken) || !errors.Is(err, cause) {
		t.Fatalf("err = %v, want ErrToken wrapping the cause", err)
	}
	if !strings.Contains(err.Error(), "Skype and Teams Tenant Admin API") {
		t.Errorf("message does not name the resource: %v", err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) || IsPermission(err) {
		t.Error("a token failure must not read as an API or permission error")
	}
	if hits.Load() != 0 {
		t.Errorf("request made despite token failure: %d", hits.Load())
	}
}

func TestConfigurationsRequiresArray(t *testing.T) {
	for name, body := range map[string]string{
		"object": `{"value":[]}`, "null": "null", "string": `"x"`, "array of strings": `["a"]`, "empty body": "",
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
			c, _ := newTestClient(t, srv, nil)
			if _, err := c.Configurations(context.Background(), "X"); err == nil {
				t.Error("nil error for a non-array body")
			}
		})
	}
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "[]") })
	c, _ := newTestClient(t, srv, nil)
	recs, err := c.Configurations(context.Background(), "X")
	if err != nil || recs == nil || len(recs) != 0 {
		t.Errorf("empty array = %v, %v; want empty non-nil, nil", recs, err)
	}
	for _, bad := range []string{"", "a/b"} {
		if _, err := c.Configurations(context.Background(), bad); err == nil {
			t.Errorf("configuration name %q accepted", bad)
		}
	}
}

func TestVoiceAppsMissingEnvelopeKey(t *testing.T) {
	for _, body := range []string{`{"Diagnostics":[]}`, `{"AutoAttendants":[]}`, `[]`, `{"CallQueues":null}`, `{"CallQueues":{}}`} {
		srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		c, _ := newTestClient(t, srv, nil)
		if _, err := c.VoiceApps(context.Background(), CallQueues); err == nil {
			t.Errorf("body %s: nil error", body)
		}
	}
}

func TestVoiceAppsTwoPagesThenEmpty(t *testing.T) {
	ps := &pagingServer{}
	srv := newServer(t, ps.handler(t, 130, 100))
	c, _ := newTestClient(t, srv, nil)
	res, err := c.VoiceApps(context.Background(), CallQueues)
	if err != nil {
		t.Fatalf("VoiceApps: %v", err)
	}
	if len(res.Records) != 130 {
		t.Errorf("records = %d, want 130", len(res.Records))
	}
	want := []string{
		"FilterInvalidObos=False&First=100&Skip=0",
		"FilterInvalidObos=False&First=100&Skip=100",
		"FilterInvalidObos=False&First=100&Skip=130",
	}
	if strings.Join(ps.queries, "|") != strings.Join(want, "|") {
		t.Errorf("queries = %v, want %v", ps.queries, want)
	}
}

func TestVoiceAppsAutoAttendantsPathAndKey(t *testing.T) {
	var queries []string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Teams.VoiceApps/auto-attendants" {
			t.Errorf("path = %q", r.URL.Path)
		}
		queries = append(queries, r.URL.RawQuery)
		items := []map[string]any{}
		if r.URL.Query().Get("Skip") == "0" {
			items = []map[string]any{{"Id": "aa-1"}}
		}
		writeJSON(t, w, map[string]any{"AutoAttendants": items, "Diagnostics": []any{}})
	})
	c, _ := newTestClient(t, srv, nil)
	res, err := c.VoiceApps(context.Background(), AutoAttendants)
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("VoiceApps = %v, %v", res, err)
	}
	if queries[0] != "First=100&Skip=0" {
		t.Errorf("first query = %q (auto attendants take no FilterInvalidObos)", queries[0])
	}
	if _, err := c.VoiceApps(context.Background(), VoiceAppKind(99)); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestVoiceAppsServerPageCapDoesNotEndWalk(t *testing.T) {
	ps := &pagingServer{}
	srv := newServer(t, ps.handler(t, 120, 50))
	c, _ := newTestClient(t, srv, nil)
	res, err := c.VoiceApps(context.Background(), CallQueues)
	if err != nil {
		t.Fatalf("VoiceApps: %v", err)
	}
	if len(res.Records) != 120 {
		t.Fatalf("records = %d, want all 120 from a server capped at 50 per page", len(res.Records))
	}
	if got := len(ps.queries); got != 4 { // 50, 50, 20, then empty
		t.Errorf("requests = %d, want 4", got)
	}
}

func TestVoiceAppsDiagnosticsCollected(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		items := []map[string]any{}
		if r.URL.Query().Get("Skip") == "0" {
			items = queueObjects(0, 2)
		}
		writeJSON(t, w, map[string]any{"CallQueues": items, "Diagnostics": []map[string]string{
			{"Level": "Warning", "Message": "conference mode"},
		}})
	})
	c, _ := newTestClient(t, srv, nil)
	res, err := c.VoiceApps(context.Background(), CallQueues)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diagnostics) == 0 || res.Diagnostics[0] != (Diagnostic{Level: "Warning", Message: "conference mode"}) {
		t.Errorf("diagnostics = %+v", res.Diagnostics)
	}
}

func TestVoiceAppsOversizedPageIsError(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"CallQueues": queueObjects(0, 101)})
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.VoiceApps(context.Background(), CallQueues)
	if err == nil || !strings.Contains(err.Error(), "exceeds First") {
		t.Errorf("err = %v, want an oversized-page error", err)
	}
}

func TestVoiceAppsRepeatedIDIsError(t *testing.T) {
	// A server that ignores Skip returns the same page forever.
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"CallQueues": queueObjects(0, 3)})
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.VoiceApps(context.Background(), CallQueues)
	if err == nil || !strings.Contains(err.Error(), "earlier page") {
		t.Errorf("err = %v, want a repeated-ID error", err)
	}
}

func TestVoiceAppsObjectWithoutIDIsError(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"CallQueues": []map[string]any{{"Name": "no id"}}})
	})
	c, _ := newTestClient(t, srv, nil)
	if _, err := c.VoiceApps(context.Background(), CallQueues); err == nil {
		t.Error("object without Identity accepted")
	}
}

func TestVoiceAppsPageCap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		total   int
		wantErr bool
	}{
		{"50 full pages then empty", 50 * 100, false},
		{"51st non-empty page", 50*100 + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := &pagingServer{}
			srv := newServer(t, ps.handler(t, tc.total, 100))
			c, _ := newTestClient(t, srv, nil)
			res, err := c.VoiceApps(context.Background(), CallQueues)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "50") {
					t.Fatalf("err = %v, want an error naming the 50-page cap", err)
				}
				if got := len(ps.queries); got != 51 {
					t.Errorf("requests = %d, want it to stop at the 51st page", got)
				}
				return
			}
			if err != nil || len(res.Records) != tc.total {
				t.Errorf("got %d records, err %v", len(res.Records), err)
			}
		})
	}
}

func TestRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	start := time.Now()
	_, err := c.Configurations(context.Background(), "X")
	if err == nil {
		t.Fatal("nil error from a hung server")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v, the 50ms request timeout was not honored", elapsed)
	}
}

func TestCallDeadlineBoundsWholeWalk(t *testing.T) {
	var n atomic.Int32
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(40 * time.Millisecond)
		i := int(n.Add(1))
		writeJSON(t, w, map[string]any{"CallQueues": queueObjects(i*10, 1)})
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.CallDeadline = 150 * time.Millisecond })
	start := time.Now()
	_, err := c.VoiceApps(context.Background(), CallQueues)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second || n.Load() >= 40 {
		t.Errorf("walk ran %v and %d requests past the 150ms call deadline", elapsed, n.Load())
	}
}

func TestRedirectIsRefused(t *testing.T) {
	var targetHits atomic.Int32
	target := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, "[]")
	})
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	})
	c, _ := newTestClient(t, srv, nil)
	_, err := c.Configurations(context.Background(), "X")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
		t.Fatalf("err = %v, want *APIError with status 302", err)
	}
	if !strings.Contains(err.Error(), "redirect refused") {
		t.Errorf("message = %q", err)
	}
	if targetHits.Load() != 0 {
		t.Errorf("redirect target was contacted %d times; the bearer token would have been replayed", targetHits.Load())
	}
}

func TestBodyOver32MiBIsError(t *testing.T) {
	big := strings.Repeat(" ", 32<<20)
	for name, tc := range map[string]struct {
		body    string
		wantErr bool
	}{
		"exactly 32 MiB":    {body: "[]" + big[:32<<20-2], wantErr: false},
		"one byte too many": {body: "[]" + big[:32<<20-1], wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, tc.body) })
			c, _ := newTestClient(t, srv, nil)
			_, err := c.Configurations(context.Background(), "X")
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "exceeds") {
				t.Errorf("err = %v, want a size error", err)
			}
		})
	}
}

func TestLimiterGatesRequests(t *testing.T) {
	var hits atomic.Int32
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "[]") })
	c, _ := newTestClient(t, srv, func(o *Options) { o.Limiter = rate.NewLimiter(rate.Every(time.Hour), 1) })
	if _, err := c.Configurations(context.Background(), "X"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Configurations(ctx, "X"); err == nil {
		t.Error("second request was not gated by the limiter")
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}
