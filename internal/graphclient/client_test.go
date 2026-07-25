package graphclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
)

// fakeCredential is a stand-in azcore.TokenCredential for offline tests.
type fakeCredential struct {
	token string
	err   error
	calls *atomic.Int32
}

func (f fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.calls != nil {
		f.calls.Add(1)
	}
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type rawRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f rawRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newRawTestClient(t *testing.T, srv *httptest.Server, cred fakeCredential, validHosts []string, opts Options) *Client {
	t.Helper()
	opts.ValidHosts = validHosts
	opts.baseTransport = srv.Client().Transport
	c, err := NewClient(context.Background(), &auth.TenantAuth{TenantID: "t", Cred: cred}, opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func testServerHost(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return u.Hostname()
}

// TestNewClientBuildsGraphClient: NewClient wires a non-nil GraphServiceClient
// from a credential without performing any network I/O.
func TestNewClientBuildsGraphClient(t *testing.T) {
	ta := &auth.TenantAuth{TenantID: "11111111-1111-1111-1111-111111111111", Cred: fakeCredential{token: "t"}}
	c, err := NewClient(context.Background(), ta, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Graph == nil {
		t.Fatal("Graph client is nil")
	}
	if c.TenantID != ta.TenantID {
		t.Errorf("TenantID = %q, want %q", c.TenantID, ta.TenantID)
	}
}

func TestNewClientNilAuth(t *testing.T) {
	if _, err := NewClient(context.Background(), nil, Options{}); err == nil {
		t.Fatal("expected error for nil TenantAuth")
	}
}

// TestRawGetUsesInstrumentedTransportAndBearer: the raw-REST escape hatch
// attaches a bearer token and reads the body through the same retrying transport
// (a 429 is retried), returning the final body.
func TestRawGetUsesInstrumentedTransportAndBearer(t *testing.T) {
	var gotAuth string
	first := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if first {
			first = false
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{RetryDelaySeconds: 1})

	body, err := c.RawGet(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("RawGet: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want the JSON payload", body)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want bearer token", gotAuth)
	}
}

// TestRawPostSendsBodyBearerAndContentType: the POST hatch (used by the Intune
// reports export-job subsystem to create jobs) attaches the bearer token, sets
// Content-Type: application/json, sends the body, reads through the retrying
// transport (a 429 is retried), and returns the response body on 2xx.
func TestRawPostSendsBodyBearerAndContentType(t *testing.T) {
	var gotAuth, gotCT, gotBody, gotMethod string
	first := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotMethod = r.Method
		// The instrumented transport's compression middleware gzips the request
		// body (Kiota default; Graph accepts it), so decompress before asserting.
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, gzErr := gzip.NewReader(r.Body)
			if gzErr != nil {
				t.Errorf("gzip.NewReader: %v", gzErr)
			} else {
				defer gz.Close()
				reader = gz
			}
		}
		b, _ := io.ReadAll(reader)
		gotBody = string(b)
		if first {
			first = false
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"job-1","status":"notStarted"}`))
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{RetryDelaySeconds: 1})

	body, err := c.RawPost(context.Background(), srv.URL, []byte(`{"reportName":"x"}`), nil)
	if err != nil {
		t.Fatalf("RawPost: %v", err)
	}
	if string(body) != `{"id":"job-1","status":"notStarted"}` {
		t.Errorf("body = %q, want the JSON payload", body)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want bearer token", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody != `{"reportName":"x"}` {
		t.Errorf("request body = %q, want the posted JSON", gotBody)
	}
}

// TestRawPostReturnsErrorWithStatusAndBodyOnNon2xx: a non-2xx POST response is
// surfaced as an error including the status and body (the export API 400s on a
// bad reportName/select column, which the subsystem must classify).
func TestRawPostReturnsErrorWithStatusAndBodyOnNon2xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"BadRequest"}}`))
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{RetryDelaySeconds: 1})
	if _, err := c.RawPost(context.Background(), srv.URL, []byte(`{}`), nil); err == nil {
		t.Fatal("expected RawPost to return an error on HTTP 400")
	}
}

// TestRawGetWithHeadersSetsHeaders: the header-capable raw GET attaches the
// caller's headers (e.g. ConsistencyLevel: eventual, required by every Entra
// directory $count/advanced-$filter query) on top of the bearer token, and
// still reads through the retrying transport.
func TestRawGetWithHeadersSetsHeaders(t *testing.T) {
	var gotConsistency, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConsistency = r.Header.Get("ConsistencyLevel")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`42`))
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{})

	body, err := c.RawGetWithHeaders(context.Background(), srv.URL, map[string]string{"ConsistencyLevel": "eventual"})
	if err != nil {
		t.Fatalf("RawGetWithHeaders: %v", err)
	}
	if string(body) != `42` {
		t.Errorf("body = %q, want 42", body)
	}
	if gotConsistency != "eventual" {
		t.Errorf("ConsistencyLevel = %q, want eventual", gotConsistency)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want bearer token", gotAuth)
	}
}

func TestRawGetTokenError(t *testing.T) {
	ta := &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{err: errors.New("cred boom")}}
	c, err := NewClient(context.Background(), ta, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.RawGet(context.Background(), "https://graph.microsoft.com/v1.0/x"); err == nil {
		t.Fatal("expected RawGet to fail when the credential cannot mint a token")
	}
}

// TestRawGetRejectsForeignHostBeforeTokenAcquisition catches a missing raw-URL
// allow-list: a foreign HTTPS endpoint must not receive a request or trigger a
// Graph token acquisition.
func TestRawGetRejectsForeignHostBeforeTokenAcquisition(t *testing.T) {
	var requests, tokenCalls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token", calls: &tokenCalls}, []string{"graph.microsoft.com"}, Options{})
	if _, err := c.RawGet(context.Background(), srv.URL); err == nil {
		t.Fatal("expected RawGet to reject a foreign host")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("foreign server requests = %d, want 0", got)
	}
	if got := tokenCalls.Load(); got != 0 {
		t.Errorf("token acquisitions = %d, want 0", got)
	}
}

// TestRawPostRejectsForeignHostBeforeTokenAcquisition catches a missing raw-URL
// allow-list on the export-job POST path.
func TestRawPostRejectsForeignHostBeforeTokenAcquisition(t *testing.T) {
	var requests, tokenCalls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token", calls: &tokenCalls}, []string{"graph.microsoft.com"}, Options{})
	if _, err := c.RawPost(context.Background(), srv.URL, []byte(`{}`), nil); err == nil {
		t.Fatal("expected RawPost to reject a foreign host")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("foreign server requests = %d, want 0", got)
	}
	if got := tokenCalls.Load(); got != 0 {
		t.Errorf("token acquisitions = %d, want 0", got)
	}
}

// TestRawGetRejectsHTTPHostBeforeTokenAcquisition catches a missing scheme
// check: even an allowed hostname must use HTTPS before a token is minted.
func TestRawGetRejectsHTTPHostBeforeTokenAcquisition(t *testing.T) {
	var requests, tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token", calls: &tokenCalls}, []string{testServerHost(t, srv)}, Options{})
	if _, err := c.RawGet(context.Background(), srv.URL); err == nil {
		t.Fatal("expected RawGet to reject an HTTP URL")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("HTTP server requests = %d, want 0", got)
	}
	if got := tokenCalls.Load(); got != 0 {
		t.Errorf("token acquisitions = %d, want 0", got)
	}
}

// TestRawGetAllowsExplicitHost preserves the supported test and sovereign-host
// escape hatch: an explicitly configured HTTPS host may receive a bearer token.
func TestRawGetAllowsExplicitHost(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{})
	if _, err := c.RawGet(context.Background(), srv.URL); err != nil {
		t.Fatalf("RawGet explicit host: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("explicit host requests = %d, want 1", got)
	}
}

// TestRawPostAllowsExplicitHost preserves explicit HTTPS-host support on the
// export-job POST path.
func TestRawPostAllowsExplicitHost(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{})
	if _, err := c.RawPost(context.Background(), srv.URL, []byte(`{}`), nil); err != nil {
		t.Fatalf("RawPost explicit host: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("explicit host requests = %d, want 1", got)
	}
}

// TestRawGetAllowsPublicAndSovereignHosts pins the two legitimate deployment
// shapes: public Graph uses the default allow-list, while a sovereign cloud is
// admitted only when its hostname is explicitly configured.
func TestRawGetAllowsPublicAndSovereignHosts(t *testing.T) {
	for _, tt := range []struct {
		name       string
		url        string
		validHosts []string
	}{
		{name: "public default", url: "https://graph.microsoft.com/v1.0/users"},
		{name: "US Government sovereign", url: "https://graph.microsoft.us/v1.0/users", validHosts: []string{"graph.microsoft.us"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			opts := Options{
				ValidHosts: tt.validHosts,
				baseTransport: rawRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					requests.Add(1)
					if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
						t.Errorf("Authorization = %q, want bearer token", got)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
						Request:    req,
					}, nil
				}),
			}
			c, err := NewClient(context.Background(), &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{token: "secret-token"}}, opts)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			body, err := c.RawGet(context.Background(), tt.url)
			if err != nil {
				t.Fatalf("RawGet %s: %v", tt.name, err)
			}
			if string(body) != `{"ok":true}` {
				t.Errorf("body = %q, want JSON payload", body)
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("requests = %d, want 1", got)
			}
		})
	}
}

func TestRawGetResponseBodyLimit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		length  int
		wantErr bool
	}{
		{name: "exact limit", length: maxRawBodyBytes},
		{name: "limit plus one", length: maxRawBodyBytes + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := bytes.Repeat([]byte("x"), tt.length)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(response)
			}))
			defer srv.Close()

			c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{})
			body, err := c.RawGet(context.Background(), srv.URL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected RawGet to reject a response over the body limit")
				}
				var limitErr interface {
					rawBodyLimit() int
					rawBodyURL() string
				}
				if !errors.As(err, &limitErr) {
					t.Fatalf("RawGet overflow error = %T (%v), want typed body-limit error", err, err)
				}
				if got := limitErr.rawBodyURL(); got != srv.URL {
					t.Errorf("overflow URL = %q, want %q", got, srv.URL)
				}
				if body != nil {
					t.Errorf("RawGet body = %d bytes, want nil on overflow", len(body))
				}
				return
			}
			if err != nil {
				t.Fatalf("RawGet exact-limit response: %v", err)
			}
			if got := len(body); got != maxRawBodyBytes {
				t.Errorf("RawGet body length = %d, want %d", got, maxRawBodyBytes)
			}
		})
	}
}

func TestRawPostResponseBodyLimit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		length  int
		wantErr bool
	}{
		{name: "exact limit", length: maxRawBodyBytes},
		{name: "limit plus one", length: maxRawBodyBytes + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := bytes.Repeat([]byte("x"), tt.length)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(response)
			}))
			defer srv.Close()

			c := newRawTestClient(t, srv, fakeCredential{token: "secret-token"}, []string{testServerHost(t, srv)}, Options{})
			body, err := c.RawPost(context.Background(), srv.URL, []byte(`{}`), nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected RawPost to reject a response over the body limit")
				}
				var limitErr interface {
					rawBodyLimit() int
					rawBodyURL() string
				}
				if !errors.As(err, &limitErr) {
					t.Fatalf("RawPost overflow error = %T (%v), want typed body-limit error", err, err)
				}
				if got := limitErr.rawBodyURL(); got != srv.URL {
					t.Errorf("overflow URL = %q, want %q", got, srv.URL)
				}
				if body != nil {
					t.Errorf("RawPost body = %d bytes, want nil on overflow", len(body))
				}
				return
			}
			if err != nil {
				t.Fatalf("RawPost exact-limit response: %v", err)
			}
			if got := len(body); got != maxRawBodyBytes {
				t.Errorf("RawPost body length = %d, want %d", got, maxRawBodyBytes)
			}
		})
	}
}
