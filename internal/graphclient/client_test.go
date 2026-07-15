package graphclient

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
}

func (f fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	ta := &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{token: "secret-token"}}
	c, err := NewClient(context.Background(), ta, Options{RetryDelaySeconds: 1})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	ta := &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{token: "secret-token"}}
	c, err := NewClient(context.Background(), ta, Options{RetryDelaySeconds: 1})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"BadRequest"}}`))
	}))
	defer srv.Close()

	ta := &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{token: "secret-token"}}
	c, err := NewClient(context.Background(), ta, Options{RetryDelaySeconds: 1})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConsistency = r.Header.Get("ConsistencyLevel")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`42`))
	}))
	defer srv.Close()

	ta := &auth.TenantAuth{TenantID: "t", Cred: fakeCredential{token: "secret-token"}}
	c, err := NewClient(context.Background(), ta, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

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
