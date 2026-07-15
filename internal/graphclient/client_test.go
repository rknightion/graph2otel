package graphclient

import (
	"context"
	"errors"
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
