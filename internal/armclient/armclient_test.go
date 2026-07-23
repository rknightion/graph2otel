package armclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeCred returns a fixed token and records the scopes it was asked for.
type fakeCred struct {
	token  string
	scopes []string
	err    error
}

func (f *fakeCred) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = opts.Scopes
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token}, nil
}

func TestRawGet_SendsBearerAndReturnsBody(t *testing.T) {
	var gotAuth, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	cred := &fakeCred{token: "tok123"}
	c := NewClient(cred, Options{HTTPClient: srv.Client()})
	body, err := c.RawGet(context.Background(), srv.URL+"/providers/microsoft.aadiam/diagnosticSettings")
	if err != nil {
		t.Fatalf("RawGet: %v", err)
	}
	if string(body) != `{"value":[]}` {
		t.Errorf("body = %q", body)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if len(cred.scopes) != 1 || cred.scopes[0] != DefaultScope {
		t.Errorf("scopes = %v, want [%s]", cred.scopes, DefaultScope)
	}
}

func TestRawGet_Non2xxIsErrorWithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`))
	}))
	defer srv.Close()

	c := NewClient(&fakeCred{token: "t"}, Options{HTTPClient: srv.Client()})
	_, err := c.RawGet(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("want error on 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "AuthorizationFailed") {
		t.Errorf("error should name status and body: %v", err)
	}
}
