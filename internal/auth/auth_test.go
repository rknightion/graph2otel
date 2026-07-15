package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
)

// TestGraphDefaultScope guards the app-only Graph scope constant against an
// accidental edit — the value is load-bearing (Graph rejects a wrong scope
// string outright rather than degrading gracefully).
func TestGraphDefaultScope(t *testing.T) {
	if auth.GraphDefaultScope != "https://graph.microsoft.com/.default" {
		t.Errorf("GraphDefaultScope = %q, want %q", auth.GraphDefaultScope, "https://graph.microsoft.com/.default")
	}
}

// TestNewTenantAuth builds a credential for a valid TenantConfig. Construction
// of a DefaultAzureCredential does not itself require a live token or even a
// fully-populated credential chain, so no live tenant is needed here — we set
// a benign AZURE_CLIENT_ID so the environment-credential leg of the chain has
// something to look at during construction.
func TestNewTenantAuth(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

	cfg := config.TenantConfig{TenantID: "tenant-a", ClientID: "client-a"}
	ta, err := auth.NewTenantAuth(cfg)
	if err != nil {
		t.Fatalf("NewTenantAuth: %v", err)
	}
	if ta == nil {
		t.Fatal("NewTenantAuth returned nil TenantAuth")
	}
	if ta.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q, want %q", ta.TenantID, "tenant-a")
	}
	if ta.Cred == nil {
		t.Error("Cred should be non-nil")
	}
}

// TestBuildAll builds one TenantAuth per tenant, each carrying its own tenant ID.
func TestBuildAll(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

	tenants := []config.TenantConfig{
		{TenantID: "tenant-a", ClientID: "client-a"},
		{TenantID: "tenant-b", ClientID: "client-b"},
	}
	built, err := auth.BuildAll(tenants)
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	if len(built) != len(tenants) {
		t.Fatalf("len(built) = %d, want %d", len(built), len(tenants))
	}
	for i, ta := range built {
		if ta.TenantID != tenants[i].TenantID {
			t.Errorf("built[%d].TenantID = %q, want %q", i, ta.TenantID, tenants[i].TenantID)
		}
		if ta.Cred == nil {
			t.Errorf("built[%d].Cred is nil", i)
		}
	}
}

// fakeCredential is a minimal azcore.TokenCredential that always returns a
// sentinel error, so SmokeToken's error-wrapping can be tested without
// reaching a live tenant.
type fakeCredential struct {
	err error
}

func (f *fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, f.err
}

var errSentinelGetToken = errors.New("AADSTS700016: application not found in directory")

// TestSmokeTokenWrapsError asserts SmokeToken wraps an underlying credential
// error into a message that identifies the tenant and preserves the cause.
func TestSmokeTokenWrapsError(t *testing.T) {
	ta := &auth.TenantAuth{
		TenantID: "tenant-a",
		Cred:     &fakeCredential{err: errSentinelGetToken},
	}
	err := ta.SmokeToken(context.Background())
	if err == nil {
		t.Fatal("SmokeToken should return an error when the credential fails")
	}
	if !strings.Contains(err.Error(), "tenant-a") {
		t.Errorf("error %q should mention the tenant id", err.Error())
	}
	if !errors.Is(err, errSentinelGetToken) {
		t.Errorf("error should wrap the underlying cause: %v", err)
	}
}

// TestSmokeTokenSucceeds asserts SmokeToken returns nil when the credential
// returns a token without error.
func TestSmokeTokenSucceeds(t *testing.T) {
	ta := &auth.TenantAuth{
		TenantID: "tenant-a",
		Cred:     &fakeCredential{err: nil},
	}
	if err := ta.SmokeToken(context.Background()); err != nil {
		t.Errorf("SmokeToken should succeed: %v", err)
	}
}
