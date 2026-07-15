package preflight

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
)

// fakeTokenCredential lets source_test build a TokenClaimsSource without a
// real azidentity credential or any network call.
type fakeTokenCredential struct {
	token string
	err   error
}

func (f fakeTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token}, nil
}

// fakeJWT builds a syntactically valid (unsigned) JWT string carrying the
// given roles claim, for exercising decodeJWTRoles / TokenClaimsSource
// without a real Entra ID token.
func fakeJWT(t *testing.T, roles []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(struct {
		Roles []string `json:"roles"`
	}{Roles: roles})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}

func TestDecodeJWTRoles(t *testing.T) {
	want := []string{"AuditLog.Read.All", "User.Read.All"}
	token := fakeJWT(t, want)

	got, err := decodeJWTRoles(token)
	if err != nil {
		t.Fatalf("decodeJWTRoles() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decodeJWTRoles() = %v, want %v", got, want)
	}
}

func TestDecodeJWTRoles_Malformed(t *testing.T) {
	if _, err := decodeJWTRoles("not-a-jwt"); err == nil {
		t.Fatal("decodeJWTRoles() error = nil, want error for malformed token")
	}
}

func TestTokenClaimsSource_GrantedPermissions(t *testing.T) {
	src := &TokenClaimsSource{
		byTenant: map[string]tokenCredential{
			"tenant-a": fakeTokenCredential{token: fakeJWT(t, []string{"Directory.Read.All"})},
		},
	}

	got, err := src.GrantedPermissions(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("GrantedPermissions() error = %v", err)
	}
	if want := []string{"Directory.Read.All"}; !reflect.DeepEqual(got, want) {
		t.Errorf("GrantedPermissions() = %v, want %v", got, want)
	}
}

func TestTokenClaimsSource_GrantedPermissions_UnknownTenant(t *testing.T) {
	src := &TokenClaimsSource{byTenant: map[string]tokenCredential{}}

	if _, err := src.GrantedPermissions(context.Background(), "unknown"); err == nil {
		t.Fatal("GrantedPermissions() error = nil, want error for unconfigured tenant")
	}
}

func TestTokenClaimsSource_GrantedPermissions_TokenError(t *testing.T) {
	src := &TokenClaimsSource{
		byTenant: map[string]tokenCredential{
			"tenant-a": fakeTokenCredential{err: errors.New("boom")},
		},
	}

	if _, err := src.GrantedPermissions(context.Background(), "tenant-a"); err == nil {
		t.Fatal("GrantedPermissions() error = nil, want error propagated from GetToken")
	}
}

func TestNewTokenClaimsSource(t *testing.T) {
	// NewTokenClaimsSource just needs to build without making any network
	// call; a TenantAuth wraps a real azidentity credential type, but
	// construction of that credential (in the auth package) is lazy — no
	// token request happens until GrantedPermissions calls GetToken.
	tenants := []*auth.TenantAuth{
		{TenantID: "tenant-a", Cred: fakeTokenCredential{token: fakeJWT(t, nil)}},
		nil, // must be skipped, not panic
	}

	src := NewTokenClaimsSource(tenants)
	if _, ok := src.byTenant["tenant-a"]; !ok {
		t.Fatal("NewTokenClaimsSource() did not register tenant-a")
	}
	if len(src.byTenant) != 1 {
		t.Errorf("byTenant has %d entries, want 1 (nil entry should be skipped)", len(src.byTenant))
	}
}
