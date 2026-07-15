package preflight

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
)

// PermissionSource enumerates the Graph application permissions actually
// granted (added to the app registration AND admin-consented) for a tenant.
// It is an interface so the pure Check/Report path stays unit-testable with
// a fake, and the real credential/network-dependent lookup lives in its own
// adapter (TokenClaimsSource) below.
type PermissionSource interface {
	GrantedPermissions(ctx context.Context, tenantID string) ([]string, error)
}

// tokenCredential is the minimal slice of azcore.TokenCredential
// TokenClaimsSource needs; a local interface keeps it fake-able in tests
// without a real azidentity credential.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// TokenClaimsSource is the real, best-effort PermissionSource adapter: for
// the client-credentials (app-only) flow, Entra ID populates an access
// token's "roles" claim with exactly the application permissions that are
// both present on the app registration and admin-consented — i.e. the
// granted set this package needs — with no separate Graph API call (and so
// no extra permission of its own) beyond the token request graph2otel
// already makes to call Graph at all.
//
// This is deliberately best-effort: the "roles" claim shape is documented
// Microsoft behavior but not a formal contract, and the JWT is decoded
// without signature verification here — acceptable because graph2otel is
// inspecting a token it just requested for itself over TLS, not
// authenticating a third party with it.
type TokenClaimsSource struct {
	byTenant map[string]tokenCredential
}

// NewTokenClaimsSource builds a TokenClaimsSource over tenants, keyed by
// TenantID. A nil entry in tenants is skipped.
func NewTokenClaimsSource(tenants []*auth.TenantAuth) *TokenClaimsSource {
	m := make(map[string]tokenCredential, len(tenants))
	for _, ta := range tenants {
		if ta == nil {
			continue
		}
		m[ta.TenantID] = ta.Cred
	}
	return &TokenClaimsSource{byTenant: m}
}

// GrantedPermissions requests an app-only Graph token for tenantID and
// returns the roles claim decoded from it.
func (s *TokenClaimsSource) GrantedPermissions(ctx context.Context, tenantID string) ([]string, error) {
	cred, ok := s.byTenant[tenantID]
	if !ok {
		return nil, fmt.Errorf("preflight: no credential configured for tenant %q", tenantID)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{auth.GraphDefaultScope}})
	if err != nil {
		return nil, fmt.Errorf("preflight: tenant %q: requesting Graph token: %w", tenantID, err)
	}

	roles, err := decodeJWTRoles(tok.Token)
	if err != nil {
		return nil, fmt.Errorf("preflight: tenant %q: %w", tenantID, err)
	}
	return roles, nil
}

// decodeJWTRoles extracts the "roles" claim from a JWT's payload segment
// without verifying its signature (see TokenClaimsSource's doc comment for
// why that is acceptable here).
func decodeJWTRoles(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: want 3 dot-separated segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}
	return claims.Roles, nil
}
