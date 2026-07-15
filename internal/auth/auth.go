// Package auth wires per-tenant Microsoft Graph credentials via
// azidentity.DefaultAzureCredential. It is deliberately Graph-SDK-agnostic:
// it hands back an azcore.TokenCredential that any Kiota-based client can
// consume, without depending on msgraph-sdk-go itself.
//
// # Credential material comes from the environment, never from YAML
//
// TenantConfig carries only public identifiers (tenant ID, client ID).
// DefaultAzureCredential resolves the actual secret from whichever of its
// supported mechanisms is configured in the process environment:
//
//   - Client secret: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
//   - Client certificate: AZURE_TENANT_ID, AZURE_CLIENT_ID,
//     AZURE_CLIENT_CERTIFICATE_PATH (optionally AZURE_CLIENT_CERTIFICATE_PASSWORD).
//   - Workload identity (e.g. AKS federated credentials):
//     AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE,
//     AZURE_AUTHORITY_HOST — normally injected by the platform, not set by hand.
//   - Managed identity: no environment variables required; the credential
//     chain falls through to the instance metadata service automatically
//     when running on an Azure host with a managed identity assigned.
//
// A single process may poll several tenants concurrently, each with its own
// TenantID pinned into the credential so a shared app registration (or
// distinct per-tenant app registrations) resolves against the right
// directory rather than whichever tenant the ambient environment defaults to.
//
// # Two manual-setup 403 traps
//
// Building a credential here only proves the credential chain itself is
// configured — it does not prove the app registration is actually usable
// against Graph. Two admin steps are easy to forget and both fail with a
// 403 at first real API call, not at credential construction:
//
//  1. Admin consent: adding an application permission (e.g.
//     Directory.Read.All) to the app registration does not grant it —
//     a tenant admin must separately consent, or every call 403s.
//  2. Directory role gating: some Graph surfaces (notably Identity
//     Protection) additionally require the calling service principal to
//     hold a directory role, not just an API permission scope. A service
//     principal with the permission but not the role still fails at
//     runtime, per collector, once that collector's first request lands.
//
// A partially-permissioned service principal therefore looks healthy right
// up until a specific collector starts polling. SmokeToken is the cheap,
// fast probe (an OAuth token request, no Graph call) used by the preflight
// command (#11) to catch the credential-chain half of this before startup;
// it cannot by itself detect missing consent or a missing directory role,
// since those only surface once Graph itself is called.
package auth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/rknightion/graph2otel/internal/config"
)

// GraphDefaultScope is the ".default" scope for app-only (client
// credentials) access to Microsoft Graph. It is the only scope an
// application-permission Graph client needs: the actual set of granted
// permissions is determined by the app registration's consented API
// permissions, not by the scope string requested here.
const GraphDefaultScope = "https://graph.microsoft.com/.default"

// TenantAuth pairs a tenant ID with the credential used to authenticate
// against that tenant's Graph API.
type TenantAuth struct {
	TenantID string
	Cred     azcore.TokenCredential
}

// NewTenantAuth builds a DefaultAzureCredential scoped to cfg.TenantID. The
// tenant ID is pinned into the credential options (rather than left to the
// ambient AZURE_TENANT_ID environment variable) so a multi-tenant process
// authenticates each tenant against its own directory, regardless of which
// tenant the environment's default credential would otherwise pick.
//
// cfg.ClientID is not injected here: DefaultAzureCredential's environment-
// credential leg reads AZURE_CLIENT_ID (and its secret/certificate
// counterparts) directly from the process environment. cfg.ClientID exists
// on TenantConfig for future collectors and diagnostics that need to know
// which app registration is in play, not as an input to credential
// construction.
func NewTenantAuth(cfg config.TenantConfig) (*TenantAuth, error) {
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		TenantID: cfg.TenantID,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: tenant %q: building default credential: %w", cfg.TenantID, err)
	}
	return &TenantAuth{TenantID: cfg.TenantID, Cred: cred}, nil
}

// BuildAll constructs one TenantAuth per entry in tenants, in order. On any
// failure it returns an error identifying which tenant could not be built,
// rather than a bare wrapped error.
func BuildAll(tenants []config.TenantConfig) ([]*TenantAuth, error) {
	built := make([]*TenantAuth, 0, len(tenants))
	for _, cfg := range tenants {
		ta, err := NewTenantAuth(cfg)
		if err != nil {
			return nil, fmt.Errorf("auth: building credential for tenant %q: %w", cfg.TenantID, err)
		}
		built = append(built, ta)
	}
	return built, nil
}

// SmokeToken requests a token for GraphDefaultScope as a cheap credential
// probe: it exercises the credential chain (and, for chain legs that call
// out to Entra ID, reachability of the tenant) without making any Graph API
// call itself. It is the preflight command's (#11) fast pre-startup check —
// a failure here means the credential chain itself is broken (unreachable
// tenant, bad client, missing consent surfaced as an auth error); it cannot
// detect a missing directory role or missing consent that Entra ID itself
// doesn't reject at token time, since those only fail on the first real
// Graph call.
func (a *TenantAuth) SmokeToken(ctx context.Context) error {
	_, err := a.Cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{GraphDefaultScope}})
	if err != nil {
		return fmt.Errorf("auth: tenant %q: requesting Graph token (check tenant reachability, client credentials, and admin consent): %w", a.TenantID, err)
	}
	return nil
}
