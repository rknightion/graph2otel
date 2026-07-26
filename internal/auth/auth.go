// Package auth wires per-tenant Microsoft Graph credentials via
// azidentity.DefaultAzureCredential. It is deliberately Graph-SDK-agnostic:
// it hands back an azcore.TokenCredential that any Kiota-based client can
// consume, without depending on msgraph-sdk-go itself.
//
// # Credential material comes from the environment, never from YAML
//
// TenantConfig carries only public identifiers: the tenant ID and an optional
// expected client ID used for diagnostics. DefaultAzureCredential resolves the
// actual application identity and secret from whichever of its supported
// mechanisms is configured in the process environment:
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
// A process has one ambient application identity selected by that credential
// chain. It may poll several tenants concurrently because each TenantAuth pins
// its TenantID into token requests, so the same ambient application resolves
// against the right directory rather than whichever tenant the environment
// defaults to. TenantConfig.ClientID does not select or override an identity;
// a process that needs a different application identity must be a separate
// process with a different ambient credential chain.
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// ApplicationIdentityFailureCode is the bounded, non-secret reason an
// authenticated application identity could not be proved from a Graph token.
type ApplicationIdentityFailureCode string

const (
	ApplicationIdentityTokenRequestFailed ApplicationIdentityFailureCode = "token_request_failed"
	ApplicationIdentityMalformedToken     ApplicationIdentityFailureCode = "malformed_token"
	ApplicationIdentityMissingAppID       ApplicationIdentityFailureCode = "missing_appid"
)

// ApplicationIdentityError carries a stable failure classification across
// package boundaries. Error deliberately omits Err's text: token-credential
// causes may contain sensitive detail. Unwrap still preserves the cause for
// errors.Is/errors.As; callers must not log the unwrapped cause.
type ApplicationIdentityError struct {
	Code ApplicationIdentityFailureCode
	Err  error
}

func (e *ApplicationIdentityError) Error() string {
	return "authenticated application identity proof failed: " + string(e.Code)
}

func (e *ApplicationIdentityError) Unwrap() error {
	return e.Err
}

// TenantBindingFailureCode is the bounded, non-secret reason a credential
// rejected a returned token before exposing it to a caller.
type TenantBindingFailureCode string

const (
	TenantBindingMalformedToken  TenantBindingFailureCode = "malformed_token"
	TenantBindingMissingTenantID TenantBindingFailureCode = "missing_tid"
	TenantBindingTenantMismatch  TenantBindingFailureCode = "tenant_mismatch"
)

// TenantBindingError carries a stable tenant-binding failure classification.
// Error deliberately omits the token, tenant IDs, and Err's text. Unwrap
// preserves the cause for errors.Is/errors.As without making it safe to log.
type TenantBindingError struct {
	Code TenantBindingFailureCode
	Err  error
}

func (e *TenantBindingError) Error() string {
	return "tenant-bound credential rejected access token: " + string(e.Code)
}

func (e *TenantBindingError) Unwrap() error {
	return e.Err
}

// TenantAuth pairs a tenant ID with the credential used to authenticate
// against that tenant's Graph API.
type TenantAuth struct {
	TenantID string
	Cred     azcore.TokenCredential
}

var buildDefaultAzureCredential = func(
	opts *azidentity.DefaultAzureCredentialOptions,
) (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(opts)
}

// NewTenantAuth builds a DefaultAzureCredential scoped to cfg.TenantID. The
// tenant ID is pinned into the credential options (rather than left to the
// ambient AZURE_TENANT_ID environment variable) so a multi-tenant process
// authenticates each tenant against its own directory, regardless of which
// tenant the environment's default credential would otherwise pick.
//
// cfg.ClientID is not injected here: DefaultAzureCredential's ambient
// credential chain selects one application identity for the whole process.
// cfg.ClientID is only an optional consistency assertion used by startup
// diagnostics; cfg.TenantID pins the directory for this tenant's token requests.
func NewTenantAuth(cfg config.TenantConfig) (*TenantAuth, error) {
	cred, err := buildDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		TenantID:                   cfg.TenantID,
		AdditionallyAllowedTenants: []string{cfg.TenantID},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: tenant %q: building default credential: %w", cfg.TenantID, err)
	}
	return &TenantAuth{
		TenantID: cfg.TenantID,
		Cred:     newTenantBoundCredential(cfg.TenantID, cred),
	}, nil
}

type tenantBoundCredential struct {
	tenantID   string
	credential azcore.TokenCredential
}

func newTenantBoundCredential(
	tenantID string,
	credential azcore.TokenCredential,
) *tenantBoundCredential {
	return &tenantBoundCredential{
		tenantID:   tenantID,
		credential: credential,
	}
}

func (c *tenantBoundCredential) GetToken(
	ctx context.Context,
	opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	pinned := opts
	pinned.Scopes = append([]string(nil), opts.Scopes...)
	pinned.TenantID = c.tenantID

	token, err := c.credential.GetToken(ctx, pinned)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	if err := validateTokenTenant(token.Token, c.tenantID); err != nil {
		return azcore.AccessToken{}, err
	}
	return token, nil
}

func validateTokenTenant(token, tenantID string) error {
	claims, err := decodeJWTClaims(token)
	if err != nil {
		return &TenantBindingError{
			Code: TenantBindingMalformedToken,
			Err:  err,
		}
	}

	rawTenantID, ok := claims["tid"]
	if !ok {
		return &TenantBindingError{
			Code: TenantBindingMissingTenantID,
			Err:  errors.New("access token has no tid claim"),
		}
	}
	var tokenTenantID string
	if err := json.Unmarshal(rawTenantID, &tokenTenantID); err != nil {
		return &TenantBindingError{
			Code: TenantBindingMalformedToken,
			Err:  errors.New("access token tid claim is not a string"),
		}
	}
	if tokenTenantID == "" {
		return &TenantBindingError{
			Code: TenantBindingMissingTenantID,
			Err:  errors.New("access token tid claim is empty"),
		}
	}
	if !strings.EqualFold(tokenTenantID, tenantID) {
		return &TenantBindingError{
			Code: TenantBindingTenantMismatch,
			Err:  errors.New("access token tid does not match configured tenant"),
		}
	}
	return nil
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

// AuthenticatedApplicationID requests a Graph access token and returns the
// non-empty appid claim identifying the application that actually
// authenticated. The payload is decoded without signature verification
// because graph2otel is inspecting a token returned by its own tenant-pinned
// TokenCredential, not authenticating a token supplied by another party.
func (a *TenantAuth) AuthenticatedApplicationID(ctx context.Context) (string, error) {
	tok, err := a.Cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{GraphDefaultScope}})
	if err != nil {
		return "", fmt.Errorf("auth: tenant %q: %w", a.TenantID, &ApplicationIdentityError{
			Code: ApplicationIdentityTokenRequestFailed,
			Err:  err,
		})
	}

	appID, err := decodeAuthenticatedApplicationID(tok.Token)
	if err != nil {
		return "", fmt.Errorf("auth: tenant %q: %w", a.TenantID, err)
	}
	return appID, nil
}

func decodeAuthenticatedApplicationID(token string) (string, error) {
	claims, err := decodeJWTClaims(token)
	if err != nil {
		return "", &ApplicationIdentityError{
			Code: ApplicationIdentityMalformedToken,
			Err:  err,
		}
	}

	rawAppID, ok := claims["appid"]
	if !ok {
		return "", &ApplicationIdentityError{
			Code: ApplicationIdentityMissingAppID,
			Err:  errors.New("graph access token has no appid claim"),
		}
	}
	var appID string
	if err := json.Unmarshal(rawAppID, &appID); err != nil {
		return "", &ApplicationIdentityError{
			Code: ApplicationIdentityMissingAppID,
			Err:  errors.New("graph access token appid claim is not a string"),
		}
	}
	if appID == "" {
		return "", &ApplicationIdentityError{
			Code: ApplicationIdentityMissingAppID,
			Err:  errors.New("graph access token appid claim is empty"),
		}
	}
	return appID, nil
}

func decodeJWTClaims(token string) (map[string]json.RawMessage, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWT segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT payload: %w", err)
	}
	if claims == nil {
		return nil, errors.New("JWT payload is not an object")
	}
	return claims, nil
}
