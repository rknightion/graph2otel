package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/rknightion/graph2otel/internal/config"
)

// TestGraphDefaultScope guards the app-only Graph scope constant against an
// accidental edit — the value is load-bearing (Graph rejects a wrong scope
// string outright rather than degrading gracefully).
func TestGraphDefaultScope(t *testing.T) {
	if GraphDefaultScope != "https://graph.microsoft.com/.default" {
		t.Errorf("GraphDefaultScope = %q, want %q", GraphDefaultScope, "https://graph.microsoft.com/.default")
	}
}

// TestNewTenantAuth captures credential construction without reaching a live
// tenant. The ambient wildcard asserts that NewTenantAuth supplies a
// deliberately narrow allow-list instead of inheriting the environment.
func TestNewTenantAuth(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	t.Setenv("AZURE_ADDITIONALLY_ALLOWED_TENANTS", "*")

	originalFactory := buildDefaultAzureCredential
	t.Cleanup(func() { buildDefaultAzureCredential = originalFactory })
	var gotOptions azidentity.DefaultAzureCredentialOptions
	underlying := &fakeCredential{}
	buildDefaultAzureCredential = func(
		opts *azidentity.DefaultAzureCredentialOptions,
	) (azcore.TokenCredential, error) {
		gotOptions = *opts
		gotOptions.AdditionallyAllowedTenants = append(
			[]string(nil), opts.AdditionallyAllowedTenants...,
		)
		return underlying, nil
	}

	cfg := config.TenantConfig{TenantID: tenantID, ClientID: "client-a"}
	ta, err := NewTenantAuth(cfg)
	if err != nil {
		t.Fatalf("NewTenantAuth: %v", err)
	}
	if ta == nil {
		t.Fatal("NewTenantAuth returned nil TenantAuth")
	}
	if ta.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", ta.TenantID, tenantID)
	}
	if ta.Cred == nil {
		t.Error("Cred should be non-nil")
	}
	if gotOptions.TenantID != tenantID {
		t.Errorf("DefaultAzureCredential TenantID = %q, want %q", gotOptions.TenantID, tenantID)
	}
	if len(gotOptions.AdditionallyAllowedTenants) != 1 ||
		gotOptions.AdditionallyAllowedTenants[0] != tenantID {
		t.Errorf(
			"DefaultAzureCredential AdditionallyAllowedTenants = %v, want [%q]",
			gotOptions.AdditionallyAllowedTenants, tenantID,
		)
	}
	bound, ok := ta.Cred.(*tenantBoundCredential)
	if !ok {
		t.Fatalf("TenantAuth.Cred = %T, want *tenantBoundCredential", ta.Cred)
	}
	if bound.tenantID != tenantID || bound.credential != underlying {
		t.Errorf("tenant-bound credential = %+v, want tenant %q over injected credential", bound, tenantID)
	}
}

// TestBuildAll builds one TenantAuth per tenant, each carrying its own tenant ID.
func TestBuildAll(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")

	tenants := []config.TenantConfig{
		{TenantID: "tenant-a", ClientID: "client-a"},
		{TenantID: "tenant-b", ClientID: "client-b"},
	}
	built, err := BuildAll(tenants)
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

// fakeCredential is a minimal azcore.TokenCredential for exercising token
// consumers without reaching a live tenant.
type fakeCredential struct {
	token string
	err   error
}

type tokenCredentialFunc func(
	context.Context,
	policy.TokenRequestOptions,
) (azcore.AccessToken, error)

func (f tokenCredentialFunc) GetToken(
	ctx context.Context,
	opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	return f(ctx, opts)
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(opts.Scopes) != 1 || opts.Scopes[0] != GraphDefaultScope {
		return azcore.AccessToken{}, errors.New("unexpected token scope")
	}
	return azcore.AccessToken{Token: f.token}, f.err
}

var errSentinelGetToken = errors.New("AADSTS700016: application not found in directory")

func applicationIdentityFailureCode(
	t *testing.T,
	err error,
) ApplicationIdentityFailureCode {
	t.Helper()
	var identityErr *ApplicationIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("errors.As(*ApplicationIdentityError) = false for %v", err)
	}
	return identityErr.Code
}

func tenantBindingFailureCode(t *testing.T, err error) TenantBindingFailureCode {
	t.Helper()
	var bindingErr *TenantBindingError
	if !errors.As(err, &bindingErr) {
		t.Fatalf("errors.As(*TenantBindingError) = false for %v", err)
	}
	return bindingErr.Code
}

func fakeJWT(t *testing.T, claims map[string]any) (token, payload string) {
	t.Helper()

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload = string(payloadBytes)
	return header + "." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".signature", payload
}

func fakeJWTWithRawPayload(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestTenantBoundCredentialPinsEveryRequestAndReturnsMatchingTenant(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	token, _ := fakeJWT(t, map[string]any{
		"tid":   tenantID,
		"appid": "authenticated-client-id",
	})

	for _, requestedTenant := range []string{
		"",
		"22222222-2222-2222-2222-222222222222",
		tenantID,
	} {
		t.Run("requested="+requestedTenant, func(t *testing.T) {
			var gotOptions policy.TokenRequestOptions
			underlying := tokenCredentialFunc(func(
				_ context.Context,
				opts policy.TokenRequestOptions,
			) (azcore.AccessToken, error) {
				gotOptions = opts
				opts.Scopes[0] = "mutated-by-underlying"
				return azcore.AccessToken{Token: token}, nil
			})
			credential := newTenantBoundCredential(tenantID, underlying)
			callerOptions := policy.TokenRequestOptions{
				Scopes:   []string{"scope-a"},
				TenantID: requestedTenant,
			}

			got, err := credential.GetToken(context.Background(), callerOptions)
			if err != nil {
				t.Fatalf("GetToken() error = %v", err)
			}
			if got.Token != token {
				t.Fatalf("GetToken() token = %q, want matching token", got.Token)
			}
			if gotOptions.TenantID != tenantID {
				t.Errorf("underlying TenantID = %q, want %q", gotOptions.TenantID, tenantID)
			}
			if callerOptions.TenantID != requestedTenant {
				t.Errorf("caller TenantID mutated to %q, want %q", callerOptions.TenantID, requestedTenant)
			}
			if callerOptions.Scopes[0] != "scope-a" {
				t.Errorf("caller Scopes mutated to %v", callerOptions.Scopes)
			}
		})
	}
}

func TestTenantBoundCredentialAcceptsConfiguredGUIDCaseVariant(t *testing.T) {
	const (
		configuredTenantID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
		tokenTenantID      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	)
	token := selfContainedJWT(t, map[string]any{"tid": tokenTenantID})
	credential := newTenantBoundCredential(
		configuredTenantID,
		tokenCredentialFunc(func(
			context.Context,
			policy.TokenRequestOptions,
		) (azcore.AccessToken, error) {
			return azcore.AccessToken{Token: token}, nil
		}),
	)

	got, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{})
	if err != nil {
		t.Fatalf("GetToken() error = %v, want semantic GUID match", err)
	}
	if got.Token != token {
		t.Fatalf("GetToken() token = %q, want matching token", got.Token)
	}
}

func TestTenantBoundCredentialRejectsInvalidTenantBeforeTokenEscape(t *testing.T) {
	const (
		tenantID      = "11111111-1111-1111-1111-111111111111"
		otherTenantID = "22222222-2222-2222-2222-222222222222"
		secretMarker  = "secret-token-payload"
	)
	tests := []struct {
		name     string
		token    string
		wantCode TenantBindingFailureCode
	}{
		{
			name:     "wrong segment count",
			token:    "sensitive-not-a-three-segment-jwt",
			wantCode: TenantBindingMalformedToken,
		},
		{
			name:     "invalid base64",
			token:    "header.sensitive%%%payload.signature",
			wantCode: TenantBindingMalformedToken,
		},
		{
			name:     "malformed JSON",
			token:    fakeJWTWithRawPayload(`{"tid":"` + secretMarker + `"`),
			wantCode: TenantBindingMalformedToken,
		},
		{
			name:     "non-object payload",
			token:    fakeJWTWithRawPayload(`null`),
			wantCode: TenantBindingMalformedToken,
		},
		{
			name:     "non-string tid",
			token:    selfContainedJWT(t, map[string]any{"tid": 42, "marker": secretMarker}),
			wantCode: TenantBindingMalformedToken,
		},
		{
			name:     "missing tid",
			token:    selfContainedJWT(t, map[string]any{"marker": secretMarker}),
			wantCode: TenantBindingMissingTenantID,
		},
		{
			name:     "empty tid",
			token:    selfContainedJWT(t, map[string]any{"tid": "", "marker": secretMarker}),
			wantCode: TenantBindingMissingTenantID,
		},
		{
			name: "mismatched tid",
			token: selfContainedJWT(t, map[string]any{
				"tid": otherTenantID, "marker": secretMarker,
			}),
			wantCode: TenantBindingTenantMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := tokenCredentialFunc(func(
				context.Context,
				policy.TokenRequestOptions,
			) (azcore.AccessToken, error) {
				return azcore.AccessToken{Token: tt.token}, nil
			})
			credential := newTenantBoundCredential(tenantID, underlying)

			got, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{})
			if err == nil {
				t.Fatal("GetToken() error = nil, want tenant-binding failure")
			}
			if got.Token != "" {
				t.Fatalf("GetToken() escaped token %q on tenant-binding failure", got.Token)
			}
			if code := tenantBindingFailureCode(t, err); code != tt.wantCode {
				t.Errorf("failure code = %q, want %q", code, tt.wantCode)
			}
			for _, forbidden := range []string{
				tt.token, tenantID, otherTenantID, secretMarker,
			} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Errorf("error %q exposes %q", err.Error(), forbidden)
				}
			}
		})
	}
}

func TestTenantBoundCredentialPreservesUnderlyingError(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cause := errors.New("credential-secret-marker")
	underlying := tokenCredentialFunc(func(
		context.Context,
		policy.TokenRequestOptions,
	) (azcore.AccessToken, error) {
		return azcore.AccessToken{Token: "must-not-escape"}, cause
	})
	credential := newTenantBoundCredential(tenantID, underlying)

	got, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{})
	if !errors.Is(err, cause) {
		t.Fatalf("GetToken() error = %v, want wrapped credential cause", err)
	}
	if got.Token != "" {
		t.Fatalf("GetToken() escaped token %q alongside credential error", got.Token)
	}
}

func TestTenantBindingCoversSmokeTokenAndApplicationIdentity(t *testing.T) {
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		appID    = "authenticated-client-id"
	)
	matchingToken := selfContainedJWT(t, map[string]any{
		"tid": tenantID, "appid": appID,
	})
	matching := &TenantAuth{
		TenantID: tenantID,
		Cred: newTenantBoundCredential(tenantID, tokenCredentialFunc(func(
			context.Context,
			policy.TokenRequestOptions,
		) (azcore.AccessToken, error) {
			return azcore.AccessToken{Token: matchingToken}, nil
		})),
	}
	if err := matching.SmokeToken(context.Background()); err != nil {
		t.Fatalf("SmokeToken() matching tid error = %v", err)
	}
	gotAppID, err := matching.AuthenticatedApplicationID(context.Background())
	if err != nil {
		t.Fatalf("AuthenticatedApplicationID() error = %v", err)
	}
	if gotAppID != appID {
		t.Errorf("AuthenticatedApplicationID() = %q, want %q", gotAppID, appID)
	}

	mismatchedToken := selfContainedJWT(t, map[string]any{
		"tid": "22222222-2222-2222-2222-222222222222",
	})
	mismatched := &TenantAuth{
		TenantID: tenantID,
		Cred: newTenantBoundCredential(tenantID, tokenCredentialFunc(func(
			context.Context,
			policy.TokenRequestOptions,
		) (azcore.AccessToken, error) {
			return azcore.AccessToken{Token: mismatchedToken}, nil
		})),
	}
	err = mismatched.SmokeToken(context.Background())
	if err == nil {
		t.Fatal("SmokeToken() mismatch error = nil")
	}
	if code := tenantBindingFailureCode(t, err); code != TenantBindingTenantMismatch {
		t.Errorf("SmokeToken() failure code = %q, want %q", code, TenantBindingTenantMismatch)
	}
	if strings.Contains(err.Error(), mismatchedToken) {
		t.Errorf("SmokeToken() error exposes token: %v", err)
	}

	_, err = mismatched.AuthenticatedApplicationID(context.Background())
	if err == nil {
		t.Fatal("AuthenticatedApplicationID() mismatch error = nil")
	}
	if code := tenantBindingFailureCode(t, err); code != TenantBindingTenantMismatch {
		t.Errorf(
			"AuthenticatedApplicationID() failure code = %q, want %q",
			code,
			TenantBindingTenantMismatch,
		)
	}
	if strings.Contains(err.Error(), mismatchedToken) {
		t.Errorf("AuthenticatedApplicationID() error exposes token: %v", err)
	}
}

func selfContainedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	token, _ := fakeJWT(t, claims)
	return token
}

// TestAuthenticatedApplicationIDProvesTokenAppID guards against using either
// configured or ambient client IDs as proof of the application that actually
// authenticated.
func TestAuthenticatedApplicationIDProvesTokenAppID(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "ambient-client-id")

	ta, err := NewTenantAuth(config.TenantConfig{
		TenantID: "tenant-a",
		ClientID: "configured-client-id",
	})
	if err != nil {
		t.Fatalf("NewTenantAuth: %v", err)
	}
	token, _ := fakeJWT(t, map[string]any{"appid": "authenticated-client-id"})
	ta.Cred = &fakeCredential{token: token}

	got, err := ta.AuthenticatedApplicationID(context.Background())
	if err != nil {
		t.Fatalf("AuthenticatedApplicationID() error = %v", err)
	}
	if got != "authenticated-client-id" {
		t.Errorf("AuthenticatedApplicationID() = %q, want %q", got, "authenticated-client-id")
	}
}

func TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken(t *testing.T) {
	const (
		paddedPayload    = `{"marker":"secret-padded"}`
		malformedPayload = `{"marker":"secret-json"`
		nonObjectPayload = `null`
	)
	paddedToken := fakeJWTWithRawPayload(paddedPayload)
	paddedToken = strings.Replace(paddedToken, ".signature", "=.signature", 1)

	tests := []struct {
		name    string
		token   string
		payload string
	}{
		{
			name:    "wrong segment count",
			token:   "sensitive-not-a-three-segment-jwt",
			payload: "sensitive",
		},
		{
			name:    "invalid base64url",
			token:   "header.sensitive%%%payload.signature",
			payload: "sensitive%%%payload",
		},
		{
			name:    "padded payload",
			token:   paddedToken,
			payload: paddedPayload,
		},
		{
			name:    "malformed JSON",
			token:   fakeJWTWithRawPayload(malformedPayload),
			payload: malformedPayload,
		},
		{
			name:    "non-object JSON",
			token:   fakeJWTWithRawPayload(nonObjectPayload),
			payload: nonObjectPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ta := &TenantAuth{
				TenantID: "tenant-a",
				Cred:     &fakeCredential{token: tt.token},
			}

			_, err := ta.AuthenticatedApplicationID(context.Background())
			if err == nil {
				t.Fatal("AuthenticatedApplicationID() error = nil, want malformed-token error")
			}
			if !strings.Contains(err.Error(), "tenant-a") {
				t.Errorf("error %q should mention the tenant id", err.Error())
			}
			if got := applicationIdentityFailureCode(t, err); got != ApplicationIdentityMalformedToken {
				t.Errorf("failure code = %q, want %q", got, ApplicationIdentityMalformedToken)
			}
			for _, secret := range []string{tt.token, tt.payload} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q exposes token material %q", err.Error(), secret)
				}
			}
		})
	}
}

func TestAuthenticatedApplicationIDRejectsInvalidAppIDWithoutLeakingPayload(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{name: "absent", claims: map[string]any{"marker": "secret-absent"}},
		{name: "empty", claims: map[string]any{"appid": "", "marker": "secret-empty"}},
		{name: "non-string", claims: map[string]any{"appid": 42, "marker": "secret-non-string"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, payload := fakeJWT(t, tt.claims)
			ta := &TenantAuth{
				TenantID: "tenant-a",
				Cred:     &fakeCredential{token: token},
			}

			_, err := ta.AuthenticatedApplicationID(context.Background())
			if err == nil {
				t.Fatal("AuthenticatedApplicationID() error = nil, want invalid-appid error")
			}
			if !strings.Contains(err.Error(), "tenant-a") {
				t.Errorf("error %q should mention the tenant id", err.Error())
			}
			if got := applicationIdentityFailureCode(t, err); got != ApplicationIdentityMissingAppID {
				t.Errorf("failure code = %q, want %q", got, ApplicationIdentityMissingAppID)
			}
			for _, secret := range []string{token, payload, "secret-"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q exposes token material %q", err.Error(), secret)
				}
			}
		})
	}
}

func TestAuthenticatedApplicationIDWrapsTokenRequestErrorWithoutLeakingToken(t *testing.T) {
	const token = "sensitive-token-returned-with-error"
	ta := &TenantAuth{
		TenantID: "tenant-a",
		Cred: &fakeCredential{
			token: token,
			err:   errSentinelGetToken,
		},
	}

	_, err := ta.AuthenticatedApplicationID(context.Background())
	if err == nil {
		t.Fatal("AuthenticatedApplicationID() error = nil, want token-request error")
	}
	if !strings.Contains(err.Error(), "tenant-a") {
		t.Errorf("error %q should mention the tenant id", err.Error())
	}
	if !errors.Is(err, errSentinelGetToken) {
		t.Errorf("error should wrap the token request cause: %v", err)
	}
	if got := applicationIdentityFailureCode(t, err); got != ApplicationIdentityTokenRequestFailed {
		t.Errorf("failure code = %q, want %q", got, ApplicationIdentityTokenRequestFailed)
	}
	if strings.Contains(err.Error(), errSentinelGetToken.Error()) {
		t.Errorf("error %q exposes raw token-request cause", err.Error())
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error %q exposes access token", err.Error())
	}
}

func TestApplicationIdentityErrorClassificationSurvivesWrappingAndMessageChanges(t *testing.T) {
	cause := errors.New("arbitrary changed failure prose")
	identityErr := &ApplicationIdentityError{
		Code: ApplicationIdentityMalformedToken,
		Err:  cause,
	}
	err := fmt.Errorf("outer wording can also change: %w", identityErr)

	if got := applicationIdentityFailureCode(t, err); got != ApplicationIdentityMalformedToken {
		t.Errorf("failure code = %q, want %q", got, ApplicationIdentityMalformedToken)
	}
	if !errors.Is(err, cause) {
		t.Errorf("typed failure should preserve its cause: %v", err)
	}
}

// TestSmokeTokenWrapsError asserts SmokeToken wraps an underlying credential
// error into a message that identifies the tenant and preserves the cause.
func TestSmokeTokenWrapsError(t *testing.T) {
	ta := &TenantAuth{
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
	ta := &TenantAuth{
		TenantID: "tenant-a",
		Cred:     &fakeCredential{err: nil},
	}
	if err := ta.SmokeToken(context.Background()); err != nil {
		t.Errorf("SmokeToken should succeed: %v", err)
	}
}
