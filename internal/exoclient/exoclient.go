// Package exoclient is graph2otel's client for the Exchange Online admin API's
// app-only PowerShell cmdlet transport — the only route to Microsoft Defender
// quarantine queue depth and MDO (Defender for Office 365) policy state, neither
// of which has any Microsoft Graph API (#233).
//
// # Why this is not internal/graphclient
//
// It is a sibling of graphclient, not a fork. Same identity provider, same
// azidentity credential, genuinely different service:
//
//   - Different audience. Tokens are issued for
//     https://outlook.office365.com/.default, NOT Graph's. A Graph token is
//     rejected. Only the scope differs, so this needs no new auth model.
//
//   - Different request shape. This is not a paged REST GET. Every call is one
//     POST to a single fixed URL, carrying a CmdletInput envelope that names the
//     cmdlet and its parameters; results come back in a flat "value" array. There
//     is no $filter and no $top — paging and filtering are cmdlet parameters,
//     not URL parameters.
//
//     CAUTION, and this client does NOT handle it: a row-returning cmdlet CAN
//     come back truncated, carrying an "@odata.nextLink" and an
//     "@adminapi.warnings" string saying so (live-measured 2026-07-23 on
//     Get-Mailbox, whose default page is ONE row). Invoke returns only the value
//     array — it neither follows the link nor surfaces the warning — so a
//     collector over such a cmdlet MUST defeat the page with the cmdlet's own
//     parameter (Get-Mailbox: -ResultSize Unlimited) or it will silently report
//     a fraction of the tenant and look perfectly healthy. See
//     internal/collectors/m365/exchangemailboxes. Surfacing truncation through
//     this seam is unbuilt.
//
//   - Different authorization model — see below; this is the single most
//     confusing thing about the transport.
//
//   - Different failure vocabulary. The HTTP status does not discriminate
//     anything (nearly every failure is 400 or 403) and the useful text is buried
//     several levels inside the error envelope. See errors.go.
//
// # Authorization needs BOTH an app role AND a directory role
//
// Two separate grants, from two separate systems, and NEITHER HALF ALONE DOES
// ANYTHING:
//
//  1. The app role Exchange.ManageAsApp (app role id
//     dc50a0fb-09a3-484d-be87-e023b12c6440 on the "Office 365 Exchange Online"
//     service principal, app id 01deb58a-8c47-4d14-888c-84c4a7844905)
//     AUTHENTICATES the service principal to the admin API.
//  2. An Entra DIRECTORY ROLE on that same service principal AUTHORIZES the
//     cmdlets it may run. Security Reader is the least-privileged role sufficient
//     for the read-only quarantine and policy cmdlets graph2otel needs.
//
// Live-measured on the m7kni tenant as graph2otel-poller, 2026-07-23, the
// progression is:
//
//	neither grant      -> HTTP 401
//	app role only      -> HTTP 403
//	app role + role    -> HTTP 200
//
// A tenant admin who grants only the app role sees a service principal that
// looks fully permissioned in the portal and 403s on every call. The 403 body is
// also NOT JSON (see below), so the failure is doubly opaque unless you know to
// look for the directory role.
//
// # The 403 body is not JSON
//
// Live-captured 2026-07-23: an unauthorized (or unknown) cmdlet answers HTTP 403
// with a body that is not JSON at all — a long run of NUL bytes. Since a missing
// directory role is the most likely production failure of the lot, that response
// is the one this client must handle best, not worst. parseCmdletError treats an
// undecodable body as an expected branch and still returns a *CmdletError naming
// the status and the cmdlet; it never surfaces a JSON-decoder message, which
// would read as a bug in graph2otel rather than as the grant problem it is.
//
// # error.message is always "Invalid Operation"
//
// The outer error.message is the literal string "Invalid Operation" whatever
// went wrong. A client that surfaces it reports nothing actionable, on every
// error, forever. The unwrapped text one or two levels down is by contrast
// excellent — an invalid enum value comes back with the complete list of valid
// members. CmdletError.Message is resolved through a fixed precedence for
// exactly this reason; see resolveMessage.
//
// # Throttling is UNMEASURED
//
// Unlike every other outbound client in this repo, there is no number to respect
// here: no published req/min figure for adminapi InvokeCommand, and no
// RateLimit-* or Retry-After header observed on any live response. The default
// limiter is a deliberately conservative guess, tagged unmeasured, NOT a
// live-measured ceiling — see ratelimit.go. There is also deliberately no retry
// transport; see newHTTPClient.
//
// # Scope
//
// This package is transport only. It decodes the envelope and hands back raw
// records; mapping records to signals belongs to a collector, and so does every
// cardinality decision about them.
package exoclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// DefaultScope is the OAuth scope for the Exchange Online admin API audience.
//
// It is NOT auth.GraphDefaultScope and the two are not interchangeable: a Graph
// token presented here is rejected by the service, having succeeded at token
// acquisition, so the mistake surfaces as a runtime failure rather than a
// credential error.
const DefaultScope = "https://outlook.office365.com/.default"

// DefaultBaseURL is the Exchange Online admin API host.
const DefaultBaseURL = "https://outlook.office365.com"

// invokePath is the single endpoint this transport has:
// {base}/adminapi/beta/{tenantID}/InvokeCommand. "beta" is the service's own
// path segment, not a Graph beta endpoint — there is no v1.0 alternative, so
// docs/api-drift.md's beta-surface canary does not apply to it.
const invokePathPrefix = "/adminapi/beta/"
const invokePathSuffix = "/InvokeCommand"

// defaultTimeout bounds one cmdlet invocation. Generous rather than tight: the
// server is running a PowerShell command, and a quarantine page routinely takes
// seconds.
const defaultTimeout = 60 * time.Second

// maxBodyBytes caps a response read so a pathological or hostile response cannot
// exhaust memory. It mirrors graphclient's cap.
const maxBodyBytes = 32 << 20

// tokenCredential is the minimal slice of azcore.TokenCredential this package
// needs. A local interface keeps it testable with a fake credential, mirroring
// graphclient and o365activityclient.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// Options configures a Client. The zero value is usable: every field falls back
// to a documented default.
type Options struct {
	// Emitter records the outbound-HTTP instrumentation, so cmdlet invocations
	// appear in graph2otel.* self-observability like every other outbound call.
	// Nil disables instrumentation; the transport still works.
	Emitter telemetry.Emitter
	// BaseURL is the admin API host; empty means DefaultBaseURL. A test may point
	// it at an httptest server.
	BaseURL string
	// Scope overrides the token audience; empty means DefaultScope. It is NOT
	// derived from BaseURL — unlike the Management Activity API, the audience
	// here is not the host, so deriving it would silently produce a wrong scope
	// against an httptest server or a sovereign cloud.
	Scope string
	// Limiter is the client-side gate; nil means DefaultLimiter(). To disable
	// gating, pass rate.NewLimiter(rate.Inf, 1) — nil means "use the default",
	// which is the safer reading of an unset field.
	Limiter *rate.Limiter
	// Timeout bounds one request; 0 means defaultTimeout.
	Timeout time.Duration
	// Logger receives transport-level debug lines; nil means slog.Default().
	Logger *slog.Logger
}

// Client is a per-tenant Exchange Online admin API client. It is safe for
// concurrent use.
type Client struct {
	tenantID   string
	baseURL    string
	scope      string
	logger     *slog.Logger
	limiter    *rate.Limiter
	cred       tokenCredential
	httpClient *http.Client
}

// NewClient builds a Client for one tenant. Construction performs no network
// I/O.
func NewClient(ta *auth.TenantAuth, opts Options) (*Client, error) {
	if ta == nil {
		return nil, fmt.Errorf("exoclient: nil TenantAuth")
	}
	if ta.TenantID == "" {
		return nil, fmt.Errorf("exoclient: empty tenant ID")
	}

	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("exoclient: parse base URL %q: %w", baseURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("exoclient: base URL %q has no host", baseURL)
	}

	scope := opts.Scope
	if scope == "" {
		scope = DefaultScope
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	limiter := opts.Limiter
	if limiter == nil {
		limiter = DefaultLimiter()
	}

	return &Client{
		tenantID:   ta.TenantID,
		baseURL:    baseURL,
		scope:      scope,
		logger:     logger,
		limiter:    limiter,
		cred:       ta.Cred,
		httpClient: newHTTPClient(opts, ta.TenantID, limiter, logger),
	}, nil
}

// cmdletInput is the invocation envelope. Parameters is always a non-nil map by
// the time it is marshaled: a nil Go map encodes as `null`, and
// `"Parameters": null` is not the same request as `"Parameters": {}`.
type cmdletInput struct {
	CmdletName string         `json:"CmdletName"`
	Parameters map[string]any `json:"Parameters"`
}

type invokeRequest struct {
	CmdletInput cmdletInput `json:"CmdletInput"`
}

// invokeResponse is the success envelope. Records are left as raw maps: mapping
// them to signals is a collector's job, not this package's.
type invokeResponse struct {
	Value []map[string]any `json:"value"`
}

// Invoke runs one Exchange Online cmdlet app-only and returns the decoded
// "value" array. A nil or empty params map sends an empty Parameters object.
//
// An absent, null or empty "value" returns an EMPTY SLICE AND A NIL ERROR, never
// an error. An empty result is the steady state — a healthy tenant has nothing
// in quarantine — so treating absence as failure would make a collector alert
// forever on a working system. CLAUDE.md's "a green tick is not evidence of
// data" rule cuts the other way here: the emptiness is real, and it is the
// mapper's job to be written against live samples so a mapping bug is not hidden
// behind it.
func (c *Client) Invoke(ctx context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	if cmdlet == "" {
		return nil, fmt.Errorf("exoclient: tenant %q: empty cmdlet name", c.tenantID)
	}
	if params == nil {
		params = map[string]any{}
	}

	body, err := json.Marshal(invokeRequest{CmdletInput: cmdletInput{CmdletName: cmdlet, Parameters: params}})
	if err != nil {
		return nil, fmt.Errorf("exoclient: %s: encode request: %w", cmdlet, err)
	}

	respBody, err := c.do(ctx, cmdlet, body)
	if err != nil {
		return nil, err
	}

	var decoded invokeResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, fmt.Errorf("exoclient: %s: decode response: %w", cmdlet, err)
	}
	if decoded.Value == nil {
		return []map[string]any{}, nil
	}
	return decoded.Value, nil
}

// invokeURL is the single endpoint: {base}/adminapi/beta/{tenantID}/InvokeCommand.
func (c *Client) invokeURL() string {
	return c.baseURL + invokePathPrefix + c.tenantID + invokePathSuffix
}

// do performs one authenticated POST and returns the body. A non-2xx becomes a
// typed *CmdletError.
func (c *Client) do(ctx context.Context, cmdlet string, body []byte) ([]byte, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return nil, fmt.Errorf("exoclient: tenant %q: acquire token for %s: %w", c.tenantID, c.scope, err)
	}

	// The cmdlet name rides the context so the transport can label its metrics
	// without re-reading the request body.
	req, err := http.NewRequestWithContext(withCmdlet(ctx, cmdlet),
		http.MethodPost, c.invokeURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("exoclient: %s: build request: %w", cmdlet, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exoclient: %s: POST %s: %w", cmdlet, c.invokeURL(), err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("exoclient: %s: read response body: %w", cmdlet, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseCmdletError(resp.StatusCode, respBody, cmdlet)
	}
	return respBody, nil
}
