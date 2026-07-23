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
//     CAUTION: a row-returning cmdlet CAN come back truncated, carrying an
//     "@odata.nextLink" and a non-empty "@adminapi.warnings" saying so. Those
//     rows are perfectly valid, so a caller that ignores the signals reports a
//     fraction of the tenant and looks entirely healthy doing it. InvokeFull
//     surfaces both (InvokeResult.Truncated and .Warnings) and logs a WARN
//     naming the cmdlet; Invoke keeps the narrower "just the rows" shape and
//     still gets the log line. See the truncation notes below, and
//     internal/collectors/m365/exchangemailboxes.
//
//   - Different authorization model — see below; this is the single most
//     confusing thing about the transport.
//
//   - Different failure vocabulary. The HTTP status does not discriminate
//     anything (nearly every failure is 400 or 403) and the useful text is buried
//     several levels inside the error envelope. See errors.go.
//
// # Truncation, and why there is no paging
//
// All live-measured on the m7kni tenant as graph2otel-poller, 2026-07-23.
//
// A complete response carries "@adminapi.warnings" PRESENT AND EMPTY and no
// "@odata.nextLink". A truncated one carries a non-empty warnings array — the
// text names the cmdlet parameter that would defeat the page — and a nextLink.
// The warnings member is declared "#Collection(String)" and really is an ARRAY;
// decoding it as a single string fails on precisely the response that matters.
//
// THE NEXTLINK IS NOT A USABLE CONTINUATION AND MUST NEVER BE FOLLOWED.
// Replaying it four ways — POST with the same body, with empty parameters, with
// the $skiptoken percent-decoded, and with a cookie jar plus an X-AnchorMailbox
// header — each answers HTTP 400 with internalexception.message "Expired or
// Invalid pagination request. Default Expiry time is 00:30:00", immediately and
// well inside that 30 minutes. The $skiptoken embeds a backend mailbox-server
// name; each POST to the front door lands on a different backend, so the
// cursor's server affinity cannot be reproduced by this client at all. That is
// why InvokeResult exposes a BOOL and not the link: exporting the link would
// invite the one implementation that cannot work.
//
// Truncation is therefore defeated with the CMDLET'S OWN PARAMETERS —
// Get-Mailbox takes -ResultSize Unlimited, Get-MessageTraceV2 has a keyset —
// which is a collector's responsibility, not this package's.
//
// The default page size is UNKNOWN. Get-Mailbox with NO parameters returns all
// three m7kni mailboxes with empty warnings and no nextLink, so the default is
// at least 3 and this tenant is too small to measure the ceiling. (An earlier
// note here claimed the default was ONE row; that was WRONG — it came from a
// probe that itself passed -ResultSize 1.) -ResultSize Unlimited remains
// correct defensive practice on any tenant, since the real default is unknown
// and a large tenant is where truncation would actually bite.
//
// The request header "Prefer: odata.maxpagesize=N" IS honored by the service
// (verified: N rows plus the truncation warning, with no cmdlet parameters at
// all). graph2otel deliberately does not set it — a SMALLER page is worthless
// when the continuation cannot be followed. It is recorded only so a future
// reader does not rediscover it and mistake it for a paging solution.
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
//
// The two non-"value" members are the truncation signals, live-captured
// 2026-07-23:
//
//   - NextLink is present only on a truncated response. It is decoded so its
//     PRESENCE can be reported and for no other reason — see InvokeResult on
//     why it is never followed and never exported.
//   - Warnings is declared "#Collection(String)" and is an ARRAY, not a string.
//     It is present-and-EMPTY on a complete response, so "no warnings" cannot be
//     inferred from the key being absent, and a client that decodes it as a
//     single string fails on exactly the response it most needs to read.
type invokeResponse struct {
	NextLink string           `json:"@odata.nextLink"`
	Warnings []string         `json:"@adminapi.warnings"`
	Value    []map[string]any `json:"value"`
}

// InvokeResult is the decoded envelope: the records plus the truncation signals
// the service can attach to them.
//
// Truncation is the failure mode this type exists for. The rows on a truncated
// response are perfectly valid, so a caller that sees only Records reports a
// fraction of the tenant and looks entirely healthy doing it. Both signals are
// therefore returned to the caller AND logged by InvokeFull.
type InvokeResult struct {
	// Records is the "value" array, verbatim and unmapped. It is an empty
	// non-nil slice when the response carried no rows.
	Records []map[string]any
	// Warnings is the service's "@adminapi.warnings" collection, verbatim. It is
	// an empty non-nil slice when there were none. On a truncated response it
	// carries the text naming the cmdlet parameter that would defeat the page
	// ("...increase the value for the ResultSize parameter"), which is the only
	// place the fix is ever stated.
	Warnings []string
	// Truncated is true iff the response carried a non-empty "@odata.nextLink".
	//
	// This is deliberately a BOOL AND NOT THE LINK, because the link is not
	// usable as a continuation and exposing it would invite exactly the wrong
	// implementation. Replaying it — POST with the same body, with empty
	// parameters, with the $skiptoken percent-decoded, with a cookie jar, and
	// with an X-AnchorMailbox header, all four tried live 2026-07-23 — answers
	// HTTP 400 "Expired or Invalid pagination request. Default Expiry time is
	// 00:30:00" immediately, well inside that 30 minutes. The $skiptoken embeds
	// a backend mailbox-server name and each POST lands on a different backend,
	// so this client cannot reproduce the cursor's affinity at all.
	//
	// Truncation must therefore be defeated with the CMDLET'S OWN PARAMETERS
	// (Get-Mailbox: -ResultSize Unlimited; Get-MessageTraceV2: its keyset
	// parameters), never by following the link. Truncated is the signal that a
	// caller has failed to do so.
	Truncated bool
}

// Invoke runs one Exchange Online cmdlet app-only and returns the decoded
// "value" array. It is InvokeFull without the envelope; every caller that does
// not need the truncation signals should keep using it.
//
// A nil or empty params map sends an empty Parameters object.
//
// An absent, null or empty "value" returns an EMPTY SLICE AND A NIL ERROR, never
// an error. An empty result is the steady state — a healthy tenant has nothing
// in quarantine — so treating absence as failure would make a collector alert
// forever on a working system. CLAUDE.md's "a green tick is not evidence of
// data" rule cuts the other way here: the emptiness is real, and it is the
// mapper's job to be written against live samples so a mapping bug is not hidden
// behind it.
//
// Truncation is still LOGGED for an Invoke caller, because InvokeFull does the
// logging — only the machine-readable signals are dropped on this path.
func (c *Client) Invoke(ctx context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	res, err := c.InvokeFull(ctx, cmdlet, params)
	if err != nil {
		return nil, err
	}
	return res.Records, nil
}

// InvokeFull runs one cmdlet and returns the full envelope.
//
// It is the seam that makes a truncated read distinguishable from a complete
// one. A response carrying an "@odata.nextLink" is reported as Truncated and
// WARNED about on the client's logger, naming the cmdlet and the service's own
// warning text — a truncated read is silent data loss, and the whole reason it
// bites is that nothing about the rows themselves looks wrong. The log line
// exists so a caller that forgets to read Truncated still cannot lose data
// invisibly.
//
// The nextLink itself is neither exported nor followed; see InvokeResult.
//
// Note for a future reader, so this is not rediscovered as a paging solution:
// the request header "Prefer: odata.maxpagesize=N" IS honored by the service
// (verified live 2026-07-23 — it returns N rows plus the truncation warning even
// with no cmdlet parameters at all). graph2otel deliberately does NOT set it.
// Being able to make the page SMALLER is worthless when the continuation cursor
// cannot be followed; the only thing it could achieve here is manufacturing the
// truncation this seam reports.
func (c *Client) InvokeFull(ctx context.Context, cmdlet string, params map[string]any) (InvokeResult, error) {
	if cmdlet == "" {
		return InvokeResult{}, fmt.Errorf("exoclient: tenant %q: empty cmdlet name", c.tenantID)
	}
	if params == nil {
		params = map[string]any{}
	}

	body, err := json.Marshal(invokeRequest{CmdletInput: cmdletInput{CmdletName: cmdlet, Parameters: params}})
	if err != nil {
		return InvokeResult{}, fmt.Errorf("exoclient: %s: encode request: %w", cmdlet, err)
	}

	respBody, err := c.do(ctx, cmdlet, body)
	if err != nil {
		return InvokeResult{}, err
	}

	var decoded invokeResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return InvokeResult{}, fmt.Errorf("exoclient: %s: decode response: %w", cmdlet, err)
	}

	// Both slices are normalized to empty-non-nil. An absent key, a null and an
	// empty array are the same fact to a caller, and all three occur live.
	res := InvokeResult{
		Records:   decoded.Value,
		Warnings:  decoded.Warnings,
		Truncated: decoded.NextLink != "",
	}
	if res.Records == nil {
		res.Records = []map[string]any{}
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}

	if res.Truncated {
		c.logger.Warn("exoclient: cmdlet result was TRUNCATED — the collector is reporting a fraction of the tenant; "+
			"defeat it with the cmdlet's own parameters (the nextLink is not followable)",
			"cmdlet", cmdlet,
			"records", len(res.Records),
			"warnings", strings.Join(res.Warnings, "; "))
	}

	return res, nil
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
