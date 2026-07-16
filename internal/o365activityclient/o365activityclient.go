// Package o365activityclient is graph2otel's client for the Office 365
// Management Activity API — the subscribe/list/fetch feed over the unified
// audit log at manage.office.com (#100).
//
// # Why this is not internal/graphclient
//
// It is a sibling of graphclient, not a fork, because the API is genuinely a
// different service that happens to share an identity provider:
//
//   - Different audience. Tokens are issued for https://manage.office.com/.default
//     (or the matching sovereign-cloud host), NOT Graph's. A Graph token is
//     rejected. The credential is the same azidentity one — only the scope
//     differs — so this needs no new auth model, just a new ".default".
//   - Different delivery model. Graph's security/auditLog/queries is an async
//     query (create -> poll -> page). This is a subscription plus content blobs,
//     built for continuous SIEM ingest: stable v1.0 rather than beta, and a
//     2,000 req/min PER-TENANT quota rather than Graph's per-workload ceilings.
//   - Different failure vocabulary. Errors carry documented AF##### codes in a
//     JSON envelope; the HTTP status alone does not discriminate them (every
//     argument error is a 400). See errors.go.
//
// # The read-only property
//
// POST /subscriptions/start is a WRITE, and it is the second break in
// graph2otel's read-only property after the Intune reports-export job. It
// creates a subscription rather than mutating tenant data, and it needs no
// ReadWrite scope — ActivityFeed.Read authorizes it — so the break is narrower
// than the export-job one. It is still a write, and callers should treat
// StartSubscription as an explicit, opt-in setup action rather than something a
// poll loop does implicitly.
//
// # Operational characteristics that shape any caller
//
//   - A 24-HOUR MAX RANGE on /subscriptions/content, separate from and tighter
//     than the lookback bound below. This is the constraint most likely to bite:
//     the API does not reliably reject a wider window, it may return PARTIAL
//     results instead. ListContent chunks so no caller has to know this.
//   - Content arrives FAST, and is backfilled on subscribe. Microsoft's
//     reference says "it can take up to 12 hours for the first content blobs to
//     become available"; live on m7kni (2026-07-16) blobs listed ~2 MINUTES
//     after /subscriptions/start, and the oldest blob's contentCreated predated
//     the subscription by ~22 hours. Do NOT build a "wait 12h before first poll"
//     behavior — poll normally and expect data.
//   - A 15-MINUTE cooldown between /subscriptions/start calls. Starting a
//     subscription per poll would be throttled; start it once at setup.
//   - Blobs are NOT sequential: "one content blob can contain actions and events
//     that occurred prior to ... an earlier content blob". Callers need a
//     watermark, an overlap window, and seen-id dedupe on contentId — exactly
//     what internal/logpipeline's checkpoint already does.
//   - A 7-DAY LOOKBACK BOUND on startTime — verified live (a -9d startTime
//     returns AF20055; -23h returns 200). ListContent clamps rather than letting
//     a caller wedge. This is NOT the same thing as blob expiry: see
//     ContentBlob.ContentExpiration, which measured ~20 days on the wire. Do not
//     conflate them, and never compute an expiry from a 7-day constant.
//   - NO server-side filtering. Every record for a subscribed content type is
//     fetched and filtered client-side, so subscribe only to the content types
//     actually mapped — never Audit.General by default.
//   - NO rate-limit headers on responses (verified live: no RateLimit-*, no
//     Retry-After). The documented 2,000/min per-tenant ceiling is not
//     observable from the wire, so the client-side Limiter is the only control —
//     the same position every Graph workload in this repo is in.
//
// # Record content is SENSITIVE — read before mapping
//
// FetchContent returns raw records that carry ModifiedProperties with OldValue
// and NewValue. CLAUDE.md's one genuine content exclusion applies: emit the
// NAMES of changed properties, NEVER their old/new VALUES, which can carry
// credentials and certificates. This package deliberately does not map records
// — that belongs to a collector — so the obligation lands on the mapper. Follow
// intune/auditevents, which already models this correctly.
package o365activityclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Base URLs per Microsoft 365 subscription plan. The plan determines the host,
// and the host in turn determines the token audience (see Client.Scope).
const (
	// CloudPublicBaseURL is the commercial/enterprise plan endpoint.
	CloudPublicBaseURL = "https://manage.office.com"
	// CloudGCCBaseURL is the GCC government plan endpoint.
	CloudGCCBaseURL = "https://manage-gcc.office.com"
	// CloudGCCHighBaseURL is the GCC High government plan endpoint.
	CloudGCCHighBaseURL = "https://manage.office365.us"
	// CloudDoDBaseURL is the DoD government plan endpoint.
	CloudDoDBaseURL = "https://manage.protection.apps.mil"
)

// apiPathPrefix is the documented root shape:
// {base}/api/v1.0/{tenant_id}/activity/feed/{operation}. v1.0 here is STABLE —
// unlike Graph's security/auditLog/queries, which is beta-only and is the sole
// reason m365.unified_audit is Experimental.
const apiPathPrefix = "/api/v1.0/"

// maxBodyBytes caps a response read so a pathological or hostile response
// cannot exhaust memory. Content blobs are aggregations of audit records and
// are far smaller than this; the cap mirrors graphclient's.
const maxBodyBytes = 32 << 20

// ContentType is one of the five content types the API aggregates activity
// into. They are not a curated subset: Audit.General is an explicit catch-all
// for every workload the others do not cover, so there is no record type this
// API structurally cannot see.
type ContentType string

const (
	// ContentAzureActiveDirectory carries Entra ID activity. It is NOT
	// audit-only: a live blob (m7kni, 2026-07-16) held 8 UserLoggedIn records
	// out of 20, so this content type overlaps entra.signins.interactive as well
	// as entra.directory_audits. Weigh that before enabling it alongside either.
	ContentAzureActiveDirectory ContentType = "Audit.AzureActiveDirectory"
	// ContentExchange carries Exchange Online activity.
	ContentExchange ContentType = "Audit.Exchange"
	// ContentSharePoint carries SharePoint and OneDrive activity.
	ContentSharePoint ContentType = "Audit.SharePoint"
	// ContentGeneral is the catch-all: "includes all other workloads not
	// included in the previous content types" (Teams among them).
	//
	// Subscribing to it on a busy tenant fetches every Exchange/SharePoint/Teams
	// event to keep the few that are mapped, because the API has no server-side
	// filtering. Never enable it by default — it is a deliberate, costed choice.
	ContentGeneral ContentType = "Audit.General"
	// ContentDLPAll carries DLP events for all workloads. Sensitive-data detail
	// requires the ActivityFeed.ReadDlp role rather than plain ActivityFeed.Read.
	ContentDLPAll ContentType = "DLP.All"
)

// ContentTypes returns every valid content type, for config validation and
// documentation generation.
func ContentTypes() []ContentType {
	return []ContentType{
		ContentAzureActiveDirectory,
		ContentExchange,
		ContentSharePoint,
		ContentGeneral,
		ContentDLPAll,
	}
}

// Valid reports whether c is one of the five documented content types. The
// service rejects anything else with AF20020; checking locally turns a config
// typo into a startup error rather than a runtime 400.
func (c ContentType) Valid() bool {
	for _, known := range ContentTypes() {
		if c == known {
			return true
		}
	}
	return false
}

// tokenCredential is the minimal slice of azcore.TokenCredential this package
// needs. A local interface keeps it testable with a fake credential, mirroring
// graphclient.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// Options configures a Client.
type Options struct {
	// Emitter records the outbound-HTTP instrumentation. Nil disables
	// instrumentation; the transport still works.
	Emitter telemetry.Emitter
	// BaseURL selects the cloud endpoint; defaults to CloudPublicBaseURL. Use
	// one of the Cloud*BaseURL constants (a test may point it at an httptest
	// server).
	BaseURL string
	// Scope overrides the token audience. Empty derives it from BaseURL as
	// "{BaseURL}/.default", which is correct for every documented cloud.
	Scope string
	// PublisherIdentifier is the tenant GUID of the vendor writing the code —
	// NOT the customer's tenant and NOT the application ID. It exists purely for
	// throttling: requests without it share one global quota, while requests
	// carrying it get a dedicated allocation. Omitted from the URL when empty.
	PublisherIdentifier string
	// Limiter is the client-side per-tenant gate. Nil disables rate limiting.
	Limiter *Limiter
	// MaxRetries caps retries of a retryable (429/5xx) response; 0 means
	// defaultMaxRetries. The initial attempt is not a retry, so N retries means
	// up to N+1 attempts.
	MaxRetries int

	// retryBase overrides the first retry's backoff (test seam; 0 = 1s).
	retryBase time.Duration
	// baseTransport overrides the innermost RoundTripper (test seam; nil =
	// http.DefaultTransport).
	baseTransport http.RoundTripper
}

// Client is a per-tenant Office 365 Management Activity API client. It is safe
// for concurrent use.
type Client struct {
	// TenantID identifies the tenant this client authenticates against. It must
	// match the tenant in the access token, or the API returns AF20010.
	TenantID string

	baseURL     string
	baseHost    string
	scope       string
	publisherID string
	httpClient  *http.Client
	cred        tokenCredential
}

// NewClient builds a client for one tenant from its credential. Construction
// performs no network I/O.
//
// The credential is the same azidentity one graphclient uses; only the
// requested scope differs, so app-only certificate auth works here exactly as
// it does for Graph.
func NewClient(ta *auth.TenantAuth, opts Options) (*Client, error) {
	if ta == nil {
		return nil, fmt.Errorf("o365activityclient: nil TenantAuth")
	}
	if ta.TenantID == "" {
		return nil, fmt.Errorf("o365activityclient: empty tenant ID")
	}

	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = CloudPublicBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("o365activityclient: parse base URL %q: %w", baseURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("o365activityclient: base URL %q has no host", baseURL)
	}

	scope := opts.Scope
	if scope == "" {
		scope = baseURL + "/.default"
	}

	return &Client{
		TenantID:    ta.TenantID,
		baseURL:     baseURL,
		baseHost:    parsed.Host,
		scope:       scope,
		publisherID: opts.PublisherIdentifier,
		httpClient:  newHTTPClient(opts, ta.TenantID),
		cred:        ta.Cred,
	}, nil
}

// Scope returns the token audience this client authenticates with.
func (c *Client) Scope() string { return c.scope }

// BaseURL returns the cloud endpoint this client targets.
func (c *Client) BaseURL() string { return c.baseURL }

// feedURL builds {base}/api/v1.0/{tenant}/activity/feed/{operation}, layering
// the PublisherIdentifier quota parameter on when configured.
func (c *Client) feedURL(operation string, q url.Values) string {
	u := c.baseURL + apiPathPrefix + c.TenantID + "/activity/feed/" + operation
	if q == nil {
		q = url.Values{}
	}
	if c.publisherID != "" {
		q.Set("PublisherIdentifier", c.publisherID)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// checkHost refuses to send a bearer token anywhere but this client's own
// endpoint.
//
// This is not paranoia about our own code: contentUri and NextPageUri are
// values taken from a RESPONSE BODY and then requested WITH the token attached.
// A compromised or spoofed response that redirected those to another host would
// exfiltrate the credential. graphclient pins an equivalent allow-list on its
// auth provider for the same reason.
func (c *Client) checkHost(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("o365activityclient: parse URL %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Host, c.baseHost) {
		return fmt.Errorf("o365activityclient: refusing to send a token to host %q (expected %q)", u.Host, c.baseHost)
	}
	return nil
}

// do performs one authenticated request and returns the body and response
// headers. A non-2xx becomes a typed *APIError.
func (c *Client) do(ctx context.Context, method, rawURL string, body []byte) ([]byte, http.Header, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return nil, nil, fmt.Errorf("o365activityclient: tenant %q: acquire token for %s: %w", c.TenantID, c.scope, err)
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("o365activityclient: build request %s %s: %w", method, rawURL, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("o365activityclient: %s %s: %w", method, rawURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("o365activityclient: read %s body: %w", rawURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, parseAPIError(resp.StatusCode, respBody, method, rawURL)
	}
	return respBody, resp.Header, nil
}
