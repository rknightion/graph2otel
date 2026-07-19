// Package mdcaclient is graph2otel's client for the Microsoft Defender for Cloud
// Apps (MDCA) legacy portal API — specifically the Cloud Discovery governance
// log at <tenant>.<region>.portal.cloudappsecurity.com (#145).
//
// # Why this is not internal/graphclient (or o365activityclient)
//
// It is a third first-party API sibling, not a fork, because it is a genuinely
// different service:
//
//   - Different host and NO Graph equivalent. Cloud Discovery upload and the
//     governance log exist ONLY on the legacy portal API; there is no Graph
//     endpoint for either. The host is per-tenant and per-region
//     (https://<tenant>.<region>.portal.cloudappsecurity.com), supplied by
//     config rather than pinned.
//   - Different auth. A STATIC portal token in "Authorization: Token <secret>",
//     NOT azidentity/DefaultAzureCredential. There is no app-registration scope
//     to grant and no token exchange — the secret is read from a file at
//     construction (see internal/config.MDCAConfig for why token_file, not env).
//   - Different quota. 30 requests/min PER TENANT across the whole MDCA API, with
//     responses capped at 100 items — an order of magnitude tighter than the
//     Management Activity API's 2,000/min.
//
// # The signal this serves
//
// The Cloud Discovery upload (upload_url -> PUT blob -> done_upload) returns 200
// the moment the blob lands and a parse task is QUEUED — that is all it means.
// The parse runs asynchronously and writes its verdict ONLY to the governance
// log, as a DiscoveryParseLogTask record. So every uploader is structurally
// blind to parse outcome, and nothing polls the governance log — 22 consecutive
// silent parse failures on m7kni (2026-07-17) produced no signal anywhere. This
// client is the poll. The mapping and alerting live in the collector; this
// package only fetches.
//
// # Read-only
//
// Every call this package makes is a read: POST /api/v1/governance/ is a QUERY
// (limit/skip/filters in the body), not a mutation. Unlike o365activityclient's
// /subscriptions/start, there is no write here and no break in graph2otel's
// read-only property.
package mdcaclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// governancePath is the governance-log query endpoint. It is a POST whose body
// carries the query (limit, skip, filters) — the API has no GET form.
const governancePath = "/api/v1/governance/"

// maxBodyBytes caps a response read so a pathological or hostile response cannot
// exhaust memory. A governance page is capped at 100 records server-side and is
// far smaller than this; the cap mirrors o365activityclient's.
const maxBodyBytes = 32 << 20

// defaultPageLimit is the API's own response cap: a governance query returns at
// most 100 records regardless of a larger requested limit, so paging by 100 is
// the natural stride.
const defaultPageLimit = 100

// maxPages bounds how many pages Governance will walk in one call, a defensive
// backstop against a total that never converges (a server bug, or a filter the
// server silently ignores). At 100/page this is 50,000 records — far beyond any
// real window — so it never truncates a legitimate result, it only refuses to
// loop forever.
const maxPages = 500

// Options configures a Client.
type Options struct {
	// Emitter records the outbound-HTTP instrumentation. Nil disables
	// instrumentation; the transport still works.
	Emitter telemetry.Emitter
	// BaseURL is the tenant's MDCA portal endpoint, e.g.
	// "https://<tenant>.<region>.portal.cloudappsecurity.com". Required.
	BaseURL string
	// Token is the static portal API token, sent as "Authorization: Token
	// <token>". Required. Read from a file by the composition root; never logged.
	Token string
	// Limiter is the client-side per-tenant gate sized to the 30 req/min MDCA
	// quota. Nil disables rate limiting.
	Limiter *Limiter
	// MaxRetries caps retries of a retryable (429/5xx) response; 0 means
	// defaultMaxRetries.
	MaxRetries int

	// retryBase overrides the first retry's backoff (test seam; 0 = 1s).
	retryBase time.Duration
	// baseTransport overrides the innermost RoundTripper (test seam; nil =
	// http.DefaultTransport).
	baseTransport http.RoundTripper
}

// Client is a per-tenant MDCA Cloud Discovery client. It is safe for concurrent
// use.
type Client struct {
	// TenantID identifies the tenant this client serves. It is used only for
	// self-observability attributes and the rate-limiter bucket key — the token,
	// not the tenant id, is what the API authenticates on.
	TenantID string

	baseURL    string
	baseHost   string
	token      string
	httpClient *http.Client
}

// NewClient builds a client for one tenant. Construction performs no network
// I/O. BaseURL and Token are required.
func NewClient(tenantID string, opts Options) (*Client, error) {
	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("mdcaclient: empty base URL")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("mdcaclient: parse base URL %q: %w", baseURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("mdcaclient: base URL %q has no host", baseURL)
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("mdcaclient: empty token")
	}

	return &Client{
		TenantID:   tenantID,
		baseURL:    baseURL,
		baseHost:   parsed.Host,
		token:      opts.Token,
		httpClient: newHTTPClient(opts, tenantID),
	}, nil
}

// BaseURL returns the portal endpoint this client targets.
func (c *Client) BaseURL() string { return c.baseURL }

// GovernanceQuery selects a page window of governance-log records.
type GovernanceQuery struct {
	// SinceMillis, when > 0, sets the server-side filter {"timestamp":{"gte":ms}}.
	// This is the ONLY governance-log filter that works server-side: taskName and
	// status filters are SILENTLY IGNORED (they return an empty set, not an
	// error), so those MUST be applied client-side by the caller. Zero means no
	// timestamp filter (a full scan of the most recent records).
	SinceMillis int64
}

// GovernancePage is one drained result: the server's reported total plus every
// record fetched across the internal pagination. Records are raw decoded JSON
// objects — the collector owns the mapping, exactly as o365activityclient hands
// raw content records to its collector.
type GovernancePage struct {
	Total   int
	Records []map[string]any
}

// governanceBody is the request payload. filters is omitted entirely when no
// timestamp filter applies, matching the API's "no filters" form.
type governanceBody struct {
	Limit   int            `json:"limit"`
	Skip    int            `json:"skip"`
	Filters map[string]any `json:"filters,omitempty"`
}

// governanceResponse decodes only the fields Governance needs from the reply.
type governanceResponse struct {
	Total int              `json:"total"`
	Data  []map[string]any `json:"data"`
}

// Governance fetches every governance-log record matching q, paging internally
// by defaultPageLimit until the server's total is reached (or a page comes back
// short). It returns the records in server order.
//
// Paging is by skip: the API caps a response at 100 records regardless of the
// requested limit, so a window wider than 100 records needs multiple requests.
// maxPages bounds the walk so a non-converging total cannot loop forever.
func (c *Client) Governance(ctx context.Context, q GovernanceQuery) (*GovernancePage, error) {
	var (
		records []map[string]any
		total   int
	)
	for page := 0; page < maxPages; page++ {
		body := governanceBody{Limit: defaultPageLimit, Skip: len(records)}
		if q.SinceMillis > 0 {
			body.Filters = map[string]any{"timestamp": map[string]any{"gte": q.SinceMillis}}
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("mdcaclient: marshal governance body: %w", err)
		}

		respBody, err := c.do(ctx, http.MethodPost, c.baseURL+governancePath, raw)
		if err != nil {
			return nil, err
		}
		var gr governanceResponse
		if err := json.Unmarshal(respBody, &gr); err != nil {
			return nil, fmt.Errorf("mdcaclient: decode governance response: %w", err)
		}
		total = gr.Total
		records = append(records, gr.Data...)

		// Stop when the server has no more: a short page (fewer than the limit)
		// or having reached the reported total. A total of 0 with an empty page
		// exits immediately.
		if len(gr.Data) < defaultPageLimit || len(records) >= total {
			break
		}
	}
	return &GovernancePage{Total: total, Records: records}, nil
}

// checkHost refuses to send the token anywhere but this client's own endpoint.
// The base URL is config-supplied and fixed, so this is a belt-and-braces guard
// (there are no response-body-derived URLs to follow here, unlike
// o365activityclient's contentUri), but it keeps the credential from ever
// leaving the configured host if a future call path is added.
func (c *Client) checkHost(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("mdcaclient: parse URL %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Host, c.baseHost) {
		return fmt.Errorf("mdcaclient: refusing to send a token to host %q (expected %q)", u.Host, c.baseHost)
	}
	return nil
}

// do performs one authenticated request and returns the body. A non-2xx becomes
// a typed *APIError.
func (c *Client) do(ctx context.Context, method, rawURL string, body []byte) ([]byte, error) {
	if err := c.checkHost(rawURL); err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("mdcaclient: build request %s %s: %w", method, rawURL, err)
	}
	// The MDCA portal API's scheme is the literal word "Token", NOT "Bearer".
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mdcaclient: %s %s: %w", method, rawURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("mdcaclient: read %s body: %w", rawURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Status: resp.StatusCode, Body: string(respBody), Method: method, URL: rawURL}
	}
	return respBody, nil
}
