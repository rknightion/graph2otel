// Package huntclient is graph2otel's client for the Microsoft Graph security
// advanced-hunting query API — POST /security/runHuntingQuery, the only route to
// the DeviceTvm* threat-and-vulnerability-management tables, which have no
// dedicated REST endpoint and are not written to any blob container (#249).
//
// # Why this is not internal/graphclient
//
// It is a sibling of graphclient, not a fork. Same identity provider, same
// azidentity credential, same Graph audience — but a genuinely different request
// shape that graphclient's paged-GET machinery cannot express:
//
//   - It is a POST, not a GET. The request carries a KQL query string in the
//     body ({"Query": "..."}); there is no URL to page.
//   - The response is not an OData collection with @odata.nextLink. It is
//     {"schema":[{name,type}...], "results":[{...}...]} — a tabular result set,
//     paged (when it is paged at all) by KQL operators inside the query, not by
//     a follow-on URL. There is no $filter, $top or $select.
//   - The one shared constraint that matters is a HARD 100,000-row ceiling per
//     query (#249). Staying under it is a query-partitioning concern for the
//     collector, not something this transport can paper over.
//
// # Read-only despite being a POST
//
// runHuntingQuery is a query language with no mutation verb. The POST body is a
// read-only KQL SELECT; it changes nothing in the tenant. It is graph2otel's one
// sanctioned non-GET Graph call.
//
// # It shares a CPU quota with humans (#106)
//
// Advanced-hunting queries draw on the same per-tenant advanced-hunting compute
// budget that a human running queries in the Defender portal draws on. That is
// the whole reason #106 chose the streaming blob export for the high-volume EDR
// event tables: tailing them here would burn that shared budget. The DeviceTvm*
// tables are the deliberate exception — they are small current-state snapshots
// with no Timestamp to tail — but the collector that uses this client MUST poll
// on a long interval (6h or daily), never at a collector-default cadence. The
// client-side limiter here is a floor on that discipline, not a substitute for
// it: see ratelimit.go.
//
// # Scope
//
// This package is transport only. It issues the query, decodes the envelope, and
// hands back the raw "results" rows as []map[string]any. Mapping rows to signals,
// and every cardinality decision about them, belongs to a collector. In
// particular, every boolean column on these tables arrives as an SByte number
// (0/1) and null datetime/dynamic cells arrive as {} — this package preserves
// both verbatim; interpreting them is the mapper's job.
package huntclient

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

// DefaultBaseURL is the Graph host. The advanced-hunting endpoint lives on the
// v1.0 surface (live-measured 2026-07-23, #249): it is NOT a beta API, so
// docs/api-drift.md's beta-surface canary does not apply.
const DefaultBaseURL = "https://graph.microsoft.com"

// runQueryPath is the single endpoint this transport has.
const runQueryPath = "/v1.0/security/runHuntingQuery"

// defaultTimeout bounds one query. Generous: the server is executing a KQL query
// over the tenant's device telemetry, and a large summarize takes seconds.
const defaultTimeout = 120 * time.Second

// maxBodyBytes caps a response read so a pathological response cannot exhaust
// memory. A 100,000-row result of wide TVM records is large, so this is set well
// above graphclient's cap.
const maxBodyBytes = 256 << 20

// tokenCredential is the minimal slice of azcore.TokenCredential this package
// needs, kept local so tests can pass a fake, mirroring the sibling clients.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// Options configures a Client. The zero value is usable: every field falls back
// to a documented default.
type Options struct {
	// Emitter records outbound-HTTP instrumentation so hunting queries appear in
	// graph2otel.* self-observability. Nil disables instrumentation.
	Emitter telemetry.Emitter
	// BaseURL is the Graph host; empty means DefaultBaseURL. A test points it at
	// an httptest server.
	BaseURL string
	// Limiter is the client-side gate; nil means DefaultLimiter().
	Limiter *rate.Limiter
	// Timeout bounds one request; 0 means defaultTimeout.
	Timeout time.Duration
	// Logger receives transport-level debug lines; nil means slog.Default().
	Logger *slog.Logger
}

// Client is a per-tenant advanced-hunting query client, safe for concurrent use.
type Client struct {
	baseURL    string
	tenantID   string
	logger     *slog.Logger
	limiter    *rate.Limiter
	cred       tokenCredential
	httpClient *http.Client
}

// NewClient builds a Client for one tenant. Construction performs no network I/O.
func NewClient(ta *auth.TenantAuth, opts Options) (*Client, error) {
	if ta == nil {
		return nil, fmt.Errorf("huntclient: nil TenantAuth")
	}
	if ta.TenantID == "" {
		return nil, fmt.Errorf("huntclient: empty tenant ID")
	}

	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("huntclient: parse base URL %q: %w", baseURL, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("huntclient: base URL %q has no host", baseURL)
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
		baseURL:    baseURL,
		tenantID:   ta.TenantID,
		logger:     logger,
		limiter:    limiter,
		cred:       ta.Cred,
		httpClient: newHTTPClient(opts, ta.TenantID, limiter, logger),
	}, nil
}

// queryRequest is the POST body: a single KQL query string.
type queryRequest struct {
	Query string `json:"Query"`
}

// queryResponse is the success envelope. The schema is decoded but discarded —
// callers read known column names off each result map — and results are left as
// raw maps: mapping is a collector's job.
type queryResponse struct {
	Results []map[string]any `json:"results"`
}

// Query runs one advanced-hunting KQL query app-only and returns the decoded
// "results" rows. label is a bounded, code-supplied name (never tenant data)
// used only to attribute self-observability metrics — every query shares one URL,
// so without it the metrics would be unsliceable.
//
// An absent, null or empty "results" returns an EMPTY SLICE AND A NIL ERROR,
// never an error: a query that matches nothing (a healthy tenant, a filter with
// no hits) is the steady state, and CLAUDE.md's "a green tick is not evidence of
// data" rule is honored by writing the mapper against live samples, not by
// treating emptiness as failure here.
func (c *Client) Query(ctx context.Context, label, kql string) ([]map[string]any, error) {
	if kql == "" {
		return nil, fmt.Errorf("huntclient: %s: empty query", label)
	}

	body, err := json.Marshal(queryRequest{Query: kql})
	if err != nil {
		return nil, fmt.Errorf("huntclient: %s: encode request: %w", label, err)
	}

	respBody, err := c.do(ctx, label, body)
	if err != nil {
		return nil, err
	}

	var decoded queryResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, fmt.Errorf("huntclient: %s: decode response: %w", label, err)
	}
	if decoded.Results == nil {
		return []map[string]any{}, nil
	}
	return decoded.Results, nil
}

// do performs one authenticated POST and returns the body. A non-2xx becomes a
// typed *QueryError.
func (c *Client) do(ctx context.Context, label string, body []byte) ([]byte, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{auth.GraphDefaultScope}})
	if err != nil {
		return nil, fmt.Errorf("huntclient: %s: acquire token: %w", label, err)
	}

	req, err := http.NewRequestWithContext(withLabel(ctx, label),
		http.MethodPost, c.baseURL+runQueryPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("huntclient: %s: build request: %w", label, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("huntclient: %s: POST %s: %w", label, runQueryPath, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("huntclient: %s: read response body: %w", label, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseQueryError(resp.StatusCode, respBody, label)
	}
	return respBody, nil
}
