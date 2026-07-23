// Package armclient is graph2otel's minimal read-only client for the Azure
// Resource Manager (ARM) control plane — the management.azure.com audience.
//
// It exists for exactly one caller: the blob-category census (#238), which reads
// the tenant-level microsoft.aadiam diagnostic-settings object to learn which
// diagnostic categories are enabled and writing to the storage account. That is
// a control-plane read the poller is authorized for by its Entra roles rather
// than by Azure RBAC (live-measured 2026-07-23: microsoft.aadiam returns 200,
// while microsoft.intune and the storage account resource return 403) — so ARM
// is reachable as the poller itself, and #134's "reading diagnostic settings
// needs a different identity" premise was wrong.
//
// It is a sibling of graphclient/exoclient, not a fork: same azidentity
// credential, different audience (https://management.azure.com/.default; a Graph
// token is rejected). It is deliberately GET-only and tiny — no paging, no
// filtering, no write verbs, no rate limiter (the one caller polls hourly). If a
// second ARM read is ever needed this is where it belongs.
package armclient

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// DefaultScope is the OAuth scope for the ARM control-plane audience. It is not
// interchangeable with the Graph scope: an ARM token presented to Graph (or the
// reverse) authenticates but is then rejected by the service.
const DefaultScope = "https://management.azure.com/.default"

// defaultTimeout bounds one ARM GET.
const defaultTimeout = 30 * time.Second

// maxBodyBytes caps a response read so a pathological response cannot exhaust
// memory. It mirrors the other outbound clients' cap.
const maxBodyBytes = 32 << 20

// tokenCredential is the minimal slice of azcore.TokenCredential this package
// needs — a local interface so tests use a fake credential, mirroring
// graphclient/exoclient.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// Options configures a Client. The zero value is usable.
type Options struct {
	// Scope overrides the token audience; empty means DefaultScope.
	Scope string
	// Timeout bounds one request; 0 means defaultTimeout.
	Timeout time.Duration
	// Logger receives transport-level debug lines; nil means slog.Default().
	Logger *slog.Logger
	// HTTPClient overrides the HTTP client; nil builds one bounded by Timeout. A
	// test points this at an httptest server.
	HTTPClient *http.Client
}

// Client is a read-only ARM control-plane client. It is safe for concurrent use.
type Client struct {
	cred       tokenCredential
	scope      string
	logger     *slog.Logger
	httpClient *http.Client
}

// NewClient builds a Client over an azidentity credential. Construction performs
// no network I/O.
func NewClient(cred azcore.TokenCredential, opts Options) *Client {
	scope := opts.Scope
	if scope == "" {
		scope = DefaultScope
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	hc := opts.HTTPClient
	if hc == nil {
		to := opts.Timeout
		if to == 0 {
			to = defaultTimeout
		}
		hc = &http.Client{Timeout: to}
	}
	return &Client{cred: cred, scope: scope, logger: logger, httpClient: hc}
}

// RawGet performs an authenticated GET against an absolute ARM URL and returns
// the raw response body. A non-2xx status is an error carrying the status and a
// bounded slice of the body, so an authorization boundary (a 403 naming a role)
// is legible rather than swallowed.
func (c *Client) RawGet(ctx context.Context, url string) ([]byte, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return nil, fmt.Errorf("armclient: acquire token for %s: %w", c.scope, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("armclient: build request %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("armclient: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("armclient: read response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		return nil, fmt.Errorf("armclient: GET %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(snippet))
	}
	return body, nil
}
