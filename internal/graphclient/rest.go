package graphclient

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
)

// tokenCredential is the minimal slice of azcore.TokenCredential the raw-REST
// hatch needs (and is satisfied by the auth package's per-tenant credential). A
// local interface keeps this package testable with a fake credential.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// RawGet performs a GET against an absolute Graph URL through the SAME
// instrumented, retrying transport as the typed client, attaching a bearer token
// for GraphDefaultScope. It is the escape hatch for beta endpoints not worth
// pulling msgraph-beta-sdk-go for: the caller hand-decodes the returned body.
// A non-2xx response is returned as an error including the status and body.
func (c *Client) RawGet(ctx context.Context, url string) ([]byte, error) {
	return c.RawGetWithHeaders(ctx, url, nil)
}

// RawGetWithHeaders is RawGet with caller-supplied request headers layered on
// top of the bearer token and Accept. It exists for the Entra directory
// aggregate queries — every `$count` segment and every advanced `$filter`
// operator (`ne`, `endsWith`, `$search`) requires the request header
// `ConsistencyLevel: eventual`, which omitting returns an error for. The
// caller's headers win over the defaults for any colliding key, so a caller
// cannot accidentally strip Authorization by passing an unrelated header set.
func (c *Client) RawGetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	if err := c.validateRawURL(url); err != nil {
		return nil, err
	}
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{auth.GraphDefaultScope}})
	if err != nil {
		return nil, fmt.Errorf("graphclient: tenant %q: acquire token: %w", c.TenantID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("graphclient: build request %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphclient: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := readRawBody(url, resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newHTTPStatusError(http.MethodGet, url, resp, body)
	}
	return body, nil
}

// RawPost performs a POST against an absolute Graph URL through the SAME
// instrumented, retrying, rate-limited transport as the typed client, attaching
// a bearer token for GraphDefaultScope and Content-Type: application/json. It is
// the create side of the Intune reports export-job subsystem (#17): POST
// /deviceManagement/reports/exportJobs to create a job. body is sent verbatim as
// the request payload; caller-supplied headers layer on top of the defaults
// (caller headers win on collision, but cannot strip Authorization). A non-2xx
// response is returned as an error including the status and body, so the caller
// can classify the export API's report-specific 400s (bad reportName/select).
func (c *Client) RawPost(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error) {
	if err := c.validateRawURL(url); err != nil {
		return nil, err
	}
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{auth.GraphDefaultScope}})
	if err != nil {
		return nil, fmt.Errorf("graphclient: tenant %q: acquire token: %w", c.TenantID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("graphclient: build request %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphclient: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := readRawBody(url, resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newHTTPStatusError(http.MethodPost, url, resp, respBody)
	}
	return respBody, nil
}

// HTTPStatusError is the error RawGet, RawGetWithHeaders and RawPost return for
// a non-2xx response that survived the transport's own retries. Its Error() text
// is the historical "graphclient: METHOD url: status N: body" string, which many
// collectors still classify with strings.Contains("status 403"), so that text
// must not change. Callers that need to act on the status — the export-job
// engine retrying a 429 within its tick — use errors.As instead.
type HTTPStatusError struct {
	Method     string
	URL        string
	StatusCode int
	Body       []byte
	// RetryAfter is the response's Retry-After in seconds form, or 0 when absent
	// or unparsable. Most throttled Graph workloads send none (see workload.go).
	RetryAfter time.Duration
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("graphclient: %s %s: status %d: %s", e.Method, e.URL, e.StatusCode, string(e.Body))
}

func newHTTPStatusError(method, url string, resp *http.Response, body []byte) *HTTPStatusError {
	return &HTTPStatusError{
		Method:     method,
		URL:        url,
		StatusCode: resp.StatusCode,
		Body:       body,
		RetryAfter: parseRetryAfter(resp.Header.Get(headerRetryAfter)),
	}
}

// maxRawBodyBytes caps a raw-REST response read so a pathological/hostile
// response cannot exhaust memory (32 MiB is generous for a paged Graph page).
const maxRawBodyBytes = 32 << 20

// rawBodyTooLargeError reports that a raw response was not returned because it
// exceeded the complete-body cap. Returning no bytes prevents callers from
// treating a valid prefix as a complete JSON or CSV payload.
type rawBodyTooLargeError struct {
	url   string
	limit int
}

func (e *rawBodyTooLargeError) Error() string {
	return fmt.Sprintf("graphclient: read %s body: exceeds %d-byte limit", e.url, e.limit)
}

func (e *rawBodyTooLargeError) rawBodyLimit() int { return e.limit }

func (e *rawBodyTooLargeError) rawBodyURL() string { return e.url }

func (c *Client) validateRawURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("graphclient: parse raw URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("graphclient: raw URL %q must use HTTPS", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if _, ok := c.validHosts[host]; !ok {
		return fmt.Errorf("graphclient: raw URL %q host %q is not allowed", rawURL, u.Hostname())
	}
	return nil
}

func readRawBody(url string, body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxRawBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("graphclient: read %s body: %w", url, err)
	}
	if len(data) > maxRawBodyBytes {
		return nil, &rawBodyTooLargeError{url: url, limit: maxRawBodyBytes}
	}
	return data, nil
}
