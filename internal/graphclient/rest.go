package graphclient

import (
	"context"
	"fmt"
	"io"
	"net/http"

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRawBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("graphclient: read %s body: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graphclient: GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}
	return body, nil
}

// maxRawBodyBytes caps a raw-REST response read so a pathological/hostile
// response cannot exhaust memory (32 MiB is generous for a paged Graph page).
const maxRawBodyBytes = 32 << 20
