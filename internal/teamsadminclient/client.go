// This file is the implementation behind api.go. The wire facts the client
// relies on (paths, paging, envelopes, auth) are recorded in
// docs/teams-admin-api.md and not repeated here.
package teamsadminclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
)

const (
	defaultTimeout      = 30 * time.Second
	defaultCallDeadline = 5 * time.Minute

	// maxBodyBytes caps a response read; a larger body is an error, not a
	// silently truncated one.
	maxBodyBytes = 32 << 20

	// pageSize is First. The API ignores invalid parameters, so every page is
	// checked against it.
	pageSize = 100
	// maxPages bounds the non-empty pages of one VoiceApps call (5,000 objects).
	maxPages = 50
)

// tokenCredential is the slice of azcore.TokenCredential this package needs.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

type client struct {
	tenantID     string
	baseURL      string
	scope        string
	callDeadline time.Duration
	cred         tokenCredential
	httpClient   *http.Client
}

func newClient(ta *auth.TenantAuth, opts Options) (*Client, error) {
	if ta == nil {
		return nil, errors.New("teamsadminclient: nil TenantAuth")
	}
	if ta.TenantID == "" {
		return nil, errors.New("teamsadminclient: empty tenant ID")
	}
	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("teamsadminclient: parse base URL: %w", err)
	}
	if parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("teamsadminclient: base URL %q needs an http(s) scheme and a host", baseURL)
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
	deadline := opts.CallDeadline
	if deadline <= 0 {
		deadline = defaultCallDeadline
	}
	return &Client{impl: &client{
		tenantID:     ta.TenantID,
		baseURL:      baseURL,
		scope:        scope,
		callDeadline: deadline,
		cred:         ta.Cred,
		httpClient:   newHTTPClient(opts, ta.TenantID, limiter, logger),
	}}, nil
}

func (c *client) configurations(ctx context.Context, name string) ([]map[string]any, error) {
	if name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("teamsadminclient: tenant %q: invalid configuration name %q", c.tenantID, name)
	}
	body, err := c.get(ctx, "/Skype.Policy/configurations/"+url.PathEscape(name), "")
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	if err := json.Unmarshal(body, &records); err != nil || records == nil {
		return nil, fmt.Errorf("teamsadminclient: configuration %s: response is not a JSON array of objects", name)
	}
	return records, nil
}

// voiceAppSpec is the per-kind wire shape.
type voiceAppSpec struct {
	path, query, key, idField string
}

func specFor(kind VoiceAppKind) (voiceAppSpec, bool) {
	switch kind {
	case AutoAttendants:
		return voiceAppSpec{path: "/Teams.VoiceApps/auto-attendants", key: "AutoAttendants", idField: "Id"}, true
	case CallQueues:
		return voiceAppSpec{path: "/Teams.VoiceApps/callqueues", query: "FilterInvalidObos=False", key: "CallQueues", idField: "Identity"}, true
	}
	return voiceAppSpec{}, false
}

// voiceApps walks one collection until an EMPTY page. Ending on a short page
// would be wrong: a server page cap below First must not end the walk early.
// Skip advances by what was received, not by First, for the same reason.
func (c *client) voiceApps(ctx context.Context, kind VoiceAppKind) (VoiceAppsResult, error) {
	spec, ok := specFor(kind)
	if !ok {
		return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: tenant %q: unknown VoiceAppKind %d", c.tenantID, kind)
	}
	ctx, cancel := context.WithTimeout(ctx, c.callDeadline)
	defer cancel()

	res := VoiceAppsResult{Records: []map[string]any{}}
	seen := map[string]struct{}{}
	nonEmpty := 0
	for skip := 0; ; {
		query := "First=" + strconv.Itoa(pageSize) + "&Skip=" + strconv.Itoa(skip)
		if spec.query != "" {
			query = spec.query + "&" + query
		}
		body, err := c.get(ctx, spec.path, query)
		if err != nil {
			return VoiceAppsResult{}, err
		}
		var env map[string]json.RawMessage
		if err := json.Unmarshal(body, &env); err != nil || env == nil {
			return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: response is not a JSON object", spec.path)
		}
		rawPage, present := env[spec.key]
		if !present {
			return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: response has no %q key", spec.path, spec.key)
		}
		var page []map[string]any
		if err := json.Unmarshal(rawPage, &page); err != nil || page == nil {
			return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: %q is not a JSON array of objects", spec.path, spec.key)
		}
		if rawDiag, ok := env["Diagnostics"]; ok {
			var diags []Diagnostic
			if err := json.Unmarshal(rawDiag, &diags); err != nil {
				return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: Diagnostics is not an array of {Level, Message}", spec.path)
			}
			res.Diagnostics = append(res.Diagnostics, diags...)
		}
		if len(page) == 0 {
			return res, nil
		}
		if len(page) > pageSize {
			return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: page of %d objects exceeds First=%d; the server ignored the paging parameters", spec.path, len(page), pageSize)
		}
		nonEmpty++
		if nonEmpty > maxPages {
			return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: more than %d non-empty pages (%d objects); refusing to continue", spec.path, maxPages, maxPages*pageSize)
		}
		for _, obj := range page {
			id, _ := obj[spec.idField].(string)
			if id == "" {
				return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: object without a string %q field", spec.path, spec.idField)
			}
			if _, dup := seen[id]; dup {
				return VoiceAppsResult{}, fmt.Errorf("teamsadminclient: %s: object ID seen on an earlier page; Skip was ignored or the order moved", spec.path)
			}
			seen[id] = struct{}{}
		}
		res.Records = append(res.Records, page...)
		skip += len(page)
	}
}

// get performs one authenticated GET and returns the capped body. A non-2xx
// becomes *APIError.
func (c *client) get(ctx context.Context, path, query string) ([]byte, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return nil, fmt.Errorf("%w: tenant %q: scope %s (the \"Skype and Teams Tenant Admin API\" resource; a tenant without its service principal fails here): %w",
			ErrToken, c.tenantID, c.scope, err)
	}
	target := c.baseURL + path
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("teamsadminclient: GET %s: build request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// The *url.Error text carries the full URL including the query; the
		// path and the underlying cause are enough.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("teamsadminclient: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("teamsadminclient: GET %s: read response body: %w", path, err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("teamsadminclient: GET %s: response body exceeds %d bytes", path, maxBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp.StatusCode, path, body)
	}
	return body, nil
}
