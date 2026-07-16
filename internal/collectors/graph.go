package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// EventualHeaders returns the header set every Microsoft Graph advanced query
// requires — a `$filter` with advanced operators (`ne`, `endsWith`, `not`,
// `$count=true`), `$search`, or `$orderby` alongside `$filter`. Pass it to
// GetAllValues for such queries. Count sets this itself, so count callers don't
// need it. A fresh map is returned each call so callers can safely add keys.
func EventualHeaders() map[string]string {
	return map[string]string{"ConsistencyLevel": "eventual"}
}

// countHeaders are the headers a `$count` segment needs. Beyond
// ConsistencyLevel, a `$count` endpoint responds with a bare integer as
// text/plain and returns HTTP 415 if the request's Accept header demands
// application/json (the RawGet default) — verified live against Graph — so the
// Accept default is overridden to text/plain here.
var countHeaders = map[string]string{"ConsistencyLevel": "eventual", "Accept": "text/plain"}

// Count issues a Graph `$count` request (which returns a bare integer body) and
// parses the scalar. It always sends "ConsistencyLevel: eventual" and
// "Accept: text/plain", so callers pass the plain count URL (with any advanced
// `$filter`) and never worry about the headers. Used for the cheap,
// correctly-bounded population gauges that slice directory objects by
// attribute without paging the full collection.
func Count(ctx context.Context, g GraphClient, url string) (int64, error) {
	body, err := g.RawGetWithHeaders(ctx, url, countHeaders)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("collectors: parse count from %q: %w", strings.TrimSpace(string(body)), err)
	}
	return n, nil
}

// CountViaCollection issues an advanced count using the `$count=true` query
// parameter on a collection endpoint (rather than the `$count` path segment),
// reading `@odata.count` from the response envelope. Some filters — notably
// `signInActivity/lastSignInDateTime` — are rejected by the `/$count` segment
// (HTTP 5xx) but work via `$count=true` on the collection, verified live; this
// is the fallback for those. The caller builds the full URL including
// `$count=true` (and typically `$top=1&$select=id` to keep the payload tiny);
// ConsistencyLevel: eventual is sent automatically.
func CountViaCollection(ctx context.Context, g GraphClient, url string) (int64, error) {
	body, err := g.RawGetWithHeaders(ctx, url, EventualHeaders())
	if err != nil {
		return 0, err
	}
	var env struct {
		Count int64 `json:"@odata.count"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return 0, fmt.Errorf("collectors: decode @odata.count from %q: %w", url, err)
	}
	return env.Count, nil
}

// maxPages caps GetAllValues' nextLink following. GetAllValues is for the
// small, bounded collections (subscribedSkus, domains, CA policies, directory
// roles, ...) — never for paging a full users/devices collection, which the
// collectors deliberately count instead. The cap is a defensive backstop
// against a runaway pagination loop, not a silent truncation of expected data.
const maxPages = 1000

// maxPageSizePreference is the Prefer header value GetAllValues sends to ask
// Graph for its largest allowed page size. 999 is the documented directory
// maximum ($top / odata.maxpagesize ceiling); Graph clamps to whatever each
// resource actually permits, so it is always safe to send. On a large
// collection (the credential-expiry applications/servicePrincipals walk, the
// Intune managedDevices fleet sweep) it cuts the absolute page count ~10x
// versus Graph's default page size, which both shortens each cycle and keeps
// the credential-expiry walk well under Graph's tighter real ~150/min
// keyCredentials sub-ceiling. On a small collection it is a no-op (still one
// page).
const maxPageSizePreference = "odata.maxpagesize=999"

// withMaxPageSize returns headers plus the max-page-size Prefer request header,
// merged non-destructively: the caller's map is never mutated, and a caller
// that already set its own Prefer keeps it (set-if-absent).
func withMaxPageSize(headers map[string]string) map[string]string {
	merged := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		merged[k] = v
	}
	if _, ok := merged["Prefer"]; !ok {
		merged["Prefer"] = maxPageSizePreference
	}
	return merged
}

// odataPage is the envelope Graph wraps a collection response in.
type odataPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// GetAllValues fetches a Graph collection, following `@odata.nextLink` until
// exhausted, and returns every element as a raw JSON message for the caller to
// unmarshal into its own type. headers (may be nil) is sent on every page
// request — pass "ConsistencyLevel: eventual" when the query uses advanced
// operators. It returns an error rather than truncating if a collection somehow
// exceeds maxPages, since that signals a wrong (full-collection) use of a
// helper meant for small collections.
func GetAllValues(ctx context.Context, g GraphClient, url string, headers map[string]string) ([]json.RawMessage, error) {
	// Ask Graph for its largest page size on every request (the nextLink
	// carries its own $skiptoken, but re-sending Prefer is harmless and keeps
	// the header uniform across pages). Merged once, before the loop.
	reqHeaders := withMaxPageSize(headers)
	var out []json.RawMessage
	next := url
	for pages := 0; next != ""; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("collectors: pagination exceeded %d pages for %q (unbounded collection?)", maxPages, url)
		}
		body, err := g.RawGetWithHeaders(ctx, next, reqHeaders)
		if err != nil {
			return nil, err
		}
		var page odataPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("collectors: decode page from %q: %w", next, err)
		}
		out = append(out, page.Value...)
		next = page.NextLink
	}
	return out, nil
}
