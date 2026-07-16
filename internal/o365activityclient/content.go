package o365activityclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Constraints the API imposes on /subscriptions/content, all enforced
// client-side here because the alternative is a collector that 400s forever.
const (
	// MaxWindow is the widest startTime..endTime the API accepts. Exceeding it
	// returns AF20030/AF20055. The reference is blunt about why a wider window
	// is not merely rejected but dangerous: "even though it is possible to
	// specify a startTime and endTime more than 24 hours apart, this is not
	// recommended ... if you do get any results ... these could be PARTIAL
	// results and should not be taken into account." Silent partial results are
	// worse than an error, so ListContent chunks rather than hoping.
	MaxWindow = 24 * time.Hour
	// MaxLookback is how far back startTime may reach: /subscriptions/content
	// refuses an older one outright. Verified live 2026-07-16 — a -9d startTime
	// returns AF20055, a -23h startTime returns 200.
	//
	// It is deliberately NOT used to reason about when a blob expires. The two
	// are different quantities and the wire disagrees with the docs: a blob with
	// contentCreated 2026-07-15T20:45 carried contentExpiration 2026-08-05T19:44
	// — roughly 20 days, not 7. Read ContentBlob.ContentExpiration for expiry;
	// this constant bounds only how far back a caller may ask.
	MaxLookback = 7 * 24 * time.Hour
	// lookbackMargin keeps a clamped startTime clear of the 7-day boundary. A
	// start clamped to exactly now-7d is already stale by the time the request
	// lands, which the service rejects.
	lookbackMargin = 5 * time.Minute
	// maxContentPages bounds NextPageUri following, so a service bug that
	// returned a self-referential page cannot spin forever.
	maxContentPages = 1000
	// apiTimeFormat is the documented YYYY-MM-DDTHH:MM:SS form. Times are UTC.
	apiTimeFormat = "2006-01-02T15:04:05"
	// headerNextPage carries the next page's URL when a listing is truncated.
	// Pagination here is a RESPONSE HEADER, not a body field like Graph's
	// @odata.nextLink — reading the body for it finds nothing and silently
	// truncates the listing.
	headerNextPage = "NextPageUri"
)

// ContentBlob is one available content blob, as returned by
// /subscriptions/content.
type ContentBlob struct {
	ContentType string `json:"contentType"`
	// ContentID is the opaque unique identifier of the blob. It is the dedupe
	// key a caller checkpoints, because blobs are NOT listed in event order and
	// an overlap window re-lists blobs already consumed.
	ContentID string `json:"contentId"`
	// ContentURI is the absolute URL to fetch this blob from. It is validated
	// against the client's own host before a token is attached.
	ContentURI string `json:"contentUri"`
	// ContentCreated is when the blob became available — the time
	// startTime/endTime filter on. It is NOT the time of the events inside,
	// which is precisely why a watermark over this field needs an overlap
	// window.
	ContentCreated time.Time `json:"contentCreated"`
	// ContentExpiration is when the blob stops being retrievable. A blob listed
	// close to this can expire before it is fetched, surfacing as AF20051.
	//
	// Read this field; never derive it. The reference's AF20051 text says
	// "content older than 7 days cannot be retrieved", but the wire says
	// otherwise: measured live 2026-07-16, contentCreated 2026-07-15T20:45 came
	// back with contentExpiration 2026-08-05T19:44 — about 20 days. Which is
	// authoritative is unresolved, so the 7-day figure is not encoded anywhere
	// near expiry.
	ContentExpiration time.Time `json:"contentExpiration"`
}

// ListContent returns every content blob for ct that became available in
// [start, end) — inclusive of start, exclusive of end, matching the API's own
// semantics so non-overlapping calls tile cleanly.
//
// Passing two zero times omits the parameters entirely, which the API defines
// as "the last 24 hours".
//
// It transparently handles three things the raw endpoint would otherwise make
// every caller re-solve:
//
//   - CHUNKING. A range wider than MaxWindow is split into <=24h requests. The
//     API does not reliably reject a wider window; it may return partial results
//     instead, so a caller asking for 26 hours after a restart would silently
//     lose data.
//   - CLAMPING. A start older than MaxLookback is moved forward, with a warning.
//     Clamping rather than erroring is deliberate: a collector resuming after a
//     week-long outage has genuinely lost that data — the blobs no longer exist
//     — and erroring would wedge it forever instead of resuming from the oldest
//     data that does exist.
//   - PAGINATION. Truncated listings are followed via the NextPageUri response
//     header until it is absent.
//
// The returned blobs are deduplicated on ContentID within this call. That is a
// defensive guard against overlapping pages, NOT a substitute for the caller's
// cross-tick dedupe: an overlap window re-lists blobs a previous tick already
// consumed, and only a checkpoint spanning ticks can catch those.
func (c *Client) ListContent(ctx context.Context, ct ContentType, start, end time.Time) ([]ContentBlob, error) {
	if !ct.Valid() {
		return nil, fmt.Errorf("o365activityclient: invalid content type %q", ct)
	}
	if start.IsZero() != end.IsZero() {
		return nil, fmt.Errorf("o365activityclient: startTime and endTime must both be set or both be zero")
	}

	// Both zero: let the API apply its own "last 24 hours" default.
	if start.IsZero() {
		return c.listContentWindow(ctx, ct, time.Time{}, time.Time{})
	}

	if end.Before(start) {
		return nil, fmt.Errorf("o365activityclient: endTime %s is before startTime %s",
			end.Format(time.RFC3339), start.Format(time.RFC3339))
	}
	start = c.clampLookback(start)
	if !start.Before(end) {
		// The whole window is either empty or has aged out of retention.
		return nil, nil
	}

	var out []ContentBlob
	seen := make(map[string]struct{})
	for from := start; from.Before(end); {
		to := from.Add(MaxWindow)
		if to.After(end) {
			to = end
		}
		blobs, err := c.listContentWindow(ctx, ct, from, to)
		if err != nil {
			return nil, err
		}
		for _, b := range blobs {
			if _, dup := seen[b.ContentID]; dup {
				continue
			}
			seen[b.ContentID] = struct{}{}
			out = append(out, b)
		}
		from = to
	}
	return out, nil
}

// clampLookback moves a startTime forward to the oldest value the API accepts.
func (c *Client) clampLookback(start time.Time) time.Time {
	oldest := time.Now().UTC().Add(-MaxLookback).Add(lookbackMargin)
	if start.After(oldest) {
		return start
	}
	slog.Warn("startTime is older than the 7-day content retention; clamping forward — the skipped window's blobs no longer exist",
		"tenant_id", c.TenantID,
		"requested_start", start.UTC().Format(time.RFC3339),
		"clamped_start", oldest.Format(time.RFC3339),
	)
	return oldest
}

// listContentWindow fetches one <=24h window, following NextPageUri.
func (c *Client) listContentWindow(ctx context.Context, ct ContentType, start, end time.Time) ([]ContentBlob, error) {
	q := url.Values{"contentType": {string(ct)}}
	if !start.IsZero() {
		q.Set("startTime", start.UTC().Format(apiTimeFormat))
		q.Set("endTime", end.UTC().Format(apiTimeFormat))
	}

	var out []ContentBlob
	next := c.feedURL("subscriptions/content", q)
	for page := 0; next != ""; page++ {
		if page >= maxContentPages {
			return nil, fmt.Errorf("o365activityclient: content listing exceeded %d pages; refusing to follow further",
				maxContentPages)
		}
		body, headers, err := c.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}

		var blobs []ContentBlob
		if err := json.Unmarshal(body, &blobs); err != nil {
			return nil, fmt.Errorf("o365activityclient: decode content listing: %w", err)
		}
		out = append(out, blobs...)

		next = headers.Get(headerNextPage)
		if next == "" {
			break
		}
		// NextPageUri comes from a response, and the next request carries a
		// bearer token, so its host is checked before it is followed.
		if err := c.checkHost(next); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// FetchContent retrieves one content blob by its URI, returning the raw audit
// records it contains.
//
// Records are returned as decoded maps rather than a typed struct on purpose:
// the blob carries a union of every workload's schema (a SharePoint record and
// an Entra sign-in record share almost no fields), and each consuming collector
// maps the subset it needs. This mirrors how blobpipeline hands
// map[string]any to a per-category Map function.
//
// # Two traps live in these records
//
// SENSITIVE VALUES. Records carry ModifiedProperties entries with OldValue and
// NewValue. CLAUDE.md's one genuine content exclusion is not negotiable: a
// mapper emits the NAMES of changed properties and NEVER their old/new VALUES,
// which can carry credentials and certificates. Because this function hands back
// the raw record, that obligation lands entirely on the mapper —
// intune/auditevents already models it correctly.
//
// NESTED JSON-IN-A-STRING. ExtendedProperties[].Value is a JSON-encoded STRING
// holding a nested document, not an object — the same class of trap as #89's
// durationMs being a string at one level and an int at another. Decoding it
// takes a second Unmarshal; treating it as a map yields nothing, silently.
//
// contentURI must be a URI this client produced from a listing; its host is
// validated before the token is attached.
func (c *Client) FetchContent(ctx context.Context, contentURI string) ([]map[string]any, error) {
	if err := c.checkHost(contentURI); err != nil {
		return nil, err
	}
	body, _, err := c.do(ctx, http.MethodGet, contentURI, nil)
	if err != nil {
		return nil, err
	}

	var records []map[string]any
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("o365activityclient: decode content blob: %w", err)
	}
	return records, nil
}
