package logpipeline

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rknightion/graph2otel/internal/graphclient"
)

// graphV1BaseURL is the Microsoft Graph v1.0 service root that EndpointConfig
// paths (e.g. "/auditLogs/signIns") resolve against for the FIRST page of a
// window. Every subsequent page is fetched via the previous page's
// already-absolute @odata.nextLink, so this constant is only ever consulted
// once per Poll call.
const graphV1BaseURL = "https://graph.microsoft.com/v1.0"

// graphPage mirrors the Graph collection response shape Poll pages through:
// a "value" array of raw records plus an opaque "@odata.nextLink" cursor,
// present only when another page follows.
type graphPage struct {
	Value    []map[string]any `json:"value"`
	NextLink string           `json:"@odata.nextLink"`
}

// graphPageFetcher is the real PageFetcher: it fetches one page through
// (*graphclient.Client).RawGet — the SAME instrumented, rate-limited,
// retrying transport as every typed SDK call, since RawGet shares the
// client's httpClient — and JSON-decodes the graphPage shape. Routing to the
// correct Graph throttle ceiling (reporting vs Identity Protection vs
// Intune, ...) happens automatically inside that transport by classifying
// the request's URL path (graphclient.ClassifyWorkload); this adapter does
// not need to, and must not, re-implement rate limiting itself.
type graphPageFetcher struct {
	client *graphclient.Client
}

// NewGraphPageFetcher returns a PageFetcher backed by client. client must be
// non-nil.
func NewGraphPageFetcher(client *graphclient.Client) PageFetcher {
	return &graphPageFetcher{client: client}
}

// FetchPage implements PageFetcher.
func (f *graphPageFetcher) FetchPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	body, err := f.client.RawGet(ctx, pageURL)
	if err != nil {
		return nil, "", fmt.Errorf("logpipeline: fetch page %s: %w", pageURL, err)
	}
	var page graphPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("logpipeline: decode page %s: %w", pageURL, err)
	}
	return page.Value, page.NextLink, nil
}
