package jobpipeline

import (
	"context"
	"encoding/json"
	"fmt"
)

// Poster is the Graph seam this adapter needs: create (RawPost) + poll/page
// (RawGetWithHeaders / RawGet-equivalent) through the instrumented,
// rate-limited, retrying transport. Satisfied by *graphclient.Client. Declared
// as an interface (rather than importing *graphclient.Client directly) so the
// adapter is unit-testable and this package doesn't hard-depend on graphclient's
// concrete type.
type Poster interface {
	RawPost(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error)
	RawGet(ctx context.Context, url string) ([]byte, error)
}

// graphJobClient is the real JobClient: create/poll via RawPost/RawGet on the
// SAME instrumented transport as every other Graph call, so the async-query
// workload is rate-limited and retried identically. Workload classification and
// throttling happen inside that transport by URL path; this adapter must not
// re-implement them.
type graphJobClient struct {
	graph Poster
}

// NewGraphJobClient returns a JobClient backed by graph (typically
// *graphclient.Client). graph must be non-nil.
func NewGraphJobClient(graph Poster) JobClient {
	return &graphJobClient{graph: graph}
}

// createResponse is the create/status response shape: a query id and status.
type createResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// recordsPage mirrors the records collection response: a "value" array plus the
// opaque "@odata.nextLink" cursor.
type recordsPage struct {
	Value    []map[string]any `json:"value"`
	NextLink string           `json:"@odata.nextLink"`
}

// CreateQuery implements JobClient.
func (g *graphJobClient) CreateQuery(ctx context.Context, createURL string, body []byte) (string, string, error) {
	resp, err := g.graph.RawPost(ctx, createURL, body, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return "", "", err
	}
	var cr createResponse
	if err := json.Unmarshal(resp, &cr); err != nil {
		return "", "", fmt.Errorf("decode create response: %w", err)
	}
	return cr.ID, cr.Status, nil
}

// QueryStatus implements JobClient.
func (g *graphJobClient) QueryStatus(ctx context.Context, queryURL string) (string, error) {
	resp, err := g.graph.RawGet(ctx, queryURL)
	if err != nil {
		return "", err
	}
	var cr createResponse
	if err := json.Unmarshal(resp, &cr); err != nil {
		return "", fmt.Errorf("decode status response: %w", err)
	}
	return cr.Status, nil
}

// FetchRecordsPage implements JobClient.
func (g *graphJobClient) FetchRecordsPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	resp, err := g.graph.RawGet(ctx, pageURL)
	if err != nil {
		return nil, "", err
	}
	var page recordsPage
	if err := json.Unmarshal(resp, &page); err != nil {
		return nil, "", fmt.Errorf("decode records page: %w", err)
	}
	return page.Value, page.NextLink, nil
}
