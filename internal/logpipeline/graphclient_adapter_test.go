package logpipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/graphclient"
)

// fakeCredential is a stand-in azcore.TokenCredential for offline tests,
// mirroring the same seam graphclient's own tests use.
type fakeCredential struct{}

func (fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token"}, nil
}

// TestGraphPageFetcherDecodesValueAndNextLink verifies the real PageFetcher
// adapter fetches through (*graphclient.Client).RawGet and decodes the
// Graph collection response shape ("value" + "@odata.nextLink") into
// PageFetcher's return values.
func TestGraphPageFetcherDecodesValueAndNextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := graphPage{
			Value: []map[string]any{
				{"id": "a", "createdDateTime": "2026-01-01T00:00:00Z"},
			},
			NextLink: "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ta := &auth.TenantAuth{TenantID: "t1", Cred: fakeCredential{}}
	client, err := graphclient.NewClient(context.Background(), ta, graphclient.Options{})
	if err != nil {
		t.Fatalf("graphclient.NewClient: %v", err)
	}

	fetcher := NewGraphPageFetcher(client)
	records, next, err := fetcher.FetchPage(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if len(records) != 1 || records[0]["id"] != "a" {
		t.Fatalf("records = %+v, want a single record with id=a", records)
	}
	if next != "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc" {
		t.Fatalf("nextLink = %q", next)
	}
}
