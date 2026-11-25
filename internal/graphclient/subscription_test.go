package graphclient

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/auth"
)

func TestRawSubscriptionDoesNotRedirectOrReplayCreate(t *testing.T) {
	const address = "https://graph.microsoft.com/v1.0/subscriptions"
	const body = `{"clientState":"synthetic-state"}`
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"redirect", http.StatusTemporaryRedirect},
		{"retryable", http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := rawRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.String() != address || req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer synthetic-token" {
					return nil, errors.New("subscription request deviated from the bound Graph destination")
				}
				var reader io.Reader = req.Body
				if req.Header.Get("Content-Encoding") == "gzip" {
					gz, err := gzip.NewReader(req.Body)
					if err != nil {
						return nil, err
					}
					defer gz.Close()
					reader = gz
				}
				b, err := io.ReadAll(reader)
				if err != nil || string(b) != body {
					return nil, errors.New("subscription create body did not reach Graph")
				}
				return &http.Response{
					StatusCode: tc.status, Request: req,
					Header: http.Header{"Location": []string{"https://elsewhere.example.invalid/collect"}, "Retry-After": []string{"0.01"}},
					Body:   io.NopCloser(strings.NewReader(body)), // simulate Graph reflecting clientState
				}, nil
			})
			client, err := NewClient(t.Context(), &auth.TenantAuth{TenantID: "synthetic-tenant", Cred: fakeCredential{token: "synthetic-token"}}, Options{baseTransport: transport})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RawSubscription(t.Context(), http.MethodPost, address, []byte(body))
			var status *HTTPStatusError
			if !errors.As(err, &status) || status.StatusCode != tc.status || calls != 1 || strings.Contains(err.Error(), "synthetic-state") {
				t.Fatalf("wanted one request and status %d, got %d requests, error %v", tc.status, calls, err)
			}
		})
	}
}
