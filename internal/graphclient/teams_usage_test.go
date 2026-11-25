package graphclient

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
)

func TestTeamsUsageSharesReportingBudget(t *testing.T) {
	const graph = "https://graph.example.com"
	const tenant = "192.0.2.20"
	const token = "synthetic-graph-token"

	limiter := NewWorkloadLimiter()
	limiter.limiters[limiterKey{tenant, WorkloadReporting}] = rate.NewLimiter(0, 5)
	var graphPaths []string
	downloads := 0
	client, err := NewClient(t.Context(), &auth.TenantAuth{TenantID: tenant, Cred: fakeCredential{token: token}}, Options{
		ValidHosts: []string{"graph.example.com"},
		Limiter:    limiter,
		baseTransport: rawRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			res := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req}
			body := "ok"
			switch req.URL.Host {
			case "graph.example.com":
				if req.Header.Get("Authorization") != "Bearer "+token {
					t.Error("Graph did not receive the bearer token")
				}
				graphPaths = append(graphPaths, req.URL.Path)
				if strings.HasPrefix(req.URL.Path, "/v1.0/reports/getTeams") {
					if req.Header.Get("Cookie") != "session=synthetic" || req.Header.Get("Referer") != graph+"/synthetic" {
						t.Error("redirect fixture did not send cookie and referrer on the initial Graph request")
					}
					res.StatusCode = http.StatusFound
					downloadHost := "reports.office.com"
					switch {
					case strings.Contains(req.URL.Path, "getTeamsDeviceUsageUserDetail"):
						downloadHost = "reportsweu.office.com"
					case strings.Contains(req.URL.Path, "getTeamsTeamActivityDetail"):
						downloadHost = "reportsweu.office.com:443"
					}
					res.Header.Set("Location", "https://"+downloadHost+"/data/download/synthetic?ticket=synthetic")
				}
			case "reports.office.com", "reportsweu.office.com", "reportsweu.office.com:443":
				downloads++
				if req.URL.Scheme != "https" {
					t.Error("download did not use HTTPS")
				}
				for _, header := range []string{"Authorization", "Cookie", "Referer"} {
					if req.Header.Get(header) != "" {
						t.Errorf("download received %s", header)
					}
				}
				if req.URL.Query().Get("ticket") != "synthetic" {
					t.Error("download lost the ticket query")
				}
				body = "csv"
			default:
				t.Errorf("unexpected host: %s", req.URL.Host)
			}
			res.Body = io.NopCloser(strings.NewReader(body))
			return res, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	existing := "/v1.0/reports/getTeamsUserActivityUserDetail(period='D7')"
	paths := []string{
		"/v1.0/reports/getMailboxUsageDetail(period='D7')",
		"/v1.0/reports/getTeamsDeviceUsageUserDetail(period='D7')",
		"/v1.0/reports/getTeamsTeamActivityDetail(period='D7')",
		"/v1.0/reports/getTeamsUserActivityUserCounts(period='D30')",
		"/v1.0/admin/reportSettings",
	}
	for _, path := range paths {
		ctx, want := t.Context(), "ok"
		if strings.HasPrefix(path, "/v1.0/reports/getTeams") {
			ctx, want = ReportDownloadContext(ctx), "csv"
		}
		if body, err := client.RawGetWithHeaders(ctx, graph+path, map[string]string{
			"Cookie": "session=synthetic", "Referer": graph + "/synthetic",
		}); err != nil || string(body) != want {
			t.Fatalf("GET %s: body=%q, err=%v, want %q", path, body, err, want)
		}
	}
	if _, err := client.RawGet(t.Context(), graph+existing); err == nil {
		t.Error("existing report was not blocked after the shared budget ran out")
	}
	if _, err := client.RawGet(t.Context(), "https://reports.office.com/data/download/synthetic"); err == nil {
		t.Error("the reporting host was allowed as an initial Graph URL")
	}
	if !slices.Equal(graphPaths, paths) || downloads != 3 {
		t.Fatalf("requests: Graph %q, download count %d; want %q and 3", graphPaths, downloads, paths)
	}
}

func TestReportDownloadDoesNotFollowSecondHop(t *testing.T) {
	const graph = "https://graph.example.com/v1.0/reports/getTeamsDeviceUsageUserDetail(period='D7')"
	const first = "https://reportsweu.office.com:443/data/download/synthetic"
	const second = "https://reports.office.com/data/download/synthetic"
	var urls []string
	client, err := NewClient(t.Context(), &auth.TenantAuth{Cred: fakeCredential{token: "synthetic-graph-token"}}, Options{
		ValidHosts: []string{"graph.example.com"},
		baseTransport: rawRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			urls = append(urls, req.URL.String())
			res := &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Request: req, Body: http.NoBody}
			switch req.URL.Host {
			case "graph.example.com":
				res.Header.Set("Location", first)
			case "reportsweu.office.com:443":
				res.Header.Set("Location", second)
			}
			return res, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RawGet(ReportDownloadContext(t.Context()), graph)
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusFound || !slices.Equal(urls, []string{graph, first}) {
		t.Fatalf("redirect: err=%v, requests=%q, want 302 after the first reporting hop", err, urls)
	}
}

func TestReportDownloadRejectsUntrustedRedirect(t *testing.T) {
	for _, tc := range []struct{ name, location string }{
		{"plaintext", "http://reports.office.com/data/download/synthetic"},
		{"foreign host", "https://downloads.example.com/csv"},
		{"loopback", "https://[::1]/csv"},
		{"lookalike", "https://reports.office.com.example.com/csv"},
		{"regional lookalike", "https://reportsweu.office.com.example.com/csv"},
		{"alternate port", "https://reports.office.com:8443/data/download/synthetic"},
		{"regional alternate port", "https://reportsweu.office.com:8443/data/download/synthetic"},
		{"user info", (&url.URL{Scheme: "https", User: url.User("synthetic"), Host: "reports.office.com", Path: "/data/download/synthetic"}).String()},
		{"relative URL", "/csv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			client, err := NewClient(t.Context(), &auth.TenantAuth{Cred: fakeCredential{token: "synthetic-graph-token"}}, Options{
				ValidHosts: []string{"graph.example.com"},
				baseTransport: rawRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					res := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: http.NoBody}
					if requests == 1 {
						res.StatusCode = http.StatusFound
						res.Header.Set("Location", tc.location)
					}
					return res, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx := ReportDownloadContext(t.Context())
			_, err = client.RawGet(ctx, "https://graph.example.com/v1.0/reports/getTeamsDeviceUsageUserDetail(period='D7')")
			var status *HTTPStatusError
			if !errors.As(err, &status) || status.StatusCode != http.StatusFound || requests != 1 {
				t.Fatalf("redirect: err=%v, requests=%d, want 302 and no second request", err, requests)
			}
		})
	}
}
