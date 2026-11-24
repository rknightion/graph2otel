package vaacclient

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Synthetic docs-derived HTTP fixtures. Never uses a socket or real identity.
const fixture = "synthetic-only-sensitive-fixture"
const tenant = "00000000-0000-0000-0000-000000000001"

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func newFixtureClient(t *testing.T, rt roundTrip) *Client {
	t.Helper()
	p := t.TempDir()
	user, pass := filepath.Join(p, "user"), filepath.Join(p, "pass")
	if err := os.WriteFile(user, []byte(fixture+"@example.invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pass, []byte(fixture+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(tenant, user, pass, rt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFetchDoesNotFollowRedirectsOrEchoRemoteErrors(t *testing.T) {
	end := time.Date(2000, 1, 1, 2, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		auth    bool
		respond func() (*http.Response, error)
		want    string
	}{
		{"token-redirect", false, redirectFixture, "token returned HTTP 307"},
		{"analytics-redirect", true, redirectFixture, "analytics returned HTTP 307"},
		{"token-status", false, func() (*http.Response, error) { return response(400, fixture), nil }, "token returned HTTP 400"},
		{"analytics-status", true, func() (*http.Response, error) { return response(403, fixture), nil }, "analytics returned HTTP 403"},
		{"token-network", false, func() (*http.Response, error) { return nil, errors.New(fixture) }, "token transport failed"},
		{"analytics-network", true, func() (*http.Response, error) { return nil, errors.New(fixture) }, "analytics transport failed"},
		{"token-malformed", false, func() (*http.Response, error) { return response(200, fixture), nil }, "token response is malformed"},
		{"analytics-malformed", true, func() (*http.Response, error) { return response(200, `{"dataResult":[]} } `+fixture), nil }, "analytics response is malformed"},
		{"analytics-columns", true, func() (*http.Response, error) { return response(200, `{"dataResult":[["`+fixture+`"]]}`), nil }, "analytics response has a column mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := 0
			c := newFixtureClient(t, func(r *http.Request) (*http.Response, error) {
				seen++
				if seen == 1 && (r.URL.Scheme != "https" || r.URL.Host != "login.microsoftonline.com" || r.Method != http.MethodPost) {
					t.Fatal("password request escaped the authority")
				}
				if seen > 1 && (r.URL.Scheme != "https" || r.URL.Host != "api.interfaces.records.teams.microsoft.com" || r.Method != http.MethodGet) {
					t.Fatal("a redirect was followed or the token escaped the analytics service")
				}
				if tc.auth && seen == 1 {
					return response(200, `{"access_token":"`+fixture+`","expires_in":3600}`), nil
				}
				return tc.respond()
			})
			_, err := c.Fetch(t.Context(), AutoAttendant, end.Add(-time.Hour), end)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), fixture) || strings.Contains(err.Error(), "query=") {
				t.Fatal("expected only a bounded VAAC failure diagnostic, not request or response data")
			}
			if tc.auth && seen != 2 || !tc.auth && seen != 1 {
				t.Fatal("unexpected request count")
			}
		})
	}
}

func TestFetchRejectsMalformedBearerBeforeAnalytics(t *testing.T) {
	for _, value := range []string{"/synthetic/private-token-path?query=fixture", "synthetic=misplaced-padding", "synthetic:malformed-token"} {
		c := newFixtureClient(t, func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Error("malformed bearer reached the analytics request")
				return response(http.StatusForbidden, ""), nil
			}
			return response(http.StatusOK, fmt.Sprintf(`{"access_token":%q}`, value)), nil
		})
		end := time.Date(2000, 1, 1, 2, 0, 0, 0, time.UTC)
		_, err := c.Fetch(t.Context(), CallQueue, end.Add(-time.Hour), end)
		if err == nil || err.Error() != "VAAC token response is malformed" {
			t.Error("expected a fixed token diagnostic without token content")
		}
	}
}

func redirectFixture() (*http.Response, error) {
	r := response(http.StatusTemporaryRedirect, fixture)
	r.Header.Set("Location", "https://redirect.example.invalid/"+fixture)
	return r, nil
}

func TestFetchSubdividesSaturatedWindowOrFailsClosed(t *testing.T) {
	start := time.Date(2000, 1, 1, 2, 0, 0, 0, time.UTC)
	for _, dense := range []bool{false, true} {
		t.Run(fmt.Sprintf("dense=%t", dense), func(t *testing.T) {
			var seen []string
			c := newFixtureClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPost {
					return response(200, `{"access_token":"synthetic-token"}`), nil
				}
				if r.URL.Host != "api.interfaces.records.teams.microsoft.com" {
					t.Fatal("unexpected analytics host")
				}
				data, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("query"))
				if err != nil {
					t.Fatal(err)
				}
				g, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer g.Close()
				var q query
				if err := json.NewDecoder(g).Decode(&q); err != nil {
					t.Fatal(err)
				}
				seen = append(seen, q.Filters[0].Value+" / "+q.Filters[1].Value)
				if dense || len(seen) == 1 {
					cols := len(q.Dimensions) + len(q.Measurements)
					row := "[" + strings.Repeat("null,", cols-1) + "null]"
					return response(200, `{"dataResult":[`+strings.Repeat(row+",", q.LimitResultRowsCount-1)+row+`],"nextLink":"https://redirect.example.invalid"}`), nil
				}
				var compressed bytes.Buffer
				zw := gzip.NewWriter(&compressed)
				if _, err := io.WriteString(zw, `{"dataResult":[]}`); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				res := response(200, compressed.String()) // Reference client also accepts gzip with no header.
				return res, nil
			})
			rows, err := c.Fetch(t.Context(), CallQueue, start, start.Add(4*time.Second))
			if dense {
				if err == nil || len(rows) != 0 || !strings.Contains(err.Error(), "saturated at second resolution") || len(seen) != 3 {
					t.Fatalf("saturated minimum window did not fail closed: %v; windows=%v", err, seen)
				}
				return
			}
			want := []string{"2000-01-01T02:00:00Z / 2000-01-01T02:00:04Z", "2000-01-01T02:00:00Z / 2000-01-01T02:00:02Z", "2000-01-01T02:00:02Z / 2000-01-01T02:00:04Z"}
			if err != nil || len(rows) != 0 || !slices.Equal(seen, want) {
				t.Fatalf("bounded split: err=%v, windows=%v, want %v", err, seen, want)
			}
		})
	}
}
