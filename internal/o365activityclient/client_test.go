package o365activityclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

const testTenantID = "41463f53-8812-40f4-890f-865bf6e35190"

// fakeCredential records every scope set it is asked for, so tests can assert
// the client requests the manage.office.com audience rather than Graph's.
type fakeCredential struct {
	mu     sync.Mutex
	token  string
	err    error
	scopes [][]string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, opts.Scopes)
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func (f *fakeCredential) requestedScopes() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.scopes))
	copy(out, f.scopes)
	return out
}

// newTestClient builds a Client pointed at srv with a fake credential.
func newTestClient(t *testing.T, srv *httptest.Server, mutate func(*Options)) (*Client, *fakeCredential) {
	t.Helper()
	cred := &fakeCredential{token: "test-token"}
	opts := Options{BaseURL: srv.URL}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: cred}, opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, cred
}

// jsonServer serves body for any request, recording the requests it saw.
func jsonServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestNewClientRejectsNilTenantAuth(t *testing.T) {
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Error("NewClient(nil) = nil error, want an error")
	}
}

// TestDefaultBaseURLAndScope pins the enterprise-plan endpoint and the audience
// derived from it. The audience is the whole point of this package existing
// separately from graphclient — a Graph token is not accepted here.
func TestDefaultBaseURLAndScope(t *testing.T) {
	if CloudPublicBaseURL != "https://manage.office.com" {
		t.Errorf("CloudPublicBaseURL = %q, want %q", CloudPublicBaseURL, "https://manage.office.com")
	}
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: &fakeCredential{}}, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, want := c.Scope(), "https://manage.office.com/.default"; got != want {
		t.Errorf("Scope() = %q, want %q", got, want)
	}
}

// TestScopeFollowsBaseURL checks each sovereign cloud gets its OWN audience,
// derived from its base URL rather than hard-coded to the commercial one — a
// GCC High deployment authenticating against manage.office.com would fail.
func TestScopeFollowsBaseURL(t *testing.T) {
	for _, tc := range []struct{ baseURL, wantScope string }{
		{CloudPublicBaseURL, "https://manage.office.com/.default"},
		{CloudGCCBaseURL, "https://manage-gcc.office.com/.default"},
		{CloudGCCHighBaseURL, "https://manage.office365.us/.default"},
		{CloudDoDBaseURL, "https://manage.protection.apps.mil/.default"},
	} {
		c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: &fakeCredential{}},
			Options{BaseURL: tc.baseURL})
		if err != nil {
			t.Fatalf("NewClient(%s): %v", tc.baseURL, err)
		}
		if got := c.Scope(); got != tc.wantScope {
			t.Errorf("BaseURL %s: Scope() = %q, want %q", tc.baseURL, got, tc.wantScope)
		}
	}
}

// TestExplicitScopeOverride lets an operator pin an audience the base-URL
// derivation does not predict, without forking the package.
func TestExplicitScopeOverride(t *testing.T) {
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: &fakeCredential{}},
		Options{BaseURL: CloudPublicBaseURL, Scope: "https://custom.example/.default"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, want := c.Scope(), "https://custom.example/.default"; got != want {
		t.Errorf("Scope() = %q, want %q", got, want)
	}
}

// TestRequestCarriesTokenForManagementAudience is the end-to-end form of the
// audience assertion: a real call must ask the credential for the management
// scope (NOT the Graph scope) and put the resulting token on the wire.
func TestRequestCarriesTokenForManagementAudience(t *testing.T) {
	var gotAuth string
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	c, cred := newTestClient(t, srv, nil)

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}

	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}
	scopes := cred.requestedScopes()
	if len(scopes) == 0 {
		t.Fatal("the credential was never asked for a token")
	}
	for _, s := range scopes {
		if len(s) != 1 || !strings.HasSuffix(s[0], "/.default") {
			t.Fatalf("requested scopes = %v, want exactly one .default scope", s)
		}
		if strings.Contains(s[0], "graph.microsoft.com") {
			t.Errorf("requested the GRAPH scope %q — this API needs the manage.office.com audience", s[0])
		}
	}
}

// TestTokenErrorSurfaces checks a credential failure is reported rather than
// producing an unauthenticated call.
func TestTokenErrorSurfaces(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c, cred := newTestClient(t, srv, nil)
	cred.err = errors.New("no credential configured")

	if _, err := c.ListSubscriptions(context.Background()); err == nil {
		t.Error("ListSubscriptions = nil error, want the credential failure")
	}
}

// TestPublisherIdentifierIsSent checks the throttling-quota parameter reaches
// the wire when configured. Without it, requests share a single global quota
// rather than getting the tenant's dedicated allocation.
func TestPublisherIdentifierIsSent(t *testing.T) {
	var gotPublisher string
	var seen int
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPublisher = r.URL.Query().Get("PublisherIdentifier")
		seen++
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.PublisherIdentifier = "pub-guid" })

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if gotPublisher != "pub-guid" {
		t.Errorf("PublisherIdentifier = %q, want %q", gotPublisher, "pub-guid")
	}
	if seen != 1 {
		t.Errorf("server saw %d requests, want 1", seen)
	}
}

// TestPublisherIdentifierOmittedWhenUnset keeps the parameter out of the URL
// entirely rather than sending an empty value.
func TestPublisherIdentifierOmittedWhenUnset(t *testing.T) {
	var hasParam bool
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, hasParam = r.URL.Query()["PublisherIdentifier"]
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if hasParam {
		t.Error("PublisherIdentifier present in the URL, want it omitted when unset")
	}
}

// TestRequestURLShape pins the documented root:
// {base}/api/v1.0/{tenant_id}/activity/feed/{operation}
func TestRequestURLShape(t *testing.T) {
	var gotPath string
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	want := "/api/v1.0/" + testTenantID + "/activity/feed/subscriptions/list"
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

// TestClassifyOperationIsBounded is a cardinality guard, not a cosmetic one. A
// content-fetch URL embeds an opaque contentId; using the raw path as a metric
// attribute would mint one series per blob — the pathological case CLAUDE.md
// bans. Every classification must collapse to a bounded, enumerable value.
func TestClassifyOperationIsBounded(t *testing.T) {
	const contentID = "492638008028$492638008028$f28ab78ad40140608012736e373933ebspo2015043022$4a81a7c326fc4aed89c62e6039ab833b$04"
	root := "/api/v1.0/" + testTenantID + "/activity/feed"

	cases := map[string]Operation{
		root + "/subscriptions/start":                              OpSubscriptionsStart,
		root + "/subscriptions/stop":                               OpSubscriptionsStop,
		root + "/subscriptions/list":                               OpSubscriptionsList,
		root + "/subscriptions/content":                            OpSubscriptionsContent,
		root + "/subscriptions/notifications":                      OpSubscriptionsNotifications,
		root + "/audit/" + contentID:                               OpContentFetch,
		"/api/v1.0/" + testTenantID + "/activity/feed/../nonsense": OpUnknown,
	}
	for path, want := range cases {
		if got := ClassifyOperation(path); got != want {
			t.Errorf("ClassifyOperation(%q) = %q, want %q", path, got, want)
		}
	}

	// The decisive property: a per-blob path must never leak its contentId into
	// the classification, whatever the classifier decides to call it.
	got := string(ClassifyOperation(root + "/audit/" + contentID))
	if strings.Contains(got, contentID) || strings.Contains(got, "492638008028") {
		t.Errorf("ClassifyOperation leaked the contentId into %q — this becomes a metric label", got)
	}
}

// TestInstrumentationIsBoundedAndRecorded checks the transport records the
// duration histogram with bounded attributes only.
func TestInstrumentationIsBoundedAndRecorded(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	rec := telemetrytest.New()
	c, _ := newTestClient(t, srv, func(o *Options) { o.Emitter = rec.Emitter() })

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}

	points := rec.MetricPoints(metricHTTPClientDuration)
	if len(points) == 0 {
		t.Fatalf("no %s recorded", metricHTTPClientDuration)
	}
	attrs := points[0].Attrs
	if got := attrs[attrOperation]; got != string(OpSubscriptionsList) {
		t.Errorf("%s = %v, want %q", attrOperation, got, OpSubscriptionsList)
	}
	if got := attrs[attrHTTPStatusCode]; got != "200" {
		t.Errorf("%s = %v, want 200", attrHTTPStatusCode, got)
	}
	if got := attrs[attrTenantID]; got != testTenantID {
		t.Errorf("%s = %v, want %q", attrTenantID, got, testTenantID)
	}
}

// TestHTTPErrorCountersRecorded checks a 4xx/5xx increments the self-obs
// counter in the graph2otel.* namespace.
func TestHTTPErrorCountersRecorded(t *testing.T) {
	for _, tc := range []struct {
		status int
		metric string
	}{
		{http.StatusNotFound, metricHTTPClient4xx},
		{http.StatusInternalServerError, metricHTTPClient5xx},
	} {
		srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":{"code":"AF50000","message":"boom"}}`))
		})
		rec := telemetrytest.New()
		c, _ := newTestClient(t, srv, func(o *Options) {
			o.Emitter = rec.Emitter()
			o.MaxRetries = 1 // keep the 5xx case from retrying for seconds
			o.retryBase = time.Millisecond
		})

		_, _ = c.ListSubscriptions(context.Background())

		if len(rec.MetricPoints(tc.metric)) == 0 {
			t.Errorf("status %d: no %s recorded", tc.status, tc.metric)
		}
	}
}

// TestNon2xxBecomesTypedAPIError checks the whole request path funnels failures
// through parseAPIError rather than returning an opaque string.
func TestNon2xxBecomesTypedAPIError(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"AF20022","message":"No subscription found for the specified content type."}}`))
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.ListContent(context.Background(), ContentAzureActiveDirectory, time.Time{}, time.Time{})
	if !IsNoSubscription(err) {
		t.Fatalf("IsNoSubscription(%v) = false, want true", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(*APIError) = false for %v", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", apiErr.StatusCode)
	}
}

// TestRetriesOn5xxThenSucceeds checks the transport retries a documented-
// retryable failure (AF50000 says "Retry the request") rather than surfacing a
// transient blip to the collector.
func TestRetriesOn5xxThenSucceeds(t *testing.T) {
	var attempts int
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"AF50000","message":"An internal error occurred. Retry the request."}}`))
			return
		}
		_, _ = w.Write([]byte(`[{"contentType":"Audit.AzureActiveDirectory","status":"enabled"}]`))
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.retryBase = time.Millisecond })

	subs, err := c.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3 (two failures then a success)", attempts)
	}
	if len(subs) != 1 {
		t.Fatalf("len(subs) = %d, want 1", len(subs))
	}
}

// TestRetriesOn429 checks a throttle response is retried too — AF429 is the
// documented quota-exhausted code and is transient by definition.
func TestRetriesOn429(t *testing.T) {
	var attempts int
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"AF429","message":"Too many requests."}}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	rec := telemetrytest.New()
	c, _ := newTestClient(t, srv, func(o *Options) {
		o.Emitter = rec.Emitter()
		o.retryBase = time.Millisecond
	})

	if _, err := c.ListSubscriptions(context.Background()); err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	if len(rec.MetricPoints(metricThrottleCount)) == 0 {
		t.Errorf("no %s recorded for a 429", metricThrottleCount)
	}
}

// TestRetryGivesUpAndReturnsTypedError checks the attempt cap holds and the
// final failure is still a typed error.
func TestRetryGivesUpAndReturnsTypedError(t *testing.T) {
	var attempts int
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"AF50000","message":"An internal error occurred. Retry the request."}}`))
	})
	c, _ := newTestClient(t, srv, func(o *Options) {
		o.MaxRetries = 2
		o.retryBase = time.Millisecond
	})

	_, err := c.ListSubscriptions(context.Background())
	if err == nil {
		t.Fatal("ListSubscriptions = nil error, want the exhausted-retry failure")
	}
	if !HasCode(err, CodeInternalError) {
		t.Errorf("HasCode(AF50000) = false for %v", err)
	}
	// MaxRetries=2 => the initial attempt plus 2 retries.
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3 (1 initial + 2 retries)", attempts)
	}
}

// TestNo4xxRetry checks a client error is NOT retried — retrying an AF20022 or
// an AF10001 just burns quota against a condition that cannot resolve itself.
func TestNo4xxRetry(t *testing.T) {
	var attempts int
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"AF20022","message":"No subscription found."}}`))
	})
	c, _ := newTestClient(t, srv, func(o *Options) { o.retryBase = time.Millisecond })

	_, _ = c.ListSubscriptions(context.Background())
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 — a 4xx must not be retried", attempts)
	}
}

// TestLimiterGatesRequests checks the limiter is actually spliced into the
// transport, not merely accepted as an option and ignored.
func TestLimiterGatesRequests(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	c, _ := newTestClient(t, srv, func(o *Options) {
		o.Limiter = newLimiterWithRate(rate.Every(20*time.Millisecond), 1)
	})

	start := time.Now()
	for range 3 {
		if _, err := c.ListSubscriptions(context.Background()); err != nil {
			t.Fatalf("ListSubscriptions: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("3 requests took %v, want >= 40ms — the limiter is not wired into the transport", elapsed)
	}
}
