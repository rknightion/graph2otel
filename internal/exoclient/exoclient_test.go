package exoclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
// the client requests the outlook.office365.com audience rather than Graph's.
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

// newTestClient builds a Client pointed at srv with a fake credential. The
// limiter is opened up by default so gating never slows an unrelated test; the
// limiter tests set their own.
func newTestClient(t *testing.T, srv *httptest.Server, mutate func(*Options)) (*Client, *fakeCredential) {
	t.Helper()
	cred := &fakeCredential{token: "test-token"}
	opts := Options{BaseURL: srv.URL, Limiter: rate.NewLimiter(rate.Inf, 1)}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: cred}, opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, cred
}

// jsonServer serves handler and closes itself at the end of the test.
func jsonServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// okServer replies with a well-formed empty result envelope.
func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	return jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
}

func TestNewClientRejectsNilTenantAuth(t *testing.T) {
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Error("NewClient(nil) = nil error, want an error")
	}
}

func TestNewClientRejectsEmptyTenantID(t *testing.T) {
	if _, err := NewClient(&auth.TenantAuth{Cred: &fakeCredential{}}, Options{}); err == nil {
		t.Error("NewClient with an empty tenant ID = nil error, want an error")
	}
}

// TestZeroOptionsDefaults pins the documented zero-value behavior of every
// Options field. The frozen contract says "the zero value is usable"; a field
// that silently defaults to nil instead would either panic or disable a control
// the operator believes is on.
func TestZeroOptionsDefaults(t *testing.T) {
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: &fakeCredential{}}, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.scope != DefaultScope {
		t.Errorf("scope = %q, want %q", c.scope, DefaultScope)
	}
	if c.logger == nil {
		t.Error("logger = nil, want slog.Default()")
	}
	if c.limiter == nil {
		t.Error("limiter = nil, want DefaultLimiter()")
	}
	if got := c.httpClient.Timeout; got != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", got, defaultTimeout)
	}
}

// TestOptionsOverrides checks each field is actually honored rather than
// accepted and ignored.
func TestOptionsOverrides(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lim := rate.NewLimiter(rate.Every(time.Hour), 1)
	c, err := NewClient(&auth.TenantAuth{TenantID: testTenantID, Cred: &fakeCredential{}}, Options{
		BaseURL: "https://outlook.office365.us/",
		Scope:   "https://outlook.office365.us/.default",
		Limiter: lim,
		Timeout: 7 * time.Second,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if want := "https://outlook.office365.us"; c.baseURL != want {
		t.Errorf("baseURL = %q, want %q (trailing slash trimmed)", c.baseURL, want)
	}
	if want := "https://outlook.office365.us/.default"; c.scope != want {
		t.Errorf("scope = %q, want %q", c.scope, want)
	}
	if c.limiter != lim {
		t.Error("limiter was not the one supplied in Options")
	}
	if c.logger != logger {
		t.Error("logger was not the one supplied in Options")
	}
	if got := c.httpClient.Timeout; got != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", got)
	}
}

// TestInvokeSendsCmdletInputEnvelope pins the exact wire shape. This is not a
// REST GET with query parameters: the whole invocation lives in a POST body,
// and a mis-cased key ("cmdletInput", "parameters") is rejected.
func TestInvokeSendsCmdletInputEnvelope(t *testing.T) {
	var (
		gotMethod      string
		gotPath        string
		gotContentType string
		gotBody        []byte
	)
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	c, _ := newTestClient(t, srv, nil)

	if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage",
		map[string]any{"PageSize": 100}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/adminapi/beta/" + testTenantID + "/InvokeCommand"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/json")
	}

	var sent struct {
		CmdletInput struct {
			CmdletName string         `json:"CmdletName"`
			Parameters map[string]any `json:"Parameters"`
		} `json:"CmdletInput"`
	}
	if err := json.Unmarshal(gotBody, &sent); err != nil {
		t.Fatalf("decode request body %q: %v", gotBody, err)
	}
	if sent.CmdletInput.CmdletName != "Get-QuarantineMessage" {
		t.Errorf("CmdletName = %q, want %q", sent.CmdletInput.CmdletName, "Get-QuarantineMessage")
	}
	if got := sent.CmdletInput.Parameters["PageSize"]; got != float64(100) {
		t.Errorf("Parameters[PageSize] = %v, want 100", got)
	}
}

// TestInvokeSerializesEmptyParametersAsObject is the trap this test exists for:
// a nil Go map marshals to `null`, and `"Parameters": null` is not the same
// request as `"Parameters": {}`.
func TestInvokeSerializesEmptyParametersAsObject(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			var gotBody []byte
			srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				_, _ = w.Write([]byte(`{"value":[]}`))
			})
			c, _ := newTestClient(t, srv, nil)

			if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", params); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if !strings.Contains(string(gotBody), `"Parameters":{}`) {
				t.Errorf("body = %s, want it to carry `\"Parameters\":{}` (never null)", gotBody)
			}
		})
	}
}

// TestInvokeDecodesValueArray checks the flat result array comes back intact,
// records and all.
func TestInvokeDecodesValueArray(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":[
			{"Identity":"aaa\\bbb","Subject":"one","Type":"Spam"},
			{"Identity":"ccc\\ddd","Subject":"two","Type":"Phish"}
		]}`))
	})
	c, _ := newTestClient(t, srv, nil)

	got, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0]["Subject"] != "one" || got[1]["Type"] != "Phish" {
		t.Errorf("decoded records = %v, want the two quarantine rows verbatim", got)
	}
}

// TestInvokeEmptyResultIsNotAnError is load-bearing, not cosmetic. An empty
// quarantine queue is the steady state on a healthy tenant, so an absent, null
// or empty `value` must be an empty slice and a nil error — a collector that
// treated "nothing quarantined" as a failure would alert forever.
func TestInvokeEmptyResultIsNotAnError(t *testing.T) {
	for name, body := range map[string]string{
		"absent value": `{}`,
		"null value":   `{"value":null}`,
		"empty value":  `{"value":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			c, _ := newTestClient(t, srv, nil)

			got, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil)
			if err != nil {
				t.Fatalf("Invoke = %v, want nil error for an empty result", err)
			}
			if got == nil {
				t.Error("Invoke returned a nil slice, want an empty non-nil slice")
			}
			if len(got) != 0 {
				t.Errorf("len = %d, want 0", len(got))
			}
		})
	}
}

// TestInvokeRequestsExchangeAudienceNotGraph is the assertion that justifies
// this package existing separately from graphclient. Both use the same
// azidentity credential; only the audience differs, and a Graph token here is
// silently useless — the request fails at the service, not at token time.
func TestInvokeRequestsExchangeAudienceNotGraph(t *testing.T) {
	var gotAuth string
	srv := jsonServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	c, cred := newTestClient(t, srv, nil)

	if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}

	scopes := cred.requestedScopes()
	if len(scopes) == 0 {
		t.Fatal("the credential was never asked for a token")
	}
	for _, s := range scopes {
		if len(s) != 1 || s[0] != DefaultScope {
			t.Fatalf("requested scopes = %v, want exactly [%s]", s, DefaultScope)
		}
		if strings.Contains(s[0], "graph.microsoft.com") {
			t.Errorf("requested the GRAPH scope %q — this API needs the outlook.office365.com audience", s[0])
		}
	}
}

func TestInvokeSurfacesTokenFailure(t *testing.T) {
	c, cred := newTestClient(t, okServer(t), nil)
	cred.err = errors.New("no credential configured")

	if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil); err == nil {
		t.Error("Invoke = nil error, want the credential failure")
	}
}

// TestInvokeUnwrapsCmdletErrors drives the live-captured failure bodies through
// the whole request path, not just the parser, so a regression in either half
// fails.
func TestInvokeUnwrapsCmdletErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status      int
		body        string
		wantCode    string
		wantType    string
		wantMessage string
	}{
		"invalid enum value": {
			status:      http.StatusBadRequest,
			body:        liveInvalidEnumBody,
			wantCode:    "BadRequest",
			wantType:    "Microsoft.Exchange.AdminApi.CommandInvocation.ParameterTransformationException",
			wantMessage: "Cannot process argument transformation on parameter 'QuarantineTypes'",
		},
		"unknown parameter": {
			status:      http.StatusBadRequest,
			body:        liveUnknownParameterBody,
			wantCode:    "BadRequest",
			wantType:    "Microsoft.Exchange.AdminApi.CommandInvocation.AmbiguousParameterSetException",
			wantMessage: "Parameter set cannot be resolved using the specified named parameters",
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			c, _ := newTestClient(t, srv, nil)

			_, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil)
			var cerr *CmdletError
			if !errors.As(err, &cerr) {
				t.Fatalf("errors.As(*CmdletError) = false for %v", err)
			}
			if cerr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", cerr.StatusCode, tc.status)
			}
			if cerr.Cmdlet != "Get-QuarantineMessage" {
				t.Errorf("Cmdlet = %q, want %q", cerr.Cmdlet, "Get-QuarantineMessage")
			}
			if cerr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", cerr.Code, tc.wantCode)
			}
			if cerr.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", cerr.Type, tc.wantType)
			}
			if !strings.Contains(cerr.Message, tc.wantMessage) {
				t.Errorf("Message = %q, want it to contain %q", cerr.Message, tc.wantMessage)
			}
			if cerr.Message == "Invalid Operation" {
				t.Error("Message is the useless literal `Invalid Operation` — the unwrapping did not happen")
			}
		})
	}
}

// TestInvokeNonJSONErrorBodyIsSurvivable covers the single most likely
// production failure: a missing app role or directory role answers 403 with a
// body that is not JSON at all (live-captured as a long run of NUL bytes). The
// client must not panic, must not report a JSON syntax error as the message,
// and must still name the status and the cmdlet.
func TestInvokeNonJSONErrorBodyIsSurvivable(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(make([]byte, 4096)) // 4 KiB of NULs, as captured live
	})
	c, _ := newTestClient(t, srv, nil)

	_, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil)
	var cerr *CmdletError
	if !errors.As(err, &cerr) {
		t.Fatalf("errors.As(*CmdletError) = false for %v", err)
	}
	if cerr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", cerr.StatusCode)
	}
	if cerr.Cmdlet != "Get-QuarantineMessage" {
		t.Errorf("Cmdlet = %q, want the cmdlet name", cerr.Cmdlet)
	}
	if !strings.Contains(cerr.Message, "not JSON") {
		t.Errorf("Message = %q, want it to say plainly that the body was not JSON", cerr.Message)
	}
	for _, leak := range []string{"invalid character", "unexpected end of JSON", "cannot unmarshal"} {
		if strings.Contains(cerr.Message, leak) {
			t.Errorf("Message = %q, want no raw JSON-decoder text (%q)", cerr.Message, leak)
		}
	}
	if strings.ContainsRune(cerr.Error(), 0) {
		t.Error("Error() carries raw NUL bytes from the response body")
	}
}

// TestInvokeAuthFailuresAreDistinguishable checks a 401 and a 403 both produce
// a typed error whose string tells an operator which half of the authorization
// model is missing — the app role authenticates, the directory role authorizes,
// and neither alone does anything.
func TestInvokeAuthFailuresAreDistinguishable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":"AccessDenied","message":"Invalid Operation",` +
				`"innererror":{"internalexception":{"message":"The user is not authorized to run this cmdlet.",` +
				`"type":"Microsoft.Exchange.AdminApi.CommandInvocation.AuthorizationException"}}}}`))
		})
		c, _ := newTestClient(t, srv, nil)

		_, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil)
		var cerr *CmdletError
		if !errors.As(err, &cerr) {
			t.Fatalf("status %d: errors.As(*CmdletError) = false for %v", status, err)
		}
		if cerr.StatusCode != status {
			t.Errorf("StatusCode = %d, want %d", cerr.StatusCode, status)
		}
		msg := cerr.Error()
		for _, want := range []string{"Get-QuarantineMessage", "not authorized"} {
			if !strings.Contains(msg, want) {
				t.Errorf("status %d: Error() = %q, want it to contain %q", status, msg, want)
			}
		}
	}
}

// TestInvokeHonorsContextCancellation keeps a cancelled poll from pinning a
// goroutine to a dead request.
func TestInvokeHonorsContextCancellation(t *testing.T) {
	c, _ := newTestClient(t, okServer(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Invoke(ctx, "Get-QuarantineMessage", nil)
	if err == nil {
		t.Fatal("Invoke with a cancelled context = nil error, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", err)
	}
}

// TestInstrumentationIsBoundedAndRecorded checks the OTEL transport is spliced
// in, and that its attributes are bounded — method, cmdlet, host, status,
// tenant. The cmdlet name comes from graph2otel's own code, never from tenant
// data, so it is safe as a metric label; nothing per-record ever is.
func TestInstrumentationIsBoundedAndRecorded(t *testing.T) {
	rec := telemetrytest.New()
	c, _ := newTestClient(t, okServer(t), func(o *Options) { o.Emitter = rec.Emitter() })

	if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	points := rec.MetricPoints(metricHTTPClientDuration)
	if len(points) == 0 {
		t.Fatalf("no %s recorded", metricHTTPClientDuration)
	}
	attrs := points[0].Attrs
	if got := attrs[attrCmdlet]; got != "Get-QuarantineMessage" {
		t.Errorf("%s = %v, want %q", attrCmdlet, got, "Get-QuarantineMessage")
	}
	if got := attrs[attrHTTPStatusCode]; got != "200" {
		t.Errorf("%s = %v, want 200", attrHTTPStatusCode, got)
	}
	if got := attrs[attrTenantID]; got != testTenantID {
		t.Errorf("%s = %v, want %q", attrTenantID, got, testTenantID)
	}
	if got := attrs[attrHTTPMethod]; got != http.MethodPost {
		t.Errorf("%s = %v, want POST", attrHTTPMethod, got)
	}
	if attrs[attrServerAddress] == "" {
		t.Errorf("%s missing", attrServerAddress)
	}
}

// TestHTTPErrorCountersRecorded checks a 4xx/5xx increments the self-obs
// counters in the graph2otel.* namespace reserved for graph2otel's own health.
func TestHTTPErrorCountersRecorded(t *testing.T) {
	for _, tc := range []struct {
		status int
		metric string
	}{
		{http.StatusForbidden, metricHTTPClient4xx},
		{http.StatusInternalServerError, metricHTTPClient5xx},
	} {
		srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":{"code":"BadRequest","message":"Invalid Operation"}}`))
		})
		rec := telemetrytest.New()
		c, _ := newTestClient(t, srv, func(o *Options) { o.Emitter = rec.Emitter() })

		_, _ = c.Invoke(context.Background(), "Get-QuarantineMessage", nil)

		if len(rec.MetricPoints(tc.metric)) == 0 {
			t.Errorf("status %d: no %s recorded", tc.status, tc.metric)
		}
	}
}

// TestThrottleCounterRecorded checks a 429 is observed. Exchange Online's
// admin-API ceiling is unmeasured, so this counter is the only way an operator
// would ever learn the conservative default limiter is still too fast.
func TestThrottleCounterRecorded(t *testing.T) {
	srv := jsonServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"Invalid Operation"}}`))
	})
	rec := telemetrytest.New()
	c, _ := newTestClient(t, srv, func(o *Options) { o.Emitter = rec.Emitter() })

	_, _ = c.Invoke(context.Background(), "Get-QuarantineMessage", nil)

	if len(rec.MetricPoints(metricThrottleCount)) == 0 {
		t.Errorf("no %s recorded for a 429", metricThrottleCount)
	}
}

// TestNilEmitterStillWorks keeps instrumentation optional: the zero Options has
// no Emitter, and the transport must still round-trip.
func TestNilEmitterStillWorks(t *testing.T) {
	c, _ := newTestClient(t, okServer(t), nil)
	if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil); err != nil {
		t.Fatalf("Invoke with a nil Emitter: %v", err)
	}
}

// TestLimiterGatesRequests checks the limiter is actually spliced into the
// transport, not merely accepted as an option and ignored.
func TestLimiterGatesRequests(t *testing.T) {
	c, _ := newTestClient(t, okServer(t), func(o *Options) {
		o.Limiter = rate.NewLimiter(rate.Every(20*time.Millisecond), 1)
	})

	start := time.Now()
	for range 3 {
		if _, err := c.Invoke(context.Background(), "Get-QuarantineMessage", nil); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("3 invocations took %v, want >= 40ms — the limiter is not wired into the transport", elapsed)
	}
}
