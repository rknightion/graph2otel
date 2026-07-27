package graphclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	nethttplibrary "github.com/microsoft/kiota-http-go"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type testRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f testRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errorReadCloser struct {
	err error
}

func (r *errorReadCloser) Read(p []byte) (int, error) {
	copy(p, "partial")
	return len("partial"), r.err
}

func (*errorReadCloser) Close() error { return nil }

func TestNewGraphHTTPClientCapsQueryBrokerRetriesOutsideKiota(t *testing.T) {
	client := newGraphHTTPClient(Options{})
	if _, ok := client.Transport.(*queryBrokerRetryTransport); !ok {
		t.Fatalf("outer transport = %T, want *queryBrokerRetryTransport so Kiota retries cannot reset its attempt cap", client.Transport)
	}
}

func TestQueryBrokerAndKiotaShareOneRetryBudget(t *testing.T) {
	calls := 0
	base := testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls%2 == 1 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"0.001"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"throttled"}}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"error":{"message":"Rate limit reached because of too many requests to query broker. Please retry after sometime."}}`,
			)),
			Request: req,
		}, nil
	})
	kiota := nethttplibrary.NewCustomTransportWithParentTransport(base, buildMiddlewares(Options{MaxRetries: 3})...)
	transport := &queryBrokerRetryTransport{
		next:       kiota,
		maxRetries: 3,
		sleep:      func(context.Context, time.Duration) error { return nil },
	}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/id/runSummary", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if calls != 4 {
		t.Errorf("physical calls = %d, want initial + 3 total retries across both retry classes", calls)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("final status = %d, want exhausted query-broker 500", resp.StatusCode)
	}
}

func TestQueryBrokerRetryTransportRetriesExactThrottleSignature(t *testing.T) {
	calls := 0
	next := testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"error":{"code":"UnknownError","message":"Rate limit reached because of too many requests to query broker. Please retry after sometime."}}`,
				)),
				Request: req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    req,
		}, nil
	})

	var delays []time.Duration
	rec := telemetrytest.New()
	transport := &queryBrokerRetryTransport{
		next:       &instrumentedTransport{next: next, emitter: rec.Emitter(), tenantID: "tenant-a"},
		backoff:    &Backoff{Base: time.Second, Max: time.Minute, jitter: func(d time.Duration) time.Duration { return d }},
		maxRetries: 3,
		sleep: func(_ context.Context, d time.Duration) error {
			delays = append(delays, d)
			return nil
		},
		emitter:  rec.Emitter(),
		tenantID: "tenant-a",
	}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/id/runSummary", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if calls != 2 {
		t.Errorf("physical calls = %d, want 2", calls)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
	if len(delays) != 1 || delays[0] != time.Second {
		t.Errorf("delays = %v, want [1s]", delays)
	}
	points := rec.MetricPoints(metricThrottleCount)
	if len(points) != 1 {
		t.Fatalf("throttle points = %d, want 1: %+v", len(points), points)
	}
	if points[0].Attrs[attrWorkload] != string(WorkloadIntuneGeneral) {
		t.Errorf("throttle workload = %q, want %q", points[0].Attrs[attrWorkload], WorkloadIntuneGeneral)
	}
	if points[0].Attrs[attrTenantID] != "tenant-a" {
		t.Errorf("throttle tenant = %q, want tenant-a", points[0].Attrs[attrTenantID])
	}
	if got := len(rec.MetricPoints(metricHTTPClientDuration)); got != 2 {
		t.Errorf("instrumented physical requests = %d, want 2", got)
	}
	if got := len(rec.MetricPoints(metricHTTPClient5xx)); got != 1 {
		t.Errorf("5xx physical responses = %d, want 1", got)
	}
}

func TestQueryBrokerRetryTransportLeavesGeneric500Untouched(t *testing.T) {
	calls := 0
	next := testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"permanent server failure"}}`)),
			Request:    req,
		}, nil
	})
	transport := &queryBrokerRetryTransport{
		next:       next,
		maxRetries: 3,
		sleep: func(_ context.Context, _ time.Duration) error {
			t.Fatal("generic 500 must not sleep or retry")
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/id/runSummary", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if calls != 1 {
		t.Errorf("physical calls = %d, want 1", calls)
	}
	if got := string(body); got != `{"error":{"message":"permanent server failure"}}` {
		t.Errorf("body = %q, want original generic 500 body", got)
	}
}

func TestQueryBrokerRetryTransportPreservesBodyAfterExhaustion(t *testing.T) {
	const body = `{"error":{"message":"Rate limit reached because of too many requests to query broker. Please retry after sometime."}}`
	calls := 0
	next := testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	transport := &queryBrokerRetryTransport{
		next:       next,
		backoff:    &Backoff{Base: time.Millisecond, Max: time.Millisecond, jitter: func(d time.Duration) time.Duration { return d }},
		maxRetries: 2,
		sleep:      func(context.Context, time.Duration) error { return nil },
	}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/id/runSummary", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if calls != 3 {
		t.Errorf("physical calls = %d, want initial + 2 retries", calls)
	}
	if string(got) != body {
		t.Errorf("body after exhaustion = %q, want %q", got, body)
	}
}

func TestQueryBrokerRetryTransportSurfacesBodyReadFailure(t *testing.T) {
	readErr := errors.New("body read failed")
	next := testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       &errorReadCloser{err: readErr},
			Request:    req,
		}, nil
	})
	transport := &queryBrokerRetryTransport{next: next}

	req, err := http.NewRequest(http.MethodGet, "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/id/runSummary", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if !errors.Is(err, readErr) {
		t.Fatalf("RoundTrip error = %v, want body read error", err)
	}
	if resp != nil {
		t.Errorf("RoundTrip response = %+v, want nil when response body cannot be inspected", resp)
	}
}
