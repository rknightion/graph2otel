// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Modified by the graph2otel project in 2026 to test the RequestObserver
// extension. See the repository root LICENSE for the combined work.

package otlpmetrichttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type recordingRequestObserver struct {
	attempts atomic.Uint64
	bytes    atomic.Uint64
}

func (o *recordingRequestObserver) Attempt(context.Context) {
	o.attempts.Add(1)
}

func (o *recordingRequestObserver) PayloadBytes(_ context.Context, n int) {
	if n > 0 {
		o.bytes.Add(uint64(n))
	}
}

// A 307 replay uses Request.GetBody, then a retry rebuilds the request with a
// derived context. Both bodies must be observed once without nested wrappers,
// while only the retry-loop invocations count as attempts.
func TestRequestObserverCountsRedirectBodiesAndExporterAttempts(t *testing.T) {
	var (
		mu        sync.Mutex
		bodyBytes uint64
		redirects uint64
		destCalls uint64
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
			return
		}
		mu.Lock()
		bodyBytes += uint64(len(body))
		mu.Unlock()

		switch r.URL.Path {
		case "/v1/metrics":
			atomic.AddUint64(&redirects, 1)
			http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
		case "/redirected":
			call := atomic.AddUint64(&destCalls, 1)
			if call == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	observer := &recordingRequestObserver{}
	exporter, err := New(
		context.Background(),
		WithEndpointURL(server.URL+"/v1/metrics"),
		WithCompression(GzipCompression),
		WithRetry(RetryConfig{
			Enabled:         true,
			InitialInterval: time.Millisecond,
			MaxInterval:     time.Millisecond,
			MaxElapsedTime:  time.Second,
		}),
		WithRequestObserver(observer),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	if err := exporter.Export(context.Background(), &metricdata.ResourceMetrics{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := observer.attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&redirects); got != 2 {
		t.Fatalf("origin requests = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&destCalls); got != 2 {
		t.Fatalf("redirect requests = %d, want 2", got)
	}
	mu.Lock()
	wantBytes := bodyBytes
	mu.Unlock()
	if got := observer.bytes.Load(); got != wantBytes || got == 0 {
		t.Fatalf("payload bytes = %d, want server-observed %d", got, wantBytes)
	}
}

// Counting reads rather than an intended buffer length is load-bearing:
// canceled or failed transports can consume only part of a payload.
func TestRequestObserverCountsOnlyBytesReadByTransport(t *testing.T) {
	observer := &recordingRequestObserver{}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		buf := make([]byte, 3)
		if _, err := io.ReadFull(req.Body, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})
	exporter, err := New(
		context.Background(),
		WithEndpointURL("http://collector.invalid/v1/metrics"),
		WithHTTPClient(&http.Client{Transport: transport}),
		WithRetry(RetryConfig{Enabled: false}),
		WithRequestObserver(observer),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	_ = exporter.Export(context.Background(), &metricdata.ResourceMetrics{})
	if got := observer.attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
	if got := observer.bytes.Load(); got != 3 {
		t.Fatalf("payload bytes = %d, want 3", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
