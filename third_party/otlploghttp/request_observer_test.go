// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Modified by the graph2otel project in 2026 to test the RequestObserver
// extension. See the repository root LICENSE for the combined work.

package otlploghttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
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
		case "/v1/logs":
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
		WithEndpointURL(server.URL+"/v1/logs"),
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

	if err := exporter.Export(context.Background(), []sdklog.Record{{}}); err != nil {
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
