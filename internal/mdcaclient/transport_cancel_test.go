package mdcaclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/graphclient"
)

func TestRetryTransportStopsAfterCanceledBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstRequest := make(chan struct{})
	var attempts int
	body := &closeTrackingBody{Reader: strings.NewReader("retryable")}
	transport := &retryTransport{
		next: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				close(firstRequest)
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header:     http.Header{headerRetryAfter: []string{"60"}},
					Body:       body,
					Request:    req,
				}, nil
			}
			return nil, req.Context().Err()
		}),
		backoff:    graphclient.NewBackoff(),
		maxRetries: 1,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/governance", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(req)
		result <- err
	}()
	<-firstRequest
	cancel()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("RoundTrip error = %v, want context.Canceled", err)
	}
	if attempts != 1 {
		t.Errorf("underlying requests = %d, want 1", attempts)
	}
	if !body.readEOF {
		t.Error("discarded retryable response body was not read to EOF")
	}
	if !body.closed {
		t.Error("discarded retryable response body was not closed")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type closeTrackingBody struct {
	io.Reader
	closed  bool
	readEOF bool
}

func (b *closeTrackingBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		b.readEOF = true
	}
	return n, err
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}
