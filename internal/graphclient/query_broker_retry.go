package graphclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	nethttplibrary "github.com/microsoft/kiota-http-go"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	queryBrokerThrottleSignature = "Rate limit reached because of too many requests to query broker. Please retry after sometime."
	defaultQueryBrokerRetries    = 3
)

// queryBrokerRetryTransport handles one Intune-specific protocol violation:
// the query broker returns HTTP 500 for an explicitly retryable throttle.
// Kiota cannot be configured to retry 500, so this narrowly matched transport
// sits around the normal instrumented, rate-limited physical request path.
type queryBrokerRetryTransport struct {
	next              http.RoundTripper
	backoff           *Backoff
	maxRetries        int
	retryDelaySeconds int
	sleep             func(context.Context, time.Duration) error
	emitter           telemetry.Emitter
	tenantID          string
}

func (t *queryBrokerRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxRetries := t.maxRetries
	if maxRetries <= 0 {
		maxRetries = defaultQueryBrokerRetries
	}
	backoff := t.backoff
	if backoff == nil {
		backoff = NewBackoff()
	}
	sleep := t.sleep
	if sleep == nil {
		sleep = sleepContext
	}

	remainingRetries := maxRetries
	brokerAttempt := 0
	for {
		retryOptions := &nethttplibrary.RetryHandlerOptions{
			MaxRetries:   maxRetries,
			DelaySeconds: t.retryDelaySeconds,
			ShouldRetry: func(_ time.Duration, _ int, _ *http.Request, _ *http.Response) bool {
				if remainingRetries <= 0 {
					return false
				}
				remainingRetries--
				return true
			},
		}
		callReq := req.Clone(context.WithValue(req.Context(), retryOptions.GetKey(), retryOptions))
		callReq.Header = req.Header.Clone()

		resp, err := t.next.RoundTrip(callReq)
		if err != nil || resp == nil {
			return resp, err
		}
		throttled, inspectErr := isQueryBrokerThrottle(callReq, resp)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if !throttled {
			return resp, nil
		}

		observeThrottleResponse(t.emitter, t.tenantID, resp, ClassifyWorkload(callReq.URL.Path))
		if remainingRetries <= 0 {
			return resp, nil
		}
		remainingRetries--
		_ = resp.Body.Close()
		if err := sleep(req.Context(), backoff.Delay(brokerAttempt, 0)); err != nil {
			return nil, err
		}
		brokerAttempt++
	}
}

func isQueryBrokerThrottle(req *http.Request, resp *http.Response) (bool, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false, nil
	}
	if resp.StatusCode != http.StatusInternalServerError || resp.Body == nil {
		return false, nil
	}
	original := resp.Body
	body, err := readRawBody(req.URL.String(), original)
	_ = original.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("graphclient: inspect query-broker response: %w", err)
	}
	return strings.Contains(string(body), queryBrokerThrottleSignature), nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
