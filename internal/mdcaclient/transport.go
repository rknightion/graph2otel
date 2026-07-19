package mdcaclient

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names, in the graph2otel.* namespace reserved for
// graph2otel's own health signals (never entra.*/intune.*/m365.*/mdca.* domain
// data — mdca.* is the DOMAIN namespace for the discovery-parse signal itself).
//
// They are namespaced under mdca rather than reusing o365activity's or
// graphclient's identically-shaped metrics on purpose: OTEL instruments are
// cached by name and the FIRST registration's description wins, so two packages
// registering one name with different descriptions produce whichever was created
// first. Distinct names keep every description honest.
const (
	metricHTTPClientDuration = "graph2otel.mdca.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.mdca.http_4xx"
	metricHTTPClient5xx      = "graph2otel.mdca.http_5xx"
	metricThrottleCount      = "graph2otel.mdca.throttle.count"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
	attrOperation      = "mdca.operation"
	attrTenantID       = "tenant_id"
)

// headerRetryAfter is honored verbatim when present; the MDCA API does not
// promise it, so the backoff is the real backstop.
const headerRetryAfter = "Retry-After"

// defaultHTTPClientTimeout bounds one attempt. A governance page is small (<=100
// records), so this is generous rather than tight.
const defaultHTTPClientTimeout = 60 * time.Second

// defaultMaxRetries is how many times a retryable response is retried before the
// failure is returned.
const defaultMaxRetries = 3

// Operation is the bounded classification of a request URL, used as a metric
// attribute so a per-request URL never becomes a metric series.
type Operation string

const (
	// OpGovernance is a governance-log query. It is the only operation this
	// package makes today.
	OpGovernance Operation = "governance"
	// OpUnknown is anything unmatched — a bounded fallback, never the raw path.
	OpUnknown Operation = "unknown"
)

// ClassifyOperation maps a request URL path to its bounded Operation.
func ClassifyOperation(urlPath string) Operation {
	if strings.Contains(urlPath, "/api/v1/governance") {
		return OpGovernance
	}
	return OpUnknown
}

// instrumentedTransport measures every PHYSICAL attempt (it sits under the retry
// transport) and counts 4xx/5xx responses. Attributes are bounded: method,
// operation class, host, status, tenant — never a URL.
type instrumentedTransport struct {
	next     http.RoundTripper
	emitter  telemetry.Emitter
	tenantID string
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.emitter == nil {
		return t.next.RoundTrip(req)
	}
	op := ClassifyOperation(req.URL.Path)

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		attrHTTPMethod:    req.Method,
		attrServerAddress: req.URL.Hostname(),
		attrOperation:     string(op),
		attrTenantID:      t.tenantID,
	}
	if resp != nil {
		attrs[attrHTTPStatusCode] = resp.StatusCode
		t.recordHTTPError(resp.StatusCode, op)
	}
	t.emitter.Histogram(metricHTTPClientDuration, "s",
		"Duration of an outbound Microsoft Defender for Cloud Apps API HTTP request.",
		elapsed, []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}, attrs)
	return resp, err
}

// recordHTTPError counts a 4xx/5xx response. The caller has already guarded
// emitter != nil.
func (t *instrumentedTransport) recordHTTPError(statusCode int, op Operation) {
	var name, desc string
	switch {
	case statusCode >= 400 && statusCode < 500:
		name = metricHTTPClient4xx
		desc = "Count of 4xx responses graph2otel received from its own outbound Microsoft Defender for Cloud Apps API calls."
	case statusCode >= 500 && statusCode < 600:
		name = metricHTTPClient5xx
		desc = "Count of 5xx responses graph2otel received from its own outbound Microsoft Defender for Cloud Apps API calls."
	default:
		return
	}
	t.emitter.Counter(name, "1", desc, 1, telemetry.Attrs{
		attrTenantID:       t.tenantID,
		attrOperation:      string(op),
		attrHTTPStatusCode: statusCode,
	})
}

// rateLimitTransport is the innermost transport: it gates outbound requests
// through the per-tenant Limiter so the 30/min quota is respected proactively,
// and observes the 429s that slip through anyway.
type rateLimitTransport struct {
	next     http.RoundTripper
	limiter  *Limiter
	tenantID string
	emitter  telemetry.Emitter
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context(), t.tenantID); err != nil {
		return nil, err
	}

	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}
	t.observeThrottle(req)
	return resp, err
}

// observeThrottle records the bounded throttle counter. Attributes are operation
// + tenant — never per-request data.
func (t *rateLimitTransport) observeThrottle(req *http.Request) {
	op := ClassifyOperation(req.URL.Path)
	if t.emitter != nil {
		t.emitter.Counter(metricThrottleCount, "1",
			"Count of 429 throttle responses observed from the Microsoft Defender for Cloud Apps API.",
			1, telemetry.Attrs{attrOperation: string(op), attrTenantID: t.tenantID})
	}
	slog.Debug("mdca API throttle response", "operation", string(op), "tenant_id", t.tenantID)
}

// retryTransport retries a retryable response (429, or any 5xx) with exponential
// backoff. It is a small hand-rolled loop rather than Kiota's middleware — this
// is not a Graph endpoint and wants none of Graph's URL-rewriting pipeline.
type retryTransport struct {
	next       http.RoundTripper
	backoff    *graphclient.Backoff
	maxRetries int
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxRetries := t.maxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}

	var resp *http.Response
	var err error
	for attempt := 0; ; attempt++ {
		resp, err = t.next.RoundTrip(req)
		if err != nil || !isRetryable(resp.StatusCode) || attempt >= maxRetries {
			return resp, err
		}

		delay := t.backoff.Delay(attempt, parseRetryAfter(resp.Header.Get(headerRetryAfter)))
		// Drain and close the discarded response's body or the connection leaks.
		_ = resp.Body.Close()

		if !sleepCtx(req, delay) {
			return t.next.RoundTrip(req)
		}
		if err := rewindBody(req); err != nil {
			return nil, err
		}
	}
}

// isRetryable reports whether a status is worth another attempt. 429 is the
// quota wall and 5xx is transient; a 4xx (401/403 token problem, 400 bad query)
// cannot resolve itself, so retrying only burns the tight 30/min budget.
func isRetryable(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || (statusCode >= 500 && statusCode < 600)
}

// sleepCtx waits for d, returning false if the request's context ended first.
func sleepCtx(req *http.Request, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		return false
	case <-timer.C:
		return true
	}
}

// rewindBody restores a request body for the next attempt. net/http populates
// GetBody for the in-memory body this package sends, so a POST retries with its
// payload rather than empty.
func rewindBody(req *http.Request) error {
	if req.Body == nil || req.GetBody == nil {
		return nil
	}
	body, err := req.GetBody()
	if err != nil {
		return err //nolint:wrapcheck // GetBody's error is already specific
	}
	req.Body = body
	return nil
}

// parseRetryAfter parses a Retry-After expressed in (fractional) seconds.
// Returns 0 for an absent or unparsable header, letting the caller's backoff
// take over.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(v, 64)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// newHTTPClient assembles the transport chain, outermost to innermost:
//
//	retryTransport -> instrumentedTransport -> rateLimitTransport -> base
//
// instrumentedTransport sits UNDER the retry loop so every physical attempt is
// measured; rateLimitTransport sits under both so a retried attempt also waits
// for a token.
func newHTTPClient(opts Options, tenantID string) *http.Client {
	base := opts.baseTransport
	if base == nil {
		base = http.DefaultTransport
	}

	base = &rateLimitTransport{
		next:     base,
		limiter:  opts.Limiter,
		tenantID: tenantID,
		emitter:  opts.Emitter,
	}
	base = &instrumentedTransport{next: base, emitter: opts.Emitter, tenantID: tenantID}

	backoff := graphclient.NewBackoff()
	if opts.retryBase > 0 {
		backoff.Base = opts.retryBase
		if backoff.Max < opts.retryBase {
			backoff.Max = opts.retryBase
		}
	}
	base = &retryTransport{next: base, backoff: backoff, maxRetries: opts.MaxRetries}

	return &http.Client{
		Transport: base,
		Timeout:   defaultHTTPClientTimeout,
	}
}
