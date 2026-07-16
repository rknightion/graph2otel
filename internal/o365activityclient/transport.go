package o365activityclient

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
// graph2otel's own health signals (never entra.*/intune.*/m365.* domain data).
//
// They are namespaced under o365activity rather than reusing graphclient's
// identically-shaped metrics on purpose: OTEL instruments are cached by name
// and the FIRST registration's description wins, so two packages registering
// one name with different descriptions produces whichever description happened
// to be created first. Distinct names keep both descriptions honest, and the
// two transports' latencies are worth separating anyway — this API's quota and
// failure modes have nothing to do with Graph's.
const (
	metricHTTPClientDuration = "graph2otel.o365activity.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.o365activity.http_4xx"
	metricHTTPClient5xx      = "graph2otel.o365activity.http_5xx"
	metricThrottleCount      = "graph2otel.o365activity.throttle.count"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
	attrOperation      = "o365.operation"
	attrTenantID       = "tenant_id"
)

// headerRetryAfter is honored verbatim when present; the reference does not
// promise it on an AF429, so the backoff below is the real backstop.
const headerRetryAfter = "Retry-After"

// defaultHTTPClientTimeout bounds one attempt. Content blobs are aggregations
// of audit records, so this is generous rather than tight.
const defaultHTTPClientTimeout = 100 * time.Second

// defaultMaxRetries is how many times a retryable response is retried before
// the failure is returned. AF50000's own documented message is "Retry the
// request", and AF429 is transient by definition, so a small retry budget is
// the difference between a blip and a failed collection.
const defaultMaxRetries = 3

// Operation is the bounded classification of a request URL, used as a metric
// attribute.
//
// It exists to make a cardinality bug impossible rather than merely unlikely: a
// content-fetch URL ends in an opaque contentId, so using the request path as
// an attribute would mint one metric series per blob — a series that receives
// exactly one sample, ever. That is the pathological TSDB case CLAUDE.md bans.
// Every URL collapses to one of the constants below.
type Operation string

const (
	OpSubscriptionsStart         Operation = "subscriptions/start"
	OpSubscriptionsStop          Operation = "subscriptions/stop"
	OpSubscriptionsList          Operation = "subscriptions/list"
	OpSubscriptionsContent       Operation = "subscriptions/content"
	OpSubscriptionsNotifications Operation = "subscriptions/notifications"
	// OpContentFetch is a GET of a content blob. Deliberately a constant rather
	// than the path: the path embeds the contentId.
	OpContentFetch Operation = "content.fetch"
	// OpResourcesDLPSensitiveTypes is the sensitive-information-type name lookup.
	OpResourcesDLPSensitiveTypes Operation = "resources/dlpSensitiveTypes"
	// OpUnknown is anything unmatched — a bounded fallback, never the raw path.
	OpUnknown Operation = "unknown"
)

// operationRules maps a path substring to its Operation. Order matters: the
// first match wins, so more specific rules precede the general ones they nest
// under.
var operationRules = []struct {
	substr string
	op     Operation
}{
	{"/subscriptions/start", OpSubscriptionsStart},
	{"/subscriptions/stop", OpSubscriptionsStop},
	{"/subscriptions/list", OpSubscriptionsList},
	{"/subscriptions/content", OpSubscriptionsContent},
	{"/subscriptions/notifications", OpSubscriptionsNotifications},
	{"/resources/dlpSensitiveTypes", OpResourcesDLPSensitiveTypes},
	{"/activity/feed/audit/", OpContentFetch},
}

// ClassifyOperation maps a request URL path to its bounded Operation.
func ClassifyOperation(urlPath string) Operation {
	for _, r := range operationRules {
		if strings.Contains(urlPath, r.substr) {
			return r.op
		}
	}
	return OpUnknown
}

// instrumentedTransport measures every PHYSICAL attempt (it sits under the
// retry transport, so a retried request contributes one measurement per
// attempt) and counts 4xx/5xx responses. Attributes are bounded: method,
// operation class, host, status, tenant — never a URL or a contentId.
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
		"Duration of an outbound Office 365 Management Activity API HTTP request.",
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
		desc = "Count of 4xx responses graph2otel received from its own outbound Office 365 Management Activity API calls."
	case statusCode >= 500 && statusCode < 600:
		name = metricHTTPClient5xx
		desc = "Count of 5xx responses graph2otel received from its own outbound Office 365 Management Activity API calls."
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
// through the per-tenant Limiter so the documented 2,000/min quota is respected
// proactively, and observes the 429s that slip through anyway.
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

// observeThrottle records the bounded throttle counter. Attributes are
// operation + tenant — never per-request data.
func (t *rateLimitTransport) observeThrottle(req *http.Request) {
	op := ClassifyOperation(req.URL.Path)
	if t.emitter != nil {
		t.emitter.Counter(metricThrottleCount, "1",
			"Count of 429 throttle responses observed from the Office 365 Management Activity API.",
			1, telemetry.Attrs{attrOperation: string(op), attrTenantID: t.tenantID})
	}
	slog.Debug("o365 management activity API throttle response",
		"operation", string(op), "tenant_id", t.tenantID)
}

// retryTransport retries a retryable response (429, or any 5xx) with
// exponential backoff.
//
// It is a small hand-rolled loop rather than Kiota's default middleware chain —
// which graphclient re-attaches — on purpose. That chain includes
// ParametersNameDecodingHandler, which rewrites percent-encoded characters in
// URLs; content blob URLs are full of literal '$' separators, so running them
// through Graph's URL-rewriting middleware is a risk taken for no benefit. This
// is not a Graph endpoint and does not want Graph's pipeline.
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
		// The body is never read on a retried attempt, so it must be drained and
		// closed or the connection leaks. Close's error is irrelevant here: the
		// response is already being discarded in favor of another attempt.
		_ = resp.Body.Close()

		if !sleepCtx(req, delay) {
			// The context died mid-backoff; re-issuing would only fail again.
			return t.next.RoundTrip(req)
		}
		if err := rewindBody(req); err != nil {
			return nil, err
		}
	}
}

// isRetryable reports whether a status is worth another attempt. 429 is the
// quota wall (transient) and 5xx includes AF50000, whose own documented message
// is "Retry the request". A 4xx is NOT retried: AF20022 (no subscription) and
// AF10001 (missing permission) cannot resolve themselves, so retrying only
// burns the tenant's quota against a certain failure.
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
// GetBody for the in-memory body types this package sends, so a POST retries
// correctly rather than sending an empty payload.
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
// Returns 0 for an absent or unparsable header, which lets the caller's own
// backoff take over.
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

// newHTTPClient assembles the transport chain. Outermost to innermost:
//
//	retryTransport -> instrumentedTransport -> rateLimitTransport -> base
//
// The ordering is load-bearing. instrumentedTransport sits UNDER the retry loop
// so every physical attempt is measured (a request retried three times records
// three durations, which is what makes a retry storm visible). rateLimitTransport
// sits under both so a retried attempt also waits for a token rather than
// jumping the queue.
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
