package huntclient

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names, in the graph2otel.* namespace reserved for
// graph2otel's own health signals.
//
// They are namespaced under hunt rather than reusing graphclient's metrics on
// purpose: OTEL instruments are cached by name and the FIRST registration's
// description wins, so two packages registering one name with different
// descriptions produce whichever was created first. Distinct names keep both
// descriptions honest, and this transport's latency profile — a server-side KQL
// query over device telemetry — is nothing like a REST read's.
const (
	metricHTTPClientDuration = "graph2otel.hunt.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.hunt.http_4xx"
	metricHTTPClient5xx      = "graph2otel.hunt.http_5xx"
	metricThrottleCount      = "graph2otel.hunt.throttle.count"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
	// attrQueryLabel is the code-supplied query label. It is bounded by
	// construction: the value comes from graph2otel's own collector code, never
	// from tenant data or a response, so the series count is the number of
	// distinct queries this repo issues. Every request shares one URL, so without
	// it these metrics would be unsliceable.
	attrQueryLabel = "hunt.query"
	attrTenantID   = "tenant_id"
)

// durationBuckets are wide: a KQL summarize over device telemetry runs
// server-side and routinely takes seconds, not milliseconds.
var durationBuckets = []float64{0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// labelContextKey carries the query label from Query down to the transport. The
// transport cannot recover it from the request: the URL is identical for every
// query and the label is not in the body, so a context value is the only seam
// that does not require re-reading the request body on every request.
type labelContextKey struct{}

func withLabel(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, labelContextKey{}, label)
}

func labelFromContext(ctx context.Context) string {
	label, _ := ctx.Value(labelContextKey{}).(string)
	return label
}

// instrumentedTransport measures every request and counts 4xx/5xx responses.
// Attributes are bounded: method, query label, host, status, tenant — never a
// query string or anything from a response.
type instrumentedTransport struct {
	next     http.RoundTripper
	emitter  telemetry.Emitter
	tenantID string
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.emitter == nil {
		return t.next.RoundTrip(req)
	}
	label := labelFromContext(req.Context())

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		attrHTTPMethod:    req.Method,
		attrServerAddress: req.URL.Hostname(),
		attrQueryLabel:    label,
		attrTenantID:      t.tenantID,
	}
	if resp != nil {
		attrs[attrHTTPStatusCode] = resp.StatusCode
		t.recordHTTPError(resp.StatusCode, label)
	}
	t.emitter.Histogram(metricHTTPClientDuration, "s",
		"Duration of an outbound advanced-hunting query.",
		elapsed, durationBuckets, attrs)
	return resp, err
}

// recordHTTPError counts a 4xx/5xx response. The caller has already guarded
// emitter != nil.
func (t *instrumentedTransport) recordHTTPError(statusCode int, label string) {
	var name, desc string
	switch {
	case statusCode >= 400 && statusCode < 500:
		name = metricHTTPClient4xx
		desc = "Count of 4xx responses graph2otel received from its own advanced-hunting queries."
	case statusCode >= 500 && statusCode < 600:
		name = metricHTTPClient5xx
		desc = "Count of 5xx responses graph2otel received from its own advanced-hunting queries."
	default:
		return
	}
	t.emitter.Counter(name, "1", desc, 1, telemetry.Attrs{
		attrTenantID:       t.tenantID,
		attrQueryLabel:     label,
		attrHTTPStatusCode: statusCode,
	})
}

// rateLimitTransport is the innermost transport: it gates outbound requests
// through the client-side limiter and observes any 429 that arrives anyway.
//
// Observing the 429 matters: the limiter is set under the documented request
// ceiling, but the SHARED advanced-hunting CPU budget (#106) is not something a
// request-rate limiter can protect, so graph2otel.hunt.throttle.count is how an
// operator learns the poll interval is starving the portal's budget.
type rateLimitTransport struct {
	next     http.RoundTripper
	limiter  *rate.Limiter
	tenantID string
	emitter  telemetry.Emitter
	logger   *slog.Logger
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limiter != nil {
		if err := t.limiter.Wait(req.Context()); err != nil {
			return nil, err //nolint:wrapcheck // the context error is the useful one
		}
	}

	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}
	t.observeThrottle(req)
	return resp, err
}

// observeThrottle records the bounded throttle counter.
func (t *rateLimitTransport) observeThrottle(req *http.Request) {
	label := labelFromContext(req.Context())
	if t.emitter != nil {
		t.emitter.Counter(metricThrottleCount, "1",
			"Count of 429 throttle responses observed from the advanced-hunting API.",
			1, telemetry.Attrs{attrQueryLabel: label, attrTenantID: t.tenantID})
	}
	if t.logger != nil {
		t.logger.Debug("advanced-hunting throttle response",
			"query", label, "tenant_id", t.tenantID)
	}
}

// newHTTPClient assembles the transport chain, outermost to innermost:
//
//	instrumentedTransport -> rateLimitTransport -> http.DefaultTransport
//
// There is deliberately NO retry transport. A failed tick is cheap — the
// collector polls again on its long interval — and the two failures that matter
// (a missing scope, an exhausted shared CPU budget) are not fixed by an
// immediate retry; retrying a 429 would spend more of the very budget that is
// already exhausted.
func newHTTPClient(opts Options, tenantID string, limiter *rate.Limiter, logger *slog.Logger) *http.Client {
	base := http.DefaultTransport
	base = &rateLimitTransport{
		next:     base,
		limiter:  limiter,
		tenantID: tenantID,
		emitter:  opts.Emitter,
		logger:   logger,
	}
	base = &instrumentedTransport{next: base, emitter: opts.Emitter, tenantID: tenantID}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{Transport: base, Timeout: timeout}
}
