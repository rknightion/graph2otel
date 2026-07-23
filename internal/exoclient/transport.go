package exoclient

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names, in the graph2otel.* namespace reserved for
// graph2otel's own health signals (never entra.*/intune.*/m365.* domain data).
//
// They are namespaced under exo rather than reusing graphclient's
// identically-shaped metrics on purpose: OTEL instruments are cached by name and
// the FIRST registration's description wins, so two packages registering one
// name with different descriptions produce whichever description happened to be
// created first. Distinct names keep both descriptions honest, and this
// transport's latency profile — a synchronous PowerShell cmdlet execution, not a
// REST read — has nothing to do with Graph's anyway.
const (
	metricHTTPClientDuration = "graph2otel.exo.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.exo.http_4xx"
	metricHTTPClient5xx      = "graph2otel.exo.http_5xx"
	metricThrottleCount      = "graph2otel.exo.throttle.count"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
	// attrCmdlet is the invoked cmdlet name. It is bounded by construction: the
	// value comes from graph2otel's own collector code, never from tenant data or
	// a response body, so the series count is the number of cmdlets this repo
	// invokes. Every request shares one URL path, so without it these metrics
	// would be unsliceable.
	attrCmdlet   = "exo.cmdlet"
	attrTenantID = "tenant_id"
)

// durationBuckets are wider than a REST client's. A cmdlet invocation runs a
// PowerShell command server-side; a quarantine page is routinely seconds, not
// milliseconds.
var durationBuckets = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// cmdletContextKey carries the cmdlet name from Invoke down to the transport.
//
// The transport cannot recover it from the request itself: the URL is identical
// for every invocation and the name lives in the POST body, which a RoundTripper
// must not consume. A context value is the only seam that does not require
// re-reading (and rewinding) the body on every request.
type cmdletContextKey struct{}

func withCmdlet(ctx context.Context, cmdlet string) context.Context {
	return context.WithValue(ctx, cmdletContextKey{}, cmdlet)
}

func cmdletFromContext(ctx context.Context) string {
	cmdlet, _ := ctx.Value(cmdletContextKey{}).(string)
	return cmdlet
}

// instrumentedTransport measures every request and counts 4xx/5xx responses.
// Attributes are bounded: method, cmdlet, host, status, tenant — never a URL, a
// parameter value, or anything from a response.
type instrumentedTransport struct {
	next     http.RoundTripper
	emitter  telemetry.Emitter
	tenantID string
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.emitter == nil {
		return t.next.RoundTrip(req)
	}
	cmdlet := cmdletFromContext(req.Context())

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		attrHTTPMethod:    req.Method,
		attrServerAddress: req.URL.Hostname(),
		attrCmdlet:        cmdlet,
		attrTenantID:      t.tenantID,
	}
	if resp != nil {
		attrs[attrHTTPStatusCode] = resp.StatusCode
		t.recordHTTPError(resp.StatusCode, cmdlet)
	}
	t.emitter.Histogram(metricHTTPClientDuration, "s",
		"Duration of an outbound Exchange Online admin API cmdlet invocation.",
		elapsed, durationBuckets, attrs)
	return resp, err
}

// recordHTTPError counts a 4xx/5xx response. The caller has already guarded
// emitter != nil.
func (t *instrumentedTransport) recordHTTPError(statusCode int, cmdlet string) {
	var name, desc string
	switch {
	case statusCode >= 400 && statusCode < 500:
		name = metricHTTPClient4xx
		desc = "Count of 4xx responses graph2otel received from its own outbound Exchange Online admin API calls."
	case statusCode >= 500 && statusCode < 600:
		name = metricHTTPClient5xx
		desc = "Count of 5xx responses graph2otel received from its own outbound Exchange Online admin API calls."
	default:
		return
	}
	t.emitter.Counter(name, "1", desc, 1, telemetry.Attrs{
		attrTenantID:       t.tenantID,
		attrCmdlet:         cmdlet,
		attrHTTPStatusCode: statusCode,
	})
}

// rateLimitTransport is the innermost transport: it gates outbound requests
// through the client-side limiter and observes any 429 that arrives anyway.
//
// Observing the 429 is not decoration. The ceiling this limiter guesses at is
// unmeasured (see ratelimit.go), so graph2otel.exo.throttle.count is the ONLY
// way an operator would ever learn the guess was too fast.
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
	cmdlet := cmdletFromContext(req.Context())
	if t.emitter != nil {
		t.emitter.Counter(metricThrottleCount, "1",
			"Count of 429 throttle responses observed from the Exchange Online admin API.",
			1, telemetry.Attrs{attrCmdlet: cmdlet, attrTenantID: t.tenantID})
	}
	if t.logger != nil {
		t.logger.Debug("exchange online admin API throttle response",
			"cmdlet", cmdlet, "tenant_id", t.tenantID)
	}
}

// newHTTPClient assembles the transport chain. Outermost to innermost:
//
//	instrumentedTransport -> rateLimitTransport -> http.DefaultTransport
//
// There is deliberately NO retry transport, unlike the sibling clients. Their
// backoff is calibrated against a documented quota and a documented retryable
// error code; neither exists here (see ratelimit.go), so a retry loop would be
// inventing a policy for a service whose behavior under load has not been
// measured. A failed tick is cheap — the collector polls again — and a wrong
// retry policy against an unknown ceiling is not.
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
