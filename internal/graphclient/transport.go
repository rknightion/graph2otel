package graphclient

import (
	"net/http"
	"time"

	nethttplibrary "github.com/microsoft/kiota-http-go"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Metric + attribute names for the outbound-HTTP instrumentation. Kept local to
// this package (rather than in internal/semconv) because they describe the Graph
// transport specifically. Attributes are deliberately bounded — method, target
// host, and status code — never the full request path/URL, which would be
// per-request high cardinality.
const (
	metricHTTPClientDuration = "graph2otel.http.client.request.duration"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
)

// defaultHTTPClientTimeout mirrors the Kiota default client's overall timeout.
// The redirect + retry handlers live in the middleware pipeline, so net/http's
// own redirect following is disabled (ErrUseLastResponse) to let the Kiota
// RedirectHandler own that behavior.
const defaultHTTPClientTimeout = 100 * time.Second

// instrumentedTransport is the base RoundTripper that sits UNDERNEATH the Kiota
// middleware pipeline: every attempt the retry handler makes passes through it,
// so each physical request (including retries) is measured. It records a
// duration histogram per request through the Emitter, or is a pass-through when
// the Emitter is nil.
type instrumentedTransport struct {
	next    http.RoundTripper
	emitter telemetry.Emitter
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.emitter == nil {
		return t.next.RoundTrip(req)
	}
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		attrHTTPMethod:    req.Method,
		attrServerAddress: req.URL.Hostname(),
	}
	if resp != nil {
		attrs[attrHTTPStatusCode] = resp.StatusCode
	}
	// Default histogram bounds (seconds) sized for Graph call latencies.
	t.emitter.Histogram(metricHTTPClientDuration, "s", "Duration of an outbound Microsoft Graph HTTP request.",
		elapsed, []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}, attrs)
	return resp, err
}

// buildMiddlewares returns Kiota's DEFAULT middleware chain (retry, redirect,
// compression, parameters-name-decoding, user-agent, headers-inspection),
// optionally overriding the retry handler's backoff/attempts. Re-attaching the
// default chain is the whole point of the factory: the SDK installs it only when
// passed a nil http.Client, so a custom transport MUST re-attach it or the 429
// retry handler is silently lost.
func buildMiddlewares(opts Options) []nethttplibrary.Middleware {
	if opts.RetryDelaySeconds <= 0 && opts.MaxRetries <= 0 {
		return nethttplibrary.GetDefaultMiddlewares()
	}
	retry := nethttplibrary.RetryHandlerOptions{
		// NewRetryHandlerWithOptions does NOT default ShouldRetry (unlike
		// NewRetryHandler), and the handler calls it unconditionally — a nil
		// ShouldRetry panics. Mirror the SDK default: retry every response the
		// other guards (retriable status, attempt cap, delay cap) already admit.
		ShouldRetry: func(_ time.Duration, _ int, _ *http.Request, _ *http.Response) bool { return true },
	}
	if opts.RetryDelaySeconds > 0 {
		retry.DelaySeconds = opts.RetryDelaySeconds
	}
	if opts.MaxRetries > 0 {
		retry.MaxRetries = opts.MaxRetries
	}
	// Only the retry handler is customized; getDefaultMiddleWare fills in every
	// other default handler, so the full default chain is still present.
	mws, err := nethttplibrary.GetDefaultMiddlewaresWithOptions(&retry)
	if err != nil {
		// The only error path is an unsupported option type, which cannot happen
		// with a single *RetryHandlerOptions; fall back defensively.
		return nethttplibrary.GetDefaultMiddlewares()
	}
	return mws
}

// newGraphHTTPClient builds the *http.Client the Graph request adapter uses: our
// instrumented base transport, wrapped by Kiota's default middleware pipeline
// (retry/redirect/compression/...). This is the unit the 429-retry regression
// test exercises directly.
func newGraphHTTPClient(opts Options) *http.Client {
	base := opts.baseTransport
	if base == nil {
		base = http.DefaultTransport
	}
	instrumented := &instrumentedTransport{next: base, emitter: opts.Emitter}
	transport := nethttplibrary.NewCustomTransportWithParentTransport(instrumented, buildMiddlewares(opts)...)
	return &http.Client{
		Transport: transport,
		// Let the Kiota RedirectHandler middleware own redirect behavior rather
		// than net/http's default follower (mirrors the SDK's default client).
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: defaultHTTPClientTimeout,
	}
}
