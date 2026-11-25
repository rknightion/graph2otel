// Package adminhttp is the one instrumented, rate-limited HTTP transport shared
// by the admin API clients (exoclient, huntclient, teamsadminclient).
//
// Each client keeps its own metric names, descriptions, buckets and bounded
// label attribute: OTEL instruments are cached by name and the first
// registration's description wins, so the names stay distinct per client and
// this package only owns the mechanics. There is deliberately NO retry
// transport: none of these services has a measured ceiling or a documented
// retryable error, so a retry loop would invent a policy.
package adminhttp

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Attribute names every admin client stamps on its transport metrics.
const (
	AttrHTTPMethod     = "http.request.method"
	AttrServerAddress  = "server.address"
	AttrHTTPStatusCode = "http.response.status_code"
	AttrTenantID       = "tenant_id"
)

// Metrics names the four self-observability instruments.
type Metrics struct {
	Duration string
	HTTP4xx  string
	HTTP5xx  string
	Throttle string
}

// Descriptions are the instrument descriptions, one per instrument.
type Descriptions struct {
	Duration string
	HTTP4xx  string
	HTTP5xx  string
	Throttle string
}

// Config describes one client's transport chain.
type Config struct {
	Metrics      Metrics
	Descriptions Descriptions
	// DurationBuckets are the histogram bucket bounds in seconds.
	DurationBuckets []float64
	// LabelAttr is the bounded attribute that slices the metrics (for example
	// "exo.cmdlet"). Label returns its value for a request; it must come from
	// graph2otel's own code, never tenant data or a response.
	LabelAttr string
	Label     func(*http.Request) string
	// ThrottleLogMessage and ThrottleLogKey shape the debug line written when a
	// 429 arrives; the value logged is Label's.
	ThrottleLogMessage string
	ThrottleLogKey     string
	// RefuseRedirects makes the client return the redirect response instead of
	// following it, so a bearer token is never replayed to another host.
	RefuseRedirects bool

	Emitter  telemetry.Emitter
	TenantID string
	Limiter  *rate.Limiter
	Logger   *slog.Logger
	// Timeout is used as given; callers apply their own default.
	Timeout time.Duration
}

type labelContextKey struct{}

// WithLabel carries a label from a client method down to the transport. The URL
// is shared by every call and the distinguishing value lives in the body, which
// a RoundTripper must not consume, so a context value is the only seam.
func WithLabel(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, labelContextKey{}, label)
}

// LabelFromRequest returns the label set by WithLabel, or "".
func LabelFromRequest(req *http.Request) string {
	label, _ := req.Context().Value(labelContextKey{}).(string)
	return label
}

// NewClient assembles instrumentedTransport -> rateLimitTransport ->
// http.DefaultTransport.
func NewClient(cfg Config) *http.Client {
	var base http.RoundTripper = http.DefaultTransport
	base = &rateLimitTransport{next: base, cfg: cfg}
	base = &instrumentedTransport{next: base, cfg: cfg}

	client := &http.Client{Transport: base, Timeout: cfg.Timeout}
	if cfg.RefuseRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return client
}

// instrumentedTransport measures every request and counts 4xx/5xx responses.
// Attributes are bounded: method, label, host, status, tenant.
type instrumentedTransport struct {
	next http.RoundTripper
	cfg  Config
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cfg.Emitter == nil {
		return t.next.RoundTrip(req)
	}
	label := t.cfg.Label(req)

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		AttrHTTPMethod:    req.Method,
		AttrServerAddress: req.URL.Hostname(),
		t.cfg.LabelAttr:   label,
		AttrTenantID:      t.cfg.TenantID,
	}
	if resp != nil {
		attrs[AttrHTTPStatusCode] = resp.StatusCode
		t.recordHTTPError(resp.StatusCode, label)
	}
	t.cfg.Emitter.Histogram(t.cfg.Metrics.Duration, "s", t.cfg.Descriptions.Duration,
		elapsed, t.cfg.DurationBuckets, attrs)
	return resp, err
}

func (t *instrumentedTransport) recordHTTPError(statusCode int, label string) {
	var name, desc string
	switch {
	case statusCode >= 400 && statusCode < 500:
		name, desc = t.cfg.Metrics.HTTP4xx, t.cfg.Descriptions.HTTP4xx
	case statusCode >= 500 && statusCode < 600:
		name, desc = t.cfg.Metrics.HTTP5xx, t.cfg.Descriptions.HTTP5xx
	default:
		return
	}
	t.cfg.Emitter.Counter(name, "1", desc, 1, telemetry.Attrs{
		AttrTenantID:       t.cfg.TenantID,
		t.cfg.LabelAttr:    label,
		AttrHTTPStatusCode: statusCode,
	})
}

// rateLimitTransport is the innermost transport: it gates requests through the
// client-side limiter and observes any 429 that arrives anyway, since the
// limiter's ceiling is at best a guess and the throttle counter is the only way
// an operator learns it was too fast.
type rateLimitTransport struct {
	next http.RoundTripper
	cfg  Config
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cfg.Limiter != nil {
		if err := t.cfg.Limiter.Wait(req.Context()); err != nil {
			return nil, err //nolint:wrapcheck // the context error is the useful one
		}
	}

	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}
	label := t.cfg.Label(req)
	if t.cfg.Emitter != nil {
		t.cfg.Emitter.Counter(t.cfg.Metrics.Throttle, "1", t.cfg.Descriptions.Throttle,
			1, telemetry.Attrs{t.cfg.LabelAttr: label, AttrTenantID: t.cfg.TenantID})
	}
	if t.cfg.Logger != nil {
		t.cfg.Logger.Debug(t.cfg.ThrottleLogMessage, t.cfg.ThrottleLogKey, label, "tenant_id", t.cfg.TenantID)
	}
	return resp, err
}
