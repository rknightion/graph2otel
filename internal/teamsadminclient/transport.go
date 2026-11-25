package teamsadminclient

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names. They are namespaced under teams_admin rather
// than reusing another client's identically-shaped metrics: OTEL instruments are
// cached by name and the first registration's description wins.
const (
	metricHTTPClientDuration = "graph2otel.teams_admin.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.teams_admin.http_4xx"
	metricHTTPClient5xx      = "graph2otel.teams_admin.http_5xx"
	metricThrottleCount      = "graph2otel.teams_admin.throttle.count"

	attrHTTPMethod     = "http.request.method"
	attrServerAddress  = "server.address"
	attrHTTPStatusCode = "http.response.status_code"
	attrTenantID       = "tenant_id"
)

var durationBuckets = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// resourceFromPath names the requested resource from a URL path alone, so no URL
// or query string ever reaches a metric. The values are bounded: configuration
// names and collection names come from graph2otel's own code.
func resourceFromPath(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) >= 2 {
		switch segs[len(segs)-2] {
		case "configurations", "Teams.VoiceApps":
			if last := segs[len(segs)-1]; last != "" {
				return last
			}
		}
	}
	return "other"
}

// instrumentedTransport measures every request and counts 4xx/5xx responses.
type instrumentedTransport struct {
	next     http.RoundTripper
	emitter  telemetry.Emitter
	tenantID string
}

func (t *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.emitter == nil {
		return t.next.RoundTrip(req)
	}
	resource := resourceFromPath(req.URL.Path)

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	attrs := telemetry.Attrs{
		attrHTTPMethod:                 req.Method,
		attrServerAddress:              req.URL.Hostname(),
		semconv.AttrTeamsAdminResource: resource,
		attrTenantID:                   t.tenantID,
	}
	if resp != nil {
		attrs[attrHTTPStatusCode] = resp.StatusCode
		t.recordHTTPError(resp.StatusCode, resource)
	}
	t.emitter.Histogram(metricHTTPClientDuration, "s",
		"Duration of an outbound Teams admin API request.",
		elapsed, durationBuckets, attrs)
	return resp, err
}

func (t *instrumentedTransport) recordHTTPError(statusCode int, resource string) {
	var name, desc string
	switch {
	case statusCode >= 400 && statusCode < 500:
		name = metricHTTPClient4xx
		desc = "Count of 4xx responses graph2otel received from its own outbound Teams admin API calls."
	case statusCode >= 500 && statusCode < 600:
		name = metricHTTPClient5xx
		desc = "Count of 5xx responses graph2otel received from its own outbound Teams admin API calls."
	default:
		return
	}
	t.emitter.Counter(name, "1", desc, 1, telemetry.Attrs{
		attrTenantID:                   t.tenantID,
		semconv.AttrTeamsAdminResource: resource,
		attrHTTPStatusCode:             statusCode,
	})
}

// rateLimitTransport gates outbound requests through the client-side limiter and
// observes any 429. The limiter's ceiling is a guess (see ratelimit.go), so
// graph2otel.teams_admin.throttle.count is the only way to learn it was too fast.
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
	resource := resourceFromPath(req.URL.Path)
	if t.emitter != nil {
		t.emitter.Counter(metricThrottleCount, "1",
			"Count of 429 throttle responses observed from the Teams admin API.",
			1, telemetry.Attrs{semconv.AttrTeamsAdminResource: resource, attrTenantID: t.tenantID})
	}
	if t.logger != nil {
		t.logger.Debug("teams admin API throttle response", "resource", resource, "tenant_id", t.tenantID)
	}
	return resp, err
}

// newHTTPClient assembles instrumentedTransport -> rateLimitTransport ->
// http.DefaultTransport. There is deliberately NO retry: the throttle behavior
// is unmeasured, so a retry policy would be invented; the next tick retries.
// Redirects are refused, so a bearer token is never replayed to another host.
func newHTTPClient(opts Options, tenantID string, limiter *rate.Limiter, logger *slog.Logger) *http.Client {
	base := http.DefaultTransport
	base = &rateLimitTransport{next: base, limiter: limiter, tenantID: tenantID, emitter: opts.Emitter, logger: logger}
	base = &instrumentedTransport{next: base, emitter: opts.Emitter, tenantID: tenantID}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{
		Transport:     base,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
