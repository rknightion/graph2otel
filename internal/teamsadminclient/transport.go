package teamsadminclient

import (
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/adminhttp"
	"github.com/rknightion/graph2otel/internal/semconv"
)

// Self-observability metric names. They are namespaced under teams_admin rather
// than reusing another client's identically-shaped metrics: OTEL instruments are
// cached by name and the first registration's description wins.
const (
	metricHTTPClientDuration = "graph2otel.teams_admin.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.teams_admin.http_4xx"
	metricHTTPClient5xx      = "graph2otel.teams_admin.http_5xx"
	metricThrottleCount      = "graph2otel.teams_admin.throttle.count"

	attrTenantID = adminhttp.AttrTenantID
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

// newHTTPClient assembles the shared transport chain (see internal/adminhttp):
// instrumentation, then the client-side limiter, then http.DefaultTransport.
// There is deliberately NO retry: the throttle behavior is unmeasured, so a
// retry policy would be invented; the next tick retries. Redirects are refused,
// so a bearer token is never replayed to another host.
func newHTTPClient(opts Options, tenantID string, limiter *rate.Limiter, logger *slog.Logger) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return adminhttp.NewClient(adminhttp.Config{
		Metrics: adminhttp.Metrics{
			Duration: metricHTTPClientDuration,
			HTTP4xx:  metricHTTPClient4xx,
			HTTP5xx:  metricHTTPClient5xx,
			Throttle: metricThrottleCount,
		},
		Descriptions: adminhttp.Descriptions{
			Duration: "Duration of an outbound Teams admin API request.",
			HTTP4xx:  "Count of 4xx responses graph2otel received from its own outbound Teams admin API calls.",
			HTTP5xx:  "Count of 5xx responses graph2otel received from its own outbound Teams admin API calls.",
			Throttle: "Count of 429 throttle responses observed from the Teams admin API.",
		},
		DurationBuckets:    durationBuckets,
		LabelAttr:          semconv.AttrTeamsAdminResource,
		Label:              func(req *http.Request) string { return resourceFromPath(req.URL.Path) },
		ThrottleLogMessage: "teams admin API throttle response",
		ThrottleLogKey:     "resource",
		RefuseRedirects:    true,
		Emitter:            opts.Emitter,
		TenantID:           tenantID,
		Limiter:            limiter,
		Logger:             logger,
		Timeout:            timeout,
	})
}
