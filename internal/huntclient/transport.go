package huntclient

import (
	"log/slog"
	"net/http"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/adminhttp"
)

// Self-observability metric names, in the graph2otel.* namespace reserved for
// graph2otel's own health signals.
//
// They are namespaced under hunt rather than reusing graphclient's metrics on
// purpose: OTEL instruments are cached by name and the FIRST registration's
// description wins, so two packages registering one name with different
// descriptions produce whichever was created first. Distinct names keep both
// descriptions honest, and this transport's latency profile - a server-side KQL
// query over device telemetry - is nothing like a REST read's.
const (
	metricHTTPClientDuration = "graph2otel.hunt.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.hunt.http_4xx"
	metricHTTPClient5xx      = "graph2otel.hunt.http_5xx"
	metricThrottleCount      = "graph2otel.hunt.throttle.count"

	attrHTTPMethod     = adminhttp.AttrHTTPMethod
	attrServerAddress  = adminhttp.AttrServerAddress
	attrHTTPStatusCode = adminhttp.AttrHTTPStatusCode
	// attrQueryLabel is the code-supplied query label. It is bounded by
	// construction: the value comes from graph2otel's own collector code, never
	// from tenant data or a response, so the series count is the number of
	// distinct queries this repo issues. Every request shares one URL, so without
	// it these metrics would be unsliceable.
	attrQueryLabel = "hunt.query"
	attrTenantID   = adminhttp.AttrTenantID
)

// durationBuckets are wide: a KQL summarize over device telemetry runs
// server-side and routinely takes seconds, not milliseconds.
var durationBuckets = []float64{0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// newHTTPClient assembles the shared transport chain (see internal/adminhttp):
// instrumentation, then the client-side limiter, then http.DefaultTransport.
//
// There is deliberately NO retry transport. A failed tick is cheap - the
// collector polls again on its long interval - and the two failures that matter
// (a missing scope, an exhausted shared CPU budget) are not fixed by an
// immediate retry; retrying a 429 would spend more of the very budget that is
// already exhausted.
//
// The query label reaches the transport through the request context: the URL is
// identical for every query and the label is not in the body.
//
// Observing the 429 matters: the limiter is set under the documented request
// ceiling, but the SHARED advanced-hunting CPU budget (#106) is not something a
// request-rate limiter can protect, so graph2otel.hunt.throttle.count is how an
// operator learns the poll interval is starving the portal's budget.
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
			Duration: "Duration of an outbound advanced-hunting query.",
			HTTP4xx:  "Count of 4xx responses graph2otel received from its own advanced-hunting queries.",
			HTTP5xx:  "Count of 5xx responses graph2otel received from its own advanced-hunting queries.",
			Throttle: "Count of 429 throttle responses observed from the advanced-hunting API.",
		},
		DurationBuckets:    durationBuckets,
		LabelAttr:          attrQueryLabel,
		Label:              adminhttp.LabelFromRequest,
		ThrottleLogMessage: "advanced-hunting throttle response",
		ThrottleLogKey:     "query",
		Emitter:            opts.Emitter,
		TenantID:           tenantID,
		Limiter:            limiter,
		Logger:             logger,
		Timeout:            timeout,
	})
}
