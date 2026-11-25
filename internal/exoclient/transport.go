package exoclient

import (
	"log/slog"
	"net/http"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/adminhttp"
)

// Self-observability metric names, in the graph2otel.* namespace reserved for
// graph2otel's own health signals (never entra.*/intune.*/m365.* domain data).
//
// They are namespaced under exo rather than reusing graphclient's
// identically-shaped metrics on purpose: OTEL instruments are cached by name and
// the FIRST registration's description wins, so two packages registering one
// name with different descriptions produce whichever description happened to be
// created first. Distinct names keep both descriptions honest, and this
// transport's latency profile - a synchronous PowerShell cmdlet execution, not a
// REST read - has nothing to do with Graph's anyway.
const (
	metricHTTPClientDuration = "graph2otel.exo.http.client.request.duration"
	metricHTTPClient4xx      = "graph2otel.exo.http_4xx"
	metricHTTPClient5xx      = "graph2otel.exo.http_5xx"
	metricThrottleCount      = "graph2otel.exo.throttle.count"

	attrHTTPMethod     = adminhttp.AttrHTTPMethod
	attrServerAddress  = adminhttp.AttrServerAddress
	attrHTTPStatusCode = adminhttp.AttrHTTPStatusCode
	// attrCmdlet is the invoked cmdlet name. It is bounded by construction: the
	// value comes from graph2otel's own collector code, never from tenant data or
	// a response body, so the series count is the number of cmdlets this repo
	// invokes. Every request shares one URL path, so without it these metrics
	// would be unsliceable.
	attrCmdlet   = "exo.cmdlet"
	attrTenantID = adminhttp.AttrTenantID
)

// durationBuckets are wider than a REST client's. A cmdlet invocation runs a
// PowerShell command server-side; a quarantine page is routinely seconds, not
// milliseconds.
var durationBuckets = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// newHTTPClient assembles the shared transport chain (see internal/adminhttp):
// instrumentation, then the client-side limiter, then http.DefaultTransport.
//
// There is deliberately NO retry transport, unlike the sibling clients. Their
// backoff is calibrated against a documented quota and a documented retryable
// error code; neither exists here (see ratelimit.go), so a retry loop would be
// inventing a policy for a service whose behavior under load has not been
// measured. A failed tick is cheap - the collector polls again - and a wrong
// retry policy against an unknown ceiling is not.
//
// The cmdlet name reaches the transport through the request context: the URL is
// identical for every invocation and the name lives in the POST body, which a
// RoundTripper must not consume.
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
			Duration: "Duration of an outbound Exchange Online admin API cmdlet invocation.",
			HTTP4xx:  "Count of 4xx responses graph2otel received from its own outbound Exchange Online admin API calls.",
			HTTP5xx:  "Count of 5xx responses graph2otel received from its own outbound Exchange Online admin API calls.",
			Throttle: "Count of 429 throttle responses observed from the Exchange Online admin API.",
		},
		DurationBuckets:    durationBuckets,
		LabelAttr:          attrCmdlet,
		Label:              adminhttp.LabelFromRequest,
		ThrottleLogMessage: "exchange online admin API throttle response",
		ThrottleLogKey:     "cmdlet",
		Emitter:            opts.Emitter,
		TenantID:           tenantID,
		Limiter:            limiter,
		Logger:             logger,
		Timeout:            timeout,
	})
}
