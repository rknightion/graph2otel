package graphclient

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Self-observability metric names for the client-side rate limiter, under the
// graph2otel.* namespace reserved for graph2otel's own health signals (never
// entra.*/intune.* domain data). Attributes are deliberately bounded to
// workload + tenant_id — never per-request path/correlation-id, which would be
// unbounded cardinality.
const (
	metricThrottleCount           = "graph2otel.throttle.count"
	metricThrottleLimitPercentage = "graph2otel.throttle.limit_percentage"
	metricThrottleEffectiveRate   = "graph2otel.throttle.effective_rate_per_minute"

	attrWorkload = "workload"
	attrTenantID = "tenant_id"
)

// Microsoft Graph throttle response headers. None of the workloads this
// package rate-limits reliably send Retry-After (see workload.go); when they
// do, it always takes precedence over our own computed backoff.
const (
	headerRetryAfter              = "Retry-After"
	headerThrottleLimitPercentage = "x-ms-throttle-limit-percentage"
	headerThrottleScope           = "x-ms-throttle-scope"
	headerThrottleInformation     = "x-ms-throttle-information"
	headerRetryAttempt            = "Retry-Attempt" // set by Kiota's retry handler on each retried attempt
)

// rateLimitTransport is the base RoundTripper that proactively gates outbound
// requests through a WorkloadLimiter and observes 429 throttle responses. It
// is deliberately NOT a second retry loop: Kiota's own retry handler (in the
// middleware pipeline above this transport) still owns retrying the request;
// this transport only (a) blocks before forwarding, so most 429s are avoided
// in the first place, and (b) on a 429 with no Retry-After, sleeps its own
// workload-aware backoff before returning the response — so Kiota's next
// retry is spaced by a delay tuned to the workload that got throttled, rather
// than Kiota's single fixed default.
type rateLimitTransport struct {
	next     http.RoundTripper
	limiter  *WorkloadLimiter
	backoff  *Backoff
	tenantID string
	emitter  telemetry.Emitter
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	wl := ClassifyWorkload(req.URL.Path)

	// The request's time is taken BEFORE it queues for a token. x/time/rate fixes
	// a queued request's slot at Wait time, under the rate of that moment, so a
	// request that waited through a decrease still ran under the old rate and
	// its response must not count against the new one.
	var issuedAt time.Time
	if t.limiter != nil {
		issuedAt = t.limiter.now()
		if err := t.limiter.Wait(req.Context(), t.tenantID, wl); err != nil {
			return nil, err
		}
		t.emitEffectiveRate(wl)
	}

	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		if t.limiter != nil && resp.StatusCode < http.StatusBadRequest {
			t.limiter.ObserveSuccess(t.tenantID, wl, issuedAt)
			// Recovery steps happen here, so publish the state they leave.
			t.emitEffectiveRate(wl)
		}
		return resp, err
	}

	observeThrottleResponse(t.emitter, t.tenantID, resp, wl)
	if t.limiter != nil {
		t.limiter.ObserveThrottle(t.tenantID, wl, issuedAt)
		t.emitEffectiveRate(wl)
	}

	if parseRetryAfter(resp.Header.Get(headerRetryAfter)) <= 0 {
		b := t.backoff
		if b == nil {
			b = NewBackoff()
		}
		delay := b.Delay(retryAttempt(req), 0)
		timer := time.NewTimer(delay)
		select {
		case <-req.Context().Done():
			timer.Stop()
		case <-timer.C:
		}
	}

	return resp, err
}

// emitEffectiveRate publishes an adaptive workload's current rate. Non-adaptive
// workloads publish nothing.
func (t *rateLimitTransport) emitEffectiveRate(wl Workload) {
	if t.emitter == nil {
		return
	}
	t.limiter.publishEffectiveRate(t.tenantID, wl, func(perMin float64) {
		t.emitter.Gauge(metricThrottleEffectiveRate, "{request}/min",
			"Current client-side request rate of an adaptive workload limiter, lowered on 429s and raised after runs of successful requests.",
			perMin, telemetry.Attrs{attrWorkload: string(wl), attrTenantID: t.tenantID})
	})
}

// observeThrottleResponse records the bounded throttle self-obs signals for
// both conventional 429s and Microsoft's query-broker throttle disguised as a
// 500. attrs are intentionally just workload + tenant_id — never per-request
// data.
func observeThrottleResponse(emitter telemetry.Emitter, tenantID string, resp *http.Response, wl Workload) {
	attrs := telemetry.Attrs{
		attrWorkload: string(wl),
		attrTenantID: tenantID,
	}

	if emitter != nil {
		emitter.Counter(metricThrottleCount, "1", "Count of throttle responses observed from Microsoft Graph.", 1, attrs)

		if pct := resp.Header.Get(headerThrottleLimitPercentage); pct != "" {
			if v, err := strconv.ParseFloat(pct, 64); err == nil {
				emitter.Gauge(metricThrottleLimitPercentage, "%",
					"Graph-reported throttle budget consumption at the time of a 429 (x-ms-throttle-limit-percentage).",
					v, attrs)
			}
		}
	}

	if scope, info := resp.Header.Get(headerThrottleScope), resp.Header.Get(headerThrottleInformation); scope != "" || info != "" {
		slog.Debug("graph throttle response",
			"workload", string(wl),
			"tenant_id", tenantID,
			"scope", scope,
			"information", info,
		)
	}
}

// retryAttempt reads Kiota's Retry-Attempt header (set on the request before
// each retried call), so our backoff calculation stays in step with which
// attempt this is. Absent or unparsable -> attempt 0 (first try).
func retryAttempt(req *http.Request) int {
	v := req.Header.Get(headerRetryAttempt)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseRetryAfter parses a Retry-After header value expressed in (fractional)
// seconds, mirroring what Microsoft Graph actually sends. Returns 0 for an
// absent or unparsable header.
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
