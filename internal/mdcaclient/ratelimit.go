package mdcaclient

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// DefaultRequestsPerMinute is the MDCA API's documented quota: 30 requests per
// minute PER TENANT, across the WHOLE MDCA API. That last part matters — the
// budget is shared with anything else this tenant runs against MDCA (e.g. the
// n8n Cloud Discovery uploader), so graph2otel must stay well under it rather
// than assume it has the ceiling to itself. Responses are also capped at 100
// items, but that is a paging concern, not a rate one.
const DefaultRequestsPerMinute = 30

// Limiter holds one client-side token bucket per tenant, created lazily. A nil
// *Limiter is valid and never gates, so rate limiting stays optional at the
// call site.
type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	every    rate.Limit
	burst    int
}

// NewLimiter returns a Limiter enforcing DefaultRequestsPerMinute per tenant.
// The burst is deliberately small (a handful of pages), matching the tight
// 30/min ceiling — a large burst would let one collection tick spend the whole
// minute's budget at once.
func NewLimiter() *Limiter {
	return newLimiterWithRate(rate.Limit(DefaultRequestsPerMinute)/rate.Limit(60), 5)
}

// newLimiterWithRate builds a Limiter with an explicit ceiling. It is the test
// seam that keeps gating tests fast.
func newLimiterWithRate(every rate.Limit, burst int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*rate.Limiter),
		every:    every,
		burst:    burst,
	}
}

// Wait blocks until a token is available for tenantID's bucket, or until ctx is
// done. A nil Limiter returns immediately.
func (l *Limiter) Wait(ctx context.Context, tenantID string) error {
	if l == nil {
		return nil
	}
	return l.limiterFor(tenantID).Wait(ctx) //nolint:wrapcheck // rate.Limiter's ctx error is the useful one
}

// limiterFor returns tenantID's bucket, creating it on first use.
func (l *Limiter) limiterFor(tenantID string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lim, ok := l.limiters[tenantID]; ok {
		return lim
	}
	lim := rate.NewLimiter(l.every, l.burst)
	l.limiters[tenantID] = lim
	return lim
}
