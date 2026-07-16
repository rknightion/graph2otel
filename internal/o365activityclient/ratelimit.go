package o365activityclient

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// DefaultRequestsPerMinute is the Management Activity API's documented baseline
// quota: 2,000 requests per minute PER TENANT.
//
// Two things make this ceiling unlike Graph's (see internal/graphclient):
// it is allocated per tenant rather than shared across a publisher's customers,
// and it is far looser than any Graph workload ceiling. Microsoft also describes
// it as a baseline rather than a fixed limit — E5 organizations get roughly
// twice as much, and the real value flexes with seat count — so treating 2,000
// as the ceiling is deliberately conservative: the worst case is that graph2otel
// under-uses a quota it was granted, never that it exceeds one it was not.
const DefaultRequestsPerMinute = 2000

// Limiter holds one client-side token bucket per tenant, created lazily. It is
// the proactive gate that keeps graph2otel inside the documented quota rather
// than discovering the ceiling by collecting AF429s.
//
// A nil *Limiter is valid and never gates, so rate limiting stays optional at
// the call site.
type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	every    rate.Limit
	burst    int
}

// NewLimiter returns a Limiter enforcing the documented DefaultRequestsPerMinute
// per tenant.
func NewLimiter() *Limiter {
	return newLimiterWithRate(rate.Limit(DefaultRequestsPerMinute)/rate.Limit(60), DefaultRequestsPerMinute)
}

// newLimiterWithRate builds a Limiter with an explicit ceiling. It is the test
// seam that keeps the gating tests fast — the real ceiling would need 2,000
// requests to observe.
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

// limiterFor returns tenantID's bucket, creating it on first use. Buckets are
// per tenant because the quota is: sharing one bucket across tenants would pin
// a multi-tenant process to a single tenant's allowance.
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
