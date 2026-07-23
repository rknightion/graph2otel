package exoclient

import "golang.org/x/time/rate"

// DefaultRequestsPerSecond and DefaultBurst size DefaultLimiter.
//
// EVIDENCE CLASS: unmeasured. Exchange Online admin-API throttling was NOT
// measured for this package. There is no published req/min figure for
// adminapi InvokeCommand, and no RateLimit-* or Retry-After header was observed
// on any live response — so unlike the Graph workload ceilings in
// internal/graphclient, or the Management Activity API's documented 2,000/min,
// there is no number here to respect. These values are a deliberately
// conservative GUESS, not a ceiling.
//
// Conservative is close to free in this case: the only consumer is a quarantine
// collector polling on a multi-minute interval and issuing a handful of cmdlets
// per tick, so it never comes near 1/s. The worst case is that graph2otel
// under-uses an allowance it was granted; the worst case of guessing high is
// tripping an unknown ceiling on a customer tenant. If a real figure is ever
// measured, replace these AND re-tag the comment as live-measured.
const (
	DefaultRequestsPerSecond = 1.0
	DefaultBurst             = 1
)

// DefaultLimiter returns the client-side gate a Client uses when Options.Limiter
// is nil.
//
// Each call returns a NEW limiter. A Client is per tenant, so two Clients
// sharing one bucket would gate a multi-tenant process to a single tenant's
// allowance — the same reason the sibling clients key their buckets by tenant.
//
// To disable gating entirely, pass rate.NewLimiter(rate.Inf, 1) rather than nil:
// nil means "use this default", which is the safer reading of an unset field.
func DefaultLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(DefaultRequestsPerSecond), DefaultBurst)
}
