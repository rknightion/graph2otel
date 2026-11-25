package teamsadminclient

import "golang.org/x/time/rate"

// DefaultRequestsPerSecond and DefaultBurst size DefaultLimiter.
//
// EVIDENCE CLASS: unmeasured. No Teams admin API throttle figure is published,
// and no Retry-After or rate-limit header was seen on any live response. These
// values are a conservative guess, not a ceiling. One poll of all five
// teams_admin collectors makes 10 requests, so burst 2 at 1/s finishes in about
// eight seconds. If a real figure is measured, replace these and re-tag this
// comment live-measured.
const (
	DefaultRequestsPerSecond = 1.0
	DefaultBurst             = 2
)

// DefaultLimiter returns the client-side gate a Client uses when Options.Limiter
// is nil. Each call returns a NEW limiter: a Client is per tenant, so two
// clients must not share one bucket. To disable gating pass
// rate.NewLimiter(rate.Inf, 1); nil means "use the default".
func DefaultLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(DefaultRequestsPerSecond), DefaultBurst)
}
