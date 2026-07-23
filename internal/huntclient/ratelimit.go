package huntclient

import "golang.org/x/time/rate"

// DefaultRequestsPerSecond and DefaultBurst size DefaultLimiter.
//
// EVIDENCE CLASS: docs-derived, deliberately conservative. Microsoft documents
// the advanced-hunting API at 45 requests/minute and 1,500 requests/hour per
// tenant, with a separate CPU-time budget SHARED with humans querying in the
// Defender portal (#106). This limiter is set well under the request ceiling —
// the shared CPU budget, not the request count, is the real scarce resource, and
// under-using the request allowance costs nothing here.
//
// It is close to free to be conservative: the only consumers are the DeviceTvm*
// snapshot collectors, which poll on a 6-hour-or-longer interval (#249) and issue
// on the order of ten queries per tick — a handful of bounded summaries plus at
// most a few partitioned twin fetches. They never approach even this floor. The
// limiter exists to keep a misconfigured short interval, or a future collector,
// from silently starving the portal's shared budget; it is a floor on the "poll
// slowly" discipline, not a throughput target. If a real per-tenant CPU figure is
// ever measured, replace these AND re-tag this comment live-measured.
const (
	DefaultRequestsPerSecond = 0.5
	DefaultBurst             = 1
)

// DefaultLimiter returns the client-side gate a Client uses when Options.Limiter
// is nil. Each call returns a NEW limiter: a Client is per tenant, and two
// Clients sharing one bucket would gate a multi-tenant process to a single
// tenant's allowance.
//
// To disable gating entirely, pass rate.NewLimiter(rate.Inf, 1) rather than nil:
// nil means "use this default", the safer reading of an unset field.
func DefaultLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(DefaultRequestsPerSecond), DefaultBurst)
}
