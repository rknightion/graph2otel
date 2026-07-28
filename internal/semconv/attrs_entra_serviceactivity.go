package semconv

// entra.service_activity attributes (#368) — the beta M365 monitoring
// serviceActivity metrics: measured tenant sign-in and Global Secure Access
// experience, as distinct from Microsoft's published incident advisories that
// m365.service_health already carries.
//
// Reused: AttrActivity (attrs_shared.go) is the bounded dimension naming WHICH
// of the nineteen metric functions a point came from — mfa_signin_success,
// ca_blocked_signin, network_access_branches_alive and so on. The names are
// graph2otel's snake_case rendering of Microsoft's function names, so they are
// a code-supplied closed set, not a Graph-supplied value set, and nothing here
// is declared to internal/wirecheck.
//
// # There are no per-user, per-app or per-branch dimensions, by construction
//
// Every function returns a bare `Collection(serviceActivityValueMetric)` — two
// fields, `intervalStartDateTime` and `value` — with no entity dimension at all
// (confirmed against the beta EDM and against all nineteen live responses,
// 2026-07-28). So this collector cannot violate #112 even in principle: the API
// hands back an aggregate and there is no per-entity detail being collapsed,
// which is also why it carries NO log twin. #114's "not a metric label means log
// twin, never dropped" does not apply where nothing was fetched to drop.
//
// # Scope correction against the issue's premise
//
// #368 was filed expecting "Teams, Exchange, M365 Apps, MFA and GSA". The beta
// EDM declares serviceActivity metric functions for **sign-in health (MFA,
// SAML, Conditional Access) and Global Secure Access only** — there is no
// Teams, Exchange or M365 Apps function on this surface. That is why this is an
// `entra.*` collector rather than the `m365.*` one the issue's area label
// implies.
// # There is deliberately no interval_start attribute — a correction
//
// An earlier draft of this file declared `interval_start`, the bucket's own
// start time, "so a reader can tell WHICH half-hour a value describes". That was
// WRONG and it is recorded here rather than quietly deleted, because it is a
// seductive mistake: the information genuinely is useful and there is no log
// twin to put it on, so a metric label looks like the only home for it.
//
// It is unbounded cardinality of the purest kind. A new bucket start every 30
// minutes means a new series every 30 minutes, forever, each receiving exactly
// one sample — the same shape #112 forbids for a correlation id, arrived at from
// a different direction. `internal/signalcapture`'s per-entity denylist is an
// exact-match keyword list and does not contain "interval_start", so the gate
// passed it mechanically; the gate not firing is not evidence of correctness.
//
// The bucket start is therefore not emitted at all. What replaces it is honesty
// in the collector doc about the sampling lag: the gauge publishes the latest
// COMPLETE bucket, so the value describes a window ending at most one
// aggregation interval ago. A reader who needs the exact window reads that,
// and Prometheus's own timestamp carries the rest.
const (
	// AttrAggregationIntervalMinutes records the bucket width actually
	// requested. The API accepts ONLY 5, 10, 15 or 30 (live-measured: 60
	// returns a 400 naming the allowed set), so this is a closed set of four
	// and a bounded label. It is on the metric because changing it changes what
	// the number MEANS — a count per 5 minutes and a count per 30 minutes are
	// not the same series and must not be graphed as one.
	AttrAggregationIntervalMinutes = "aggregation_interval_minutes"
)
