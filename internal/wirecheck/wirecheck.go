// Package wirecheck reports API responses that do not match what graph2otel
// was built against — an enum value outside the known set, an expected field
// that is absent, or a measured API guarantee that has stopped holding.
//
// # Why this exists
//
// Essentially every load-bearing detail on this project's path was established
// by MEASURING a live tenant, because Microsoft's documentation was wrong about
// it (CLAUDE.md's "wire over docs" rule). That leaves a standing exposure:
// a measurement is a fact about one tenant at one moment, and Microsoft can add
// an enum member, rename a field, or change a filter's behavior at any time.
// Without something watching, such a change is SILENT — the collector keeps
// returning HTTP 200 and keeps emitting numbers that are quietly wrong.
//
// The prior art in this repo shows both halves of the problem. Several
// collectors bucket an unrecognized enum to the literal "unknown", so a new
// Microsoft value disappears into a bucket nobody inspects. m365.service_health
// does the opposite and maps an unmapped status to -1 specifically so it is
// VISIBLE rather than silently counted as healthy (#119). This package
// generalizes the second approach so a collector does not have to invent a
// sentinel per field.
//
// # The shape: bounded counter, unbounded detail in the log
//
// Two outputs per finding, which is CLAUDE.md's cardinality rule turned on
// graph2otel's own telemetry:
//
//   - a COUNTER, MetricUnexpected, labeled {collector, field, kind}. Every label
//     is a string from graph2otel's own source, so the series count is fixed by
//     this codebase and cannot grow with tenant size or with whatever Microsoft
//     invents. This is the alertable signal.
//   - a WARN LOG carrying the offending VALUE. The value is unbounded by
//     definition — it is the thing nobody predicted — so it must never become a
//     metric label. The log is where per-entity detail belongs.
//
// # Logged once, counted always
//
// A collector polls on a multi-minute loop, so a persistently unmapped value
// would log on every tick forever and train its reader to ignore the log. Each
// distinct (kind, field, value) logs ONCE per process; the counter increments
// on every occurrence. The log says what it is, the counter says it is still
// happening. A restart re-logs, which is the right trade: a fresh process
// should re-announce what it is seeing.
//
// # What this is NOT
//
// It is not a schema validator and does not diff whole payloads. It reports the
// specific assumptions a collector chose to declare, which keeps the signal
// worth reading. An unexpected value is also NOT an error: the collector emits
// its record regardless. Dropping data because a field grew a new enum member
// would turn a cosmetic surprise into an outage.
package wirecheck

import (
	"log/slog"
	"sync"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricUnexpected counts API responses that did not match expectations. Its
// label set — collector, field, kind — is bounded by graph2otel's own source.
const MetricUnexpected = "graph2otel.api.unexpected"

// The kinds of finding, the bounded value set of the `kind` label.
const (
	// KindUnmappedValue is a field carrying a value outside its known set —
	// most often Microsoft adding an enum member. The important case is a field
	// used as a METRIC LABEL, where a new value silently creates a new series.
	KindUnmappedValue = "unmapped_value"
	// KindMissingField is an expected field that was absent, when the caller has
	// decided the absence matters (a join key, say). Ordinary optional fields
	// must NOT be reported this way — they are absent all the time and would
	// bury the real findings.
	KindMissingField = "missing_field"
	// KindInvariant is a measured API guarantee that has stopped holding — a
	// server-side filter no longer filtering, an id no longer parseable. These
	// are the highest-value findings: they are exactly the assumptions taken on
	// trust from a single measurement.
	KindInvariant = "invariant"
)

// Enum is a bounded set of values a wire field is expected to take.
type Enum map[string]struct{}

// NewEnum builds an Enum from the known values of a field.
func NewEnum(values ...string) Enum {
	e := make(Enum, len(values))
	for _, v := range values {
		e[v] = struct{}{}
	}
	return e
}

// Has reports whether v is a known member.
func (e Enum) Has(v string) bool {
	_, ok := e[v]
	return ok
}

// Reporter records findings for one collector. Safe for concurrent use; a
// collector may keep one for its lifetime, which is what makes the log-once
// behavior span polls rather than resetting every tick.
type Reporter struct {
	collector string
	logger    *slog.Logger

	mu   sync.Mutex
	seen map[[3]string]struct{}
}

// New builds a Reporter for the named collector. A nil logger falls back to
// slog.Default(), so a zero-config caller still counts and still logs.
func New(collector string, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{collector: collector, logger: logger, seen: map[[3]string]struct{}{}}
}

// Value reports field carrying a value outside allowed.
//
// An EMPTY value is never a finding: absent optional fields are the normal case
// across every Microsoft API this project touches, and reporting them would
// drown the real signal. A caller that needs an absence reported says so
// explicitly with MissingField.
func (r *Reporter) Value(e telemetry.Emitter, field, value string, allowed Enum) {
	if value == "" || allowed.Has(value) {
		return
	}
	r.report(e, KindUnmappedValue, field, value,
		"unexpected value on a Microsoft API response — graph2otel was built against a different set")
}

// MissingField reports an expected field that was absent. Reserve it for fields
// whose absence actually costs something (a join key, an event time); an
// ordinary optional field is not a finding.
func (r *Reporter) MissingField(e telemetry.Emitter, field string) {
	r.report(e, KindMissingField, field, "",
		"expected field absent from a Microsoft API response")
}

// Invariant reports that a measured API guarantee has stopped holding. rule
// names the guarantee (it becomes the bounded `field` label); detail carries
// the unbounded specifics into the log.
func (r *Reporter) Invariant(e telemetry.Emitter, rule, detail string) {
	r.report(e, KindInvariant, rule, detail,
		"a measured Microsoft API guarantee no longer holds — an assumption in this collector may now be wrong")
}

// report increments the counter unconditionally and logs the first time it sees
// a given (kind, field, value).
func (r *Reporter) report(e telemetry.Emitter, kind, field, value, msg string) {
	if e != nil {
		e.Counter(MetricUnexpected, semconv.UnitDimensionless,
			"Microsoft API responses that did not match what this collector was built against, by kind. Non-zero means an assumption needs re-checking; see the WARN log for the offending value.",
			1, telemetry.Attrs{
				semconv.AttrCollector: r.collector,
				semconv.AttrField:     field,
				semconv.AttrKind:      kind,
			})
	}

	key := [3]string{kind, field, value}
	r.mu.Lock()
	_, dup := r.seen[key]
	if !dup {
		r.seen[key] = struct{}{}
	}
	r.mu.Unlock()
	if dup {
		return
	}

	r.logger.Warn(msg,
		"collector", r.collector,
		"kind", kind,
		"field", field,
		"value", value,
	)
}
