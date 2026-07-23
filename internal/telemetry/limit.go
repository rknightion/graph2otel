package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sort"
	"strings"
	"sync"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// The central cardinality limiter (#235).
//
// # What it replaces
//
// graph2otel used to bound metric cardinality three unrelated ways: two
// hand-maintained per-collector allow-lists, the OTEL SDK's per-instrument cap,
// and one hand-rolled `other` bucket. The allow-lists were a standing guess
// about what matters — on m7kni the app-health list discarded 100% of the live
// data, because the one row the tenant produces is LogonUI.exe. The SDK cap was
// worse in a subtler way: it is ARRIVAL-ordered, so the series that survive are
// whichever happened to show up first, and the ones that do not collapse into an
// opaque otel.metric.overflow that names nothing.
//
// This is one policy, applied at the emitter boundary, that keeps the MOST
// SIGNIFICANT series and folds the rest into a bucket that says what it is. The
// SDK cap is disabled outright in favor of it (provider.go), so this is the only
// thing bounding series count and it has to be the only thing.
//
// # Where it sits, and why innermost
//
// The Provider wraps its own emitter with this, so WithTenant and WithTransport
// decorate OUTSIDE it and their stamps are already applied by the time a point
// arrives. That matters: tenant_id is part of series identity (#143), so a
// limiter that ran before the stamp would rank and fold across tenants.
//
// # What it deliberately does NOT license
//
// This is not permission to put per-entity identity on a metric label. With a
// 5000 cap on a 50,000-user tenant, labeling by UPN buys an arbitrary 5000
// series and a meaningless bucket, at full cost, when the log twin already
// answers "which one" better and for free. #112/#114 stand unchanged: metrics
// carry bounded aggregates, logs carry entities, and "not a metric label" still
// means LOG TWIN, never dropped. This mechanism is for dimensions that are
// MODERATELY unbounded and genuinely aggregate-shaped — application names, OS
// versions, policy names, endpoint paths — where the tail is long but the head
// means something.

const (
	// otherBucket is the attribute value a clipped series' unbounded dimension
	// takes. A named bucket rather than the SDK's otel.metric.overflow: a reader
	// can tell what it represents, and a dashboard can sum it back in.
	otherBucket = "other"

	// hysteresisPercent widens the eviction threshold above the admission
	// threshold, so a series oscillating around the boundary keeps its slot
	// instead of appearing and disappearing every cycle (#235 fork 4). The
	// admitted set is therefore bounded by limit + band, not by limit — an
	// operator setting 5000 may briefly see up to 5500 while membership churns.
	hysteresisPercent = 10

	// maxFoldGroups bounds the fold itself. Folding preserves every attribute
	// except the clip key, so a metric with several unbounded dimensions could
	// produce a wide `other` set — a cardinality limiter that emits unbounded
	// cardinality. Past this, everything collapses to a single fully-`other`
	// series. Expressed as a fraction of the limit, with a floor: a handful of
	// bounded values (two platforms, four statuses) is the normal shape and must
	// survive even at a small limit, and never more groups than the limit itself.
	maxFoldGroupsDivisor = 10
	minFoldGroups        = 8

	// keyValueCap bounds how many distinct values are remembered per attribute
	// key while choosing a clip key on the synchronous path, where there is no
	// complete set to measure. Only the ARGMAX matters, so a bounded sample is
	// enough to identify the unbounded dimension.
	keyValueCap = 1024
)

// Self-observability for the limiter itself. Clipping is data loss, so it must
// be impossible for it to happen silently (#235 fork 6).
const (
	seriesClippedMetric = seriesSelfPrefix + "clipped"
	seriesTotalMetric   = seriesSelfPrefix + "total"
)

// Limits is the cardinality policy. Zero means unlimited on either axis, which
// is the escape hatch for self-hosted Prometheus/Mimir operators who do not pay
// per active series.
type Limits struct {
	// PerMetric caps the distinct series a single metric may emit per cycle.
	PerMetric int
	// Global caps the total across every metric. It cannot be honored by a
	// per-metric cap alone — 200 metrics at 5000 each is a million series — so it
	// is arbitrated separately, by EffectiveLimits.
	Global int
}

// Limiter applies a Limits policy across every metric an Emitter carries, and
// reports what it clipped. It is safe for concurrent use.
type Limiter struct {
	limits Limits
	logger *slog.Logger

	mu     sync.Mutex
	states map[string]*metricState // keyed by metric name \x00 tenant
	// effective is the per-metric limit after global arbitration, recomputed once
	// per export interval by Report. A metric absent from it uses limits.PerMetric.
	effective map[string]int
	// clipped accumulates per-metric clip counts for the current interval.
	clipped map[clipKey]int
}

type clipKey struct{ metric, mode string }

// metricState is the per-(metric, tenant) memory the limiter needs. Keyed by
// tenant as well as name because tenant_id is part of series identity, so two
// tenants' snapshots of one metric are two independent sets to rank.
type metricState struct {
	mu sync.Mutex
	// clip is the attribute key whose value becomes `other`: the dimension with
	// the most distinct values. STICKY — chosen on the first clip and kept — so
	// the fold's shape cannot churn cycle to cycle as distinct counts shift.
	clip string
	// keyValues samples distinct values per attribute key, used to choose clip on
	// the synchronous path where no complete set is ever visible.
	keyValues map[string]map[string]struct{}
	// admitted is the synchronous path's sticky admission set, by fingerprint.
	admitted map[uint64]struct{}
	// prevAdmitted is the previous cycle's snapshot membership, for hysteresis.
	prevAdmitted map[uint64]struct{}
	// clipping tracks the transition, so the WARN fires once rather than per cycle.
	clipping bool
}

// NewLimiter returns a Limiter enforcing the given policy.
func NewLimiter(l Limits) *Limiter {
	return &Limiter{
		limits:  l,
		states:  map[string]*metricState{},
		clipped: map[clipKey]int{},
	}
}

// SetLogger gives the limiter somewhere to announce that a metric has started
// clipping. Clipping is data loss, and a metric quietly shedding its tail while
// every dashboard still renders is precisely the failure that goes unnoticed —
// so it says so once, on the transition. Without a logger it stays silent and
// the graph2otel.series.clipped metric carries the signal alone.
func (l *Limiter) SetLogger(lg *slog.Logger) {
	l.mu.Lock()
	l.logger = lg
	l.mu.Unlock()
}

// Wrap returns an Emitter that applies this Limiter's policy to everything
// passing through it.
func (l *Limiter) Wrap(e Emitter) Emitter { return &limiterEmitter{Emitter: e, lim: l} }

// WithCardinalityLimits is the one-shot form for a limiter nobody needs to
// Report on — collector tests, and any caller that wants the clipping behavior
// without the self-observability.
func WithCardinalityLimits(e Emitter, l Limits) Emitter { return NewLimiter(l).Wrap(e) }

// limiterEmitter overrides every Emitter method explicitly, for the reason
// tenantEmitter does: an un-overridden method would be promoted from the
// embedded Emitter, compile perfectly, and emit unlimited. TestEveryEmitterMethod
// parses the interface and fails if one is missing.
type limiterEmitter struct {
	Emitter
	lim *Limiter
}

// limitFor returns the effective per-metric limit, or 0 when this metric is not
// a clip candidate at all.
//
// graph2otel.* is never a candidate. Self-observability is bounded by collector
// count and tenant count by construction, and silently dropping our own health
// signals under load would remove the evidence at exactly the moment it is
// needed. Those series still COUNT toward the reported total; they are simply
// never the ones given up.
func (l *Limiter) limitFor(name string) int {
	if strings.HasPrefix(name, selfObsPrefix) {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if eff, ok := l.effective[name]; ok {
		return eff
	}
	return l.limits.PerMetric
}

// selfObsPrefix is the namespace exempt from clipping. It is the whole
// graph2otel.* family, not just graph2otel.series.*, because every self-obs
// signal is bounded by design.
const selfObsPrefix = "graph2otel."

func (l *Limiter) state(name, tenant string) *metricState {
	key := name + "\x00" + tenant
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.states[key]
	if !ok {
		st = &metricState{keyValues: map[string]map[string]struct{}{}, admitted: map[uint64]struct{}{}}
		l.states[key] = st
	}
	return st
}

func (l *Limiter) noteClipped(metric, mode string, n int) {
	if n == 0 {
		return
	}
	l.mu.Lock()
	l.clipped[clipKey{metric: metric, mode: mode}] += n
	l.mu.Unlock()
}

// announceClipping logs the TRANSITION into clipping for a metric, once. A WARN
// every export interval for a steady state is noise nobody reads, and noise is
// how a real one gets missed.
func (l *Limiter) announceClipping(st *metricState, metric, mode string, limit, total int) {
	st.mu.Lock()
	first := !st.clipping
	st.clipping = true
	st.mu.Unlock()
	if !first {
		return
	}
	l.mu.Lock()
	lg := l.logger
	l.mu.Unlock()
	if lg == nil {
		return
	}
	lg.Warn("metric cardinality limit reached; excess series are being clipped",
		"metric", metric, "limit", limit, "series", total, "mode", mode)
}

// GaugeSnapshot is the ranked path, and the only one where ranking is even
// definable: it receives the COMPLETE set of series for the metric, so
// significance can be read off the values. Every other instrument arrives one
// point at a time with no set boundary.
func (e *limiterEmitter) GaugeSnapshot(name, unit, desc string, points []GaugePoint) {
	e.gaugeSnapshotFor("", name, unit, desc, points)
}

// gaugeSnapshotFor applies the same policy and carries the tenant scope (#236)
// through to the base emitter.
//
// The LIMIT is still keyed on the tenant stamped on the points, not on the
// scope, and that is not an oversight: the stamp is what series identity is made
// of, and this path is only ever reached with points to read it from (an empty
// snapshot is len(points) <= limit and returns above). So #235's meaning is
// untouched — the cap remains per (metric, tenant) — and the scope is carried
// purely so the base emitter knows which partition to replace.
func (e *limiterEmitter) gaugeSnapshotFor(tenant, name, unit, desc string, points []GaugePoint) {
	limit := e.lim.limitFor(name)
	if limit <= 0 || len(points) <= limit {
		snapshotFor(e.Emitter, tenant, name, unit, desc, points)
		return
	}

	st := e.lim.state(name, tenantOfPoints(points))
	kept, tail := st.rank(points, limit)

	if semconv.MetricAdditive(unit, "gauge") {
		kept = append(kept, st.fold(tail, limit)...)
		e.lim.noteClipped(name, "folded", len(tail))
		e.lim.announceClipping(st, name, "folded", limit, len(points))
	} else {
		// Summing a tail of scores or ratios emits a number that was never
		// measured, under a name that looks legitimate. Losing it is the smaller
		// failure, and unlike the invented aggregate it is reported.
		e.lim.noteClipped(name, "dropped", len(tail))
		e.lim.announceClipping(st, name, "dropped", limit, len(points))
	}
	snapshotFor(e.Emitter, tenant, name, unit, desc, kept)
}

// rank splits a snapshot into the series that keep their own identity and the
// tail, by value descending.
//
// Hysteresis lives here (#235 fork 4). Admission is immediate — the top `limit`
// by value always get a slot — but eviction requires falling clear of the band
// above it. A series oscillating inside the band therefore keeps its slot rather
// than appearing and disappearing every cycle, which would leave gaps in every
// graph while still being billed as an active series. The cost is that the
// admitted set is bounded by limit+band rather than by limit.
func (st *metricState) rank(points []GaugePoint, limit int) (kept, tail []GaugePoint) {
	sorted := make([]GaugePoint, len(points))
	copy(sorted, points)
	// Value descending; ties broken on the rendered attributes so the outcome
	// does not depend on the caller's slice order or on map iteration.
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Value != sorted[j].Value {
			return sorted[i].Value > sorted[j].Value
		}
		return renderAttrs(sorted[i].Attrs) < renderAttrs(sorted[j].Attrs)
	})

	band := limit * hysteresisPercent / 100
	if band < 1 {
		band = 1
	}

	st.mu.Lock()
	prev := st.prevAdmitted
	now := make(map[uint64]struct{}, limit)
	st.mu.Unlock()

	for i, p := range sorted {
		fp := fingerprint(p.Attrs)
		switch {
		case i < limit:
			kept = append(kept, p)
			now[fp] = struct{}{}
		case i < limit+band && contains(prev, fp):
			kept = append(kept, p)
			now[fp] = struct{}{}
		default:
			tail = append(tail, p)
		}
	}

	st.mu.Lock()
	st.prevAdmitted = now
	st.mu.Unlock()
	return kept, tail
}

func contains(m map[uint64]struct{}, fp uint64) bool {
	if m == nil {
		return false
	}
	_, ok := m[fp]
	return ok
}

// fold collapses the tail into `other` series, preserving every attribute except
// the clip key.
//
// Preserving the rest is the point. Folding {app_name, platform} by setting BOTH
// to `other` would destroy the platform breakdown — bounded, and exactly the
// shape #112 wants on a metric. Only the unbounded dimension may be surrendered,
// which is what graphactivity has hand-coded since #185: it sets normalized_path
// to `other` and leaves method and status class intact.
func (st *metricState) fold(tail []GaugePoint, limit int) []GaugePoint {
	if len(tail) == 0 {
		return nil
	}
	clip := st.chooseClip(tail)

	groups := map[string]*GaugePoint{}
	var order []string
	for _, p := range tail {
		attrs := make(Attrs, len(p.Attrs))
		maps.Copy(attrs, p.Attrs)
		if _, has := attrs[clip]; has {
			attrs[clip] = otherBucket
		}
		k := renderAttrs(attrs)
		g, ok := groups[k]
		if !ok {
			groups[k] = &GaugePoint{Value: p.Value, Attrs: attrs}
			order = append(order, k)
			continue
		}
		g.Value += p.Value
	}

	maxGroups := limit / maxFoldGroupsDivisor
	if maxGroups < minFoldGroups {
		maxGroups = minFoldGroups
	}
	if maxGroups > limit {
		maxGroups = limit
	}
	if len(groups) > maxGroups {
		// Several unbounded dimensions: a fold that stays wide is a cardinality
		// limiter emitting unbounded cardinality. Collapse everything.
		total := 0.0
		attrs := Attrs{}
		for k := range tail[0].Attrs {
			attrs[k] = otherBucket
		}
		for _, p := range tail {
			total += p.Value
		}
		return []GaugePoint{{Value: total, Attrs: attrs}}
	}

	sort.Strings(order)
	out := make([]GaugePoint, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	return out
}

// chooseClip returns the attribute key whose value becomes `other`: the one with
// the most distinct values, which is the dimension actually driving the metric's
// cardinality. Ties break lexicographically so the choice is deterministic.
//
// STICKY once chosen. Distinct counts shift between cycles, and a clip key that
// moved with them would change the shape of the `other` series underneath a
// dashboard. The state is in-process only, so a restart re-chooses.
func (st *metricState) chooseClip(points []GaugePoint) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.clip != "" {
		return st.clip
	}
	counts := map[string]map[string]struct{}{}
	for _, p := range points {
		for k, v := range p.Attrs {
			vals, ok := counts[k]
			if !ok {
				vals = map[string]struct{}{}
				counts[k] = vals
			}
			vals[fmt.Sprint(v)] = struct{}{}
		}
	}
	st.clip = argmaxKey(counts)
	return st.clip
}

// argmaxKey returns the key with the most distinct values, ties broken
// lexicographically for determinism across runs and map iteration orders.
func argmaxKey(counts map[string]map[string]struct{}) string {
	best, bestN := "", -1
	for k, vals := range counts {
		n := len(vals)
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

// admitSync is the synchronous instruments' path: Counter, Gauge, UpDownCounter
// and Histogram arrive one point at a time, with no set to rank.
//
// Admission is therefore by arrival — but STICKY, and that is what makes it
// safe. A series that never won its own slot contributes to `other` from its
// FIRST observation, so `other` is monotonic and no series ever migrates into it
// after being reported independently (#235 fork 3). This is the shape
// graphactivity's cappedPath has run in production since #185, generalised.
//
// Returns the attributes to emit with, and false when the point must be dropped
// (a non-additive metric, where folding several entities' last values into one
// series yields whichever wrote last).
func (st *metricState) admitSync(attrs Attrs, limit int, additive bool) (Attrs, bool) {
	fp := fingerprint(attrs)

	st.mu.Lock()
	defer st.mu.Unlock()

	if _, ok := st.admitted[fp]; ok {
		return attrs, true
	}
	if len(st.admitted) < limit {
		st.admitted[fp] = struct{}{}
		st.sampleLocked(attrs)
		return attrs, true
	}
	if !additive {
		return nil, false
	}
	if st.clip == "" {
		st.clip = argmaxKey(st.keyValues)
	}
	out := make(Attrs, len(attrs))
	maps.Copy(out, attrs)
	if _, has := out[st.clip]; has {
		out[st.clip] = otherBucket
	}
	// The `other` series is itself one series and holds a slot, so a metric never
	// exceeds limit+1 on this path.
	st.admitted[fingerprint(out)] = struct{}{}
	return out, true
}

// sampleLocked records distinct attribute values so a clip key can be chosen on
// a path that never sees a complete set. Bounded per key: only the argmax
// matters, and a sample is enough to identify the unbounded dimension.
func (st *metricState) sampleLocked(attrs Attrs) {
	for k, v := range attrs {
		vals, ok := st.keyValues[k]
		if !ok {
			vals = map[string]struct{}{}
			st.keyValues[k] = vals
		}
		if len(vals) < keyValueCap {
			vals[fmt.Sprint(v)] = struct{}{}
		}
	}
}

// syncAttrs applies the synchronous policy for one point, returning the
// attributes to emit with and whether to emit at all.
func (e *limiterEmitter) syncAttrs(name, unit, kind string, attrs Attrs) (Attrs, bool) {
	limit := e.lim.limitFor(name)
	if limit <= 0 {
		return attrs, true
	}
	st := e.lim.state(name, tenantOf(attrs))
	additive := semconv.MetricAdditive(unit, kind)
	out, ok := st.admitSync(attrs, limit, additive)
	if !ok {
		e.lim.noteClipped(name, "dropped", 1)
		e.lim.announceClipping(st, name, "dropped", limit, limit+1)
		return nil, false
	}
	if len(out) > 0 && !sameAttrs(out, attrs) {
		e.lim.noteClipped(name, "folded", 1)
		e.lim.announceClipping(st, name, "folded", limit, limit+1)
	}
	return out, true
}

func sameAttrs(a, b Attrs) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || fmt.Sprint(v) != fmt.Sprint(bv) {
			return false
		}
	}
	return true
}

func (e *limiterEmitter) Counter(name, unit, desc string, add float64, attrs Attrs) {
	if out, ok := e.syncAttrs(name, unit, "sum", attrs); ok {
		e.Emitter.Counter(name, unit, desc, add, out)
	}
}

func (e *limiterEmitter) Gauge(name, unit, desc string, value float64, attrs Attrs) {
	if out, ok := e.syncAttrs(name, unit, "gauge", attrs); ok {
		e.Emitter.Gauge(name, unit, desc, value, out)
	}
}

func (e *limiterEmitter) UpDownCounter(name, unit, desc string, value float64, attrs Attrs) {
	if out, ok := e.syncAttrs(name, unit, "sum", attrs); ok {
		e.Emitter.UpDownCounter(name, unit, desc, value, out)
	}
}

func (e *limiterEmitter) Histogram(name, unit, desc string, value float64, bounds []float64, attrs Attrs) {
	e.HistogramCtx(context.Background(), name, unit, desc, value, bounds, attrs)
}

func (e *limiterEmitter) HistogramCtx(ctx context.Context, name, unit, desc string, value float64,
	bounds []float64, attrs Attrs,
) {
	if out, ok := e.syncAttrs(name, unit, "histogram", attrs); ok {
		e.Emitter.HistogramCtx(ctx, name, unit, desc, value, bounds, out)
	}
}

// LogEvent is a deliberate passthrough. Log attributes are Loki structured
// metadata, not stream labels (#90), so a log record's attribute set does not
// create a time series and costs nothing in active-series terms. Clipping logs
// would delete exactly the per-entity detail #114 requires be kept.
func (e *limiterEmitter) LogEvent(ev Event) { e.Emitter.LogEvent(ev) }

// Report emits the limiter's self-observability and recomputes the global
// arbitration for the next interval.
//
// active is the per-metric distinct-series count from CardinalityTracker's last
// completed interval — the accounting already exists, so the arbiter consumes it
// rather than counting twice. Pass nil to skip global arbitration.
func (l *Limiter) Report(e Emitter, active []SeriesCount) {
	l.mu.Lock()
	clipped := l.clipped
	l.clipped = map[clipKey]int{}
	l.mu.Unlock()

	keys := make([]clipKey, 0, len(clipped))
	for k := range clipped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].metric != keys[j].metric {
			return keys[i].metric < keys[j].metric
		}
		return keys[i].mode < keys[j].mode
	})
	for _, k := range keys {
		e.Gauge(seriesClippedMetric, semconv.UnitSeries,
			"Series clipped from `metric.name` during the last interval: `mode=folded` were summed "+
				"into the `other` bucket, `mode=dropped` were discarded because the metric is not "+
				"additive and a synthetic aggregate would be worse than the loss.",
			float64(clipped[k]),
			Attrs{semconv.AttrMetricName: k.metric, semconv.AttrClipMode: k.mode})
	}

	total := 0
	counts := make(map[string]int, len(active))
	for _, a := range active {
		total += a.Count
		counts[a.Metric] = a.Count
	}
	e.Gauge(seriesTotalMetric, semconv.UnitSeries,
		"Total distinct active time series across every metric during the last export interval, "+
			"against cardinality.global_limit.", float64(total), nil)

	if len(active) == 0 {
		return
	}
	eff := EffectiveLimits(counts, l.limits.Global, l.limits.PerMetric)
	l.mu.Lock()
	l.effective = eff
	l.mu.Unlock()
}

// EffectiveLimits arbitrates a global series budget across metrics by MAX-MIN
// FAIRNESS, returning the per-metric limit each should be held to (#235 fork 5).
//
// A per-metric cap alone cannot honor a total: 200 metrics at 5000 each is a
// million series. Something has to decide which metric gives up its slots, and
// left unspecified that decision becomes emergent and unpredictable. Max-min
// fairness is the standard answer and states in one sentence: every metric may
// have its fair share of the budget, and whatever the metrics under their share
// do not use is redistributed among the ones over it, repeatedly, until it
// settles. So small metrics are never shrunk to pay for a large one's overage,
// and the metric actually responsible absorbs it.
//
// A global of 0 means unlimited and returns the unmodified per-metric limit.
func EffectiveLimits(active map[string]int, global, perMetric int) map[string]int {
	out := make(map[string]int, len(active))
	for m := range active {
		out[m] = perMetric
	}
	if global <= 0 || len(active) == 0 {
		return out
	}
	total := 0
	for _, n := range active {
		total += n
	}
	if total <= global {
		return out
	}

	// Water-filling: settle every metric already under the current fair share,
	// return its unused budget to the pool, and recompute the share for the rest.
	unsettled := make(map[string]int, len(active))
	maps.Copy(unsettled, active)
	remaining := global

	for len(unsettled) > 0 {
		share := remaining / len(unsettled)
		settledAny := false
		for m, n := range unsettled {
			if n <= share {
				remaining -= n
				delete(unsettled, m)
				settledAny = true
			}
		}
		if !settledAny {
			// Everyone left is over the share: they each get exactly it.
			for m := range unsettled {
				if share < out[m] {
					out[m] = share
				}
			}
			break
		}
	}
	return out
}

// tenantOf reads the tenant a record belongs to. The limiter runs INNERMOST, so
// WithTenant has already stamped it (#143), and two tenants' series for one
// metric are two independent sets that must not be ranked against each other.
func tenantOf(attrs Attrs) string {
	if v, ok := attrs[semconv.AttrTenantID]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func tenantOfPoints(points []GaugePoint) string {
	if len(points) == 0 {
		return ""
	}
	return tenantOf(points[0].Attrs)
}

// renderAttrs is a deterministic textual rendering of an attribute set, used as
// a sort tie-break and as a fold-group key. Unlike fingerprint it is
// collision-free, which a grouping key has to be.
func renderAttrs(attrs Attrs) string {
	if len(attrs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0x1f)
		fmt.Fprint(&b, attrs[k])
		b.WriteByte(0x1e)
	}
	return b.String()
}
