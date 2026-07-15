package telemetry

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// Self-cardinality metric names. The tracker never measures any metric in the
// graph2otel.series.* family — both to avoid measuring itself and to break
// the Report -> Gauge -> Observe recursion (Report emits these from inside the
// emit hot path that calls Observe).
const (
	seriesSelfPrefix     = "graph2otel.series."
	seriesActiveMetric   = seriesSelfPrefix + "active"
	seriesLimitMetric    = seriesSelfPrefix + "limit"
	seriesOverflowMetric = seriesSelfPrefix + "overflowing"
)

// defaultSeriesCap bounds the distinct fingerprints tracked per source metric.
// Once a metric reaches the cap the reported value pins at the cap (a visible
// signal that the true cardinality is at least this high) and further distinct
// series for that metric are not counted, bounding memory.
const defaultSeriesCap = 10000

// seriesSet is the distinct fingerprint set for one source metric within the
// current export interval. capped records whether the per-metric cap was hit so
// the reported value can be pinned at the cap.
type seriesSet struct {
	fps    map[uint64]struct{}
	capped bool
}

// SeriesCount is the distinct active-series count for one source metric during
// the last completed export interval. Capped is true when the per-metric cap was
// hit, in which case Count is pinned at defaultSeriesCap (or the configured cap).
type SeriesCount struct {
	Metric string
	Count  int
	Capped bool
}

// CardinalityTracker counts the EXACT number of distinct attribute combinations
// (time series) emitted per source metric within an export interval. Observe is
// called from the emit hot path for every metric data point; Report snapshots
// the per-metric distinct counts, resets the sets, and emits the
// graph2otel.series.active gauge once per source metric. The same per-metric
// counts are retained for the most recent interval and exposed via Snapshot for
// in-process introspection.
//
// All methods are safe for concurrent use and are no-ops on a nil receiver.
type CardinalityTracker struct {
	mu              sync.Mutex
	sets            map[string]*seriesSet
	seriesCap       int           // per-source-metric distinct-series cap (pins the reported count)
	configuredLimit int           // raw cardinality limit (<=0 means "unlimited"; suppresses series.limit/overflowing)
	last            []SeriesCount // counts from the most recent Report; nil before the first
}

// NewCardinalityTracker returns an empty tracker using the package default
// per-metric cap (defaultSeriesCap).
func NewCardinalityTracker() *CardinalityTracker {
	return NewCardinalityTrackerWithCap(defaultSeriesCap)
}

// NewCardinalityTrackerWithCap returns an empty tracker that pins each source
// metric's distinct-series count at seriesCap. Pass the configured OTLP
// cardinality limit so graph2otel.series.active pins exactly when a metric
// reaches the limit (and overflows into otel.metric.overflow). A non-positive
// seriesCap (the "unlimited OTLP limit" case) falls back to defaultSeriesCap as a
// memory guard so the tracker never grows unboundedly.
func NewCardinalityTrackerWithCap(seriesCap int) *CardinalityTracker {
	configured := seriesCap
	if seriesCap <= 0 {
		seriesCap = defaultSeriesCap
	}
	return &CardinalityTracker{sets: map[string]*seriesSet{}, seriesCap: seriesCap, configuredLimit: configured}
}

// Observe records one emitted data point for the source metric name with the
// given attributes. It is a no-op on a nil tracker and for the self-metric
// itself (self-exclusion, which also prevents Report->Gauge->Observe
// recursion). Once a metric reaches the tracker's per-metric cap, further
// distinct combinations are dropped (the metric is marked capped).
func (t *CardinalityTracker) Observe(name string, attrs Attrs) {
	if t == nil || strings.HasPrefix(name, seriesSelfPrefix) {
		return
	}
	fp := fingerprint(attrs)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sets[name]
	if s == nil {
		s = &seriesSet{fps: make(map[uint64]struct{})}
		t.sets[name] = s
	}
	if len(s.fps) >= t.seriesCap {
		s.capped = true
		return
	}
	s.fps[fp] = struct{}{}
}

// Report emits one graph2otel.series.active gauge per source metric observed
// since the previous Report, carrying the EXACT distinct-series count (pinned
// at the configured cap when it was hit), then resets all sets so the next
// interval measures active-per-interval cardinality afresh. It is a no-op on a
// nil tracker.
func (t *CardinalityTracker) Report(e Emitter) {
	if t == nil {
		return
	}

	t.mu.Lock()
	limit := t.configuredLimit
	last := make([]SeriesCount, 0, len(t.sets))
	for name, s := range t.sets {
		last = append(last, SeriesCount{Metric: name, Count: len(s.fps), Capped: s.capped})
	}
	// Replace (rather than clear) so the next interval starts empty and metrics
	// that stopped emitting are dropped.
	t.sets = map[string]*seriesSet{}
	// Stable, presentation-friendly order: highest cardinality first, then name.
	// Retained for Snapshot; emission order is irrelevant.
	sort.Slice(last, func(i, j int) bool {
		if last[i].Count != last[j].Count {
			return last[i].Count > last[j].Count
		}
		return last[i].Metric < last[j].Metric
	})
	t.last = last
	t.mu.Unlock()

	// A configured limit <=0 means the SDK is unlimited (no real otel.metric.overflow):
	// suppress series.limit and force overflowing to 0 even if the memory-guard cap was hit.
	limited := limit > 0

	for _, en := range last {
		e.Gauge(seriesActiveMetric, semconv.UnitSeries,
			"Exact distinct active time series emitted for `metric.name` during the last export interval; bounded by a per-metric cap (the value pins at the cap when exceeded).",
			float64(en.Count), Attrs{semconv.AttrMetricName: en.Metric})
		overflowing := 0.0
		if limited && en.Capped {
			overflowing = 1
		}
		e.Gauge(seriesOverflowMetric, semconv.UnitDimensionless,
			"1 when `metric.name` reached the per-metric series cap during the last interval (excess series silently dropped into otel.metric.overflow), else 0.",
			overflowing, Attrs{semconv.AttrMetricName: en.Metric})
	}
	if limited {
		e.Gauge(seriesLimitMetric, semconv.UnitSeries,
			"Effective per-metric active-series cap: the point at which excess series collapse into otel.metric.overflow (silent per-series loss). Emitted only when a positive limit is configured.",
			float64(limit), nil)
	}
}

// Snapshot returns the per-source-metric active-series counts from the last
// completed export interval (the most recent Report), sorted by count desc then
// metric name. It returns nil before the first Report and is a no-op (nil) on a
// nil receiver. The returned slice is a copy the caller may retain or mutate.
func (t *CardinalityTracker) Snapshot() []SeriesCount {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		return nil
	}
	out := make([]SeriesCount, len(t.last))
	copy(out, t.last)
	return out
}

// fingerprint computes a deterministic, low-allocation 64-bit hash of an
// attribute set. Map iteration order is randomized, so the keys are sorted
// first; the value is then folded in with an inline FNV-1a 64-bit hash using
// per-field (0x1f) and per-pair (0x1e) separators to keep distinct attribute
// sets from colliding via concatenation.
func fingerprint(attrs Attrs) uint64 {
	const (
		offset uint64 = 1469598103934665603
		prime  uint64 = 1099511628211
	)
	h := offset
	if len(attrs) == 0 {
		return h
	}

	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	writeString := func(s string) {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= prime
		}
	}
	writeByte := func(b byte) {
		h ^= uint64(b)
		h *= prime
	}

	for _, k := range keys {
		writeString(k)
		writeByte(0x1f)
		switch v := attrs[k].(type) {
		case string:
			writeString(v)
		case bool:
			if v {
				writeByte('1')
			} else {
				writeByte('0')
			}
		case int:
			writeString(strconv.FormatInt(int64(v), 10))
		case int64:
			writeString(strconv.FormatInt(v, 10))
		case float64:
			writeString(strconv.FormatFloat(v, 'g', -1, 64))
		case []string:
			for i, s := range v {
				if i > 0 {
					writeByte(0x1f)
				}
				writeString(s)
			}
		}
		writeByte(0x1e)
	}
	return h
}
