package admin

import "github.com/rknightion/graph2otel/internal/telemetry"

// CardinalityView is the output-side active-series snapshot rendered on the
// Cardinality tab and served at /api/cardinality.json (#215). graph2otel is
// OTLP-push, so "active series" is the set of series it is about to ship during
// an export interval, already counted and capped by the CardinalityTracker —
// this view only READS that tracker's last completed snapshot (no new
// computation) plus the configured metric_limit from config.
type CardinalityView struct {
	// TotalActiveSeries is the sum of per-metric distinct series counts.
	TotalActiveSeries int `json:"total_active_series"`
	// MetricLimit is the configured per-instrument cap (cardinality.metric_limit);
	// 0 means unlimited.
	MetricLimit int `json:"metric_limit"`
	// MetricCount is the number of source metrics that emitted in the last interval.
	MetricCount int `json:"metric_count"`
	// Metrics is the per-metric breakdown, highest cardinality first (the order
	// the tracker's Snapshot already returns).
	Metrics []CardinalityMetric `json:"metrics"`
	// Offenders is the high-cardinality subset: metrics that hit the per-metric
	// cap or sit within 20% of the configured limit.
	Offenders []CardinalityMetric `json:"offenders,omitempty"`
}

// CardinalityMetric is one source metric's active-series count.
type CardinalityMetric struct {
	Metric string `json:"metric"`
	Count  int    `json:"count"`
	// Capped is true when the metric hit the per-metric series cap (its count is
	// pinned and excess series collapse into otel.metric.overflow).
	Capped bool `json:"capped"`
	// HeadroomPct is (limit-count)/limit*100, clamped to [0,100]. Meaningful only
	// when MetricLimit > 0; 0 when unlimited.
	HeadroomPct float64 `json:"headroom_pct,omitempty"`
}

// cardinalityView assembles the cardinality snapshot from the injected tracker
// and the configured metric limit. A nil tracker (self-obs off) yields an empty
// metric list; a nil cfg yields an unlimited (0) limit. It makes no live call —
// Snapshot is a pure in-memory read of the most recent export interval.
func (s *Server) cardinalityView() CardinalityView {
	limit := 0
	if s.cfg != nil {
		limit = s.cfg.Cardinality.MetricLimit
	}
	var counts []telemetry.SeriesCount
	if s.card != nil {
		counts = s.card.Snapshot()
	}
	v := CardinalityView{MetricLimit: limit, MetricCount: len(counts)}
	metrics := make([]CardinalityMetric, 0, len(counts))
	total := 0
	for _, sc := range counts {
		total += sc.Count
		m := CardinalityMetric{Metric: sc.Metric, Count: sc.Count, Capped: sc.Capped}
		if limit > 0 {
			hp := float64(limit-sc.Count) / float64(limit) * 100
			switch {
			case hp < 0:
				hp = 0
			case hp > 100:
				hp = 100
			}
			m.HeadroomPct = hp
		}
		metrics = append(metrics, m)
	}
	v.TotalActiveSeries = total
	v.Metrics = metrics
	v.Offenders = cardinalityOffenders(metrics, limit)
	return v
}

// cardinalityOffenders picks the high-cardinality metrics worth flagging: any
// capped metric, plus (when a limit is configured) any metric at or above 80% of
// it. Returns nil when none qualify.
func cardinalityOffenders(metrics []CardinalityMetric, limit int) []CardinalityMetric {
	var out []CardinalityMetric
	for _, m := range metrics {
		if m.Capped || (limit > 0 && m.Count*5 >= limit*4) {
			out = append(out, m)
		}
	}
	return out
}
