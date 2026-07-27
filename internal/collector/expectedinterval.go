package collector

import (
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricCollectorExpectedInterval is the effective poll interval, in seconds,
// the scheduler uses for each registered collector (#299). It is a gauge, and
// deliberately NON-ADDITIVE — semconv.UnitSeconds already classifies "s" that
// way in internal/semconv/additive.go, so no per-metric entry is needed there,
// but TestEveryEmittedUnitIsClassifiedForAdditivity (cmd/graph2otel) still
// gates it: a future unit change that left this unclassified would fail loud,
// not silently drop the tail.
const MetricCollectorExpectedInterval = "graph2otel.collector.expected_interval"

const (
	expectedIntervalUnit = semconv.UnitSeconds
	expectedIntervalDesc = "Effective poll interval, in seconds, the scheduler uses for each " +
		"registered collector — the value actually applied after a non-positive " +
		"override fell back to the collector's own default, never the raw config value."
)

// EmitExpectedIntervals publishes the complete current set of effective poll
// intervals for every collector registered in r, one series per collector,
// matching how graph2otel.collector.availability is stamped
// (internal/availability.Tracker.Emit is the reference shape): the point
// attributes here carry ONLY the collector identity, and tenant_id is applied
// at the emitter boundary by telemetry.WithTenant — this method never sets it
// itself. An empty tenantID omits the tenant label, the same passthrough
// WithTenant documents for a single-tenant deploy.
//
// Entry.Interval is already resolved by Register/RegisterWindow (collector.go:
// a non-positive override falls back to the collector's DefaultInterval), so
// the reported value is exactly what the scheduler will use, never the raw
// config override.
//
// Unlike availability's Tracker this needs no periodic re-emission: a
// collector's effective interval is fixed for the life of the process (a
// config change takes effect only on restart), so there is nothing to refresh.
// GaugeSnapshot registers an OBSERVABLE gauge whose callback keeps reporting
// this exact snapshot on every export interval on its own (see
// telemetry.Emitter.GaugeSnapshot). Calling this with an empty registry (or a
// registry a collector has been removed from) clears its series entirely —
// GaugeSnapshot's documented way to drop a series — rather than leaving a
// stale value behind, which is the explicit, non-accidental outcome for a
// deliberately removed collector.
func (r *Registry) EmitExpectedIntervals(e telemetry.Emitter, tenantID string) {
	entries := r.Entries()
	points := make([]telemetry.GaugePoint, 0, len(entries))
	for _, entry := range entries {
		points = append(points, telemetry.GaugePoint{
			Value: entry.Interval.Seconds(),
			Attrs: telemetry.Attrs{
				semconv.AttrCollector: entry.Collector.Name(),
			},
		})
	}
	telemetry.WithTenant(e, tenantID).GaugeSnapshot(
		MetricCollectorExpectedInterval,
		expectedIntervalUnit,
		expectedIntervalDesc,
		points,
	)
}
