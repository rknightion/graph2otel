package availability

import (
	"slices"
	"sync"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricCollectorAvailability is the tenant-scoped current availability
// snapshot for every configured logical collector.
const MetricCollectorAvailability = "graph2otel.collector.availability"

const (
	collectorAvailabilityUnit = "{collector}"
	collectorAvailabilityDesc = "Current bounded availability state for each logical collector."
)

// Tracker owns one tenant's immutable logical collector census and the latest
// completed run summary for each member. Static decisions never change after
// construction; completed runs are recorded independently under a lock.
type Tracker struct {
	tenantID string
	static   []Static
	names    map[string]struct{}

	mu       sync.RWMutex
	outcomes map[string]recordoutcome.Summary
}

// NewTracker returns a concurrency-safe availability tracker for one tenant.
// The initial census and its bounded detail slices are copied and sorted by
// collector name. Duplicate collector names collapse to one logical point.
func NewTracker(tenantID string, initial []Static) *Tracker {
	static := make([]Static, 0, len(initial))
	names := make(map[string]struct{}, len(initial))
	for _, decision := range initial {
		if _, exists := names[decision.Collector]; exists {
			continue
		}
		decision.Limitations = slices.Clone(decision.Limitations)
		decision.MissingCapabilities = slices.Clone(decision.MissingCapabilities)
		static = append(static, decision)
		names[decision.Collector] = struct{}{}
	}
	slices.SortFunc(static, func(a, b Static) int {
		switch {
		case a.Collector < b.Collector:
			return -1
		case a.Collector > b.Collector:
			return 1
		default:
			return 0
		}
	})
	return &Tracker{
		tenantID: tenantID,
		static:   static,
		names:    names,
		outcomes: make(map[string]recordoutcome.Summary, len(static)),
	}
}

// Record stores the latest completed run summary for a logical collector.
// Names outside the immutable census are ignored.
func (t *Tracker) Record(name string, summary recordoutcome.Summary) {
	if t == nil {
		return
	}
	if _, exists := t.names[name]; !exists {
		return
	}
	t.mu.Lock()
	t.outcomes[name] = summary
	t.mu.Unlock()
}

// Snapshot derives a deterministic immutable availability point slice from the
// static census and the latest completed runs.
func (t *Tracker) Snapshot() []Point {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	outcomes := make(map[string]recordoutcome.Summary, len(t.outcomes))
	for name, summary := range t.outcomes {
		outcomes[name] = summary
	}
	t.mu.RUnlock()

	points := make([]Point, 0, len(t.static))
	for _, decision := range t.static {
		var summary *recordoutcome.Summary
		if outcome, ok := outcomes[decision.Collector]; ok {
			summary = &outcome
		}
		points = append(points, Derive(decision, summary))
	}
	return points
}

// Emit publishes the complete current collector availability set. Tenant
// scoping is applied only at the telemetry emitter boundary, so the four
// availability-specific attributes remain exact and the shared observable
// gauge keeps different tenants in separate snapshot partitions.
func (t *Tracker) Emit(e telemetry.Emitter) {
	if t == nil {
		return
	}
	snapshot := t.Snapshot()
	points := make([]telemetry.GaugePoint, 0, len(snapshot))
	for _, point := range snapshot {
		points = append(points, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{
				semconv.AttrCollector:          point.Collector,
				semconv.AttrCollectorTransport: string(point.Transport),
				semconv.AttrState:              string(point.State),
				semconv.AttrReason:             string(point.Reason),
			},
		})
	}
	telemetry.WithTenant(e, t.tenantID).GaugeSnapshot(
		MetricCollectorAvailability,
		collectorAvailabilityUnit,
		collectorAvailabilityDesc,
		points,
	)
}
