// Package collector defines the pluggable data-source model: the Collector
// interfaces every source implements, a Registry of enabled collectors, the
// checkpoint store for time-window pollers, and the Scheduler that drives them.
package collector

import (
	"context"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Collector is implemented by every Graph API data source (Entra ID and
// Intune alike).
type Collector interface {
	// Name is a stable identifier (e.g. "devices", "auditlogs"). Used in
	// self-observability attributes and as the checkpoint key.
	Name() string
	// DefaultInterval is the suggested poll cadence; config may override it.
	DefaultInterval() time.Duration
}

// SnapshotCollector fetches the current state on each tick (directory
// objects, device compliance, license SKUs, and other inventory-shaped data).
type SnapshotCollector interface {
	Collector
	Collect(ctx context.Context, e telemetry.Emitter) error
}

// WindowCollector fetches a time window [from, to] on each tick (sign-in
// logs, directory audits, Intune audit events, and other event-stream data
// with no Graph delta-query support). It returns the high-water mark actually
// consumed so the scheduler can persist it as the next window's start.
type WindowCollector interface {
	Collector
	CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (highWaterMark time.Time, err error)
	// Lag is the trailing safety margin; the scheduler sets to = now - Lag()
	// so it never queries up to "now" (where late records may still arrive).
	Lag() time.Duration
}

// Entry is a registered collector with its resolved poll interval. The window
// fields apply only to WindowCollectors.
type Entry struct {
	Collector       Collector
	Interval        time.Duration
	InitialLookback time.Duration // cold-start lookback (window collectors)
	MaxWindow       time.Duration // per-tick window cap (window collectors)
}

// Registry holds the enabled collectors to run.
type Registry struct {
	entries []Entry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a snapshot collector with the given interval. A non-positive
// interval falls back to the collector's DefaultInterval.
//
// The parameter is the typed SnapshotCollector (not the base Collector) so a
// collector that fails to implement Collect — wrong receiver, missing method —
// is a COMPILE error here rather than a silent no-op that still reports
// scrape.success=1 every tick. This mirrors RegisterWindow's WindowCollector
// guarantee and makes the scheduler's "neither interface" branch defensive-only
// (#58).
func (r *Registry) Register(c SnapshotCollector, interval time.Duration) {
	if interval <= 0 {
		interval = c.DefaultInterval()
	}
	r.entries = append(r.entries, Entry{Collector: c, Interval: interval})
}

// RegisterWindow adds a window collector with its interval and window bounds.
// A non-positive interval falls back to the collector's DefaultInterval.
func (r *Registry) RegisterWindow(c WindowCollector, interval, initialLookback, maxWindow time.Duration) {
	if interval <= 0 {
		interval = c.DefaultInterval()
	}
	r.entries = append(r.entries, Entry{
		Collector:       c,
		Interval:        interval,
		InitialLookback: initialLookback,
		MaxWindow:       maxWindow,
	})
}

// Entries returns the registered collectors in registration order.
func (r *Registry) Entries() []Entry { return r.entries }
