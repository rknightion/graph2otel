// Package checkpoint persists, per (tenant, endpoint), the durable cursor a
// WindowCollector needs to resume polling a log-shaped Graph endpoint across
// restarts without gapping or duplicating events.
//
// None of the log-shaped Graph endpoints (signIns, directoryAudits,
// provisioning, riskDetections, riskyUsers, Intune auditEvents) support a
// delta query, so graph2otel owns the watermark itself. Events can also
// arrive out of order, so a bare high-water mark would silently drop data —
// a Checkpoint instead carries a watermark, an overlap window to re-query on
// restart, and a bounded set of recently-seen ids to dedupe that overlap.
package checkpoint

import "time"

// schemaVersion identifies the on-disk Checkpoint layout, so a future format
// change can detect and migrate (or reject) an older file instead of
// silently misinterpreting it.
const schemaVersion = 1

// Checkpoint is the durable cursor for one (TenantID, Endpoint) window
// poller.
type Checkpoint struct {
	// Schema is the on-disk format version (see schemaVersion).
	Schema int `json:"schema"`
	// TenantID identifies the Entra tenant this checkpoint belongs to.
	TenantID string `json:"tenant_id"`
	// Endpoint identifies the Graph endpoint this checkpoint belongs to
	// (e.g. "/auditLogs/signIns"), forming the namespace key together with
	// TenantID.
	Endpoint string `json:"endpoint"`
	// Watermark is the last fully-processed event timestamp, minus a safety
	// lag applied by the caller (#13). On restart, polling resumes from
	// Watermark - OverlapWindow rather than from Watermark itself, so an
	// event that was still landing out of order at the last poll is not
	// missed.
	Watermark time.Time `json:"watermark"`
	// OverlapWindow is how far behind Watermark a restart re-queries, to
	// catch events that arrived out of order. SeenIDs makes that re-query
	// idempotent.
	OverlapWindow time.Duration `json:"overlap_window"`
	// SeenIDs is the bounded set of event ids observed within the current
	// overlap window, used to dedupe the re-queried range on restart.
	SeenIDs SeenIDs `json:"seen_ids"`
}

// EvictStale prunes SeenIDs entries older than Watermark - OverlapWindow,
// keeping the set bounded to the current overlap window rather than growing
// unboundedly on a busy tenant.
func (cp *Checkpoint) EvictStale() {
	cp.SeenIDs.Evict(cp.Watermark.Add(-cp.OverlapWindow))
}

// SeenIDs is a bounded set of event ids, each recorded with the event
// timestamp it was seen at so it can be evicted once that timestamp falls
// outside the overlap window (see Evict).
type SeenIDs map[string]time.Time

// NewSeenIDs returns an empty SeenIDs set.
func NewSeenIDs() SeenIDs {
	return make(SeenIDs)
}

// Add records id as seen at eventTime.
func (s SeenIDs) Add(id string, eventTime time.Time) {
	s[id] = eventTime
}

// Has reports whether id has been recorded.
func (s SeenIDs) Has(id string) bool {
	_, ok := s[id]
	return ok
}

// Evict removes every id whose recorded event time is strictly before
// horizon, bounding the set's growth to whatever falls within the overlap
// window.
func (s SeenIDs) Evict(horizon time.Time) {
	for id, t := range s {
		if t.Before(horizon) {
			delete(s, id)
		}
	}
}
