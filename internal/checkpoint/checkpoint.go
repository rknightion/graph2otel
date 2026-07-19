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
//
// When to bump it, because this is easy to get wrong in both directions:
// version an INCOMPATIBLE change — a field whose meaning, units or type
// changed, a rename, a removal, anything a reader could misinterpret. Do NOT
// version an ADDITIVE, OPTIONAL field. Adding one is compatible in both
// directions already: a new binary reading an old file sees the field absent and
// falls back, and an old binary reading a new file ignores it (encoding/json
// drops unknown fields) and degrades to its previous behavior. Bumping for an
// additive field would signal an incompatible layout to a future reader that
// gates on this number, which is a lie that costs a needless migration path.
//
// InFlight (#118) is exactly that additive/optional case, so it did NOT bump
// this — see TestCheckpointSchemaBackwardTolerance and
// TestCheckpointSchemaForwardTolerance, which pin both directions of that claim.
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
	// InFlight is the server-side async job this poller created but had not
	// finished consuming when the checkpoint was last written, so a restart can
	// adopt it rather than orphan it and submit a second one (#118). Nil — and
	// omitted from the file — for every collector on the plain paged-GET engine
	// (logpipeline), which creates no jobs at all.
	InFlight *InFlightJob `json:"in_flight,omitempty"`
	// ParseHealth is the mdca.discovery_parse collector's extra durable state
	// (#145): the last successful parse time per input stream, kept so the
	// last_success age gauge keeps climbing when uploads STOP — the alert-on-
	// silence signal a failure counter structurally cannot produce (a dead
	// uploader emits no failed tasks either). Nil — and omitted from the file —
	// for every other collector, the same family-specific-optional-state pattern
	// as InFlight. It is deliberately NOT evicted with SeenIDs: it must survive
	// however long a pipeline stays silent.
	ParseHealth *ParseHealth `json:"parse_health,omitempty"`
}

// ParseHealth carries the mdca.discovery_parse collector's parse-health cursor
// (#145). It is separate from Watermark/SeenIDs because it answers a different
// question — "how did each stream last parse" — and must outlive the overlap
// window that EvictStale bounds SeenIDs to, so a gauge derived from it keeps
// reporting when a stream goes silent (the alert-on-silence signal).
type ParseHealth struct {
	// Streams maps an MDCA inputStreamId to its last successful parse. Streams
	// are single-digit per tenant, so this map is bounded by tenant shape, not by
	// tenant size (#112).
	Streams map[string]StreamHealth `json:"streams"`
}

// StreamHealth is the last successful DiscoveryParseLogTask observed for one
// Cloud Discovery input stream. Persisting the counts (not just the time) keeps
// the transactions/cloud_services gauges STABLE across quiet ticks rather than
// flapping to absent whenever a window carries no new success.
type StreamHealth struct {
	// LastSuccess is the event time of the most recent successful parse.
	LastSuccess time.Time `json:"last_success"`
	// LastTransactions / LastCloudServices are that parse's discovered counts,
	// from templateMessage.parameters.
	LastTransactions  int64 `json:"last_transactions"`
	LastCloudServices int64 `json:"last_cloud_services"`
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
