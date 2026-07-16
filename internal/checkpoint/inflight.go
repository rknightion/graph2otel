package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// InFlightJob records a server-side async job that a collector created but had
// not finished consuming when the checkpoint was last written, so a restart can
// ADOPT it (resume polling the same id) instead of orphaning it and submitting a
// second one for the same work (#118).
//
// Why this is worth persisting: both async engines POST a job, then poll it to a
// terminal state. An audit-log query took over 10 minutes to reach `succeeded`
// live (#100) against a collector that polls every 30 minutes — so roughly a
// third of that cycle has a job in flight, and a redeploy landing in it re-creates
// against exactly the APIs that punish duplication (rapid audit-query creation
// returns 429, #98; the Intune reports-export API allows 48 req/min per app).
//
// This does NOT protect against data loss and must not be sold as if it does:
// the watermark deliberately does not advance on failure, so an orphaned job's
// window is retried in full on the next tick. What it saves is wasted calls,
// orphaned server-side jobs, and throttle pressure.
type InFlightJob struct {
	// ID is the server-side job/query id returned by the create call.
	ID string `json:"id"`
	// CreatedAt is when the job was created, by the engine's own clock. It is
	// what Expired bounds, so a dead job cannot wedge a collector forever.
	CreatedAt time.Time `json:"created_at"`
	// WindowFrom/WindowTo are the time window the job covers, for an engine whose
	// jobs are windowed (jobpipeline). Zero for an engine whose jobs are not
	// (exportjob, whose reports are snapshots — see Scope).
	WindowFrom time.Time `json:"window_from,omitzero"`
	WindowTo   time.Time `json:"window_to,omitzero"`
	// Scope identifies WHAT the job covers for an engine with no time window: a
	// fingerprint of the request that created it. Adopting a job whose request
	// no longer matches the one this tick would make (an upgrade changed the
	// report's columns, say) would silently return the old shape, so the two must
	// agree. Empty for a windowed engine.
	Scope string `json:"scope,omitempty"`
}

// Expired reports whether j is too old to adopt: a job that will never reach a
// terminal state (deleted server-side, or one whose status poll fails
// permanently) must not be re-polled forever, because a poll error is
// deliberately NOT treated as terminal — a transient 429/5xx on the status poll
// would otherwise orphan a perfectly healthy job, which is the bug this whole
// mechanism exists to prevent. Age is that escape hatch, so maxAge bounds how
// long a wedge can last.
//
// A maxAge of 0 disables expiry. A CreatedAt in the future (clock skew, a
// restored checkpoint) is treated as fresh rather than expired: refusing to
// adopt is the safe direction, but so is waiting, and treating skew as expiry
// would silently reintroduce the duplicate create.
func (j *InFlightJob) Expired(now time.Time, maxAge time.Duration) bool {
	if j == nil || maxAge <= 0 {
		return false
	}
	return now.Sub(j.CreatedAt) >= maxAge
}

// CoversWindow reports whether j's window is still the right one to adopt for a
// tick that would request [from, to].
//
// The rule is deliberately NOT window equality, and this is the subtle part.
// `to` is now-lag (collector/window.go), so it advances with wall-clock on every
// tick: a persisted job's window can never equal the next tick's window, and an
// equality check would mean the job is never adopted and this feature does
// nothing. So:
//
//   - `from` must match exactly. It is derived from the watermark, which does not
//     advance while a job is in flight — so a differing `from` means the watermark
//     moved on and the job is for a window already dealt with. Discard it.
//   - j's window must be a PREFIX of the requested one (WindowTo not after `to`).
//     Draining [from, WindowTo] and advancing the watermark only that far is
//     lossless and is exactly what the MaxWindow clamp already does: the remainder
//     is picked up by the next tick. A WindowTo BEYOND the requested `to` is not a
//     prefix — the clock went backwards or the config changed — so discard it
//     rather than advance the watermark past what this tick believes is safe.
func (j *InFlightJob) CoversWindow(from, to time.Time) bool {
	if j == nil {
		return false
	}
	return j.WindowFrom.Equal(from) && !j.WindowTo.After(to)
}

// JobRecord is the standalone durable record of one in-flight async job, for a
// collector that has no window checkpoint to hang an InFlightJob off of.
//
// The Intune reports-export collectors (internal/exportjob) are SNAPSHOT
// collectors: each tick re-derives the whole fleet's state from a fresh export,
// so there is no watermark, no overlap and no SeenIDs — nothing a Checkpoint is
// for. They still create a server-side job and poll it, though, which is the one
// thing they share with jobpipeline and the one thing worth persisting. Hence a
// separate, deliberately tiny record rather than a Checkpoint with every other
// field left zero.
type JobRecord struct {
	// Schema is the on-disk format version (see schemaVersion).
	Schema int `json:"schema"`
	// TenantID identifies the Entra tenant this record belongs to.
	TenantID string `json:"tenant_id"`
	// Key identifies the job namespace this record belongs to (e.g. an export
	// report name), forming the store key together with TenantID.
	Key string `json:"key"`
	// InFlight is the job awaiting adoption, or nil when none is outstanding.
	InFlight *InFlightJob `json:"in_flight,omitempty"`
}

// jobFileKey namespaces job records separately from window checkpoints and blob
// cursors, so a collector that creates jobs under name "x" and a window poller on
// endpoint "x" cannot overwrite each other's file with an incompatible shape.
func jobFileKey(tenantID, key string) string {
	return fileKey(tenantID, "jobrecord\x00"+key)
}

// LoadJob returns the persisted job record for (tenantID, key). A missing file
// is not an error: it returns an empty record (no job in flight) so cold start
// works.
//
// A corrupt file IS an error. The blast radius is smaller than a blob cursor's
// (worst case here is one duplicate export job), but a record that cannot be read
// also cannot be cleared, and silently starting from "no job in flight" on every
// tick would make the failure invisible — the exact silent degradation #117
// removed from the checkpoint dir.
func (s *Store) LoadJob(tenantID, key string) (*JobRecord, error) {
	fk := jobFileKey(tenantID, key)
	lock := s.keyLock(fk)
	lock.Lock()
	defer lock.Unlock()

	path := s.path(fk)
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from our own dir + a sanitized key, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return &JobRecord{Schema: schemaVersion, TenantID: tenantID, Key: key}, nil
		}
		return nil, fmt.Errorf("read job record %s: %w", path, err)
	}

	var rec JobRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("decode job record %s: %w", path, err)
	}
	return &rec, nil
}

// SaveJob persists rec atomically (temp file + rename), so a crash mid-write can
// never leave a partial record in place of the last good one. A rec with a nil
// InFlight is the normal way to clear a finished job: the file stays, empty.
func (s *Store) SaveJob(rec *JobRecord) error {
	fk := jobFileKey(rec.TenantID, rec.Key)
	lock := s.keyLock(fk)
	lock.Lock()
	defer lock.Unlock()

	if rec.Schema == 0 {
		rec.Schema = schemaVersion
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode job record: %w", err)
	}
	return s.writeAtomic(s.path(fk), data)
}
