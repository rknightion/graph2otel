package collector

import "time"

// Checkpoint-state kinds. They select which fields of a CheckpointState carry
// meaning: a window poller has a Watermark; a blob consumer has a byte offset.
const (
	// CheckpointKindWindow is a watermark-based window poller (logpipeline,
	// jobpipeline, o365pipeline): its durable progress is a timestamp plus a
	// bounded dedupe set, and optionally an adopted in-flight async job id.
	CheckpointKindWindow = "window"
	// CheckpointKindBlob is an Azure Storage byte-offset consumer (blobpipeline):
	// its durable progress is a byte offset per blob, not a timestamp (see
	// checkpoint.BlobCursor for why a watermark cannot express it).
	CheckpointKindBlob = "blob"
)

// CheckpointState is a read-only snapshot of one collector's durable checkpoint
// progress, surfaced on the admin status page so an operator can see "is it
// keeping up", not just "is it registered" (#178 Part B). It is loaded fresh
// from the checkpoint store at render time and never mutated — the admin page
// has no control-plane authority.
//
// Kind selects which fields are populated; the zero value of the others is not
// meaningful. This is ops visibility over an internal page, not OTLP: a
// watermark, a byte offset and a job id are fine to show, but it deliberately
// carries no per-entity detail.
type CheckpointState struct {
	// Kind is one of the CheckpointKind* constants.
	Kind string

	// Window fields (CheckpointKindWindow).

	// Watermark is the last fully-processed event timestamp. Zero on a cold
	// start (no window drained yet).
	Watermark time.Time
	// SeenIDs is how many event ids the collector is holding in its overlap
	// dedupe set — a cheap read of len(Checkpoint.SeenIDs).
	SeenIDs int
	// InFlightJob is the id of a server-side async job this poller created but
	// had not finished consuming (jobpipeline). Empty when none is outstanding.
	InFlightJob string

	// Blob fields (CheckpointKindBlob).

	// ByteOffset is the total bytes consumed across every tracked blob (the sum
	// of the cursor's per-blob offsets).
	ByteOffset int64
	// BlobsTracked is how many blobs have a saved offset (bounded by the storage
	// account's retention lifecycle).
	BlobsTracked int
	// NewestBlob is the lexically-greatest tracked blob name — the newest hour
	// consumed, since the blobs are hour-partitioned by an ordered path.
	NewestBlob string
}

// CheckpointReporter is implemented by a collector that persists a durable
// cursor and can report it read-only. Only the engine that owns the cursor
// knows its checkpoint key, so the engine implements this (it reads its own
// checkpoint.Store with its own key); a collector that persists nothing does
// not implement it.
type CheckpointReporter interface {
	// CheckpointState returns the collector's current durable state, or nil when
	// there is nothing to show (no cursor persisted yet, or a read failed — the
	// page shows nothing rather than erroring, and a genuine load failure already
	// surfaces as the collector's own run error).
	CheckpointState() *CheckpointState
}

// CheckpointStateOf returns c's checkpoint state if it is a CheckpointReporter,
// else nil. It is how the admin status page reads each collector's durable
// cursor at render time (#178) without a second, drift-prone source of truth —
// the same shape as TransportOf.
func CheckpointStateOf(c Collector) *CheckpointState {
	if r, ok := c.(CheckpointReporter); ok {
		return r.CheckpointState()
	}
	return nil
}
