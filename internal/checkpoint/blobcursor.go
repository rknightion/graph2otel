package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
)

// BlobCursor is the durable cursor for one (TenantID, Key) Azure Storage blob
// consumer, where Key is the container (or an explicit namespace when several
// collectors read one container).
//
// It is a byte offset per blob rather than a timestamp watermark, and that is
// forced by how Azure Monitor writes diagnostic-settings data (#89, verified
// live 2026-07-16): blobs are partitioned by EVENT time and Azure backfills
// history into already-closed hours progressively — an h=00 blob was still
// being appended to 13 hours after that hour closed. So "this hour is complete"
// is never true and a time watermark cannot express progress: it would either
// stall at the oldest still-growing hour or walk past records not yet written.
//
// A byte offset works precisely because the blobs are APPEND blobs: bytes once
// written never change, so an offset is monotonic and stable, and re-reading is
// structurally impossible rather than deduped after the fact. That is why this
// type carries no SeenIDs — the Graph-path Checkpoint needs them because a time
// re-query legitimately returns records it has already seen, and a byte range
// never does.
type BlobCursor struct {
	// Schema is the on-disk format version (see schemaVersion).
	Schema int `json:"schema"`
	// TenantID identifies the Entra tenant this cursor belongs to.
	TenantID string `json:"tenant_id"`
	// Key identifies the container/namespace this cursor belongs to (e.g.
	// "insights-logs-microsoftgraphactivitylogs"), forming the store key
	// together with TenantID.
	Key string `json:"key"`
	// Offsets maps a blob's name to the number of bytes of it already emitted.
	// Bounded by the storage account's lifecycle rule (~168 hourly blobs per
	// category at the 7-day retention #89 provisions), because Poll prunes
	// entries for blobs that no longer exist.
	Offsets map[string]int64 `json:"offsets"`
}

// cursorFileKey namespaces blob cursors separately from window checkpoints, so
// a collector reading container "x" and a window poller on endpoint "x" cannot
// overwrite each other's file with an incompatible shape.
func cursorFileKey(tenantID, key string) string {
	return fileKey(tenantID, "blobcursor\x00"+key)
}

// LoadCursor returns the persisted blob cursor for (tenantID, key). A missing
// file is not an error: it returns a usable empty cursor so cold start works.
//
// A corrupt file IS an error, deliberately: unlike a window checkpoint (whose
// worst case is one cold-start re-query), silently starting a blob consumer
// from offset 0 would re-emit every byte of every retained blob — up to a
// week of records per category. That is a duplicate storm, so it must surface
// rather than degrade.
func (s *Store) LoadCursor(tenantID, key string) (*BlobCursor, error) {
	fk := cursorFileKey(tenantID, key)
	lock := s.keyLock(fk)
	lock.Lock()
	defer lock.Unlock()

	path := s.path(fk)
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from our own dir + a sanitized key, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return &BlobCursor{
				Schema:   schemaVersion,
				TenantID: tenantID,
				Key:      key,
				Offsets:  map[string]int64{},
			}, nil
		}
		return nil, fmt.Errorf("read blob cursor %s: %w", path, err)
	}

	var cur BlobCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		return nil, fmt.Errorf("decode blob cursor %s: %w", path, err)
	}
	if cur.Offsets == nil {
		cur.Offsets = map[string]int64{}
	}
	return &cur, nil
}

// SaveCursor persists cur atomically (temp file + rename), so a crash mid-write
// can never leave a partial cursor in place of the last good one.
func (s *Store) SaveCursor(cur *BlobCursor) error {
	fk := cursorFileKey(cur.TenantID, cur.Key)
	lock := s.keyLock(fk)
	lock.Lock()
	defer lock.Unlock()

	if cur.Schema == 0 {
		cur.Schema = schemaVersion
	}
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return fmt.Errorf("encode blob cursor: %w", err)
	}
	return s.writeAtomic(s.path(fk), data)
}
