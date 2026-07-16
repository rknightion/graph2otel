package checkpoint

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store is a file-based CheckpointStore rooted at a directory (config's
// CheckpointDir, #2), with one JSON file per (tenantID, endpoint). It is
// safe for concurrent use by multiple WindowCollectors polling different
// endpoints on their own goroutines.
type Store struct {
	dir string

	mu    sync.Mutex // guards locks
	locks map[string]*sync.Mutex
}

// NewStore returns a Store rooted at dir. dir need not exist yet: Save
// creates it (and any missing parents) on first write.
func NewStore(dir string) *Store {
	return &Store{
		dir:   dir,
		locks: make(map[string]*sync.Mutex),
	}
}

// Verify reports whether the checkpoint directory is usable, creating it (and
// any missing parents) if it does not exist. It is meant to be called ONCE at
// startup, before any collector runs, and to abort the process on failure.
//
// Why this exists rather than letting Save fail (#117): Save's failure is
// caught by the scheduler, logged at Warn, and the tick continues — so an
// unwritable checkpoint dir degrades SILENTLY. The watermark never persists,
// every window collector re-polls its InitialLookback window on every cycle
// forever, and the only symptom is duplicate log records in the backend and a
// Warn line nobody reads. That is a bad failure mode for a security-posture
// exporter, and the shipped docker-compose reference hit it from day one:
// read_only:true plus a relative checkpoint_dir means there is no writable
// path at all.
//
// The probe is a real write-then-remove rather than a mode-bit inspection,
// because the failure modes that matter here (a root-owned bind mount under
// `user: 65532`, a read-only rootfs, a full or read-only volume) are not all
// visible in the mode bits alone.
func (s *Store) Verify() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("checkpoint dir %q is not creatable (window collectors cannot persist their watermark; "+
			"mount a writable volume there and ensure it is owned by the container's user): %w", s.dir, err)
	}

	probe := filepath.Join(s.dir, ".writable-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("checkpoint dir %q is not writable (window collectors cannot persist their watermark, so "+
			"every restart would re-poll and re-emit duplicate logs; ensure the mounted path is owned by the "+
			"container's user, e.g. chown 65532:65532): %w", s.dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("checkpoint dir %q: probe file %q could not be removed: %w", s.dir, probe, err)
	}
	return nil
}

// keyLock returns the mutex guarding key's file, creating one on first use.
// Per-key (rather than a single store-wide) locking lets collectors on
// different endpoints Save/Load without blocking on each other.
func (s *Store) keyLock(key string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.locks[key]
	if !ok {
		l = &sync.Mutex{}
		s.locks[key] = l
	}
	return l
}

// Load returns the persisted checkpoint for (tenantID, endpoint). A missing
// file is not an error: it returns a usable initial checkpoint (zero
// watermark, empty SeenIDs) so cold start works. An error is returned only
// for a real IO or decode failure.
func (s *Store) Load(tenantID, endpoint string) (*Checkpoint, error) {
	key := fileKey(tenantID, endpoint)
	lock := s.keyLock(key)
	lock.Lock()
	defer lock.Unlock()

	path := s.path(key)
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from our own dir + a sanitized key, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return &Checkpoint{
				Schema:   schemaVersion,
				TenantID: tenantID,
				Endpoint: endpoint,
				SeenIDs:  NewSeenIDs(),
			}, nil
		}
		return nil, fmt.Errorf("read checkpoint %s: %w", path, err)
	}

	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("decode checkpoint %s: %w", path, err)
	}
	if cp.SeenIDs == nil {
		cp.SeenIDs = NewSeenIDs()
	}
	return &cp, nil
}

// Save persists cp atomically: it writes a temp file in the same directory
// then renames it over the target, so a crash mid-write can never leave a
// corrupt or partial checkpoint in place of the last good one.
func (s *Store) Save(cp *Checkpoint) error {
	key := fileKey(cp.TenantID, cp.Endpoint)
	lock := s.keyLock(key)
	lock.Lock()
	defer lock.Unlock()

	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("create checkpoint dir %s: %w", s.dir, err)
	}

	if cp.Schema == 0 {
		cp.Schema = schemaVersion
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}

	return s.writeAtomic(s.path(key), data)
}

// writeAtomic writes data to path via a temp file in the same directory
// followed by a rename, so a crash mid-write can never leave a corrupt or
// partial file in place of the last good one. It creates the store's directory
// on first use. Callers must hold the key's lock.
func (s *Store) writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("create checkpoint dir %s: %w", s.dir, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp checkpoint %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename checkpoint %s to %s: %w", tmp, path, err)
	}
	return nil
}

func (s *Store) path(key string) string {
	return filepath.Join(s.dir, key+".json")
}

// fileKey derives a filesystem-safe, human-inspectable name for a
// (tenantID, endpoint) pair: each component has every non
// alphanumeric/hyphen/underscore rune (notably "/" in endpoints like
// "/auditLogs/signIns") replaced with "_", joined by "__", with an 8-byte
// sha256 hex suffix of the original (unsanitized) pair to keep otherwise
// colliding sanitized names (e.g. two endpoints differing only in a
// replaced character) distinct.
func fileKey(tenantID, endpoint string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + endpoint))
	return fmt.Sprintf("%s__%s__%x", sanitize(tenantID), sanitize(endpoint), sum[:8])
}

func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
