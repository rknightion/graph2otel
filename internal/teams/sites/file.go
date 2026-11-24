package sites

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// File provides immutable snapshots of a tenant's CSV table. The zero value is
// disabled. A File must not be copied after first use.
//
// Callers control the reload cadence; File does not start a watcher.
type File struct {
	path   string
	active atomic.Pointer[Table]

	mu     sync.Mutex // allows only one reload at a time
	digest [sha256.Size]byte
}

// Open loads and validates the file synchronously. An empty path disables site
// mapping. An unreadable or invalid configured file is a startup error.
func Open(path string) (*File, error) {
	f := &File{path: path}
	if err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reload reads the configured file and publishes a new snapshot only if its
// contents changed and it passed validation. If reading or parsing fails,
// Reload returns the error and keeps the last good snapshot.
// Write updates by replacing the file atomically, not by truncating it in place.
func (f *File) Reload() error {
	if f.path == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("read Teams sites file: %w", err)
	}
	digest := sha256.Sum256(data)
	if f.active.Load() != nil && digest == f.digest {
		return nil
	}
	table, err := parseTable(data)
	if err != nil {
		return fmt.Errorf("invalid Teams sites file: %w", err)
	}
	f.digest = digest
	f.active.Store(table)
	return nil
}

// Snapshot returns the current table (nil when disabled). Keep one snapshot
// for a batch of lookups so a reload cannot change the mapping mid-batch.
func (f *File) Snapshot() *Table {
	return f.active.Load()
}
