package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCursorColdStartIsUsable(t *testing.T) {
	store := NewStore(t.TempDir())

	cur, err := store.LoadCursor("tenant-a", "insights-logs-microsoftgraphactivitylogs")
	if err != nil {
		t.Fatalf("LoadCursor() error = %v", err)
	}
	if cur.TenantID != "tenant-a" || cur.Key != "insights-logs-microsoftgraphactivitylogs" {
		t.Errorf("cold-start cursor = %+v, want the requested tenant/key", cur)
	}
	if cur.Offsets == nil {
		t.Error("cold-start cursor has a nil Offsets map; callers would panic writing to it")
	}
	if len(cur.Offsets) != 0 {
		t.Errorf("cold-start cursor has %d offsets, want 0", len(cur.Offsets))
	}
}

func TestSaveCursorRoundTrips(t *testing.T) {
	store := NewStore(t.TempDir())

	cur := &BlobCursor{
		TenantID: "tenant-a",
		Key:      "insights-logs-microsoftgraphactivitylogs",
		Offsets: map[string]int64{
			"tenantId=4b8c18bd/y=2026/m=07/d=16/h=13/m=00/PT1H.json": 6104227,
		},
	}
	if err := store.SaveCursor(cur); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}

	got, err := store.LoadCursor("tenant-a", "insights-logs-microsoftgraphactivitylogs")
	if err != nil {
		t.Fatalf("LoadCursor() error = %v", err)
	}
	if got.Offsets["tenantId=4b8c18bd/y=2026/m=07/d=16/h=13/m=00/PT1H.json"] != 6104227 {
		t.Errorf("round-tripped offsets = %v, want the saved byte offset", got.Offsets)
	}
	if got.Schema != schemaVersion {
		t.Errorf("Schema = %d, want %d (stamped on save so a format change is detectable)", got.Schema, schemaVersion)
	}
}

// A blob cursor and a window checkpoint for the same (tenant, key) string must
// not overwrite each other's file — they are different cursor kinds with
// different shapes.
func TestCursorAndCheckpointDoNotCollideOnDisk(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	if err := store.SaveCursor(&BlobCursor{
		TenantID: "tenant-a",
		Key:      "/auditLogs/signIns",
		Offsets:  map[string]int64{"blob": 1},
	}); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}
	if err := store.Save(&Checkpoint{
		TenantID: "tenant-a",
		Endpoint: "/auditLogs/signIns",
		SeenIDs:  NewSeenIDs(),
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	cur, err := store.LoadCursor("tenant-a", "/auditLogs/signIns")
	if err != nil {
		t.Fatalf("LoadCursor() error = %v", err)
	}
	if cur.Offsets["blob"] != 1 {
		t.Errorf("the window checkpoint clobbered the blob cursor: offsets = %v", cur.Offsets)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("checkpoint dir holds %v, want two distinct files", names)
	}
}

// A corrupt cursor file must surface as an error rather than decode into a
// zero cursor — silently restarting from offset 0 would re-emit up to 7 days of
// every blob, which is a duplicate storm, not a graceful degradation.
func TestLoadCursorRejectsACorruptFile(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cur := &BlobCursor{TenantID: "tenant-a", Key: "k", Offsets: map[string]int64{"b": 1}}
	if err := store.SaveCursor(cur); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	path := filepath.Join(dir, entries[0].Name())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := store.LoadCursor("tenant-a", "k"); err == nil {
		t.Fatal("LoadCursor() returned nil error on a corrupt file; the consumer would silently re-read every blob from 0")
	}
}
