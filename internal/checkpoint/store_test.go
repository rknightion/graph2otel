package checkpoint

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	store := NewStore(t.TempDir())
	watermark := time.Date(2026, 7, 15, 9, 30, 0, 0, time.UTC)

	want := &Checkpoint{
		TenantID:      "tenant-a",
		Endpoint:      "/auditLogs/signIns",
		Watermark:     watermark,
		OverlapWindow: 4 * time.Hour,
		SeenIDs:       NewSeenIDs(),
	}
	want.SeenIDs.Add("event-1", watermark.Add(-time.Minute))

	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := store.Load("tenant-a", "/auditLogs/signIns")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !got.Watermark.Equal(want.Watermark) {
		t.Errorf("Watermark = %v, want %v", got.Watermark, want.Watermark)
	}
	if got.OverlapWindow != want.OverlapWindow {
		t.Errorf("OverlapWindow = %v, want %v", got.OverlapWindow, want.OverlapWindow)
	}
	if got.TenantID != want.TenantID || got.Endpoint != want.Endpoint {
		t.Errorf("TenantID/Endpoint = %q/%q, want %q/%q", got.TenantID, got.Endpoint, want.TenantID, want.Endpoint)
	}
	if !got.SeenIDs.Has("event-1") {
		t.Error("SeenIDs.Has(\"event-1\") = false after round-trip, want true")
	}
}

func TestStoreLoadMissingKeyReturnsInitialCheckpoint(t *testing.T) {
	store := NewStore(t.TempDir())

	cp, err := store.Load("tenant-x", "/auditLogs/directoryAudits")
	if err != nil {
		t.Fatalf("Load() on missing key error = %v, want nil (cold start must not error)", err)
	}
	if cp == nil {
		t.Fatal("Load() on missing key = nil, want a usable initial checkpoint")
	}
	if !cp.Watermark.IsZero() {
		t.Errorf("Watermark = %v, want zero value on cold start", cp.Watermark)
	}
	if cp.SeenIDs == nil {
		t.Error("SeenIDs = nil, want an initialized (empty) set")
	}
	if cp.TenantID != "tenant-x" || cp.Endpoint != "/auditLogs/directoryAudits" {
		t.Errorf("TenantID/Endpoint = %q/%q, want tenant-x//auditLogs/directoryAudits", cp.TenantID, cp.Endpoint)
	}
}

func TestStoreNamespacesByTenantAndEndpoint(t *testing.T) {
	store := NewStore(t.TempDir())

	save := func(tenantID, endpoint string, wm time.Time) {
		t.Helper()
		cp := &Checkpoint{TenantID: tenantID, Endpoint: endpoint, Watermark: wm, SeenIDs: NewSeenIDs()}
		if err := store.Save(cp); err != nil {
			t.Fatalf("Save(%q, %q) error = %v", tenantID, endpoint, err)
		}
	}

	wmA1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wmA2 := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	wmB1 := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)

	// Same tenant, two endpoints.
	save("tenant-a", "/auditLogs/signIns", wmA1)
	save("tenant-a", "/auditLogs/directoryAudits", wmA2)
	// Same endpoint, two tenants.
	save("tenant-b", "/auditLogs/signIns", wmB1)

	got, err := store.Load("tenant-a", "/auditLogs/signIns")
	if err != nil {
		t.Fatalf("Load(tenant-a, signIns) error = %v", err)
	}
	if !got.Watermark.Equal(wmA1) {
		t.Errorf("tenant-a/signIns watermark = %v, want %v", got.Watermark, wmA1)
	}

	got, err = store.Load("tenant-a", "/auditLogs/directoryAudits")
	if err != nil {
		t.Fatalf("Load(tenant-a, directoryAudits) error = %v", err)
	}
	if !got.Watermark.Equal(wmA2) {
		t.Errorf("tenant-a/directoryAudits watermark = %v, want %v", got.Watermark, wmA2)
	}

	got, err = store.Load("tenant-b", "/auditLogs/signIns")
	if err != nil {
		t.Fatalf("Load(tenant-b, signIns) error = %v", err)
	}
	if !got.Watermark.Equal(wmB1) {
		t.Errorf("tenant-b/signIns watermark = %v, want %v", got.Watermark, wmB1)
	}
}

// TestStoreCrashMidWriteLeavesPriorCheckpointIntact simulates a crash between
// writing the temp file and the rename: a stray .tmp file must not corrupt or
// replace the last successfully-saved checkpoint.
func TestStoreCrashMidWriteLeavesPriorCheckpointIntact(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	good := &Checkpoint{
		TenantID:  "tenant-a",
		Endpoint:  "/auditLogs/signIns",
		Watermark: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SeenIDs:   NewSeenIDs(),
	}
	if err := store.Save(good); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Simulate a crashed writer: drop a stray temp file for the same key
	// without renaming it over the real checkpoint file.
	key := fileKey(good.TenantID, good.Endpoint)
	tmp := filepath.Join(dir, key+".json.tmp")
	if err := os.WriteFile(tmp, []byte("not valid json {{{"), 0o600); err != nil {
		t.Fatalf("write stray temp file: %v", err)
	}

	got, err := store.Load(good.TenantID, good.Endpoint)
	if err != nil {
		t.Fatalf("Load() error = %v after stray temp file, want the prior good checkpoint", err)
	}
	if !got.Watermark.Equal(good.Watermark) {
		t.Errorf("Watermark = %v, want %v (prior checkpoint untouched by stray temp file)", got.Watermark, good.Watermark)
	}
}

func TestStoreConcurrentSaveLoadAcrossKeysIsRaceClean(t *testing.T) {
	store := NewStore(t.TempDir())
	const goroutines = 8
	const itersPerGoroutine = 20

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tenantID := "tenant"
			endpoint := filepath.Join("/endpoint", string(rune('a'+n)))
			for j := 0; j < itersPerGoroutine; j++ {
				cp := &Checkpoint{
					TenantID:  tenantID,
					Endpoint:  endpoint,
					Watermark: time.Now(),
					SeenIDs:   NewSeenIDs(),
				}
				if err := store.Save(cp); err != nil {
					t.Errorf("Save() error = %v", err)
					return
				}
				if _, err := store.Load(tenantID, endpoint); err != nil {
					t.Errorf("Load() error = %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
