package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestStoreSaveLoadParseHealthRoundTrip(t *testing.T) {
	store := NewStore(t.TempDir())
	watermark := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	lastSuccess := watermark.Add(-3 * time.Minute)

	want := &Checkpoint{
		TenantID:      "tenant-a",
		Endpoint:      "/api/v1/governance#mdca.discovery_parse",
		Watermark:     watermark,
		OverlapWindow: 30 * time.Minute,
		SeenIDs:       NewSeenIDs(),
		ParseHealth: &ParseHealth{
			Streams: map[string]StreamHealth{"stream-1": {
				LastSuccess:       lastSuccess,
				LastTransactions:  21559,
				LastCloudServices: 70,
			}},
		},
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load("tenant-a", "/api/v1/governance#mdca.discovery_parse")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.ParseHealth == nil {
		t.Fatal("ParseHealth = nil after round-trip, want the persisted state")
	}
	sh, ok := got.ParseHealth.Streams["stream-1"]
	if !ok {
		t.Fatalf("ParseHealth.Streams[stream-1] missing after round-trip")
	}
	if !sh.LastSuccess.Equal(lastSuccess) || sh.LastTransactions != 21559 || sh.LastCloudServices != 70 {
		t.Errorf("StreamHealth = %+v, want {%v 21559 70}", sh, lastSuccess)
	}
}

// TestCheckpointParseHealthOmittedWhenNil pins that a non-MDCA collector's
// checkpoint file carries no parse_health key — the omitempty contract that
// keeps this MDCA-specific state invisible to every other collector, exactly as
// InFlight is omitted for non-job collectors.
func TestCheckpointParseHealthOmittedWhenNil(t *testing.T) {
	cp := &Checkpoint{TenantID: "t", Endpoint: "/auditLogs/signIns", SeenIDs: NewSeenIDs()}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(b), "parse_health") {
		t.Errorf("nil ParseHealth serialized a parse_health key: %s", b)
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

// TestVerifyCreatesDirAndSucceedsWhenWritable asserts Verify is a usable
// startup gate: it creates a missing checkpoint dir and reports success,
// leaving no probe file behind.
func TestVerifyCreatesDirAndSucceedsWhenWritable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "checkpoints")
	s := NewStore(dir)

	if err := s.Verify(); err != nil {
		t.Fatalf("Verify on a writable parent: %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("Verify did not create %s: err=%v", dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Verify left %d file(s) behind, want none: %v", len(entries), entries)
	}
}

// TestVerifyFailsActionablyWhenNotWritable is the whole point of #117: a
// read-only or wrong-owner checkpoint dir must fail FAST at startup with a
// message naming the dir, not degrade into a per-tick Warn that silently
// re-emits duplicate logs forever.
func TestVerifyFailsActionablyWhenNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not restrict writes")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil { // r-x: exists but not writable
		t.Fatalf("Mkdir: %v", err)
	}

	err := NewStore(dir).Verify()
	if err == nil {
		t.Fatal("Verify must fail on a non-writable checkpoint dir")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error must name the offending dir; got: %v", err)
	}
	if !strings.Contains(err.Error(), "checkpoint") {
		t.Errorf("error must say what is broken (checkpoints); got: %v", err)
	}
}
