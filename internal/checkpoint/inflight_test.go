package checkpoint

import (
	"encoding/json"
	"testing"
	"time"
)

func TestInFlightJobExpired(t *testing.T) {
	created := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	j := &InFlightJob{ID: "q1", CreatedAt: created}

	tests := []struct {
		name   string
		now    time.Time
		maxAge time.Duration
		want   bool
	}{
		{name: "fresh", now: created.Add(5 * time.Minute), maxAge: time.Hour, want: false},
		{name: "exactly at max age is expired", now: created.Add(time.Hour), maxAge: time.Hour, want: true},
		{name: "past max age", now: created.Add(2 * time.Hour), maxAge: time.Hour, want: true},
		{name: "clock skewed backwards is not expired", now: created.Add(-time.Hour), maxAge: time.Hour, want: false},
		{name: "zero max age never expires", now: created.Add(100 * time.Hour), maxAge: 0, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := j.Expired(tt.now, tt.maxAge); got != tt.want {
				t.Errorf("Expired(%v, %v) = %v, want %v", tt.now, tt.maxAge, got, tt.want)
			}
		})
	}
}

func TestInFlightJobExpiredNil(t *testing.T) {
	var j *InFlightJob
	if j.Expired(time.Now(), time.Hour) {
		t.Error("a nil InFlightJob must not report Expired (there is nothing to expire)")
	}
}

// TestInFlightJobCoversWindow pins the adoption rule that makes this feature
// work at all: `to` is now-lag (collector/window.go), so it advances every tick
// and a persisted job's window can NEVER equal the next tick's window. Adoption
// therefore matches on `from` and requires the job to cover a PREFIX of the
// requested window — draining [from, jobTo] and letting the watermark advance
// only that far is exactly what the MaxWindow clamp already does across ticks.
func TestInFlightJobCoversWindow(t *testing.T) {
	from := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	jobTo := from.Add(time.Hour)
	j := &InFlightJob{ID: "q1", WindowFrom: from, WindowTo: jobTo}

	tests := []struct {
		name     string
		from, to time.Time
		want     bool
	}{
		{name: "identical window", from: from, to: jobTo, want: true},
		{name: "requested to has advanced past the job's to", from: from, to: jobTo.Add(30 * time.Minute), want: true},
		{name: "from moved on: watermark advanced, job is for a stale window", from: from.Add(time.Minute), to: jobTo.Add(time.Hour), want: false},
		{name: "from moved back", from: from.Add(-time.Minute), to: jobTo, want: false},
		{name: "job's to is beyond the requested to", from: from, to: jobTo.Add(-time.Minute), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := j.CoversWindow(tt.from, tt.to); got != tt.want {
				t.Errorf("CoversWindow(%v, %v) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestInFlightJobCoversWindowNil(t *testing.T) {
	var j *InFlightJob
	if j.CoversWindow(time.Now(), time.Now().Add(time.Hour)) {
		t.Error("a nil InFlightJob covers no window")
	}
}

// TestCheckpointSchemaBackwardTolerance proves a checkpoint written by a binary
// that predates the in_flight field decodes cleanly: the field is absent, so
// InFlight is nil and the collector simply creates a job as it always did.
func TestCheckpointSchemaBackwardTolerance(t *testing.T) {
	old := []byte(`{
	  "schema": 1,
	  "tenant_id": "t1",
	  "endpoint": "/security/auditLog/queries",
	  "watermark": "2026-07-16T10:00:00Z",
	  "overlap_window": 7200000000000,
	  "seen_ids": {"a": "2026-07-16T09:59:00Z"}
	}`)

	var cp Checkpoint
	if err := json.Unmarshal(old, &cp); err != nil {
		t.Fatalf("decode pre-in_flight checkpoint: %v", err)
	}
	if cp.InFlight != nil {
		t.Errorf("InFlight = %+v, want nil for a checkpoint written before the field existed", cp.InFlight)
	}
	if !cp.Watermark.Equal(time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Watermark = %v, want the value from the old file", cp.Watermark)
	}
	if !cp.SeenIDs.Has("a") {
		t.Error("SeenIDs from the old file did not survive the decode")
	}
}

// TestCheckpointSchemaForwardTolerance proves the other direction: a checkpoint
// carrying in_flight, read by a binary that has never heard of the field (modeled
// by decoding into a struct without it), decodes without error and keeps every
// field that binary does know. encoding/json ignores unknown fields, so an older
// graph2otel downgrades to today's behavior (orphan the job, create a new one)
// rather than failing to start.
func TestCheckpointSchemaForwardTolerance(t *testing.T) {
	cp := &Checkpoint{
		Schema:        schemaVersion,
		TenantID:      "t1",
		Endpoint:      "/security/auditLog/queries",
		Watermark:     time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC),
		OverlapWindow: 2 * time.Hour,
		SeenIDs:       SeenIDs{"a": time.Date(2026, 7, 16, 9, 59, 0, 0, time.UTC)},
		InFlight: &InFlightJob{
			ID:         "query-1",
			CreatedAt:  time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC),
			WindowFrom: time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC),
			WindowTo:   time.Date(2026, 7, 16, 9, 45, 0, 0, time.UTC),
		},
	}
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// The pre-#118 Checkpoint layout, verbatim.
	var older struct {
		Schema        int               `json:"schema"`
		TenantID      string            `json:"tenant_id"`
		Endpoint      string            `json:"endpoint"`
		Watermark     time.Time         `json:"watermark"`
		OverlapWindow time.Duration     `json:"overlap_window"`
		SeenIDs       map[string]string `json:"seen_ids"`
	}
	if err := json.Unmarshal(data, &older); err != nil {
		t.Fatalf("a pre-#118 binary failed to decode a checkpoint carrying in_flight: %v", err)
	}
	if older.Schema != schemaVersion {
		t.Errorf("Schema = %d, want %d: adding an OPTIONAL field is a compatible change, so the version must NOT be bumped "+
			"(both directions of this pair of tests prove the layout still round-trips)", older.Schema, schemaVersion)
	}
	if !older.Watermark.Equal(cp.Watermark) {
		t.Errorf("Watermark = %v, want %v", older.Watermark, cp.Watermark)
	}
	if len(older.SeenIDs) != 1 {
		t.Errorf("SeenIDs = %v, want the one entry to survive", older.SeenIDs)
	}
}

// TestCheckpointInFlightOmittedWhenNil keeps the on-disk file clean (and the
// forward-tolerance story simple) for the overwhelmingly common case: no job in
// flight.
func TestCheckpointInFlightOmittedWhenNil(t *testing.T) {
	data, err := json.Marshal(&Checkpoint{Schema: schemaVersion, TenantID: "t1", Endpoint: "/e"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["in_flight"]; ok {
		t.Errorf("in_flight is present in %s, want it omitted when there is no job in flight", data)
	}
}

func TestStoreJobRecordRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())

	created := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	rec := &JobRecord{
		TenantID: "t1",
		Key:      "DefenderAgents",
		InFlight: &InFlightJob{ID: "job-1", CreatedAt: created, Scope: "fingerprint-abc"},
	}
	if err := s.SaveJob(rec); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	got, err := s.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if got.Schema != schemaVersion {
		t.Errorf("Schema = %d, want %d (SaveJob must stamp it)", got.Schema, schemaVersion)
	}
	if got.InFlight == nil {
		t.Fatal("InFlight = nil, want the saved job")
	}
	if got.InFlight.ID != "job-1" || got.InFlight.Scope != "fingerprint-abc" {
		t.Errorf("InFlight = %+v, want id job-1 / scope fingerprint-abc", got.InFlight)
	}
	if !got.InFlight.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", got.InFlight.CreatedAt, created)
	}
}

// TestStoreLoadJobMissingIsEmpty pins cold start: no file yet is not an error,
// it is "no job in flight".
func TestStoreLoadJobMissingIsEmpty(t *testing.T) {
	s := NewStore(t.TempDir())
	got, err := s.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob on a fresh store: %v", err)
	}
	if got.InFlight != nil {
		t.Errorf("InFlight = %+v, want nil on cold start", got.InFlight)
	}
	if got.TenantID != "t1" || got.Key != "DefenderAgents" {
		t.Errorf("record = %+v, want it self-describing", got)
	}
}

// TestStoreJobRecordNamespacedApartFromCheckpoint guards the same hazard
// cursorFileKey guards: a job record and a window checkpoint that happen to
// share a (tenant, name) pair must not overwrite each other with an
// incompatible shape.
func TestStoreJobRecordNamespacedApartFromCheckpoint(t *testing.T) {
	s := NewStore(t.TempDir())

	if err := s.Save(&Checkpoint{TenantID: "t1", Endpoint: "x", Watermark: time.Now(), SeenIDs: NewSeenIDs()}); err != nil {
		t.Fatalf("Save checkpoint: %v", err)
	}
	if err := s.SaveJob(&JobRecord{TenantID: "t1", Key: "x", InFlight: &InFlightJob{ID: "job-1"}}); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	cp, err := s.Load("t1", "x")
	if err != nil {
		t.Fatalf("Load checkpoint: %v", err)
	}
	if cp.Watermark.IsZero() {
		t.Error("the job record clobbered the window checkpoint sharing its (tenant, name)")
	}
	rec, err := s.LoadJob("t1", "x")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if rec.InFlight == nil || rec.InFlight.ID != "job-1" {
		t.Errorf("job record = %+v, want it intact alongside the checkpoint", rec)
	}
}

// TestStoreSaveJobClearsInFlight proves the record can be emptied (the job
// finished) without deleting the file.
func TestStoreSaveJobClearsInFlight(t *testing.T) {
	s := NewStore(t.TempDir())

	if err := s.SaveJob(&JobRecord{TenantID: "t1", Key: "k", InFlight: &InFlightJob{ID: "job-1"}}); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}
	if err := s.SaveJob(&JobRecord{TenantID: "t1", Key: "k"}); err != nil {
		t.Fatalf("SaveJob clearing: %v", err)
	}
	got, err := s.LoadJob("t1", "k")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if got.InFlight != nil {
		t.Errorf("InFlight = %+v, want nil after being cleared", got.InFlight)
	}
}
