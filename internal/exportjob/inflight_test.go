package exportjob

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// defenderReq is a representative export request (matches the shipped
// intune.defender_agents collector's shape closely enough to be realistic).
func defenderReq() Request {
	return Request{ReportName: "DefenderAgents", Select: []string{"DeviceId", "DeviceName"}}
}

// completedBody is a poll response for a completed job whose SAS url expires at
// expiry.
func completedBody(id string, expiry time.Time) []byte {
	return fmt.Appendf(nil, `{"id":%q,"status":"completed","url":"https://blob.example/sas","expirationDateTime":%q}`,
		id, expiry.Format(time.RFC3339))
}

// fixedNow pins Options.Now, so job age is deterministic.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// exportPoster builds a Poster that records every created job and answers polls
// from statusFor.
type exportPoster struct {
	createCalls int
	pollURLs    []string
	statusFor   func(url string) ([]byte, error)
}

func (p *exportPoster) RawPost(_ context.Context, _ string, _ []byte, _ map[string]string) ([]byte, error) {
	p.createCalls++
	return fmt.Appendf(nil, `{"id":"job-%d","status":"notStarted"}`, p.createCalls), nil
}

func (p *exportPoster) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	p.pollURLs = append(p.pollURLs, url)
	return p.statusFor(url)
}

func csvZip(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, "export.csv", []byte("DeviceId,DeviceName\nd1,laptop\n"))
}

// TestExport_RestartAdoptsInFlightJob is acceptance criterion #1 for the export
// engine, end to end through the real file store: process A creates an export job
// and dies while polling it; process B starts, and must POLL that job rather than
// POST a second one against an API capped at 48 req/min per app.
func TestExport_RestartAdoptsInFlightJob(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	// --- process A: creates the job, then dies mid-poll.
	posterA := &exportPoster{statusFor: func(string) ([]byte, error) {
		return nil, errors.New("process is going away")
	}}
	clientA := New(posterA, &fakeDownloader{}, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays),
	})
	if _, err := clientA.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("Export: want an error when polling never completes")
	}
	if posterA.createCalls != 1 {
		t.Fatalf("process A created %d jobs, want 1", posterA.createCalls)
	}

	// The id must be on DISK before the poll loop ran.
	rec, err := store.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if rec.InFlight == nil || rec.InFlight.ID != "job-1" {
		t.Fatalf("persisted InFlight = %+v, want job-1 recorded before polling", rec.InFlight)
	}

	// --- process B: restarted a minute later, adopts job-1.
	later := now.Add(time.Minute)
	posterB := &exportPoster{statusFor: func(url string) ([]byte, error) {
		return completedBody("job-1", later.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	clientB := New(posterB, dl, Options{
		Store: store, TenantID: "t1", Now: fixedNow(later), Sleep: noSleep(&delays),
	})

	rows, err := clientB.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("process B Export: %v", err)
	}
	if posterB.createCalls != 0 {
		t.Errorf("process B created %d jobs, want 0 — it must adopt process A's in-flight job", posterB.createCalls)
	}
	if len(posterB.pollURLs) == 0 || posterB.pollURLs[0] != defaultBaseURL+"/deviceManagement/reports/exportJobs/job-1" {
		t.Errorf("process B polled %v, want the adopted job-1", posterB.pollURLs)
	}
	if len(rows) != 1 || rows[0]["DeviceName"] != "laptop" {
		t.Errorf("rows = %v, want the adopted job's single row", rows)
	}

	after, err := store.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if after.InFlight != nil {
		t.Errorf("persisted InFlight = %+v after a completed export, want nil", after.InFlight)
	}
}

// TestExport_StaleInFlightDoesNotWedge is acceptance criterion #2 for this
// engine: an export job that never reaches a terminal state must not block the
// collector forever. Past JobMaxAge it is dropped and replaced with no operator
// intervention.
func TestExport_StaleInFlightDoesNotWedge(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	if err := store.SaveJob(&checkpoint.JobRecord{
		TenantID: "t1",
		Key:      "DefenderAgents",
		InFlight: &checkpoint.InFlightJob{
			ID:        "job-zombie",
			CreatedAt: now.Add(-6 * time.Hour),
			Scope:     requestScope(defenderReq(), FormatCSV),
		},
	}); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	client := New(poster, dl, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays), JobMaxAge: 30 * time.Minute,
	})

	if _, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if poster.createCalls != 1 {
		t.Errorf("created %d jobs, want 1 — the zombie must be dropped and replaced", poster.createCalls)
	}
	for _, u := range poster.pollURLs {
		if u == defaultBaseURL+"/deviceManagement/reports/exportJobs/job-zombie" {
			t.Errorf("polled the zombie job (%s) instead of discarding it", u)
		}
	}
}

// TestExport_DiscardsInFlightWhenRequestChanged is the export engine's analog of
// jobpipeline's window check. An export job has no time window — its identity IS
// its request — so adopting one created for a DIFFERENT request (an upgrade added
// a Select column, say) would silently return the old column set and look like a
// data bug, not an error.
func TestExport_DiscardsInFlightWhenRequestChanged(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	oldReq := Request{ReportName: "DefenderAgents", Select: []string{"DeviceId"}}
	if err := store.SaveJob(&checkpoint.JobRecord{
		TenantID: "t1",
		Key:      "DefenderAgents",
		InFlight: &checkpoint.InFlightJob{
			ID:        "job-oldcolumns",
			CreatedAt: now.Add(-time.Minute),
			Scope:     requestScope(oldReq, FormatCSV),
		},
	}); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	client := New(poster, dl, Options{Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays)})

	// The new request adds a column, so its fingerprint differs.
	if _, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if poster.createCalls != 1 {
		t.Errorf("created %d jobs, want 1 — a job for a different request must not be adopted", poster.createCalls)
	}
}

// TestExport_NegativeJobMaxAgeDisablesAdoption pins the escape hatch: a negative
// JobMaxAge must mean "never adopt", NOT "never expire" — the opposite reading
// would turn the knob into the permanent wedge it exists to prevent.
func TestExport_NegativeJobMaxAgeDisablesAdoption(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	// A perfectly adoptable job: fresh, identical request.
	if err := store.SaveJob(&checkpoint.JobRecord{
		TenantID: "t1",
		Key:      "DefenderAgents",
		InFlight: &checkpoint.InFlightJob{
			ID:        "job-adoptable",
			CreatedAt: now.Add(-time.Minute),
			Scope:     requestScope(defenderReq(), FormatCSV),
		},
	}); err != nil {
		t.Fatalf("SaveJob: %v", err)
	}

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	client := New(poster, dl, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays), JobMaxAge: -1,
	})

	if _, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if poster.createCalls != 1 {
		t.Errorf("created %d jobs, want 1 — a negative JobMaxAge must disable adoption entirely", poster.createCalls)
	}
}

func TestRequestScope(t *testing.T) {
	base := defenderReq()
	scope := requestScope(base, FormatCSV)

	if scope == "" {
		t.Fatal("requestScope returned empty")
	}
	if got := requestScope(base, FormatCSV); got != scope {
		t.Errorf("requestScope is not stable: %q then %q", scope, got)
	}

	tests := []struct {
		name   string
		req    Request
		format Format
	}{
		{name: "different report", req: Request{ReportName: "Other", Select: base.Select}, format: FormatCSV},
		{name: "extra column", req: Request{ReportName: base.ReportName, Select: []string{"DeviceId", "DeviceName", "UPN"}}, format: FormatCSV},
		{name: "column order", req: Request{ReportName: base.ReportName, Select: []string{"DeviceName", "DeviceId"}}, format: FormatCSV},
		{name: "filter added", req: Request{ReportName: base.ReportName, Select: base.Select, Filter: "(OwnerType eq '1')"}, format: FormatCSV},
		{name: "localization added", req: Request{ReportName: base.ReportName, Select: base.Select, LocalizationType: "ReplaceLocalizableValues"}, format: FormatCSV},
		{name: "different format", req: base, format: FormatJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestScope(tt.req, tt.format); got == scope {
				t.Errorf("requestScope collides with the base request; a %s must produce a different fingerprint", tt.name)
			}
		})
	}
}

// TestExport_ClearsInFlightOnJobFailed: a failed job can never complete, so
// keeping its id would only waste the next tick re-polling it.
func TestExport_ClearsInFlightOnJobFailed(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return []byte(`{"id":"job-1","status":"failed"}`), nil
	}}
	client := New(poster, &fakeDownloader{}, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays),
	})

	_, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter())
	if !errors.Is(err, ErrJobFailed) {
		t.Fatalf("Export error = %v, want ErrJobFailed", err)
	}
	rec, err := store.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if rec.InFlight != nil {
		t.Errorf("persisted InFlight = %+v after a failed job, want nil", rec.InFlight)
	}
}

// TestExport_ClearsInFlightOnSASExpired: the job completed but its download url
// is gone, so only a NEW job can produce the data. Retaining the id would make
// every subsequent tick re-poll a job it can never download.
func TestExport_ClearsInFlightOnSASExpired(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(-time.Minute)), nil // already expired
	}}
	client := New(poster, &fakeDownloader{}, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays),
	})

	_, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter())
	if !errors.Is(err, ErrSASExpired) {
		t.Fatalf("Export error = %v, want ErrSASExpired", err)
	}
	rec, err := store.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if rec.InFlight != nil {
		t.Errorf("persisted InFlight = %+v after an expired SAS, want nil", rec.InFlight)
	}
}

// TestExport_KeepsInFlightOnPollError is the resume path: a transient poll
// failure must LEAVE the record, because that is exactly the job the next tick
// should adopt.
func TestExport_KeepsInFlightOnPollError(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return nil, errors.New("graph: status 429")
	}}
	client := New(poster, &fakeDownloader{}, Options{
		Store: store, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays),
	})

	if _, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("Export: want an error on a failing poll")
	}
	rec, err := store.LoadJob("t1", "DefenderAgents")
	if err != nil {
		t.Fatalf("LoadJob: %v", err)
	}
	if rec.InFlight == nil || rec.InFlight.ID != "job-1" {
		t.Errorf("persisted InFlight = %+v after a transient poll failure, want job-1 retained for adoption", rec.InFlight)
	}
}

// TestExport_NoStoreStillWorks pins that persistence is OPTIONAL: an Options with
// no Store behaves exactly as it did before #118 (create every tick, never
// adopt). Every existing test in this package runs that way, and the composition
// root is the only thing that wires a store.
func TestExport_NoStoreStillWorks(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	client := New(poster, dl, Options{Now: fixedNow(now), Sleep: noSleep(&delays)})

	rows, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("Export with no Store: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows = %v, want 1", rows)
	}
	if poster.createCalls != 1 {
		t.Errorf("created %d jobs, want 1", poster.createCalls)
	}
}

// TestExport_StoreFailureDoesNotAbandonTheCreatedJob: the job exists server-side
// by the time the record is written, so a store failure must not throw it away —
// that would waste the create AND return no rows.
func TestExport_StoreFailureDoesNotAbandonTheCreatedJob(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	var delays []time.Duration

	poster := &exportPoster{statusFor: func(string) ([]byte, error) {
		return completedBody("job-1", now.Add(time.Hour)), nil
	}}
	dl := &fakeDownloader{download: func(context.Context, string) ([]byte, error) { return csvZip(t), nil }}
	client := New(poster, dl, Options{
		Store: failingJobStore{}, TenantID: "t1", Now: fixedNow(now), Sleep: noSleep(&delays),
	})

	rows, err := client.Export(context.Background(), defenderReq(), telemetrytest.New().Emitter())
	if err != nil {
		t.Fatalf("Export: %v — a store failure must not abandon the job it just created", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows = %v, want 1", rows)
	}
}

// failingJobStore fails every operation, modeling an unusable checkpoint dir.
type failingJobStore struct{}

func (failingJobStore) LoadJob(string, string) (*checkpoint.JobRecord, error) {
	return nil, errors.New("checkpoint dir is unreadable")
}
func (failingJobStore) SaveJob(*checkpoint.JobRecord) error {
	return errors.New("checkpoint dir is unwritable")
}
