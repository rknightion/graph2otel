package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// errBoom is the sentinel failure a fakeCollector reports to exercise the
// failed-run path.
var errBoom = errors.New("boom")

// fakeCollector is a minimal collector.SnapshotCollector. Driving it through
// a real collector.Scheduler (see runOnceAndTrack) means these tests exercise
// the exact CollectorRun/CollectorHistory shape the admin package will see in
// production, rather than a hand-built stand-in.
type fakeCollector struct {
	name string
	err  error
}

func (f *fakeCollector) Name() string                                         { return f.name }
func (f *fakeCollector) DefaultInterval() time.Duration                       { return time.Hour }
func (f *fakeCollector) Collect(_ context.Context, _ telemetry.Emitter) error { return f.err }

// runOnceAndTrack registers a fake collector, runs the scheduler until it has
// recorded exactly one tick, then cancels it. It returns the StatusTracker
// and Registry the tick populated, both built entirely through collector's
// own public API (NewScheduler/Run/StatusTracker) so admin's tests never
// depend on collector's unexported record method.
func runOnceAndTrack(t *testing.T, name string, err error) (*collector.StatusTracker, *collector.Registry) {
	t.Helper()

	reg := collector.NewRegistry()
	reg.Register(&fakeCollector{name: name, err: err}, time.Hour)

	tr := collector.NewStatusTracker()
	sched := collector.NewScheduler(telemetrytest.New().Emitter(), collector.NewMemoryStore(),
		collector.WithStaggerWindow(0),
		collector.WithSelfObs(false),
		collector.WithStatusTracker(tr),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = sched.Run(ctx, reg)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := tr.Snapshot()[name]; ok && r.Runs > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if r, ok := tr.Snapshot()[name]; !ok || r.Runs == 0 {
		cancel()
		<-done
		t.Fatalf("collector %q never recorded a run", name)
	}

	cancel()
	<-done
	return tr, reg
}

func TestBuildTenantStatuses_RegisteredCollectorReflectsRun(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, time.Now())

	if len(tenants) != 1 {
		t.Fatalf("len(tenants) = %d, want 1", len(tenants))
	}
	tenant := tenants[0]
	if tenant.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q, want tenant-a", tenant.TenantID)
	}
	if len(tenant.Collectors) != 1 {
		t.Fatalf("len(Collectors) = %d, want 1", len(tenant.Collectors))
	}
	c := tenant.Collectors[0]
	if c.Name != "devices" {
		t.Errorf("Name = %q, want devices", c.Name)
	}
	if !c.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	if c.SkipReason != "" {
		t.Errorf("SkipReason = %q, want empty", c.SkipReason)
	}
	if !c.HasRun {
		t.Errorf("HasRun = false, want true")
	}
	if !c.LastSuccess {
		t.Errorf("LastSuccess = false, want true")
	}
	if c.Runs != 1 {
		t.Errorf("Runs = %d, want 1", c.Runs)
	}
	if c.LastFinishedAt == "" {
		t.Errorf("LastFinishedAt is empty, want an RFC3339 timestamp")
	}
}

func TestBuildTenantStatuses_LastErrorSurfaced(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "auditlogs", errBoom)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, time.Now())

	c := tenants[0].Collectors[0]
	if c.LastSuccess {
		t.Errorf("LastSuccess = true, want false")
	}
	if c.LastError != errBoom.Error() {
		t.Errorf("LastError = %q, want %q", c.LastError, errBoom.Error())
	}
	if c.Failures != 1 {
		t.Errorf("Failures = %d, want 1", c.Failures)
	}
	if c.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", c.ConsecutiveFailures)
	}
}

func TestBuildTenantStatuses_SkippedCollectorShowsReason(t *testing.T) {
	reg := collector.NewRegistry() // nothing registered: the collector was skipped entirely
	tr := collector.NewStatusTracker()

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "identityprotection"}: "requires P2",
	}, time.Now())

	if len(tenants[0].Collectors) != 1 {
		t.Fatalf("len(Collectors) = %d, want 1", len(tenants[0].Collectors))
	}
	c := tenants[0].Collectors[0]
	if c.Name != "identityprotection" {
		t.Errorf("Name = %q, want identityprotection", c.Name)
	}
	if c.Enabled {
		t.Errorf("Enabled = true, want false (skipped)")
	}
	if c.SkipReason != "requires P2" {
		t.Errorf("SkipReason = %q, want %q", c.SkipReason, "requires P2")
	}
	if c.HasRun {
		t.Errorf("HasRun = true, want false")
	}
}

func TestBuildTenantStatuses_SkipReasonForOtherTenantIgnored(t *testing.T) {
	reg := collector.NewRegistry()
	tr := collector.NewStatusTracker()

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, map[SkipKey]string{
		{TenantID: "tenant-b", Collector: "identityprotection"}: "requires P2",
	}, time.Now())

	if len(tenants[0].Collectors) != 0 {
		t.Fatalf("len(Collectors) = %d, want 0 (skip reason belongs to a different tenant)", len(tenants[0].Collectors))
	}
}

func TestDeriveHealth_HealthyWhenAllSucceed(t *testing.T) {
	tenants := []TenantStatus{{Collectors: []CollectorStatus{
		{Name: "a", Enabled: true, HasRun: true, LastSuccess: true},
	}}}
	health, reasons := deriveHealth(tenants)
	if health != healthHealthy {
		t.Errorf("health = %q, want %q", health, healthHealthy)
	}
	if len(reasons) != 0 {
		t.Errorf("reasons = %v, want empty", reasons)
	}
}

func TestDeriveHealth_StartingWhenPending(t *testing.T) {
	tenants := []TenantStatus{{Collectors: []CollectorStatus{
		{Name: "a", Enabled: true, HasRun: false},
	}}}
	health, reasons := deriveHealth(tenants)
	if health != healthStarting {
		t.Errorf("health = %q, want %q", health, healthStarting)
	}
	if len(reasons) == 0 {
		t.Errorf("reasons is empty, want an explanation")
	}
}

func TestDeriveHealth_DegradedOnConsecutiveFailures(t *testing.T) {
	tenants := []TenantStatus{{Collectors: []CollectorStatus{
		{Name: "a", Enabled: true, HasRun: true, LastSuccess: false, ConsecutiveFailures: 3},
	}}}
	health, reasons := deriveHealth(tenants)
	if health != healthDegraded {
		t.Errorf("health = %q, want %q", health, healthDegraded)
	}
	if len(reasons) == 0 {
		t.Errorf("reasons is empty, want an explanation")
	}
}

func TestDeriveHealth_SkippedCollectorNeverDegradesHealth(t *testing.T) {
	tenants := []TenantStatus{{Collectors: []CollectorStatus{
		{Name: "a", Enabled: false, SkipReason: "requires P2"},
	}}}
	health, reasons := deriveHealth(tenants)
	if health != healthHealthy {
		t.Errorf("health = %q, want %q", health, healthHealthy)
	}
	if len(reasons) != 0 {
		t.Errorf("reasons = %v, want empty", reasons)
	}
}
