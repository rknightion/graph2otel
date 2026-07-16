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

func TestCollectorStatusFor_NextRunAndOverdue(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	interval := time.Hour

	t.Run("next run computed from last start", func(t *testing.T) {
		started := now.Add(-20 * time.Minute)
		runs := map[string]collector.CollectorRun{
			"c": {Runs: 1, LastStarted: started, LastFinished: started.Add(time.Second), LastSuccess: true},
		}
		cs := collectorStatusFor("c", interval, runs, nil, now)
		// last start was 20m ago on a 60m interval -> ~40m until next run.
		wantSec := int64((40 * time.Minute) / time.Second)
		if cs.NextRunInSec != wantSec {
			t.Errorf("NextRunInSec = %d, want %d", cs.NextRunInSec, wantSec)
		}
		if cs.NextRunIn == "" {
			t.Errorf("NextRunIn is empty, want a human duration")
		}
		if cs.Overdue {
			t.Errorf("Overdue = true, want false (within one interval)")
		}
	})

	t.Run("overdue past twice the interval", func(t *testing.T) {
		started := now.Add(-3 * time.Hour) // 3h ago on a 1h interval
		runs := map[string]collector.CollectorRun{
			"c": {Runs: 5, LastStarted: started, LastFinished: started.Add(time.Second), LastSuccess: true},
		}
		cs := collectorStatusFor("c", interval, runs, nil, now)
		if !cs.Overdue {
			t.Errorf("Overdue = false, want true (last start > 2 intervals ago)")
		}
		if cs.NextRunInSec != 0 {
			t.Errorf("NextRunInSec = %d, want 0 (already due)", cs.NextRunInSec)
		}
	})

	t.Run("no next run before first run", func(t *testing.T) {
		cs := collectorStatusFor("c", interval, map[string]collector.CollectorRun{}, nil, now)
		if cs.HasRun || cs.NextRunInSec != 0 || cs.NextRunIn != "" || cs.Overdue {
			t.Errorf("unrun collector = %+v, want zero next-run/overdue", cs)
		}
	})
}

func TestSkipCategory(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"requires entra_p2", skipCatLicense},
		{"disabled by config", skipCatDisabled},
		{"beta; enable explicitly to opt in", skipCatExperimental},
		{"something else entirely", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := skipCategory(tc.reason); got != tc.want {
			t.Errorf("skipCategory(%q) = %q, want %q", tc.reason, got, tc.want)
		}
	}
}

func TestBuildTenantStatuses_SkipCategoryAndCounts(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", errBoom) // one enabled, failing collector

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "riskyusers"}:  "requires entra_p2",
		{TenantID: "tenant-a", Collector: "auditbeta"}:   "beta; enable explicitly to opt in",
		{TenantID: "tenant-a", Collector: "signins_off"}: "disabled by config",
	}, time.Now())

	ten := tenants[0]
	// 1 enabled (failing) + 3 skipped rows.
	if ten.EnabledCount != 1 {
		t.Errorf("EnabledCount = %d, want 1", ten.EnabledCount)
	}
	if ten.FailingCount != 1 {
		t.Errorf("FailingCount = %d, want 1", ten.FailingCount)
	}
	if ten.SkippedCount != 3 {
		t.Errorf("SkippedCount = %d, want 3", ten.SkippedCount)
	}

	byName := map[string]CollectorStatus{}
	for _, c := range ten.Collectors {
		byName[c.Name] = c
	}
	if got := byName["riskyusers"].SkipCategory; got != skipCatLicense {
		t.Errorf("riskyusers SkipCategory = %q, want %q", got, skipCatLicense)
	}
	if got := byName["auditbeta"].SkipCategory; got != skipCatExperimental {
		t.Errorf("auditbeta SkipCategory = %q, want %q", got, skipCatExperimental)
	}
	if got := byName["signins_off"].SkipCategory; got != skipCatDisabled {
		t.Errorf("signins_off SkipCategory = %q, want %q", got, skipCatDisabled)
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
