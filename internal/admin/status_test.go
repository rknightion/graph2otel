package admin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
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

func (f *fakeCollector) Name() string                   { return f.name }
func (f *fakeCollector) DefaultInterval() time.Duration { return time.Hour }
func (f *fakeCollector) Collect(
	_ context.Context,
	_ telemetry.Emitter,
	_ *recordoutcome.Recorder,
) error {
	return f.err
}

// sequenceCollector returns one result per scheduler tick. It lets readiness
// tests prove that a lifetime success survives a later transient failure using
// the real scheduler and StatusTracker rather than a hand-built run snapshot.
type sequenceCollector struct {
	name    string
	mu      sync.Mutex
	results []error
	next    int
}

func (f *sequenceCollector) Name() string                   { return f.name }
func (f *sequenceCollector) DefaultInterval() time.Duration { return time.Millisecond }
func (f *sequenceCollector) Collect(
	_ context.Context,
	_ telemetry.Emitter,
	_ *recordoutcome.Recorder,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.next >= len(f.results) {
		return f.results[len(f.results)-1]
	}
	err := f.results[f.next]
	f.next++
	return err
}

func runSequenceAndTrack(t *testing.T, name string, results ...error) (*collector.StatusTracker, *collector.Registry) {
	t.Helper()
	if len(results) == 0 {
		t.Fatal("runSequenceAndTrack requires at least one result")
	}

	reg := collector.NewRegistry()
	reg.Register(&sequenceCollector{name: name, results: results}, time.Millisecond)
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
		if r, ok := tr.Snapshot()[name]; ok && r.Runs >= int64(len(results)) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if r, ok := tr.Snapshot()[name]; !ok || r.Runs < int64(len(results)) {
		cancel()
		<-done
		t.Fatalf("collector %q recorded %+v, want at least %d runs", name, r, len(results))
	}
	cancel()
	<-done
	return tr, reg
}

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

// fakeTwin is a registered collector that ingests over a non-graph transport and
// (optionally) declares the polled peer it covers via ConflictsWith — the shape of
// a blob/o365 twin, used to exercise the Transport + CoveredBy derivation (#178).
type fakeTwin struct {
	name      string
	transport telemetry.Transport
	conflicts []string
}

func (f *fakeTwin) Name() string                   { return f.name }
func (f *fakeTwin) DefaultInterval() time.Duration { return time.Hour }
func (f *fakeTwin) Collect(
	context.Context,
	telemetry.Emitter,
	*recordoutcome.Recorder,
) error {
	return nil
}
func (f *fakeTwin) IngestTransport() telemetry.Transport { return f.transport }
func (f *fakeTwin) ConflictsWith() []string              { return f.conflicts }

func TestBuildTenantStatuses_AvailabilitySnapshotDrivesCompleteStartupFailedCensus(t *testing.T) {
	const collectorCount = 148
	initial := make([]availability.Static, 0, collectorCount)
	for i := range collectorCount {
		initial = append(initial, availability.Static{
			Collector: fmt.Sprintf("collector.%03d", i),
			Transport: telemetry.TransportGraph,
			State:     availability.StateStartupFailed,
			Reason:    availability.ReasonCredentialInitializationFailed,
		})
	}

	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID:       "tenant-startup-failed",
		StartupFailure: StartupFailureCredentialInitialization,
		Availability:   availability.NewTracker("tenant-startup-failed", initial),
	}}, map[SkipKey]string{
		{TenantID: "tenant-startup-failed", Collector: "raw-free-form-row"}: "secret raw startup error",
	}, time.Now())

	if got := len(tenants[0].Collectors); got != collectorCount {
		t.Fatalf("collector rows = %d, want canonical %d-row census", got, collectorCount)
	}
	if got := tenants[0].FailingCount; got != collectorCount {
		t.Errorf("FailingCount = %d, want %d canonical startup failures", got, collectorCount)
	}
	if got := tenants[0].SkippedCount; got != 0 {
		t.Errorf("SkippedCount = %d, want 0 (startup failures are failures, not skips)", got)
	}
	if got := tenants[0].EnabledCount; got != 0 {
		t.Errorf("EnabledCount = %d, want 0 while startup-failed compatibility rows remain disabled", got)
	}
	for i, row := range tenants[0].Collectors {
		wantName := fmt.Sprintf("collector.%03d", i)
		if row.Name != wantName {
			t.Fatalf("row[%d].Name = %q, want %q", i, row.Name, wantName)
		}
		if row.Availability == nil ||
			row.Availability.State != availability.StateStartupFailed ||
			row.Availability.Reason != availability.ReasonCredentialInitializationFailed ||
			row.Availability.Transport != telemetry.TransportGraph {
			t.Fatalf("row[%d].Availability = %+v, want bounded startup failure", i, row.Availability)
		}
	}
}

func TestBuildTenantStatuses_AvailabilityProjectsCompatibilityAndPreservesCheckpoint(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	reg := collector.NewRegistry()
	reg.Register(&fakeStateful{name: "active", state: &collector.CheckpointState{
		Kind: collector.CheckpointKindWindow, Watermark: now.Add(-time.Minute),
	}}, time.Hour)
	reg.Register(&fakeTwin{
		name:      "blob-twin",
		transport: telemetry.TransportBlob,
		conflicts: []string{"covered-peer"},
	}, time.Hour)

	tracker := availability.NewTracker("tenant-a", []availability.Static{
		{Collector: "active", Transport: telemetry.TransportGraph, State: availability.StateStarting, Reason: availability.ReasonNoCompletedRun},
		{Collector: "blob-twin", Transport: telemetry.TransportBlob, State: availability.StateStarting, Reason: availability.ReasonNoCompletedRun},
		{Collector: "covered-peer", Transport: telemetry.TransportGraph, State: availability.StateCovered, Reason: availability.ReasonCoveredByAlternative},
		{Collector: "disabled", Transport: telemetry.TransportGraph, State: availability.StateDisabled, Reason: availability.ReasonExperimentalNotEnabled},
		{
			Collector: "limited", Transport: telemetry.TransportGraph,
			State: availability.StateLimited, Reason: availability.ReasonPartialLicense,
			Limitations: []availability.Limitation{"premium_signal"},
		},
	})
	tracker.Record("limited", recordoutcome.Summary{
		Result: recordoutcome.ResultSuccess,
		Counts: recordoutcome.Counts{Fetched: 2, Mapped: 2, Emitted: 2},
	})

	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID:     "tenant-a",
		Registry:     reg,
		Status:       collector.NewStatusTracker(),
		Availability: tracker,
	}}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "disabled"}: "raw free-form skip must not win",
	}, now)

	byName := map[string]CollectorStatus{}
	for _, row := range tenants[0].Collectors {
		byName[row.Name] = row
	}

	if got := byName["active"].State; got == nil || got.Kind != collector.CheckpointKindWindow {
		t.Fatalf("active durable checkpoint state = %+v, want preserved window state", got)
	}
	if got := byName["active"].Availability; got == nil ||
		got.State != availability.StateStarting ||
		got.Transport != telemetry.TransportGraph {
		t.Fatalf("active availability = %+v, want canonical starting/graph", got)
	}
	if got := byName["disabled"]; got.Enabled ||
		got.SkipReason != string(availability.ReasonExperimentalNotEnabled) ||
		got.SkipCategory != skipCatExperimental ||
		got.Transport != string(telemetry.TransportGraph) {
		t.Errorf("disabled compatibility = %+v, want typed disabled projection", got)
	}
	covered := byName["covered-peer"]
	if covered.Enabled || covered.CoveredBy == nil ||
		covered.CoveredBy.Collector != "blob-twin" ||
		covered.CoveredBy.Transport != string(telemetry.TransportBlob) {
		t.Errorf("covered compatibility = %+v, want current ConflictsWith twin identity", covered)
	}
	limited := byName["limited"]
	if !limited.Enabled || limited.SkipReason != "" ||
		limited.Availability == nil ||
		len(limited.Availability.Limitations) != 1 ||
		limited.LastOutcome == nil ||
		limited.LastOutcome.Result != recordoutcome.ResultSuccess ||
		limited.LastOutcome.Counts.Fetched != 2 {
		t.Errorf("limited row = %+v, want enabled typed limitation and last outcome", limited)
	}
}

func TestCollectorAvailabilityFromCopiesBoundedDetails(t *testing.T) {
	point := availability.Point{
		State:               availability.StateLimited,
		Reason:              availability.ReasonPartialLicense,
		Transport:           telemetry.TransportGraph,
		Limitations:         []availability.Limitation{availability.LimitationRiskyUsers},
		MissingCapabilities: []availability.MissingCapability{availability.MissingCapabilityEntraP2},
	}
	got := collectorAvailabilityFrom(point)
	point.Limitations[0] = "mutated"
	point.MissingCapabilities[0] = "mutated"
	if !reflect.DeepEqual(got.Limitations, []availability.Limitation{availability.LimitationRiskyUsers}) {
		t.Fatalf("Limitations = %v, want independent copy", got.Limitations)
	}
	if !reflect.DeepEqual(got.MissingCapabilities, []availability.MissingCapability{availability.MissingCapabilityEntraP2}) {
		t.Fatalf("MissingCapabilities = %v, want independent copy", got.MissingCapabilities)
	}
}

func TestBuildTenantStatuses_RawErrorsCannotChangeBoundedAvailability(t *testing.T) {
	const rawSecret = "https://graph.example/token?client_secret=hunter2"
	status, reg := runOnceAndTrack(t, "collector", errors.New(rawSecret))
	tracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "collector",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	tracker.Record("collector", recordoutcome.Summary{
		Result: recordoutcome.ResultFailure,
		Cause:  recordoutcome.CauseSourceError,
	})

	row := buildTenantStatuses([]CollectorSource{{
		TenantID:     "tenant-a",
		Registry:     reg,
		Status:       status,
		Availability: tracker,
	}}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "collector"}: rawSecret,
	}, time.Now())[0].Collectors[0]

	if row.LastError != rawSecret {
		t.Fatalf("LastError = %q, want compatibility diagnostic preserved", row.LastError)
	}
	bounded := fmt.Sprintf("%s %s %s %v",
		row.Availability.State,
		row.Availability.Reason,
		row.Availability.Transport,
		row.Availability.Limitations,
	)
	if strings.Contains(bounded, rawSecret) {
		t.Fatalf("bounded availability exposes raw LastError: %q", bounded)
	}
	if row.Availability.State != availability.StateFailed ||
		row.Availability.Reason != availability.ReasonSourceError {
		t.Fatalf("availability = %+v, want tracker-derived failed/source_error", row.Availability)
	}
}

func TestBuildTenantStatuses_TransportReflectsEngine(t *testing.T) {
	// A plain fakeCollector polls Graph inline (no engine) -> graph.
	trGraph, regGraph := runOnceAndTrack(t, "entra.risk", nil)

	// A registered blob twin declares blob transport.
	regBlob := collector.NewRegistry()
	regBlob.Register(&fakeTwin{name: "entra.signins.non_interactive.blob", transport: telemetry.TransportBlob}, time.Hour)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "graph-t", Registry: regGraph, Status: trGraph},
		{TenantID: "blob-t", Registry: regBlob, Status: collector.NewStatusTracker()},
	}, nil, time.Now())

	if got := tenants[0].Collectors[0].Transport; got != string(telemetry.TransportGraph) {
		t.Errorf("graph collector Transport = %q, want %q", got, telemetry.TransportGraph)
	}
	if got := tenants[1].Collectors[0].Transport; got != string(telemetry.TransportBlob) {
		t.Errorf("blob twin Transport = %q, want %q", got, telemetry.TransportBlob)
	}
}

func TestBuildTenantStatuses_CoveredBySkipRendersNotAGap(t *testing.T) {
	// A blob twin is REGISTERED and names the polled peer it covers; that peer is
	// SKIPPED (beta, off by default). The skipped row must report CoveredBy so the
	// page shows the signal is collected over blob, not missing.
	reg := collector.NewRegistry()
	reg.Register(&fakeTwin{
		name:      "entra.signins.non_interactive.blob",
		transport: telemetry.TransportBlob,
		conflicts: []string{"entra.signins.non_interactive"},
	}, time.Hour)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "t", Registry: reg, Status: collector.NewStatusTracker()},
	}, map[SkipKey]string{
		{TenantID: "t", Collector: "entra.signins.non_interactive"}: "beta; enable explicitly to opt in",
		// A genuinely-off collector with no covering twin: stays an honest gap.
		{TenantID: "t", Collector: "entra.identityprotection"}: "requires entra_p2",
	}, time.Now())

	byName := map[string]CollectorStatus{}
	for _, c := range tenants[0].Collectors {
		byName[c.Name] = c
	}

	covered := byName["entra.signins.non_interactive"]
	if covered.CoveredBy == nil {
		t.Fatalf("entra.signins.non_interactive CoveredBy = nil, want the blob twin")
	}
	if covered.CoveredBy.Collector != "entra.signins.non_interactive.blob" {
		t.Errorf("CoveredBy.Collector = %q, want the blob twin", covered.CoveredBy.Collector)
	}
	if covered.CoveredBy.Transport != string(telemetry.TransportBlob) {
		t.Errorf("CoveredBy.Transport = %q, want %q", covered.CoveredBy.Transport, telemetry.TransportBlob)
	}

	// The uncovered skip must NOT be dressed up as covered.
	if got := byName["entra.identityprotection"].CoveredBy; got != nil {
		t.Errorf("uncovered skip CoveredBy = %+v, want nil (honest gap)", got)
	}

	// The header roll-up must count the covered collector apart from the real
	// skip, so it is never tallied as a gap (#178).
	if ten := tenants[0]; ten.CoveredCount != 1 || ten.SkippedCount != 1 {
		t.Errorf("counts = {covered %d, skipped %d}, want {1, 1}", ten.CoveredCount, ten.SkippedCount)
	}
}

// fakeStateful is a registered collector that reports a durable checkpoint
// state — the shape of an engine collector (logpipeline/blobpipeline), used to
// exercise the State derivation (#178 Part B).
type fakeStateful struct {
	name  string
	state *collector.CheckpointState
}

func (f *fakeStateful) Name() string                   { return f.name }
func (f *fakeStateful) DefaultInterval() time.Duration { return time.Hour }
func (f *fakeStateful) Collect(
	context.Context,
	telemetry.Emitter,
	*recordoutcome.Recorder,
) error {
	return nil
}
func (f *fakeStateful) CheckpointState() *collector.CheckpointState { return f.state }

func TestBuildTenantStatuses_CheckpointStateSurfaced(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	wm := now.Add(-5 * time.Minute)

	reg := collector.NewRegistry()
	reg.Register(&fakeStateful{name: "entra.signins", state: &collector.CheckpointState{
		Kind: collector.CheckpointKindWindow, Watermark: wm, SeenIDs: 4, InFlightJob: "job-1",
	}}, time.Hour)
	reg.Register(&fakeStateful{name: "entra.signins.blob", state: &collector.CheckpointState{
		Kind: collector.CheckpointKindBlob, ByteOffset: 4096, BlobsTracked: 2, NewestBlob: "h=05/x.json",
	}}, time.Hour)
	// A collector that persists no cursor (not a CheckpointReporter) -> nil State.
	reg.Register(&fakeCollector{name: "devices.plain"}, time.Hour)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "t", Registry: reg, Status: collector.NewStatusTracker()},
	}, map[SkipKey]string{
		{TenantID: "t", Collector: "off.one"}: "disabled by config",
	}, now)

	byName := map[string]CollectorStatus{}
	for _, c := range tenants[0].Collectors {
		byName[c.Name] = c
	}

	win := byName["entra.signins"].State
	if win == nil {
		t.Fatalf("entra.signins State = nil, want a window checkpoint")
	}
	if win.Kind != collector.CheckpointKindWindow {
		t.Errorf("window Kind = %q, want %q", win.Kind, collector.CheckpointKindWindow)
	}
	if win.Watermark != wm.UTC().Format(time.RFC3339) {
		t.Errorf("window Watermark = %q, want %q", win.Watermark, wm.UTC().Format(time.RFC3339))
	}
	if win.StalenessSec != 300 || win.Staleness != "5m0s" {
		t.Errorf("window staleness = {%d, %q}, want {300, 5m0s}", win.StalenessSec, win.Staleness)
	}
	if win.SeenIDs != 4 {
		t.Errorf("window SeenIDs = %d, want 4", win.SeenIDs)
	}
	if win.InFlightJob != "job-1" {
		t.Errorf("window InFlightJob = %q, want job-1", win.InFlightJob)
	}

	blob := byName["entra.signins.blob"].State
	if blob == nil {
		t.Fatalf("entra.signins.blob State = nil, want a blob cursor")
	}
	if blob.Kind != collector.CheckpointKindBlob {
		t.Errorf("blob Kind = %q, want %q", blob.Kind, collector.CheckpointKindBlob)
	}
	if blob.ByteOffset != 4096 || blob.BlobsTracked != 2 || blob.NewestBlob != "h=05/x.json" {
		t.Errorf("blob state = %+v, want offset 4096 / 2 blobs / newest h=05/x.json", blob)
	}
	if blob.Watermark != "" || blob.Staleness != "" {
		t.Errorf("blob state carries a watermark %+v, want none", blob)
	}

	// A non-reporter collector and a skipped row both carry no State.
	if got := byName["devices.plain"].State; got != nil {
		t.Errorf("plain collector State = %+v, want nil", got)
	}
	if got := byName["off.one"].State; got != nil {
		t.Errorf("skipped collector State = %+v, want nil", got)
	}
}

// A zero (cold-start) watermark surfaces no watermark/staleness, so the page can
// say "cold start" rather than print a 1970 timestamp with a decades-long lag.
func TestBuildTenantStatuses_ColdStartWatermarkOmitted(t *testing.T) {
	reg := collector.NewRegistry()
	reg.Register(&fakeStateful{name: "entra.signins", state: &collector.CheckpointState{
		Kind: collector.CheckpointKindWindow, SeenIDs: 0,
	}}, time.Hour)

	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "t", Registry: reg, Status: collector.NewStatusTracker()},
	}, nil, time.Now())

	st := tenants[0].Collectors[0].State
	if st == nil {
		t.Fatalf("State = nil, want a (cold) window checkpoint")
	}
	if st.Watermark != "" || st.Staleness != "" || st.StalenessSec != 0 {
		t.Errorf("cold-start state = %+v, want empty watermark/staleness", st)
	}
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

func TestDeriveHealth_IntentionalAvailabilityStatesDoNotDegradeOrHoldStarting(t *testing.T) {
	tenants := []TenantStatus{{Collectors: []CollectorStatus{
		{
			Name: "disabled",
			Availability: &CollectorAvailability{
				State: availability.StateDisabled, Reason: availability.ReasonDisabledByConfig,
			},
		},
		{
			Name: "covered",
			Availability: &CollectorAvailability{
				State: availability.StateCovered, Reason: availability.ReasonCoveredByAlternative,
			},
		},
		{
			Name:    "limited",
			Enabled: true,
			Availability: &CollectorAvailability{
				State: availability.StateLimited, Reason: availability.ReasonPartialLicense,
			},
		},
	}}}

	health, reasons := deriveHealth(tenants)
	if health != healthHealthy || len(reasons) != 0 {
		t.Fatalf("deriveHealth(intentional states) = %q, %v; want healthy with no reasons", health, reasons)
	}
}

func TestDeriveHealth_UsesCanonicalBlockedStateWithoutRawRunError(t *testing.T) {
	const rawSecret = "raw API failure with secret"
	tenants := []TenantStatus{{TenantID: "tenant-a", Collectors: []CollectorStatus{{
		Name:      "blocked",
		Enabled:   true,
		LastError: rawSecret,
		Availability: &CollectorAvailability{
			State: availability.StateBlocked, Reason: availability.ReasonPermissionDenied,
		},
	}}}}

	health, reasons := deriveHealth(tenants)
	if health != healthDegraded {
		t.Fatalf("health = %q, want degraded for blocked availability", health)
	}
	joined := strings.Join(reasons, " ")
	if !strings.Contains(joined, string(availability.ReasonPermissionDenied)) {
		t.Errorf("health reasons = %q, want bounded permission_denied reason", joined)
	}
	if strings.Contains(joined, rawSecret) {
		t.Fatalf("health reasons expose raw LastError: %q", joined)
	}
}

func TestDeriveHealth_StaticLicenseBlockDoesNotDegrade(t *testing.T) {
	tenants := []TenantStatus{{TenantID: "tenant-a", Collectors: []CollectorStatus{{
		Name:    "license-blocked",
		Enabled: false,
		Availability: &CollectorAvailability{
			State: availability.StateBlocked, Reason: availability.ReasonLicenseUnavailable,
		},
	}}}}

	health, reasons := deriveHealth(tenants)
	if health != healthHealthy || len(reasons) != 0 {
		t.Fatalf("deriveHealth(license block) = %q, %v; want healthy with no reasons", health, reasons)
	}
}

func TestBuildTenantStatuses_StartupFailureIsSanitized(t *testing.T) {
	reg := collector.NewRegistry()
	reg.Register(&fakeCollector{name: "must-not-count-as-working"}, time.Hour)
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID:       "tenant-bad",
		Registry:       reg,
		Status:         collector.NewStatusTracker(),
		StartupFailure: StartupFailureCredentialInitialization,
	}}, nil, time.Now())

	if len(tenants) != 1 {
		t.Fatalf("Tenants = %d, want 1", len(tenants))
	}
	failure := tenants[0].StartupFailure
	if failure == nil {
		t.Fatal("StartupFailure = nil, want sanitized credential failure")
	}
	if failure.Code != StartupFailureCredentialInitialization {
		t.Errorf("StartupFailure.Code = %q, want %q", failure.Code, StartupFailureCredentialInitialization)
	}
	if failure.Reason != "credential initialization failed" {
		t.Errorf("StartupFailure.Reason = %q, want sanitized operator reason", failure.Reason)
	}
	if tenants[0].Working {
		t.Error("Working = true for a tenant whose startup failed")
	}
}

func TestBuildTenantStatuses_UnknownStartupFailureCannotExposeRawText(t *testing.T) {
	const secret = "client secret hunter2"
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID:       "tenant-bad",
		StartupFailure: StartupFailureCode(secret),
	}}, nil, time.Now())

	if got := tenants[0].StartupFailure; got != nil {
		t.Fatalf("StartupFailure = %+v, want unknown code omitted", got)
	}
	if got := strings.Join(deriveTenantHealthReasons(tenants[0]), " "); strings.Contains(got, secret) {
		t.Fatalf("health reasons expose raw startup failure %q", got)
	}
}

func TestDeriveReadiness_ZeroConfiguredTenantsIsReady(t *testing.T) {
	got := deriveReadiness(nil)
	want := ReadinessStatus{
		Ready:  true,
		State:  readinessReady,
		Reason: "ready: no tenants configured",
	}
	if got != want {
		t.Errorf("deriveReadiness(nil) = %+v, want %+v", got, want)
	}
}

func TestDeriveReadiness_EmptyRegistryIsNotWorking(t *testing.T) {
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID: "tenant-empty",
		Registry: collector.NewRegistry(),
		Status:   collector.NewStatusTracker(),
	}}, nil, time.Now())

	got := deriveReadiness(tenants)
	if got.Ready || got.State != readinessNoWorkingTenants {
		t.Errorf("readiness = %+v, want not ready/%q", got, readinessNoWorkingTenants)
	}
	if got.ConfiguredTenants != 1 || got.WorkingTenants != 0 || got.SuccessfulTenants != 0 {
		t.Errorf("readiness counts = %+v, want configured=1 working=0 successful=0", got)
	}
}

func TestDeriveReadiness_WorkingCollectorWaitsForFirstSuccess(t *testing.T) {
	reg := collector.NewRegistry()
	reg.Register(&fakeCollector{name: "healthy-empty"}, time.Hour)
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID: "tenant-a",
		Registry: reg,
		Status:   collector.NewStatusTracker(),
	}}, nil, time.Now())

	got := deriveReadiness(tenants)
	if got.Ready || got.State != readinessWaitingForFirstSuccess {
		t.Errorf("readiness = %+v, want not ready/%q", got, readinessWaitingForFirstSuccess)
	}
	if got.WorkingTenants != 1 || got.SuccessfulTenants != 0 {
		t.Errorf("readiness counts = %+v, want working=1 successful=0", got)
	}
}

func TestDeriveReadiness_NonEnabledCanonicalRowsCannotLatchHistoricalSuccess(t *testing.T) {
	tenants := []TenantStatus{{
		TenantID: "tenant-a",
		Working:  true,
		Collectors: []CollectorStatus{
			{
				Name:    "disabled",
				Enabled: false,
				Runs:    1,
				Availability: &CollectorAvailability{
					State: availability.StateDisabled, Reason: availability.ReasonDisabledByConfig,
				},
			},
			{
				Name:    "covered",
				Enabled: false,
				Runs:    1,
				Availability: &CollectorAvailability{
					State: availability.StateCovered, Reason: availability.ReasonCoveredByAlternative,
				},
			},
			{
				Name:    "startup-failed",
				Enabled: false,
				Runs:    1,
				Availability: &CollectorAvailability{
					State:  availability.StateStartupFailed,
					Reason: availability.ReasonCredentialInitializationFailed,
				},
			},
		},
	}}

	got := deriveReadiness(tenants)
	if got.Ready || got.State != readinessWaitingForFirstSuccess || got.SuccessfulTenants != 0 {
		t.Fatalf("readiness = %+v, want waiting with no successful tenant from disabled historical rows", got)
	}
}

func TestDeriveReadiness_HealthyEmptyCollectionCountsAsSuccess(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "healthy-empty", nil)
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID: "tenant-a",
		Registry: reg,
		Status:   tr,
	}}, nil, time.Now())

	got := deriveReadiness(tenants)
	if !got.Ready || got.State != readinessReady || got.SuccessfulTenants != 1 {
		t.Errorf("readiness = %+v, want ready after successful empty collection", got)
	}
}

func TestDeriveReadiness_PartialTenantSuccessIsReady(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	tenants := buildTenantStatuses([]CollectorSource{
		{TenantID: "tenant-bad", StartupFailure: StartupFailureGraphClientInitialization},
		{TenantID: "tenant-good", Registry: reg, Status: tr},
	}, nil, time.Now())

	got := deriveReadiness(tenants)
	if !got.Ready || got.State != readinessReady {
		t.Errorf("readiness = %+v, want ready from partial tenant success", got)
	}
	if got.ConfiguredTenants != 2 || got.WorkingTenants != 1 || got.SuccessfulTenants != 1 {
		t.Errorf("readiness counts = %+v, want configured=2 working=1 successful=1", got)
	}

	health, reasons := deriveHealth(tenants)
	if health != healthDegraded {
		t.Errorf("health = %q, want degraded while failed tenant remains visible", health)
	}
	if got := strings.Join(reasons, " "); !strings.Contains(got, "graph client initialization failed") {
		t.Errorf("health reasons = %q, want sanitized startup failure", got)
	}
}

func TestDeriveReadiness_LifetimeSuccessSurvivesLaterFailure(t *testing.T) {
	tr, reg := runSequenceAndTrack(t, "devices", nil, errBoom)
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "devices",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	availabilityTracker.Record("devices", tr.Snapshot()["devices"].LastOutcome)
	tenants := buildTenantStatuses([]CollectorSource{{
		TenantID:     "tenant-a",
		Registry:     reg,
		Status:       tr,
		Availability: availabilityTracker,
	}}, nil, time.Now())

	row := tenants[0].Collectors[0]
	if row.LastSuccess || row.Runs <= row.Failures ||
		row.Availability == nil ||
		row.Availability.State != availability.StateFailed {
		t.Fatalf("collector run = %+v, want last failure after a lifetime success", row)
	}
	got := deriveReadiness(tenants)
	if !got.Ready || got.State != readinessReady || got.SuccessfulTenants != 1 {
		t.Errorf("readiness = %+v, want latched ready from lifetime success", got)
	}
}
