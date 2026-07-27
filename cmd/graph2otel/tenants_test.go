package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

type gateTestCollector struct {
	name         string
	experimental bool
	highVolume   bool
}

func (c gateTestCollector) Name() string                 { return c.name }
func (gateTestCollector) DefaultInterval() time.Duration { return time.Minute }
func (c gateTestCollector) Experimental() bool           { return c.experimental }
func (c gateTestCollector) HighVolume() bool             { return c.highVolume }

type premiumGateTestCollector struct {
	gateTestCollector
	capability license.Capability
}

func (c premiumGateTestCollector) RequiredCapability() license.Capability { return c.capability }

var _ collector.Collector = gateTestCollector{}
var _ collectors.Experimental = gateTestCollector{}
var _ collectors.HighVolume = gateTestCollector{}
var _ license.CapabilityRequirer = premiumGateTestCollector{}

type capacityWiringCollector struct {
	done chan struct{}
}

func TestTenantSchedulerStorePersistsAcrossProcessRestart(t *testing.T) {
	cfg := &config.Config{CheckpointDir: t.TempDir()}
	const tenantID = "11111111-1111-1111-1111-111111111111"
	want := time.Unix(1_700_000_123, 0).UTC()

	first, err := newTenantSchedulerStore(cfg, tenantID)
	if err != nil {
		t.Fatalf("newTenantSchedulerStore first process: %v", err)
	}
	if err := first.Set(tenantID+"/entra.signins", want); err != nil {
		t.Fatalf("persist scheduler checkpoint: %v", err)
	}

	second, err := newTenantSchedulerStore(cfg, tenantID)
	if err != nil {
		t.Fatalf("newTenantSchedulerStore restarted process: %v", err)
	}
	got, ok := second.Get(tenantID + "/entra.signins")
	if !ok {
		t.Fatal("restarted scheduler store lost persisted checkpoint")
	}
	if !got.Equal(want) {
		t.Fatalf("restarted scheduler checkpoint = %v, want %v", got, want)
	}
}

func (capacityWiringCollector) Name() string                   { return "capacity.wiring" }
func (capacityWiringCollector) DefaultInterval() time.Duration { return time.Hour }
func (c capacityWiringCollector) Collect(
	_ context.Context,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
) error {
	e.Gauge("entra.capacity.wiring", "{record}", "", 1, nil)
	// The timestamp must stay RECENT, not a fixed epoch. The scheduler wraps every
	// collector emitter in the #401 horizon guard, which drops a log record older
	// than the backend's accept window — so a fixture dated 2023 is dropped, and
	// this test then measures the guard rather than capacity accounting. Using a
	// fixed old constant here previously made exactly that mistake.
	e.LogEvent(telemetry.Event{
		Name:      "entra.capacity.wiring",
		Timestamp: time.Now().Add(-time.Minute),
	})
	outcomes.Add(recordoutcome.OutcomeFetched, 2)
	outcomes.Add(recordoutcome.OutcomeMapped, 2)
	outcomes.Add(recordoutcome.OutcomeEmitted, 2)
	close(c.done)
	return nil
}

func TestTenantSchedulerOptionsWireProviderCapacityAccounting(t *testing.T) {
	provider, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		ServiceName:    "capacity-wiring-test",
		Protocol:       "stdout",
		StdoutWriter:   io.Discard,
		SelfObsEnabled: true,
		Limits:         telemetry.Limits{PerMetric: 100, Global: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown provider: %v", err)
		}
	})

	done := make(chan struct{})
	registry := collector.NewRegistry()
	registry.Register(capacityWiringCollector{done: done}, time.Hour)
	status := collector.NewStatusTracker()
	availabilityTracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector: "capacity.wiring",
		Transport: telemetry.TransportGraph,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}})
	base := telemetry.WithTenant(
		telemetry.WithTransport(provider.Emitter(), telemetry.TransportGraph),
		"tenant-a",
	)
	opts := tenantSchedulerOptions(
		provider,
		"tenant-a",
		status,
		availabilityTracker,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	opts = append(opts, collector.WithStaggerWindow(0))
	scheduler := collector.NewScheduler(
		base,
		collector.NewMemoryStore(),
		opts...,
	)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- scheduler.Run(ctx, registry) }()
	select {
	case <-done:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("collector did not run")
	}
	<-runDone

	rows := provider.Volume()
	if len(rows) != 1 {
		t.Fatalf("capacity rows = %+v, want one", rows)
	}
	row := rows[0]
	// The log handoff produces its collector-bound event-lag histogram as well
	// as the domain gauge, so both billable SDK metric points are attributable.
	if row.TenantID != "tenant-a" || row.Collector != "capacity.wiring" ||
		row.Transport != telemetry.TransportGraph ||
		row.TrafficClass != telemetry.TrafficClassSteadyState ||
		row.SourceRecords != 2 || row.MetricPoints != 2 || row.LogPoints != 1 {
		t.Fatalf("capacity row = %+v, want fully attributed exact counts", row)
	}
}

func TestCollectorGate(t *testing.T) {
	trueValue := true
	tests := []struct {
		name      string
		collector collector.Collector
		cfg       *config.Config
		caps      license.Capabilities
		want      bool
	}{
		{
			name:      "missing capability",
			collector: premiumGateTestCollector{gateTestCollector: gateTestCollector{name: "premium"}, capability: license.CapEntraP1},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "experimental default disabled",
			collector: gateTestCollector{name: "beta", experimental: true},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "high volume default disabled",
			collector: gateTestCollector{name: "firehose", highVolume: true},
			cfg:       &config.Config{}, caps: license.Capabilities{}, want: false,
		},
		{
			name:      "explicit experimental enabled",
			collector: gateTestCollector{name: "beta", experimental: true},
			cfg:       &config.Config{Collectors: map[string]config.CollectorConfig{"beta": {Enabled: &trueValue}}}, caps: license.Capabilities{}, want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, _ := collectorGate(tt.collector, tt.cfg, "tenant-a", tt.caps)
			if got != tt.want {
				t.Errorf("collectorGate() enabled = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNilActiveRuntimeCollectorBecomesBoundedStartupFailure(t *testing.T) {
	candidate := availabilityCandidate{
		Name:      "m365.message_trace",
		Family:    availabilityFamilyWindow,
		Transport: telemetry.TransportExchangeOnline,
	}
	active := []availability.Static{{
		Collector: candidate.Name,
		Transport: candidate.Transport,
		State:     availability.StateStarting,
		Reason:    availability.ReasonNoCompletedRun,
	}}
	var failures []availabilityStartupFailure

	if runtimeCollectorReady(
		nil,
		candidate,
		active,
		&failures,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	) {
		t.Fatal("nil runtime collector reported ready")
	}
	if len(failures) != 1 {
		t.Fatalf("startup failures = %+v, want one bounded failure", failures)
	}
	got := failures[0]
	if got.collector != candidate.Name ||
		got.family != candidate.Family ||
		got.transport != candidate.Transport ||
		got.reason != availability.ReasonTransportInitializationFailed {
		t.Fatalf("startup failure = %+v, want bounded transport initialization failure", got)
	}

	disabled := []availability.Static{{
		Collector: candidate.Name,
		Transport: candidate.Transport,
		State:     availability.StateDisabled,
		Reason:    availability.ReasonTransportNotConfigured,
	}}
	failures = nil
	if runtimeCollectorReady(
		nil,
		candidate,
		disabled,
		&failures,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	) {
		t.Fatal("nil disabled runtime collector reported ready")
	}
	if len(failures) != 0 {
		t.Fatalf("disabled optional collector produced startup failures: %+v", failures)
	}
}

type runtimeCensusTestCollector struct{ name string }

func (c runtimeCensusTestCollector) Name() string { return c.name }
func (runtimeCensusTestCollector) DefaultInterval() time.Duration {
	return time.Minute
}
func (runtimeCensusTestCollector) Collect(
	context.Context,
	telemetry.Emitter,
	*recordoutcome.Recorder,
) error {
	return nil
}

func TestRuntimeRegistryNamesAreContainedInCanonicalSevenPathCensus(t *testing.T) {
	registry := collector.NewRegistry()
	var paths runtimeFactoryVisitor
	visitRegisteredCollectorFactories(&paths)

	for _, factory := range paths.snapshot {
		registry.Register(factory(collectors.Deps{}), time.Minute)
	}
	for _, factory := range paths.window {
		rw := factory(snapshotWindowDeps())
		registry.RegisterWindow(rw.Collector, time.Minute, rw.InitialLookback, rw.MaxWindow)
	}
	for _, factory := range paths.blob {
		registry.Register(factory(collectors.BlobDeps{}), time.Minute)
	}
	for _, factory := range paths.o365 {
		rw := factory(collectors.O365Deps{Store: checkpoint.NewStore(t.TempDir())})
		registry.RegisterWindow(rw.Collector, time.Minute, rw.InitialLookback, rw.MaxWindow)
	}
	for _, factory := range paths.mdca {
		rw := factory(collectors.MDCADeps{Store: checkpoint.NewStore(t.TempDir())})
		registry.RegisterWindow(rw.Collector, time.Minute, rw.InitialLookback, rw.MaxWindow)
	}
	for _, factory := range paths.exo {
		registry.Register(factory(collectors.EXODeps{Client: inertEXO{}}), time.Minute)
	}
	for _, factory := range paths.hunt {
		registry.Register(factory(collectors.HuntDeps{}), time.Minute)
	}

	inventory := resolveAvailabilityInventory(
		&config.Config{},
		"",
		allAvailabilityTestCapabilities(),
		true,
	)
	if err := validateRuntimeRegistryCensus(registry, inventory); err != nil {
		t.Fatalf("seven-path runtime registry escaped canonical census: %v", err)
	}

	registry.Register(runtimeCensusTestCollector{name: "not.in.canonical.census"}, time.Minute)
	if err := validateRuntimeRegistryCensus(registry, inventory); err == nil {
		t.Fatal("runtime registry accepted a collector absent from the canonical census")
	}
}
