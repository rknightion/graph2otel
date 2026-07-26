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
