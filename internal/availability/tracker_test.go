package availability

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

func TestTrackerSnapshotIsDeterministicAndImmutable(t *testing.T) {
	initial := []Static{
		{
			Collector:           "zeta",
			Transport:           telemetry.TransportBlob,
			State:               StateLimited,
			Reason:              ReasonPartialLicense,
			Limitations:         []Limitation{"premium_signal"},
			MissingCapabilities: []MissingCapability{MissingCapabilityEntraP2},
		},
		{
			Collector: "alpha",
			Transport: telemetry.TransportGraph,
			State:     StateStarting,
			Reason:    ReasonNoCompletedRun,
		},
	}
	tracker := NewTracker("tenant-a", initial)
	initial[0].Collector = "mutated"
	initial[0].Limitations[0] = "mutated"
	initial[0].MissingCapabilities[0] = "mutated"

	summary := recordoutcome.Summary{Result: recordoutcome.ResultSuccess}
	tracker.Record("alpha", summary)
	summary.Result = recordoutcome.ResultFailure

	got := tracker.Snapshot()
	if names := []string{got[0].Collector, got[1].Collector}; !reflect.DeepEqual(names, []string{"alpha", "zeta"}) {
		t.Fatalf("Snapshot collector order = %v, want [alpha zeta]", names)
	}
	if got[0].LastOutcome == nil || got[0].LastOutcome.Result != recordoutcome.ResultSuccess {
		t.Fatalf("alpha LastOutcome = %+v, want immutable success summary", got[0].LastOutcome)
	}
	if !reflect.DeepEqual(got[1].Limitations, []Limitation{"premium_signal"}) {
		t.Fatalf("zeta Limitations = %v, want [premium_signal]", got[1].Limitations)
	}
	if !reflect.DeepEqual(got[1].MissingCapabilities, []MissingCapability{MissingCapabilityEntraP2}) {
		t.Fatalf("zeta MissingCapabilities = %v, want [entra_p2]", got[1].MissingCapabilities)
	}

	got[0].LastOutcome.Result = recordoutcome.ResultFailure
	got[1].Limitations[0] = "output mutation"
	got[1].MissingCapabilities[0] = "output mutation"
	again := tracker.Snapshot()
	if again[0].LastOutcome == nil || again[0].LastOutcome.Result != recordoutcome.ResultSuccess {
		t.Fatalf("mutating snapshot changed tracker outcome: %+v", again[0].LastOutcome)
	}
	if !reflect.DeepEqual(again[1].Limitations, []Limitation{"premium_signal"}) {
		t.Fatalf("mutating snapshot changed tracker limitations: %v", again[1].Limitations)
	}
	if !reflect.DeepEqual(again[1].MissingCapabilities, []MissingCapability{MissingCapabilityEntraP2}) {
		t.Fatalf("mutating snapshot changed tracker missing capabilities: %v", again[1].MissingCapabilities)
	}

	tracker.Record("not-in-census", recordoutcome.Summary{Result: recordoutcome.ResultFailure})
	if got := tracker.Snapshot(); len(got) != 2 {
		t.Fatalf("recording unknown collector changed census size to %d, want 2", len(got))
	}
}

func TestTrackerConcurrentRecordPublishesOnePointPerCollector(t *testing.T) {
	const collectors = 64
	initial := make([]Static, 0, collectors)
	for i := collectors - 1; i >= 0; i-- {
		initial = append(initial, Static{
			Collector: fmt.Sprintf("collector-%02d", i),
			Transport: telemetry.TransportGraph,
			State:     StateStarting,
			Reason:    ReasonNoCompletedRun,
		})
	}
	tracker := NewTracker("tenant-a", initial)

	var wg sync.WaitGroup
	for i := 0; i < collectors; i++ {
		name := fmt.Sprintf("collector-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Record(name, recordoutcome.Summary{Result: recordoutcome.ResultSuccess})
			_ = tracker.Snapshot()
		}()
	}
	wg.Wait()

	got := tracker.Snapshot()
	if len(got) != collectors {
		t.Fatalf("Snapshot points = %d, want %d", len(got), collectors)
	}
	for i, point := range got {
		wantName := fmt.Sprintf("collector-%02d", i)
		if point.Collector != wantName {
			t.Fatalf("Snapshot[%d].Collector = %q, want %q", i, point.Collector, wantName)
		}
		if point.State != StateHealthy || point.Reason != ReasonSuccess {
			t.Fatalf("%s state/reason = %q/%q, want healthy/success", point.Collector, point.State, point.Reason)
		}
	}
}

func TestTrackerEmitReplacesTransitionedSeriesWithExactAttributes(t *testing.T) {
	rec := telemetrytest.New()
	tracker := NewTracker("tenant-a", []Static{
		{
			Collector: "entra.users",
			Transport: telemetry.TransportGraph,
			State:     StateStarting,
			Reason:    ReasonNoCompletedRun,
		},
		{
			Collector:   "entra.risk",
			Transport:   telemetry.TransportGraph,
			State:       StateLimited,
			Reason:      ReasonPartialLicense,
			Limitations: []Limitation{"risky_users"},
		},
	})

	tracker.Emit(rec.Emitter())
	assertAvailabilityMetric(t, rec, map[string][2]string{
		"entra.risk":  {string(StateLimited), string(ReasonPartialLicense)},
		"entra.users": {string(StateStarting), string(ReasonNoCompletedRun)},
	})

	tracker.Record("entra.users", recordoutcome.Summary{
		Result: recordoutcome.ResultFailure,
		Cause:  recordoutcome.CausePermissionDenied,
	})
	tracker.Emit(rec.Emitter())
	assertAvailabilityMetric(t, rec, map[string][2]string{
		"entra.risk":  {string(StateLimited), string(ReasonPartialLicense)},
		"entra.users": {string(StateBlocked), string(ReasonPermissionDenied)},
	})
}

func TestTrackerEmitKeepsTenantSnapshotsIsolated(t *testing.T) {
	rec := telemetrytest.New()
	tenantA := NewTracker("tenant-a", []Static{{
		Collector: "entra.users",
		Transport: telemetry.TransportGraph,
		State:     StateStarting,
		Reason:    ReasonNoCompletedRun,
	}})
	tenantB := NewTracker("tenant-b", []Static{{
		Collector: "entra.users",
		Transport: telemetry.TransportGraph,
		State:     StateDisabled,
		Reason:    ReasonDisabledByConfig,
	}})

	tenantA.Emit(rec.Emitter())
	tenantB.Emit(rec.Emitter())

	points := rec.MetricPoints(MetricCollectorAvailability)
	if len(points) != 2 {
		t.Fatalf("%s points = %d, want 2 tenant-isolated points: %v", MetricCollectorAvailability, len(points), points)
	}
	got := map[string][2]string{}
	for _, point := range points {
		got[point.Attrs[semconv.AttrTenantID]] = [2]string{
			point.Attrs[semconv.AttrState],
			point.Attrs[semconv.AttrReason],
		}
	}
	want := map[string][2]string{
		"tenant-a": {string(StateStarting), string(ReasonNoCompletedRun)},
		"tenant-b": {string(StateDisabled), string(ReasonDisabledByConfig)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tenant snapshots = %v, want %v", got, want)
	}
}

func assertAvailabilityMetric(
	t *testing.T,
	rec *telemetrytest.Recorder,
	want map[string][2]string,
) {
	t.Helper()
	points := rec.MetricPoints(MetricCollectorAvailability)
	if len(points) != len(want) {
		t.Fatalf("%s points = %d, want %d: %v", MetricCollectorAvailability, len(points), len(want), points)
	}
	for _, point := range points {
		if point.Name != "graph2otel.collector.availability" ||
			point.Unit != "{collector}" ||
			point.Kind != "gauge" ||
			point.Value != 1 {
			t.Errorf("availability point instrument = name %q unit %q kind %q value %v", point.Name, point.Unit, point.Kind, point.Value)
		}
		if len(point.Attrs) != 5 {
			t.Errorf("%s attrs = %v, want exactly five attributes", point.Attrs[semconv.AttrCollector], point.Attrs)
		}
		for _, key := range []string{
			semconv.AttrTenantID,
			semconv.AttrCollector,
			semconv.AttrCollectorTransport,
			semconv.AttrState,
			semconv.AttrReason,
		} {
			if _, ok := point.Attrs[key]; !ok {
				t.Errorf("%s attrs = %v, missing %q", point.Attrs[semconv.AttrCollector], point.Attrs, key)
			}
		}
		if point.Attrs[semconv.AttrTenantID] != "tenant-a" {
			t.Errorf("%s tenant_id = %q, want tenant-a", point.Attrs[semconv.AttrCollector], point.Attrs[semconv.AttrTenantID])
		}
		if point.Attrs[semconv.AttrCollectorTransport] != string(telemetry.TransportGraph) {
			t.Errorf("%s collector.transport = %q, want graph", point.Attrs[semconv.AttrCollector], point.Attrs[semconv.AttrCollectorTransport])
		}
		name := point.Attrs[semconv.AttrCollector]
		stateReason, ok := want[name]
		if !ok {
			t.Errorf("unexpected collector point %q: %v", name, point.Attrs)
			continue
		}
		if point.Attrs[semconv.AttrState] != stateReason[0] ||
			point.Attrs[semconv.AttrReason] != stateReason[1] {
			t.Errorf("%s state/reason = %q/%q, want %q/%q",
				name,
				point.Attrs[semconv.AttrState],
				point.Attrs[semconv.AttrReason],
				stateReason[0],
				stateReason[1],
			)
		}
	}
}
