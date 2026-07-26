package admin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// fakeLimiter is a stand-in RateLimiter returning a fixed headroom snapshot, so
// the admin panel wiring is exercised without a live *graphclient.WorkloadLimiter.
type fakeLimiter struct {
	headroom []graphclient.WorkloadHeadroom
}

func (f fakeLimiter) Snapshot(time.Time) []graphclient.WorkloadHeadroom { return f.headroom }

// fakeTelemetryStatus is the process-wide provider shape consumed by the
// Overview page: throughput is emit-side SDK handoff, while delivery is the
// independent exporter-callback snapshot. rawError proves the admin boundary
// never reflects arbitrary provider internals.
type fakeTelemetryStatus struct {
	throughput telemetry.Throughput
	delivery   telemetry.DeliverySnapshot
	rawError   string
}

func (f fakeTelemetryStatus) Throughput() telemetry.Throughput { return f.throughput }
func (f fakeTelemetryStatus) Delivery() telemetry.DeliverySnapshot {
	return f.delivery
}

type fakeCapacityTelemetryStatus struct {
	fakeTelemetryStatus
	volume     []telemetry.VolumeRow
	transport  telemetry.OTLPTransportSnapshot
	rawPayload string
	endpoint   string
	enforced   int
}

func (f fakeCapacityTelemetryStatus) Volume() []telemetry.VolumeRow {
	return f.volume
}
func (f fakeCapacityTelemetryStatus) Transport() telemetry.OTLPTransportSnapshot {
	return f.transport
}
func (f *fakeCapacityTelemetryStatus) EnforceBudget() { f.enforced++ }

func TestSnapshot_RateLimitsLandOnRightTenant(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	lim := fakeLimiter{headroom: []graphclient.WorkloadHeadroom{
		// tenant-a: two buckets, one half-drained, one full.
		{TenantID: "tenant-a", Workload: graphclient.WorkloadReporting, LimitPerSec: 0.5, Burst: 5, Tokens: 2.5},
		{TenantID: "tenant-a", Workload: graphclient.WorkloadIPC, LimitPerSec: 1, Burst: 1, Tokens: 1},
		// A bucket for a tenant the page has no source for: dropped, not attached anywhere.
		{TenantID: "ghost", Workload: graphclient.WorkloadDirectory, LimitPerSec: 5, Burst: 50, Tokens: 50},
	}}
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, lim, nil, nil, nil)

	snap := s.snapshot()
	if len(snap.Tenants) != 1 {
		t.Fatalf("Tenants = %d, want 1", len(snap.Tenants))
	}
	rl := snap.Tenants[0].RateLimits
	if len(rl) != 2 {
		t.Fatalf("tenant-a RateLimits = %+v, want the 2 tenant-a buckets (ghost dropped)", rl)
	}
	byWL := map[string]RateLimitStatus{}
	for _, r := range rl {
		byWL[r.Workload] = r
	}
	rep := byWL[string(graphclient.WorkloadReporting)]
	if rep.Burst != 5 || rep.Tokens != 2.5 || rep.HeadroomPct != 50 {
		t.Errorf("reporting = %+v, want burst 5 / tokens 2.5 / headroom 50", rep)
	}
	ipc := byWL[string(graphclient.WorkloadIPC)]
	if ipc.Burst != 1 || ipc.HeadroomPct != 100 {
		t.Errorf("ipc = %+v, want burst 1 / headroom 100", ipc)
	}
}

func TestSnapshot_NilLimiterNoPanel(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	// A nil limiter must render no panel and never panic.
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, nil, nil, nil, nil)
	if rl := s.snapshot().Tenants[0].RateLimits; rl != nil {
		t.Errorf("RateLimits = %+v, want nil with no limiter", rl)
	}
}

func TestNew_DisabledReturnsNil(t *testing.T) {
	s := New(config.AdminConfig{Enabled: false, Addr: ":9090"}, nil, nil, nil, nil, nil, nil)
	if s != nil {
		t.Fatalf("New() with Enabled=false = %v, want nil", s)
	}
}

func TestNew_DisabledServerStartIsNoop(t *testing.T) {
	var s *Server
	if err := s.Start(t.Context()); err != nil {
		t.Fatalf("Start() on disabled server = %v, want nil", err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() on disabled server = %v, want nil", err)
	}
}

func TestHealthz_ReturnsOK(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil, nil, nil, nil, nil)
	if s == nil {
		t.Fatal("New() returned nil for an enabled config")
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestReadyz_ZeroConfiguredTenantsReturnsOK(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /readyz status = %d, want %d", w.Code, http.StatusOK)
	}
	var got ReadinessStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal /readyz: %v", err)
	}
	if !got.Ready || got.State != readinessReady {
		t.Errorf("readiness = %+v, want ready", got)
	}
}

func TestReadyz_WorkingCollectorWaitsForFirstSuccess(t *testing.T) {
	reg := collector.NewRegistry()
	reg.Register(&fakeCollector{name: "devices"}, time.Hour)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
		TenantID: "tenant-a",
		Registry: reg,
		Status:   collector.NewStatusTracker(),
	}}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	var got ReadinessStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal /readyz: %v", err)
	}
	if got.Ready || got.State != readinessWaitingForFirstSuccess {
		t.Errorf("readiness = %+v, want waiting for first success", got)
	}
}

func TestReadyz_SuccessfulCollectorReturnsOK(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
		TenantID: "tenant-a",
		Registry: reg,
		Status:   tr,
	}}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /readyz status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHealthz_RemainsLiveWhenNoTenantCanStart(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
		TenantID:       "tenant-bad",
		StartupFailure: StartupFailureCredentialInitialization,
	}}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleStatusJSON_ReflectsCollectorState(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(got.Tenants) != 1 || len(got.Tenants[0].Collectors) != 1 {
		t.Fatalf("Tenants = %+v, want one tenant with one collector", got.Tenants)
	}
	c := got.Tenants[0].Collectors[0]
	if c.Name != "devices" || !c.Enabled || !c.HasRun || !c.LastSuccess {
		t.Errorf("collector row = %+v, want devices/enabled/has-run/last-success", c)
	}
	if got.Service.Version == "" {
		t.Errorf("Service.Version is empty")
	}
}

func TestHandleStatusJSON_DeliveryProjectsIndependentBoundedSignals(t *testing.T) {
	const secret = "Authorization: Bearer delivery-secret"
	provider := fakeTelemetryStatus{
		rawError: secret,
		delivery: telemetry.DeliverySnapshot{
			Metrics: telemetry.DeliverySignal{
				State:              telemetry.DeliveryStateDegraded,
				ExportAttempts:     4,
				ExportSuccesses:    2,
				ExportFailures:     2,
				ForceFlushFailures: 1,
				ShutdownFailures:   1,
				LastSuccessAt:      "2026-07-26T10:00:00.123456789Z",
				LastFailureAt:      "2026-07-26T10:01:00.123456789Z",
				LastFailureCode:    telemetry.DeliveryFailureShutdownFailed,
			},
			Logs: telemetry.DeliverySignal{
				State:           telemetry.DeliveryStateHealthy,
				ExportAttempts:  7,
				ExportSuccesses: 7,
				LastSuccessAt:   "2026-07-26T10:02:00.123456789Z",
			},
		},
	}
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil, nil, nil, nil, provider)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("delivery JSON retained provider error secret: %s", w.Body.String())
	}

	var got struct {
		Delivery *struct {
			Metrics struct {
				State              telemetry.DeliveryState       `json:"state"`
				ExportAttempts     uint64                        `json:"export_attempts"`
				ExportSuccesses    uint64                        `json:"export_successes"`
				ExportFailures     uint64                        `json:"export_failures"`
				ForceFlushFailures uint64                        `json:"force_flush_failures"`
				ShutdownFailures   uint64                        `json:"shutdown_failures"`
				LastSuccessAt      string                        `json:"last_success_at"`
				LastFailureAt      string                        `json:"last_failure_at"`
				LastFailureCode    telemetry.DeliveryFailureCode `json:"last_failure_code"`
			} `json:"metrics"`
			Logs struct {
				State           telemetry.DeliveryState       `json:"state"`
				ExportAttempts  uint64                        `json:"export_attempts"`
				ExportSuccesses uint64                        `json:"export_successes"`
				ExportFailures  uint64                        `json:"export_failures"`
				LastSuccessAt   string                        `json:"last_success_at"`
				LastFailureAt   string                        `json:"last_failure_at"`
				LastFailureCode telemetry.DeliveryFailureCode `json:"last_failure_code"`
			} `json:"logs"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.Delivery == nil {
		t.Fatal("delivery JSON is absent with a DeliverySource")
	}
	if m := got.Delivery.Metrics; m.State != telemetry.DeliveryStateDegraded ||
		m.ExportAttempts != 4 || m.ExportSuccesses != 2 || m.ExportFailures != 2 ||
		m.ForceFlushFailures != 1 || m.ShutdownFailures != 1 ||
		m.LastSuccessAt != "2026-07-26T10:00:00.123456789Z" ||
		m.LastFailureAt != "2026-07-26T10:01:00.123456789Z" ||
		m.LastFailureCode != telemetry.DeliveryFailureShutdownFailed {
		t.Errorf("metric delivery = %+v, want independent degraded snapshot", m)
	}
	if l := got.Delivery.Logs; l.State != telemetry.DeliveryStateHealthy ||
		l.ExportAttempts != 7 || l.ExportSuccesses != 7 || l.ExportFailures != 0 ||
		l.LastSuccessAt != "2026-07-26T10:02:00.123456789Z" ||
		l.LastFailureAt != "" || l.LastFailureCode != "" {
		t.Errorf("log delivery = %+v, want independent healthy snapshot", l)
	}
}

func TestHandleStatusJSON_CapacityProjectsOnlyExactBoundedCounters(t *testing.T) {
	const (
		secret      = "Authorization: Bearer capacity-secret"
		rawPayload  = `{"userPrincipalName":"secret@example.test"}`
		endpointURL = "https://otlp.example.test/private-path"
	)
	provider := &fakeCapacityTelemetryStatus{
		fakeTelemetryStatus: fakeTelemetryStatus{rawError: secret},
		rawPayload:          rawPayload,
		endpoint:            endpointURL,
		volume: []telemetry.VolumeRow{
			{
				Attribution: telemetry.Attribution{
					TenantID:     "tenant-a",
					Collector:    "entra.signins",
					Transport:    telemetry.TransportGraph,
					TrafficClass: telemetry.TrafficClassSteadyState,
				},
				SourceRecords: 11,
				MetricPoints:  3,
				LogPoints:     7,
			},
			{
				Attribution: telemetry.Attribution{
					TenantID:     "tenant-b",
					Collector:    "intune.devices",
					Transport:    telemetry.TransportBlob,
					TrafficClass: telemetry.TrafficClassColdStartBackfill,
				},
				SourceRecords: 5,
				MetricPoints:  2,
				LogPoints:     1,
			},
		},
		transport: telemetry.OTLPTransportSnapshot{
			Metrics: telemetry.OTLPTransportSignal{PayloadBytes: 1234, RetryAttempts: 2},
			Logs:    telemetry.OTLPTransportSignal{PayloadBytes: 5678, RetryAttempts: 3},
		},
	}
	cfg := &config.Config{}
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil, nil, cfg, nil, provider)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}
	for _, forbidden := range []string{secret, rawPayload, endpointURL} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Errorf("capacity JSON retained forbidden provider data %q", forbidden)
		}
	}

	var got struct {
		Capacity *struct {
			Volume []struct {
				TenantID        string                 `json:"tenant_id"`
				Collector       string                 `json:"collector"`
				IngestTransport telemetry.Transport    `json:"ingest_transport"`
				TrafficClass    telemetry.TrafficClass `json:"traffic_class"`
				SourceRecords   uint64                 `json:"source_records"`
				MetricPoints    uint64                 `json:"metric_points"`
				LogPoints       uint64                 `json:"log_points"`
			} `json:"volume"`
			Transport struct {
				Metrics struct {
					TransmittedPayloadBytes uint64 `json:"transmitted_payload_bytes"`
					RetryAttempts           uint64 `json:"retry_attempts"`
				} `json:"metrics"`
				Logs struct {
					TransmittedPayloadBytes uint64 `json:"transmitted_payload_bytes"`
					RetryAttempts           uint64 `json:"retry_attempts"`
				} `json:"logs"`
			} `json:"transport"`
			Cost json.RawMessage `json:"cost"`
		} `json:"capacity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal capacity response: %v", err)
	}
	if got.Capacity == nil {
		t.Fatal("capacity JSON is absent with a CapacitySource")
	}
	if len(got.Capacity.Volume) != 2 {
		t.Fatalf("capacity volume rows = %+v, want two exact rows", got.Capacity.Volume)
	}
	first := got.Capacity.Volume[0]
	if first.TenantID != "tenant-a" || first.Collector != "entra.signins" ||
		first.IngestTransport != telemetry.TransportGraph ||
		first.TrafficClass != telemetry.TrafficClassSteadyState ||
		first.SourceRecords != 11 || first.MetricPoints != 3 || first.LogPoints != 7 {
		t.Errorf("first capacity row = %+v, want exact cumulative counters", first)
	}
	if got.Capacity.Transport.Metrics.TransmittedPayloadBytes != 1234 ||
		got.Capacity.Transport.Metrics.RetryAttempts != 2 ||
		got.Capacity.Transport.Logs.TransmittedPayloadBytes != 5678 ||
		got.Capacity.Transport.Logs.RetryAttempts != 3 {
		t.Errorf("process transport = %+v, want exact cumulative totals", got.Capacity.Transport)
	}
	if len(got.Capacity.Cost) != 0 && string(got.Capacity.Cost) != "null" {
		t.Errorf("cost JSON = %s, want absent/null while disabled", got.Capacity.Cost)
	}
	if provider.enforced != 0 {
		t.Errorf("budget enforcement calls = %d, want 0", provider.enforced)
	}
}

func TestHandleStatusJSON_CostPreservesSignalAllocationAndRecurringScopes(t *testing.T) {
	sourceRate, metricRate, logRate, payloadRate := int64(1), int64(1), int64(1), int64(1)
	provider := &fakeCapacityTelemetryStatus{
		volume: []telemetry.VolumeRow{{
			Attribution: telemetry.Attribution{
				TenantID:     "tenant-a",
				Collector:    "collector-a",
				Transport:    telemetry.TransportGraph,
				TrafficClass: telemetry.TrafficClassSteadyState,
			},
			SourceRecords: 10,
			MetricPoints:  10,
			LogPoints:     10,
		}},
		transport: telemetry.OTLPTransportSnapshot{
			Metrics: telemetry.OTLPTransportSignal{PayloadBytes: 100},
			Logs:    telemetry.OTLPTransportSignal{PayloadBytes: 200},
		},
	}
	cfg := &config.Config{Cost: *testCostConfig(
		2*time.Minute,
		1000,
		&sourceRate,
		&metricRate,
		&logRate,
		&payloadRate,
	)}
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil, nil, cfg, nil, provider)
	clk := newStepClock()
	s.trend.now = clk.now
	s.trend.sample()

	provider.volume[0].SourceRecords = 11
	provider.volume[0].MetricPoints = 13
	provider.volume[0].LogPoints = 12
	provider.transport.Metrics.PayloadBytes = 106
	provider.transport.Logs.PayloadBytes = 204
	clk.advance(2 * time.Minute)
	s.trend.sample()

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}
	var got struct {
		Capacity struct {
			Cost struct {
				IntervalScope   string `json:"interval_scope"`
				ProjectionScope string `json:"projection_scope"`
				Rows            []struct {
					Attribution                 string `json:"attribution"`
					AllocatedMetricPayloadBytes uint64 `json:"allocated_metric_payload_bytes"`
					AllocatedLogPayloadBytes    uint64 `json:"allocated_log_payload_bytes"`
					AllocatedPayloadBytes       uint64 `json:"allocated_payload_bytes"`
					IntervalMicrounits          uint64 `json:"interval_microunits"`
					ProjectedPeriodMicrounits   uint64 `json:"projected_period_microunits"`
				} `json:"rows"`
			} `json:"cost"`
		} `json:"capacity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal capacity cost JSON: %v", err)
	}
	if got.Capacity.Cost.IntervalScope != "all_observed_traffic" ||
		got.Capacity.Cost.ProjectionScope != "recurring_steady_state_only" {
		t.Errorf("cost JSON scopes = %q/%q, want all-observed/recurring-steady",
			got.Capacity.Cost.IntervalScope, got.Capacity.Cost.ProjectionScope)
	}
	if len(got.Capacity.Cost.Rows) != 1 {
		t.Fatalf("cost JSON rows = %+v, want one", got.Capacity.Cost.Rows)
	}
	row := got.Capacity.Cost.Rows[0]
	if row.Attribution != "estimated" ||
		row.AllocatedMetricPayloadBytes != 6 ||
		row.AllocatedLogPayloadBytes != 4 ||
		row.AllocatedPayloadBytes != 10 ||
		row.IntervalMicrounits == 0 ||
		row.ProjectedPeriodMicrounits == 0 {
		t.Errorf("cost JSON row = %+v, want auditable signal allocation and both costs", row)
	}
	if provider.enforced != 0 {
		t.Errorf("budget enforcement calls = %d, want 0", provider.enforced)
	}
}

func TestDeliveryDegradation_DoesNotChangeHealthzOrReadyz(t *testing.T) {
	provider := fakeTelemetryStatus{delivery: telemetry.DeliverySnapshot{
		Metrics: telemetry.DeliverySignal{
			State:           telemetry.DeliveryStateDegraded,
			ExportAttempts:  1,
			ExportFailures:  1,
			LastFailureCode: telemetry.DeliveryFailureExportFailed,
		},
		Logs: telemetry.DeliverySignal{State: telemetry.DeliveryStateStarting},
	}}

	t.Run("successful tenant stays live and ready", func(t *testing.T) {
		tr, reg := runOnceAndTrack(t, "devices", nil)
		s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
			TenantID: "tenant-a",
			Registry: reg,
			Status:   tr,
		}}, nil, nil, nil, nil, provider)

		for _, path := range []string{"/healthz", "/readyz"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("GET %s status = %d, want %d under degraded delivery",
					path, w.Code, http.StatusOK)
			}
		}
	})

	t.Run("waiting tenant still waits for first collector success", func(t *testing.T) {
		reg := collector.NewRegistry()
		reg.Register(&fakeCollector{name: "devices"}, time.Hour)
		s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
			TenantID: "tenant-a",
			Registry: reg,
			Status:   collector.NewStatusTracker(),
		}}, nil, nil, nil, nil, provider)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET /readyz status = %d, want %d while waiting for first success",
				w.Code, http.StatusServiceUnavailable)
		}
		var got ReadinessStatus
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal /readyz: %v", err)
		}
		if got.State != readinessWaitingForFirstSuccess {
			t.Errorf("readiness state = %q, want %q", got.State, readinessWaitingForFirstSuccess)
		}
	})
}

func TestHandleStatusJSON_ExposesNestedCanonicalAvailabilityAndLastOutcome(t *testing.T) {
	tracker := availability.NewTracker("tenant-a", []availability.Static{{
		Collector:           "entra.risk",
		Transport:           telemetry.TransportGraph,
		State:               availability.StateLimited,
		Reason:              availability.ReasonPartialLicense,
		Limitations:         []availability.Limitation{availability.LimitationRiskyUsers},
		MissingCapabilities: []availability.MissingCapability{availability.MissingCapabilityEntraP2},
	}})
	tracker.Record("entra.risk", recordoutcome.Summary{
		Result: recordoutcome.ResultSuccess,
		Counts: recordoutcome.Counts{
			Fetched: 4,
			Mapped:  3,
			Emitted: 2,
			Deduped: 1,
		},
	})
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{{
		TenantID:     "tenant-a",
		Availability: tracker,
	}}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status.json status = %d, want %d", w.Code, http.StatusOK)
	}

	var payload struct {
		Tenants []struct {
			Collectors []json.RawMessage `json:"collectors"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal status response: %v", err)
	}
	if len(payload.Tenants) != 1 || len(payload.Tenants[0].Collectors) != 1 {
		t.Fatalf("tenant collector payload = %+v, want one canonical row", payload.Tenants)
	}

	var row struct {
		Availability struct {
			State               string   `json:"state"`
			Reason              string   `json:"reason"`
			Transport           string   `json:"transport"`
			Limitations         []string `json:"limitations"`
			MissingCapabilities []string `json:"missing_capabilities"`
		} `json:"availability"`
		LastOutcome struct {
			Result string `json:"result"`
			Cause  string `json:"cause"`
			Counts struct {
				Fetched uint64 `json:"fetched"`
				Mapped  uint64 `json:"mapped"`
				Emitted uint64 `json:"emitted"`
				Deduped uint64 `json:"deduped"`
			} `json:"counts"`
		} `json:"last_outcome"`
	}
	if err := json.Unmarshal(payload.Tenants[0].Collectors[0], &row); err != nil {
		t.Fatalf("unmarshal collector row: %v", err)
	}
	if row.Availability.State != string(availability.StateLimited) ||
		row.Availability.Reason != string(availability.ReasonPartialLicense) ||
		row.Availability.Transport != string(telemetry.TransportGraph) ||
		len(row.Availability.Limitations) != 1 ||
		row.Availability.Limitations[0] != string(availability.LimitationRiskyUsers) ||
		len(row.Availability.MissingCapabilities) != 1 ||
		row.Availability.MissingCapabilities[0] != string(availability.MissingCapabilityEntraP2) {
		t.Errorf("availability JSON = %+v, want canonical limited point", row.Availability)
	}
	if row.LastOutcome.Result != string(recordoutcome.ResultSuccess) ||
		row.LastOutcome.Cause != "" ||
		row.LastOutcome.Counts.Fetched != 4 ||
		row.LastOutcome.Counts.Mapped != 3 ||
		row.LastOutcome.Counts.Emitted != 2 ||
		row.LastOutcome.Counts.Deduped != 1 {
		t.Errorf("last_outcome JSON = %+v, want typed result/cause/counts", row.LastOutcome)
	}
}

func TestHandleStatusJSON_SkippedCollectorShowsReason(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a"},
	}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "identityprotection"}: "requires P2",
	}, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var got Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	c := got.Tenants[0].Collectors[0]
	if c.Name != "identityprotection" || c.Enabled || c.SkipReason != "requires P2" {
		t.Errorf("collector row = %+v, want identityprotection/skipped/\"requires P2\"", c)
	}
}

func TestHandleStatusJSON_StartupFailureIsSanitizedAndReadinessIncluded(t *testing.T) {
	const secret = "client secret hunter2"
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-credential", StartupFailure: StartupFailureCredentialInitialization},
		{TenantID: "tenant-invalid", StartupFailure: StartupFailureCode(secret)},
	}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status.json", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("status JSON exposed raw startup failure: %s", body)
	}

	var got Status
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.Readiness.Ready || got.Readiness.State != readinessNoWorkingTenants {
		t.Errorf("readiness = %+v, want no working tenants", got.Readiness)
	}
	if failure := got.Tenants[0].StartupFailure; failure == nil ||
		failure.Code != StartupFailureCredentialInitialization ||
		failure.Reason != "credential initialization failed" {
		t.Errorf("credential tenant failure = %+v, want bounded sanitized failure", failure)
	}
	if failure := got.Tenants[1].StartupFailure; failure != nil {
		t.Errorf("invalid tenant failure = %+v, want omitted", failure)
	}
}

func TestHandleIndex_RendersHTML(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "devices") {
		t.Errorf("body does not contain collector name %q", "devices")
	}
	if !strings.Contains(strings.ToLower(body), "healthy") {
		t.Errorf("body does not contain health state %q", "healthy")
	}
}

func TestServer_StartAndShutdown(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	if s == nil {
		t.Fatal("New() returned nil for an enabled config")
	}

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()

	// Give the listener a moment to bind before we cancel it.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start() = %v, want nil after graceful shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return after ctx cancel")
	}
}

func TestServer_BindFailureStopsAndJoinsTrendSampler(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy admin address: %v", err)
	}
	defer occupied.Close()

	s := New(config.AdminConfig{Enabled: true, Addr: occupied.Addr().String()}, nil, nil, nil, nil, nil, nil)
	if s == nil {
		t.Fatal("New() returned nil for an enabled config")
	}

	started := make(chan struct{})
	exited := make(chan struct{})
	s.runSampler = func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(exited)
	}

	if err := s.Start(t.Context()); err == nil {
		t.Fatal("Start() on an occupied address = nil, want bind failure")
	}

	// Start must not return until the sampler has observed cancellation and
	// exited. Non-blocking receives are deterministic here because the join is
	// the behavior under test; no sleeps or goroutine-count heuristics.
	select {
	case <-started:
	default:
		t.Fatal("Start() returned before the trend sampler started")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Start() returned before the trend sampler exited")
	}
}
