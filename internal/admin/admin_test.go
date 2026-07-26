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
