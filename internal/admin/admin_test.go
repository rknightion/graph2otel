package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/config"
)

func TestNew_DisabledReturnsNil(t *testing.T) {
	s := New(config.AdminConfig{Enabled: false, Addr: ":9090"}, nil, nil)
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
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, nil, nil)
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

func TestHandleStatusJSON_ReflectsCollectorState(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil)

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

func TestHandleStatusJSON_SkippedCollectorShowsReason(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a"},
	}, map[SkipKey]string{
		{TenantID: "tenant-a", Collector: "identityprotection"}: "requires P2",
	})

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

func TestHandleIndex_RendersHTML(t *testing.T) {
	tr, reg := runOnceAndTrack(t, "devices", nil)
	s := New(config.AdminConfig{Enabled: true, Addr: ":0"}, []CollectorSource{
		{TenantID: "tenant-a", Registry: reg, Status: tr},
	}, nil)

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
	s := New(config.AdminConfig{Enabled: true, Addr: "127.0.0.1:0"}, nil, nil)
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
