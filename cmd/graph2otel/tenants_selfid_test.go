package main

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/config"
)

// TestTenantBlobExcludeSelfResolvesClientID pins how #154's self-exhaust filter
// identifies "self": the tenant's configured client_id wins, falling back to the
// AZURE_CLIENT_ID env leg that DefaultAzureCredential already uses, so an
// env-authenticated deployment (the common case, e.g. camden) can enable
// exclude_self without duplicating its app id into config. Only when neither is
// set is "self" unidentifiable (the caller then warns and the filter no-ops).
func TestTenantBlobExcludeSelfResolvesClientID(t *testing.T) {
	const (
		configID = "config-app-id"
		envID    = "env-app-id"
	)
	cfg := &config.Config{
		Tenants: []config.TenantConfig{
			{TenantID: "t-config", ClientID: configID, BlobIngest: config.BlobIngestConfig{ExcludeSelf: true}},
			{TenantID: "t-envfallback", ClientID: "", BlobIngest: config.BlobIngestConfig{ExcludeSelf: true}},
			{TenantID: "t-off", ClientID: configID, BlobIngest: config.BlobIngestConfig{ExcludeSelf: false}},
		},
	}

	t.Run("config client_id wins over the environment", func(t *testing.T) {
		t.Setenv("AZURE_CLIENT_ID", envID)
		excl, id := tenantBlobExcludeSelf(cfg, "t-config")
		if !excl || id != configID {
			t.Fatalf("got (%v, %q), want (true, %q) — config client_id must win", excl, id, configID)
		}
	})

	t.Run("falls back to AZURE_CLIENT_ID when config client_id is empty", func(t *testing.T) {
		t.Setenv("AZURE_CLIENT_ID", envID)
		excl, id := tenantBlobExcludeSelf(cfg, "t-envfallback")
		if !excl || id != envID {
			t.Fatalf("got (%v, %q), want (true, %q) — must fall back to AZURE_CLIENT_ID", excl, id, envID)
		}
	})

	t.Run("neither set leaves self unidentifiable", func(t *testing.T) {
		t.Setenv("AZURE_CLIENT_ID", "")
		excl, id := tenantBlobExcludeSelf(cfg, "t-envfallback")
		if !excl || id != "" {
			t.Fatalf("got (%v, %q), want (true, \"\") — no client_id and no env means empty self", excl, id)
		}
	})

	t.Run("exclude_self off returns false regardless", func(t *testing.T) {
		t.Setenv("AZURE_CLIENT_ID", envID)
		excl, _ := tenantBlobExcludeSelf(cfg, "t-off")
		if excl {
			t.Fatalf("exclude_self is false for t-off, want excludeSelf=false")
		}
	})

	t.Run("unknown tenant is off with empty self", func(t *testing.T) {
		excl, id := tenantBlobExcludeSelf(cfg, "nope")
		if excl || id != "" {
			t.Fatalf("got (%v, %q), want (false, \"\")", excl, id)
		}
	})
}
