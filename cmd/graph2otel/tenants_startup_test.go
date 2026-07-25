package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestStartTenantsWithBuildersRetainsEveryConfiguredTenantInOrder(t *testing.T) {
	cfg := &config.Config{Tenants: []config.TenantConfig{
		{TenantID: "tenant-credential-failure"},
		{TenantID: "tenant-working"},
		{TenantID: "tenant-client-failure"},
	}}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))

	authBuilder := func(tc config.TenantConfig) (*auth.TenantAuth, error) {
		if tc.TenantID == "tenant-credential-failure" {
			return nil, errors.New("credential super-secret")
		}
		return &auth.TenantAuth{TenantID: tc.TenantID}, nil
	}
	setup := func(
		_ context.Context,
		ta *auth.TenantAuth,
		_ *config.Config,
		_ *telemetry.Provider,
		_ *slog.Logger,
		_ *graphclient.WorkloadLimiter,
		_ map[admin.SkipKey]string,
		_ *sync.WaitGroup,
	) (admin.CollectorSource, error) {
		if ta.TenantID == "tenant-client-failure" {
			return admin.CollectorSource{
				TenantID:       ta.TenantID,
				StartupFailure: admin.StartupFailureGraphClientInitialization,
			}, nil
		}
		return admin.CollectorSource{
			TenantID: ta.TenantID,
			Registry: collector.NewRegistry(),
			Status:   collector.NewStatusTracker(),
		}, nil
	}

	sources, _, _, wait, err := startTenantsWithBuilders(
		context.Background(), cfg, nil, logger, authBuilder, setup,
	)
	if err != nil {
		t.Fatalf("startTenantsWithBuilders() error = %v", err)
	}
	wait()

	if got, want := len(sources), len(cfg.Tenants); got != want {
		t.Fatalf("source count = %d, want %d (one retained source per configured tenant)", got, want)
	}
	for i, want := range []string{"tenant-credential-failure", "tenant-working", "tenant-client-failure"} {
		if got := sources[i].TenantID; got != want {
			t.Errorf("sources[%d].TenantID = %q, want %q (configuration order)", i, got, want)
		}
	}
	if got := sources[0].StartupFailure; got != admin.StartupFailureCredentialInitialization {
		t.Errorf("credential failure code = %q, want %q", got, admin.StartupFailureCredentialInitialization)
	}
	if got := sources[1].StartupFailure; got != "" {
		t.Errorf("working tenant startup failure = %q, want empty", got)
	}
	if got := sources[2].StartupFailure; got != admin.StartupFailureGraphClientInitialization {
		t.Errorf("Graph client failure code = %q, want %q", got, admin.StartupFailureGraphClientInitialization)
	}
	for _, source := range sources {
		if strings.Contains(string(source.StartupFailure), "super-secret") {
			t.Fatal("retained startup state contains raw credential error")
		}
	}
	if !strings.Contains(logOutput.String(), "credential super-secret") {
		t.Errorf("startup log = %q, want raw credential error for operator diagnosis", logOutput.String())
	}
}

func TestSetupTenantWithGraphClientBuilderSanitizesConstructionFailure(t *testing.T) {
	provider, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		Protocol:     "stdout",
		StdoutWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("provider shutdown: %v", err)
		}
	})

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphClientBuilder(
		context.Background(),
		&auth.TenantAuth{TenantID: "tenant-a"},
		&config.Config{CheckpointDir: t.TempDir()},
		provider,
		logger,
		graphclient.NewWorkloadLimiter(),
		map[admin.SkipKey]string{},
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return nil, errors.New("client super-secret")
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphClientBuilder() error = %v, want recoverable source", err)
	}
	wg.Wait()

	if got, want := source.TenantID, "tenant-a"; got != want {
		t.Errorf("TenantID = %q, want %q", got, want)
	}
	if got := source.StartupFailure; got != admin.StartupFailureGraphClientInitialization {
		t.Errorf("StartupFailure = %q, want %q", got, admin.StartupFailureGraphClientInitialization)
	}
	if source.Registry != nil || source.Status != nil {
		t.Error("failed tenant retained live registry/status")
	}
	if strings.Contains(string(source.StartupFailure), "super-secret") {
		t.Fatal("retained Graph-client startup state contains raw error")
	}
	if !strings.Contains(logOutput.String(), "client super-secret") {
		t.Errorf("startup log = %q, want raw Graph-client error for operator diagnosis", logOutput.String())
	}
}
