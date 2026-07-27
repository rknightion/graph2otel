package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/admin"
	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/huntclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/o365activityclient"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type startupTokenCredential struct {
	err error
}

func (c startupTokenCredential) GetToken(
	context.Context,
	policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "header.payload.signature"}, c.err
}

func startupTenantAuth(tenantID string) *auth.TenantAuth {
	return &auth.TenantAuth{
		TenantID: tenantID,
		Cred:     startupTokenCredential{},
	}
}

func TestSetupTenantTokenProofFailureRetainsBoundedStartupFailure(t *testing.T) {
	const sentinel = "tenant-proof super-secret"
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

	cfg := &config.Config{
		CheckpointDir: t.TempDir(),
		Tenants:       []config.TenantConfig{{TenantID: "tenant-a"}},
	}
	var wg sync.WaitGroup
	var logOutput bytes.Buffer
	source, err := setupTenantWithGraphAndLicenseBuilders(
		context.Background(),
		&auth.TenantAuth{
			TenantID: "tenant-a",
			Cred:     startupTokenCredential{err: errors.New(sentinel)},
		},
		cfg,
		provider,
		slog.New(slog.NewTextHandler(&logOutput, nil)),
		graphclient.NewWorkloadLimiter(),
		map[admin.SkipKey]string{},
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			t.Fatal("Graph client builder called after tenant token proof failed")
			return nil, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			t.Fatal("license detector called after tenant token proof failed")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v, want recoverable source", err)
	}
	wg.Wait()

	if got := source.StartupFailure; got != admin.StartupFailureCredentialInitialization {
		t.Fatalf("StartupFailure = %q, want %q", got, admin.StartupFailureCredentialInitialization)
	}
	if source.Availability == nil {
		t.Fatal("failed tenant has nil availability tracker")
	}
	for _, point := range source.Availability.Snapshot() {
		if point.State == availability.StateDisabled {
			continue
		}
		if point.State != availability.StateStartupFailed ||
			point.Reason != availability.ReasonCredentialInitializationFailed {
			t.Fatalf("%s = %+v, want bounded credential startup failure", point.Collector, point)
		}
	}
	if strings.Contains(string(source.StartupFailure), sentinel) {
		t.Fatal("retained startup state contains raw token error")
	}
	if !strings.Contains(logOutput.String(), sentinel) {
		t.Fatalf("startup log = %q, want operator-visible token error", logOutput.String())
	}
}

func TestStartTenantsCredentialFailureRetainsCompleteBoundedAvailability(t *testing.T) {
	const sentinel = "credential super-secret"
	disabled := false
	cfg := &config.Config{
		Tenants: []config.TenantConfig{{TenantID: "tenant-a"}},
		Collectors: map[string]config.CollectorConfig{
			"entra.domains": {Enabled: &disabled},
		},
	}
	assertTenantWideFailureCoveragePrecondition(
		t, cfg, availability.ReasonExperimentalNotEnabled,
	)
	var logOutput bytes.Buffer
	sources, _, _, wait, err := startTenantsWithBuilders(
		context.Background(),
		cfg,
		nil,
		slog.New(slog.NewTextHandler(&logOutput, nil)),
		func(config.TenantConfig) (*auth.TenantAuth, error) {
			return nil, errors.New(sentinel)
		},
		func(
			context.Context,
			*auth.TenantAuth,
			*config.Config,
			*telemetry.Provider,
			*slog.Logger,
			*graphclient.WorkloadLimiter,
			map[admin.SkipKey]string,
			*sync.WaitGroup,
		) (admin.CollectorSource, error) {
			t.Fatal("setup called after credential construction failed")
			return admin.CollectorSource{}, nil
		},
	)
	if err != nil {
		t.Fatalf("startTenantsWithBuilders() error = %v", err)
	}
	wait()
	if len(sources) != 1 || sources[0].Availability == nil {
		t.Fatalf("sources = %+v, want one source with a non-nil availability tracker", sources)
	}

	points := sources[0].Availability.Snapshot()
	if got, want := len(points), 148; got != want {
		t.Fatalf("availability point count = %d, want %d", got, want)
	}
	for _, point := range points {
		switch point.Collector {
		case "entra.domains":
			if point.State != availability.StateDisabled ||
				point.Reason != availability.ReasonDisabledByConfig {
				t.Fatalf("%s = %+v, want intentional config-disabled state preserved", point.Collector, point)
			}
			continue
		case "m365.unified_audit":
			if point.State != availability.StateDisabled ||
				point.Reason != availability.ReasonExperimentalNotEnabled {
				t.Fatalf("%s = %+v, want experimental-disabled state preserved", point.Collector, point)
			}
			continue
		}
		if point.State == availability.StateDisabled {
			continue
		}
		if point.State != availability.StateStartupFailed ||
			point.Reason != availability.ReasonCredentialInitializationFailed {
			t.Fatalf("%s = %+v, want bounded credential startup failure", point.Collector, point)
		}
		if strings.Contains(
			string(point.State)+" "+string(point.Reason)+" "+
				string(point.Transport)+" "+fmt.Sprint(point.Limitations),
			sentinel,
		) {
			t.Fatalf("%s availability exposed raw sentinel: %+v", point.Collector, point)
		}
	}
	if !strings.Contains(logOutput.String(), sentinel) {
		t.Fatalf("startup log = %q, want raw sentinel for operator diagnosis", logOutput.String())
	}
}

func TestStartTenantsCredentialFailureEmitsInitialAvailabilityWhenProviderExists(t *testing.T) {
	var metrics bytes.Buffer
	provider, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		ServiceName:    "graph2otel",
		Protocol:       "stdout",
		StdoutWriter:   &metrics,
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	cfg := &config.Config{Tenants: []config.TenantConfig{{TenantID: "tenant-a"}}}
	sources, _, _, wait, err := startTenantsWithBuilders(
		context.Background(),
		cfg,
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(config.TenantConfig) (*auth.TenantAuth, error) {
			return nil, errors.New("credential unavailable")
		},
		func(
			context.Context,
			*auth.TenantAuth,
			*config.Config,
			*telemetry.Provider,
			*slog.Logger,
			*graphclient.WorkloadLimiter,
			map[admin.SkipKey]string,
			*sync.WaitGroup,
		) (admin.CollectorSource, error) {
			t.Fatal("setup called after credential construction failed")
			return admin.CollectorSource{}, nil
		},
	)
	if err != nil {
		t.Fatalf("startTenantsWithBuilders() error = %v", err)
	}
	wait()
	if len(sources) != 1 || sources[0].Availability == nil {
		t.Fatalf("sources = %+v, want retained availability source", sources)
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("provider shutdown: %v", err)
	}

	output := metrics.String()
	for _, want := range []string{
		availability.MetricCollectorAvailability,
		"tenant-a",
		string(availability.ReasonCredentialInitializationFailed),
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("initial metric export missing %q; got:\n%s", want, output)
		}
	}
}

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
	disabled := false
	cfg := &config.Config{
		CheckpointDir: t.TempDir(),
		Tenants:       []config.TenantConfig{{TenantID: "tenant-a"}},
		Collectors: map[string]config.CollectorConfig{
			"m365.unified_audit": {Enabled: &disabled},
		},
	}
	assertTenantWideFailureCoveragePrecondition(
		t, cfg, availability.ReasonDisabledByConfig,
	)
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphClientBuilder(
		context.Background(),
		startupTenantAuth("tenant-a"),
		cfg,
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
	if source.Availability == nil {
		t.Fatal("failed tenant has nil availability tracker")
	}
	points := source.Availability.Snapshot()
	if got, want := len(points), 148; got != want {
		t.Fatalf("availability point count = %d, want %d", got, want)
	}
	for _, point := range points {
		switch point.Collector {
		case "m365.unified_audit":
			if point.State != availability.StateDisabled ||
				point.Reason != availability.ReasonDisabledByConfig {
				t.Fatalf("%s = %+v, want config-disabled state preserved", point.Collector, point)
			}
			continue
		}
		if point.State == availability.StateDisabled {
			continue
		}
		if point.State != availability.StateStartupFailed ||
			point.Reason != availability.ReasonGraphClientInitializationFailed {
			t.Fatalf("%s = %+v, want bounded Graph-client startup failure", point.Collector, point)
		}
	}
	if strings.Contains(string(source.StartupFailure), "super-secret") {
		t.Fatal("retained Graph-client startup state contains raw error")
	}
	if !strings.Contains(logOutput.String(), "client super-secret") {
		t.Errorf("startup log = %q, want raw Graph-client error for operator diagnosis", logOutput.String())
	}
}

func TestSetupTenantLicenseProbeFailureOnlyFailsCapabilityDependentAvailability(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx,
		startupTenantAuth("tenant-a"),
		&config.Config{CheckpointDir: t.TempDir()},
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphclient.NewWorkloadLimiter(),
		map[admin.SkipKey]string{},
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: "tenant-a"}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return nil, errors.New("license super-secret")
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v", err)
	}
	wg.Wait()
	if source.Availability == nil {
		t.Fatal("source has nil availability tracker")
	}

	byName := map[string]availability.Point{}
	for _, point := range source.Availability.Snapshot() {
		byName[point.Collector] = point
	}
	for _, name := range []string{"entra.signins.interactive", "entra.risk", "entra.users"} {
		point := byName[name]
		if point.State != availability.StateStartupFailed ||
			point.Reason != availability.ReasonLicenseDetectionFailed {
			t.Errorf("%s = %+v, want license-detection startup failure", name, point)
		}
	}
	if point := byName["entra.domains"]; point.State != availability.StateStarting ||
		point.Reason != availability.ReasonNoCompletedRun {
		t.Errorf("entra.domains = %+v, want capability-independent collector to keep starting", point)
	}
	if source.Registry == nil {
		t.Fatal("capability-independent collectors were not registered")
	}
	registered := map[string]bool{}
	for _, entry := range source.Registry.Entries() {
		registered[entry.Collector.Name()] = true
	}
	for _, name := range []string{"entra.signins.interactive", "entra.risk", "entra.users"} {
		if registered[name] {
			t.Errorf("license-dependent startup-failed collector %q was registered", name)
		}
	}
	if !registered["entra.domains"] {
		t.Error("capability-independent collector entra.domains was not registered")
	}
}

func TestSetupTenantInvalidO365ConfigurationRecomputesCoverage(t *testing.T) {
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

	const sentinel = "Not.A.Real.ContentType"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &config.Config{
		CheckpointDir: t.TempDir(),
		Tenants: []config.TenantConfig{{
			TenantID: "tenant-a",
			O365Activity: config.O365ActivityConfig{
				ContentTypes: []string{sentinel},
			},
		}},
	}
	var wg sync.WaitGroup
	skips := map[admin.SkipKey]string{}
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx,
		startupTenantAuth("tenant-a"),
		cfg,
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphclient.NewWorkloadLimiter(),
		skips,
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: "tenant-a"}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return allAvailabilityTestCapabilities(), nil
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v", err)
	}
	wg.Wait()

	byName := map[string]availability.Point{}
	for _, point := range source.Availability.Snapshot() {
		byName[point.Collector] = point
	}
	activity := byName["m365.activity"]
	if activity.State != availability.StateStartupFailed ||
		activity.Reason != availability.ReasonInvalidTransportConfiguration {
		t.Fatalf("m365.activity = %+v, want bounded invalid transport configuration", activity)
	}
	unifiedAudit := byName["m365.unified_audit"]
	if unifiedAudit.State != availability.StateDisabled ||
		unifiedAudit.Reason != availability.ReasonExperimentalNotEnabled {
		t.Fatalf("m365.unified_audit = %+v, want its own experimental opt-out after declarer failure", unifiedAudit)
	}
	for _, point := range source.Availability.Snapshot() {
		if strings.Contains(
			string(point.State)+" "+string(point.Reason)+" "+
				string(point.Transport)+" "+fmt.Sprint(point.Limitations),
			sentinel,
		) {
			t.Fatalf("%s availability exposed raw sentinel: %+v", point.Collector, point)
		}
	}
	for key, reason := range skips {
		if strings.Contains(reason, sentinel) {
			t.Fatalf("legacy skip %v exposed raw sentinel: %q", key, reason)
		}
	}
}

func TestSetupTenantWithoutBlobConfigurationDoesNotRegisterBlobCategories(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx,
		startupTenantAuth("tenant-a"),
		&config.Config{CheckpointDir: t.TempDir()},
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphclient.NewWorkloadLimiter(),
		map[admin.SkipKey]string{},
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: "tenant-a"}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return allAvailabilityTestCapabilities(), nil
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v", err)
	}
	wg.Wait()

	for _, entry := range source.Registry.Entries() {
		if entry.Collector.Name() == "graph2otel.blob_categories" {
			t.Fatal("blob-category no-op collector registered without blob configuration")
		}
	}
	for _, point := range source.Availability.Snapshot() {
		if point.Collector != "graph2otel.blob_categories" {
			continue
		}
		if point.State != availability.StateDisabled ||
			point.Reason != availability.ReasonTransportNotConfigured {
			t.Fatalf("blob-category availability = %+v, want transport-not-configured", point)
		}
		return
	}
	t.Fatal("blob-category logical point disappeared from availability census")
}

// TestSetupTenantEmitsExpectedIntervalPerRegisteredCollector is the #299
// composition-root wiring test: once the registry is final, setupTenant must
// publish graph2otel.collector.expected_interval for every registered
// collector, stamped with this tenant, using the SAME effective (resolved)
// interval value the scheduler itself will tick on.
func TestSetupTenantEmitsExpectedIntervalPerRegisteredCollector(t *testing.T) {
	var metrics bytes.Buffer
	provider, err := telemetry.NewProvider(context.Background(), telemetry.Options{
		ServiceName:    "graph2otel",
		Protocol:       "stdout",
		StdoutWriter:   &metrics,
		MetricInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx,
		startupTenantAuth("tenant-a"),
		&config.Config{CheckpointDir: t.TempDir()},
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphclient.NewWorkloadLimiter(),
		map[admin.SkipKey]string{},
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: "tenant-a"}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return allAvailabilityTestCapabilities(), nil
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v", err)
	}
	wg.Wait()

	entries := source.Registry.Entries()
	if len(entries) == 0 {
		t.Fatal("registry has no entries — test fixture is not exercising the wiring")
	}

	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("provider shutdown: %v", err)
	}

	// Decode the exported points for exactly this metric — never a whole-blob
	// substring count, which would also match graph2otel.collector.availability
	// (also keyed by "collector") emitted by the same setupTenant call.
	got := decodeExpectedIntervalPoints(t, metrics.Bytes())
	want := map[string]float64{}
	for _, entry := range entries {
		want[entry.Collector.Name()] = entry.Interval.Seconds()
	}
	if len(got) != len(want) {
		t.Fatalf("expected_interval series count = %d, want %d (one per registered collector): %+v",
			len(got), len(want), got)
	}
	for collectorName, wantSeconds := range want {
		gotPoint, ok := got[collectorName]
		if !ok {
			t.Fatalf("no expected_interval series for collector %q; got: %+v", collectorName, got)
		}
		if gotPoint.seconds != wantSeconds {
			t.Errorf("collector %q expected_interval = %v seconds, want %v (its resolved Registry.Entry interval)",
				collectorName, gotPoint.seconds, wantSeconds)
		}
		if gotPoint.tenantID != "tenant-a" {
			t.Errorf("collector %q tenant_id = %q, want tenant-a", collectorName, gotPoint.tenantID)
		}
	}
}

// stdoutMetricPoint is the fields this test needs from one exported
// stdoutmetric data point.
type stdoutMetricPoint struct {
	seconds  float64
	tenantID string
}

// decodeExpectedIntervalPoints parses the stdout metrics exporter's JSON
// output (one or more concatenated top-level documents — Shutdown may flush
// more than once) and returns every graph2otel.collector.expected_interval
// data point, keyed by its "collector" attribute. Real decoding rather than
// substring counting is deliberate: several self-obs metrics this same
// setupTenant call emits (graph2otel.collector.availability chief among them)
// are ALSO keyed by a "collector" attribute, so a whole-blob string count
// would over-count.
func decodeExpectedIntervalPoints(t *testing.T, raw []byte) map[string]stdoutMetricPoint {
	t.Helper()
	type attr struct {
		Key   string `json:"Key"`
		Value struct {
			Value string `json:"Value"`
		} `json:"Value"`
	}
	type dataPoint struct {
		Attributes []attr  `json:"Attributes"`
		Value      float64 `json:"Value"`
	}
	type metric struct {
		Name string `json:"Name"`
		Data struct {
			DataPoints []dataPoint `json:"DataPoints"`
		} `json:"Data"`
	}
	var doc struct {
		ScopeMetrics []struct {
			Metrics []metric `json:"Metrics"`
		} `json:"ScopeMetrics"`
	}

	out := map[string]stdoutMetricPoint{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for dec.More() {
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decoding stdout metrics export: %v\nraw:\n%s", err, raw)
		}
		for _, sm := range doc.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != collector.MetricCollectorExpectedInterval {
					continue
				}
				for _, dp := range m.Data.DataPoints {
					var collectorName string
					point := stdoutMetricPoint{seconds: dp.Value}
					for _, a := range dp.Attributes {
						switch a.Key {
						case "collector":
							collectorName = a.Value.Value
						case "tenant_id":
							point.tenantID = a.Value.Value
						}
					}
					out[collectorName] = point
				}
			}
		}
	}
	return out
}

func TestSetupTenantBlobInitializationFailureRecomputesCoverage(t *testing.T) {
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

	disabled := false
	const sentinel = "not-an-https-account-url"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &config.Config{
		CheckpointDir: t.TempDir(),
		Tenants: []config.TenantConfig{{
			TenantID:   "tenant-a",
			BlobIngest: config.BlobIngestConfig{AccountURL: sentinel},
			Collectors: map[string]config.CollectorConfig{
				"entra.signins.managed_identity": {Enabled: &disabled},
			},
		}},
	}
	var wg sync.WaitGroup
	skips := map[admin.SkipKey]string{}
	source, err := setupTenantWithGraphAndLicenseBuilders(
		ctx,
		startupTenantAuth("tenant-a"),
		cfg,
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphclient.NewWorkloadLimiter(),
		skips,
		&wg,
		func(context.Context, *auth.TenantAuth, graphclient.Options) (*graphclient.Client, error) {
			return &graphclient.Client{TenantID: "tenant-a"}, nil
		},
		func(context.Context, *graphclient.Client) (license.Capabilities, error) {
			return allAvailabilityTestCapabilities(), nil
		},
	)
	if err != nil {
		t.Fatalf("setupTenantWithGraphAndLicenseBuilders() error = %v", err)
	}
	wg.Wait()

	byName := map[string]availability.Point{}
	for _, point := range source.Availability.Snapshot() {
		byName[point.Collector] = point
	}
	blob := byName["entra.signins.managed_identity.blob"]
	if blob.State != availability.StateStartupFailed ||
		blob.Reason != availability.ReasonTransportInitializationFailed {
		t.Fatalf("blob declarer = %+v, want bounded transport initialization failure", blob)
	}
	graph := byName["entra.signins.managed_identity"]
	if graph.State != availability.StateDisabled ||
		graph.Reason != availability.ReasonDisabledByConfig {
		t.Fatalf("Graph peer = %+v, want own disabled state after declarer failure", graph)
	}
	for _, point := range source.Availability.Snapshot() {
		if strings.Contains(
			string(point.State)+" "+string(point.Reason)+" "+
				string(point.Transport)+" "+fmt.Sprint(point.Limitations),
			sentinel,
		) {
			t.Fatalf("%s availability exposed raw sentinel: %+v", point.Collector, point)
		}
	}
	for key, reason := range skips {
		if strings.Contains(reason, sentinel) {
			t.Fatalf("legacy skip %v exposed raw sentinel: %q", key, reason)
		}
	}
}

func TestConfiguredOptionalLaneConstructionFailuresAreBoundedAndSanitized(t *testing.T) {
	const sentinel = "transport super-secret"
	tokenFile := t.TempDir() + "/mdca-token"
	if err := os.WriteFile(tokenFile, []byte("token"), 0o600); err != nil {
		t.Fatalf("write MDCA token: %v", err)
	}

	tests := []struct {
		name string
		run  func(*slog.Logger, map[admin.SkipKey]string, *collector.Registry) availability.Reason
	}{
		{
			name: "mdca",
			run: func(
				logger *slog.Logger,
				skips map[admin.SkipKey]string,
				registry *collector.Registry,
			) availability.Reason {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID: "tenant-a",
					MDCA: config.MDCAConfig{
						PortalURL: "https://example.portal.cloudappsecurity.com",
						TokenFile: tokenFile,
					},
				}}}
				return registerMDCACollectors(
					cfg,
					startupTenantAuth("tenant-a"),
					allAvailabilityTestCapabilities(),
					checkpoint.NewStore(t.TempDir()),
					logger,
					telemetrytest.New().Emitter(),
					registry,
					skips,
					collectors.MDCAAll(),
					func(string, mdcaclient.Options) (*mdcaclient.Client, error) {
						return nil, errors.New(sentinel)
					},
					nil,
					nil,
				)
			},
		},
		{
			name: "exchange_online",
			run: func(
				logger *slog.Logger,
				skips map[admin.SkipKey]string,
				registry *collector.Registry,
			) availability.Reason {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID:       "tenant-a",
					ExchangeOnline: config.ExchangeOnlineConfig{Enabled: true},
				}}}
				return registerEXOCollectors(
					cfg,
					startupTenantAuth("tenant-a"),
					allAvailabilityTestCapabilities(),
					logger,
					nil,
					errors.New(sentinel),
					registry,
					skips,
					collectors.EXOAll(),
					nil,
					nil,
				)
			},
		},
		{
			name: "hunt",
			run: func(
				logger *slog.Logger,
				skips map[admin.SkipKey]string,
				registry *collector.Registry,
			) availability.Reason {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID: "tenant-a",
					Hunting:  config.HuntingConfig{Enabled: true},
				}}}
				return registerHuntCollectors(
					cfg,
					startupTenantAuth("tenant-a"),
					allAvailabilityTestCapabilities(),
					logger,
					telemetrytest.New().Emitter(),
					registry,
					skips,
					collectors.HuntAll(),
					func(*auth.TenantAuth, huntclient.Options) (*huntclient.Client, error) {
						return nil, errors.New(sentinel)
					},
					nil,
					nil,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logOutput bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logOutput, nil))
			skips := map[admin.SkipKey]string{}
			registry := collector.NewRegistry()

			if got := tt.run(logger, skips, registry); got != availability.ReasonTransportInitializationFailed {
				t.Fatalf("startup reason = %q, want %q", got, availability.ReasonTransportInitializationFailed)
			}
			if len(registry.Entries()) != 0 {
				t.Fatalf("registered %d collectors after client construction failed", len(registry.Entries()))
			}
			if !strings.Contains(logOutput.String(), sentinel) {
				t.Fatalf("operator log = %q, want raw construction error", logOutput.String())
			}
			for key, reason := range skips {
				if strings.Contains(reason, sentinel) {
					t.Fatalf("legacy skip %v exposed raw sentinel: %q", key, reason)
				}
			}
		})
	}
}

type conditionalRuntimeSnapshotCollector struct {
	name      string
	transport telemetry.Transport
}

func (c conditionalRuntimeSnapshotCollector) Name() string { return c.name }
func (conditionalRuntimeSnapshotCollector) DefaultInterval() time.Duration {
	return time.Minute
}
func (c conditionalRuntimeSnapshotCollector) IngestTransport() telemetry.Transport {
	return c.transport
}
func (conditionalRuntimeSnapshotCollector) Collect(
	context.Context,
	telemetry.Emitter,
	*recordoutcome.Recorder,
) error {
	return nil
}

type conditionalRuntimeWindowCollector struct {
	name      string
	transport telemetry.Transport
}

func (c conditionalRuntimeWindowCollector) Name() string { return c.name }
func (conditionalRuntimeWindowCollector) DefaultInterval() time.Duration {
	return time.Minute
}
func (c conditionalRuntimeWindowCollector) IngestTransport() telemetry.Transport {
	return c.transport
}
func (conditionalRuntimeWindowCollector) CollectWindow(
	_ context.Context,
	_, to time.Time,
	_ telemetry.Emitter,
	_ *recordoutcome.Recorder,
) (time.Time, error) {
	return to, nil
}
func (conditionalRuntimeWindowCollector) Lag() time.Duration { return 0 }

type runtimeFactoryTestBlobSource struct{}

func (runtimeFactoryTestBlobSource) List(context.Context, string, string) ([]blobpipeline.BlobInfo, error) {
	return nil, nil
}
func (runtimeFactoryTestBlobSource) ReadRange(
	context.Context,
	string,
	string,
	int64,
	int64,
) ([]byte, error) {
	return nil, nil
}

func TestOptionalRuntimeFactoriesCannotSilentlyReturnNilWhenActive(t *testing.T) {
	const tenantID = "tenant-a"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ta := &auth.TenantAuth{TenantID: tenantID}
	emitter := telemetrytest.New().Emitter()
	store := checkpoint.NewStore(t.TempDir())

	tests := []struct {
		name      string
		family    availabilityFamily
		transport telemetry.Transport
		run       func(
			[]availability.Static,
			*[]availabilityStartupFailure,
			*collector.Registry,
		)
	}{
		{
			name:      "blob",
			family:    availabilityFamilyBlob,
			transport: telemetry.TransportBlob,
			run: func(
				inventory []availability.Static,
				failures *[]availabilityStartupFailure,
				registry *collector.Registry,
			) {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID:   tenantID,
					BlobIngest: config.BlobIngestConfig{AccountURL: "https://example.blob.core.windows.net"},
				}}}
				_ = registerBlobCollectors(
					cfg, ta, nil, store, logger, tenantSelfIdentity{},
					registry, map[admin.SkipKey]string{}, nil,
					[]collectors.BlobFactory{func(d collectors.BlobDeps) collector.SnapshotCollector {
						if d.Source != nil {
							return nil
						}
						return conditionalRuntimeSnapshotCollector{
							name: "test.blob", transport: telemetry.TransportBlob,
						}
					}},
					func(string, *auth.TenantAuth) (blobpipeline.Source, error) {
						return runtimeFactoryTestBlobSource{}, nil
					},
					inventory, failures,
				)
			},
		},
		{
			name:      "o365",
			family:    availabilityFamilyO365,
			transport: telemetry.TransportO365Activity,
			run: func(
				inventory []availability.Static,
				failures *[]availabilityStartupFailure,
				registry *collector.Registry,
			) {
				_ = registerO365Collectors(
					&config.Config{}, ta, nil, store, logger, emitter, registry,
					map[admin.SkipKey]string{},
					[]collectors.O365Factory{func(d collectors.O365Deps) collectors.RegisteredWindow {
						if d.Client != nil {
							return collectors.RegisteredWindow{}
						}
						return collectors.RegisteredWindow{Collector: conditionalRuntimeWindowCollector{
							name: "test.o365", transport: telemetry.TransportO365Activity,
						}}
					}},
					func(*auth.TenantAuth, o365activityclient.Options) (*o365activityclient.Client, error) {
						return &o365activityclient.Client{}, nil
					},
					inventory, failures,
				)
			},
		},
		{
			name:      "mdca",
			family:    availabilityFamilyMDCA,
			transport: telemetry.TransportMDCA,
			run: func(
				inventory []availability.Static,
				failures *[]availabilityStartupFailure,
				registry *collector.Registry,
			) {
				tokenFile := t.TempDir() + "/token"
				if err := os.WriteFile(tokenFile, []byte("token"), 0o600); err != nil {
					t.Fatalf("write MDCA token: %v", err)
				}
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID: tenantID,
					MDCA: config.MDCAConfig{
						PortalURL: "https://example.portal.cloudappsecurity.com",
						TokenFile: tokenFile,
					},
				}}}
				_ = registerMDCACollectors(
					cfg, ta, nil, store, logger, emitter, registry, map[admin.SkipKey]string{},
					[]collectors.MDCAFactory{func(d collectors.MDCADeps) collectors.RegisteredWindow {
						if d.Client != nil {
							return collectors.RegisteredWindow{}
						}
						return collectors.RegisteredWindow{Collector: conditionalRuntimeWindowCollector{
							name: "test.mdca", transport: telemetry.TransportMDCA,
						}}
					}},
					func(string, mdcaclient.Options) (*mdcaclient.Client, error) {
						return &mdcaclient.Client{}, nil
					},
					inventory, failures,
				)
			},
		},
		{
			name:      "exchange_online",
			family:    availabilityFamilyEXO,
			transport: telemetry.TransportExchangeOnline,
			run: func(
				inventory []availability.Static,
				failures *[]availabilityStartupFailure,
				registry *collector.Registry,
			) {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID:       tenantID,
					ExchangeOnline: config.ExchangeOnlineConfig{Enabled: true},
				}}}
				_ = registerEXOCollectors(
					cfg, ta, nil, logger, inertEXO{}, nil, registry, map[admin.SkipKey]string{},
					[]collectors.EXOFactory{func(d collectors.EXODeps) collector.SnapshotCollector {
						if d.Client != nil {
							return nil
						}
						return conditionalRuntimeSnapshotCollector{
							name: "test.exo", transport: telemetry.TransportExchangeOnline,
						}
					}},
					inventory, failures,
				)
			},
		},
		{
			name:      "hunt",
			family:    availabilityFamilyHunt,
			transport: telemetry.TransportGraph,
			run: func(
				inventory []availability.Static,
				failures *[]availabilityStartupFailure,
				registry *collector.Registry,
			) {
				cfg := &config.Config{Tenants: []config.TenantConfig{{
					TenantID: tenantID,
					Hunting:  config.HuntingConfig{Enabled: true},
				}}}
				_ = registerHuntCollectors(
					cfg, ta, nil, logger, emitter, registry, map[admin.SkipKey]string{},
					[]collectors.HuntFactory{func(d collectors.HuntDeps) collector.SnapshotCollector {
						if d.Client != nil {
							return nil
						}
						return conditionalRuntimeSnapshotCollector{
							name: "test.hunt", transport: telemetry.TransportGraph,
						}
					}},
					func(*auth.TenantAuth, huntclient.Options) (*huntclient.Client, error) {
						return &huntclient.Client{}, nil
					},
					inventory, failures,
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inventory := []availability.Static{{
				Collector: "test." + tt.name,
				Transport: tt.transport,
				State:     availability.StateStarting,
				Reason:    availability.ReasonNoCompletedRun,
			}}
			if tt.name == "exchange_online" {
				inventory[0].Collector = "test.exo"
			}
			var failures []availabilityStartupFailure
			registry := collector.NewRegistry()

			tt.run(inventory, &failures, registry)

			if len(registry.Entries()) != 0 {
				t.Fatalf("nil runtime factory registered %d collectors", len(registry.Entries()))
			}
			if len(failures) != 1 {
				t.Fatalf("startup failures = %+v, want one", failures)
			}
			if got := failures[0]; got.collector != inventory[0].Collector ||
				got.family != tt.family ||
				got.transport != tt.transport ||
				got.reason != availability.ReasonTransportInitializationFailed {
				t.Fatalf("startup failure = %+v, want bounded %s transport initialization failure", got, tt.family)
			}
		})
	}
}

func assertTenantWideFailureCoveragePrecondition(
	t *testing.T,
	cfg *config.Config,
	wantUnderlyingReason availability.Reason,
) {
	t.Helper()
	baseline := availabilityStaticsByName(
		t,
		resolveAvailabilityInventory(cfg, "tenant-a", nil, false),
	)
	point := baseline["m365.unified_audit"]
	if point.State != availability.StateCovered ||
		point.Reason != availability.ReasonCoveredByAlternative {
		t.Fatalf(
			"test precondition m365.unified_audit = %+v, want covered/covered_by_alternative before tenant-wide failure from underlying %s",
			point,
			wantUnderlyingReason,
		)
	}
}
