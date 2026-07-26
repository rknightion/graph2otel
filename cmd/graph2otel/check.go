package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/exoclient"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const exchangeOnlineManualPrerequisite = "Exchange.ManageAsApp and the required Entra directory role cannot be proven from a Graph token"

var buildTenantAuths = auth.BuildAll

// runCheck implements `graph2otel check`: a read-only, side-effect-free
// permission preflight (#11). It loads config, builds each tenant's real
// credential, and delegates the actual check to runCheckCore so the
// credential/network-dependent wiring stays out of what's unit-tested.
func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("graph2otel check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the YAML config file (empty = env-only defaults)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: graph2otel check [-config <path>]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Validates that each enabled collector, per configured tenant, has its required")
		fmt.Fprintln(stderr, "Microsoft Graph application permissions granted (added to the app registration")
		fmt.Fprintln(stderr, "AND admin-consented), reporting anything missing up front instead of a runtime 403.")
		fmt.Fprintln(stderr)
		fmt.Fprint(stderr, preflight.HelpText())
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadValidatedConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	tenantAuths, err := buildTenantAuths(cfg.Tenants)
	if err != nil {
		fmt.Fprintf(stderr, "failed to build tenant credentials: %v\n", err)
		return 1
	}
	requirements, warnings, err := preflightRequirements(ctx, cfg, tenantAuths, detectPreflightCapabilities)
	if err != nil {
		fmt.Fprintf(stderr, "failed to build preflight requirements: %v\n", err)
		return 1
	}
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "preflight warning: %v; using base-tier collector selection\n", warning)
	}

	return runCheckCore(ctx, cfg, preflight.NewTokenClaimsSource(tenantAuths), func(tenantID string) []preflight.CollectorReq {
		return requirements[tenantID]
	}, stdout, stderr)
}

// runCheckCore runs the preflight check given an already-loaded config and
// an injected PermissionSource/Requirements func, and maps the result to a
// process exit code. Splitting this out of runCheck is what makes the
// subcommand's plumbing testable with a fake PermissionSource, without
// touching flag parsing, config loading, or a real azidentity credential
// (which runCheck builds from cfg.Tenants and which must never be exercised
// in CI).
func runCheckCore(
	ctx context.Context,
	cfg *config.Config,
	source preflight.PermissionSource,
	reqFn func(tenantID string) []preflight.CollectorReq,
	stdout, stderr io.Writer,
) int {
	ok, err := preflight.Run(ctx, preflight.RunOptions{
		Config:       cfg,
		Source:       source,
		Requirements: reqFn,
		Out:          stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "preflight check failed: %v\n", err)
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}

// capabilityDetector is the read-only subscribed-SKU probe used to make
// preflight's license gates exactly match runtime's selection.
type capabilityDetector func(context.Context, *auth.TenantAuth) (license.Capabilities, error)

// preflightFactoryVisitor owns the preflight view of every runtime
// registration family. It intentionally has its own implementation of the
// visitor contract rather than sharing runtime state.
type preflightFactoryVisitor struct {
	snapshot []collectors.Factory
	window   []collectors.WindowFactory
	blob     []collectors.BlobFactory
	o365     []collectors.O365Factory
	mdca     []collectors.MDCAFactory
	exo      []collectors.EXOFactory
	hunt     []collectors.HuntFactory
}

func (v *preflightFactoryVisitor) Snapshot(fs []collectors.Factory)     { v.snapshot = fs }
func (v *preflightFactoryVisitor) Window(fs []collectors.WindowFactory) { v.window = fs }
func (v *preflightFactoryVisitor) Blob(fs []collectors.BlobFactory)     { v.blob = fs }
func (v *preflightFactoryVisitor) O365(fs []collectors.O365Factory)     { v.o365 = fs }
func (v *preflightFactoryVisitor) MDCA(fs []collectors.MDCAFactory)     { v.mdca = fs }
func (v *preflightFactoryVisitor) EXO(fs []collectors.EXOFactory)       { v.exo = fs }
func (v *preflightFactoryVisitor) Hunt(fs []collectors.HuntFactory)     { v.hunt = fs }

var _ collectorFactoryVisitor = (*preflightFactoryVisitor)(nil)

// preflightRequirements builds requirement inventories with the same detected
// capabilities runtime uses. A failed read follows runtime's base-tier
// fallback: premium-gated collectors are not selected, and the warning makes
// that reduced proof boundary explicit.
func preflightRequirements(
	ctx context.Context,
	cfg *config.Config,
	tenantAuths []*auth.TenantAuth,
	detect capabilityDetector,
) (map[string][]preflight.CollectorReq, []error, error) {
	if cfg == nil {
		return nil, nil, errors.New("nil config")
	}
	configuredTenants := make(map[string]bool, len(cfg.Tenants))
	for _, tenant := range cfg.Tenants {
		configuredTenants[tenant.TenantID] = true
	}
	tenantAuthByID := make(map[string]*auth.TenantAuth, len(tenantAuths))
	for _, ta := range tenantAuths {
		if ta == nil {
			return nil, nil, errors.New("nil TenantAuth")
		}
		if !configuredTenants[ta.TenantID] {
			return nil, nil, fmt.Errorf("TenantAuth for unconfigured tenant %q", ta.TenantID)
		}
		if _, exists := tenantAuthByID[ta.TenantID]; exists {
			return nil, nil, fmt.Errorf("duplicate TenantAuth for tenant %q", ta.TenantID)
		}
		tenantAuthByID[ta.TenantID] = ta
	}
	requirements := make(map[string][]preflight.CollectorReq, len(cfg.Tenants))
	var warnings []error
	for _, tenant := range cfg.Tenants {
		ta, ok := tenantAuthByID[tenant.TenantID]
		if !ok {
			return nil, nil, fmt.Errorf("missing TenantAuth for configured tenant %q", tenant.TenantID)
		}
		caps, err := detect(ctx, ta)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("tenant %s: detecting licenses: %w", tenant.TenantID, err))
			caps = license.Capabilities{}
		}
		reqs, err := requiredCollectorPermissions(cfg, tenant.TenantID, caps)
		if err != nil {
			return nil, nil, fmt.Errorf("tenant %s: %w", tenant.TenantID, err)
		}
		requirements[tenant.TenantID] = reqs
	}
	return requirements, warnings, nil
}

// detectPreflightCapabilities mirrors setupTenant's read-only subscribed-SKU
// detection. The GET /subscribedSkus probe is the unavoidable read required to
// apply license gates exactly; it neither grants permissions nor changes a
// tenant.
func detectPreflightCapabilities(ctx context.Context, ta *auth.TenantAuth) (license.Capabilities, error) {
	gc, err := graphclient.NewClient(ctx, ta, graphclient.Options{TenantID: ta.TenantID})
	if err != nil {
		return license.Capabilities{}, err
	}
	return license.Detect(ctx, license.NewGraphSkuLister(gc))
}

// requiredCollectorPermissions constructs a tenant's runtime-selected
// collector inventory without creating any transport client. Its capabilities
// are supplied by the same read-only detection runtime uses.
func requiredCollectorPermissions(cfg *config.Config, tenantID string, caps license.Capabilities) ([]preflight.CollectorReq, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	var tenant *config.TenantConfig
	for i := range cfg.Tenants {
		if cfg.Tenants[i].TenantID == tenantID {
			tenant = &cfg.Tenants[i]
			break
		}
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant %q is not configured", tenantID)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var paths preflightFactoryVisitor
	visitRegisteredCollectorFactories(&paths)
	candidates := map[string]any{}
	manual := map[string][]string{}
	add := func(c collector.Collector, prerequisite ...string) {
		if !collectorEnabledForConfig(c, cfg, tenantID, caps) {
			return
		}
		candidates[c.Name()] = c
		manual[c.Name()] = append(manual[c.Name()], prerequisite...)
	}
	addManual := func(c collector.Collector, prerequisite ...string) {
		if !collectorEnabledForConfig(c, cfg, tenantID, caps) {
			return
		}
		candidates[c.Name()] = manualOnlyCollector{Collector: c}
		manual[c.Name()] = append(manual[c.Name()], prerequisite...)
	}

	deps := collectors.Deps{TenantID: tenantID, Logger: logger, Caps: caps}
	polledNames := map[string]bool{}
	for _, factory := range paths.snapshot {
		c := factory(deps)
		polledNames[c.Name()] = true
		if c.Name() == "graph2otel.blob_categories" && tenant.BlobIngest.AccountURL != "" {
			add(c, "ARM diagnostic-settings read access and Azure Storage category configuration cannot be proven from a Graph token")
			continue
		}
		add(c)
	}

	var exo collectors.EXOClient
	if tenant.ExchangeOnline.Enabled {
		exo = preflightEXOClient{}
	}
	store := checkpoint.NewStore("")
	for _, factory := range paths.window {
		rw := factory(collectors.WindowDeps{TenantID: tenantID, Logger: logger, Caps: caps, EXO: exo, Store: store})
		if rw.Collector == nil {
			continue
		}
		polledNames[rw.Collector.Name()] = true
		if !graphPollingActive(cfg.CollectorSource(tenantID, rw.Collector.Name()), tenant.BlobIngest.AccountURL != "") {
			continue
		}
		add(rw.Collector, transportManualPrerequisites(rw.Collector)...)
	}

	if tenant.BlobIngest.AccountURL != "" {
		for _, factory := range paths.blob {
			c := factory(collectors.BlobDeps{TenantID: tenantID, Logger: logger})
			if !blobTwinSelected(c.Name(), polledNames, cfg.CollectorSource(tenantID, c.Name())) {
				continue
			}
			add(c, "Azure Storage data-plane access and diagnostic-settings delivery cannot be proven from a Graph token")
		}
	}

	for _, factory := range paths.o365 {
		rw := factory(collectors.O365Deps{TenantID: tenantID, Logger: logger})
		if rw.Collector != nil {
			addManual(rw.Collector, o365ManualPrerequisites(tenant.O365Activity.ContentTypes)...)
		}
	}
	if tenant.MDCA.Configured() {
		for _, factory := range paths.mdca {
			rw := factory(collectors.MDCADeps{TenantID: tenantID, Logger: logger, Store: store, Client: &mdcaclient.Client{}})
			if rw.Collector != nil {
				add(rw.Collector, "MDCA portal URL and static token validity cannot be proven from a Graph token")
			}
		}
	}
	if tenant.ExchangeOnline.Enabled {
		for _, factory := range paths.exo {
			add(factory(collectors.EXODeps{TenantID: tenantID, Logger: logger}), exchangeOnlineManualPrerequisite)
		}
	}
	if tenant.Hunting.Enabled {
		for _, factory := range paths.hunt {
			add(factory(collectors.HuntDeps{TenantID: tenantID, Logger: logger}), "Defender Advanced Hunting entitlement and per-tenant CPU budget cannot be proven from a Graph token")
		}
	}

	reqs := preflight.BuildRequirements(candidates)
	if len(reqs) == 0 {
		return nil, errors.New("enabled collector requirement inventory is empty")
	}
	for i := range reqs {
		reqs[i].UnverifiablePrereqs = manual[reqs[i].Name]
	}
	return reqs, nil
}

// manualOnlyCollector deliberately exposes only collector.Collector. O365
// app roles are minted for manage.office.com, not Graph, so passing through its
// RequiredPermissions declaration would compare an audience-specific role to a
// Graph token and report a false missing permission.
type manualOnlyCollector struct{ collector.Collector }

func o365ManualPrerequisites(contentTypes []string) []string {
	prerequisites := []string{
		"ActivityFeed.Read on the manage.office.com audience and Office 365 Management Activity subscription setup cannot be proven from a Graph token",
	}
	for _, contentType := range contentTypes {
		if contentType == "DLP.All" {
			return append(prerequisites, "ActivityFeed.ReadDlp on the manage.office.com audience cannot be proven from a Graph token")
		}
	}
	return prerequisites
}

// transportManualPrerequisites keeps preflight honest for collectors whose
// declared transport needs authorization that a Microsoft Graph token cannot
// establish. It deliberately follows the collector's typed transport
// declaration rather than collector names, so a future EXO-backed window
// collector inherits the same proof boundary automatically.
func transportManualPrerequisites(c collector.Collector) []string {
	if collector.TransportOf(c) != telemetry.TransportExchangeOnline {
		return nil
	}
	return []string{exchangeOnlineManualPrerequisite}
}

// preflightEXOClient is construction-only. A WindowFactory only needs a
// non-nil EXO seam to declare its collector; the preflight never invokes it.
type preflightEXOClient struct{}

func (preflightEXOClient) Invoke(context.Context, string, map[string]any) ([]map[string]any, error) {
	return nil, errors.New("preflight EXO client must not be invoked")
}

func (preflightEXOClient) InvokeFull(context.Context, string, map[string]any) (exoclient.InvokeResult, error) {
	return exoclient.InvokeResult{}, errors.New("preflight EXO client must not be invoked")
}
