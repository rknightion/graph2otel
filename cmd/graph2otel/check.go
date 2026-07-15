package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/rknightion/graph2otel/internal/auth"
	"github.com/rknightion/graph2otel/internal/config"
	"github.com/rknightion/graph2otel/internal/preflight"
)

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

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed to load config: %v\n", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "invalid config: %v\n", err)
		return 1
	}

	tenantAuths, err := auth.BuildAll(cfg.Tenants)
	if err != nil {
		fmt.Fprintf(stderr, "failed to build tenant credentials: %v\n", err)
		return 1
	}

	return runCheckCore(ctx, cfg, preflight.NewTokenClaimsSource(tenantAuths), requiredCollectorPermissions, stdout, stderr)
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

// requiredCollectorPermissions is the composition root's wiring point for
// per-tenant collector permission requirements. Once concrete collectors
// exist (#11's M2-M5 dependency: collectors land after this scaffold), this
// should look up tenantID's enabled collector instances from the registry
// and call preflight.BuildRequirements over them. Until then there are no
// concrete collectors to declare a requirement, so `check` still runs (and
// still prints the least-privilege/admin-consent help text) but has nothing
// tenant-specific to compare against.
func requiredCollectorPermissions(tenantID string) []preflight.CollectorReq {
	return nil
}
