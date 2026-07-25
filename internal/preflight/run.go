package preflight

import (
	"context"
	"fmt"
	"io"

	"github.com/rknightion/graph2otel/internal/config"
)

// RunOptions configures a preflight run across every tenant in Config.
type RunOptions struct {
	// Config is the loaded, validated graph2otel configuration; Run checks
	// every tenant listed in Config.Tenants.
	Config *config.Config
	// Source enumerates each tenant's granted Graph application permissions.
	Source PermissionSource
	// Requirements returns the []CollectorReq to check for a given tenant.
	// Every configured tenant must have a non-empty inventory; accepting an
	// absent inventory would turn a broken composition root into a false OK.
	Requirements func(tenantID string) []CollectorReq
	// Out receives the human-readable report.
	Out io.Writer
}

// Run checks every tenant in opts.Config against opts.Requirements, writes a
// report to opts.Out, and returns whether every tenant's requirements were
// fully satisfied. A false return (or a non-nil error) should map to a
// non-zero process exit — see cmd/graph2otel's `check` subcommand.
func Run(ctx context.Context, opts RunOptions) (bool, error) {
	if opts.Config == nil {
		return false, fmt.Errorf("preflight: nil Config")
	}
	if opts.Source == nil {
		return false, fmt.Errorf("preflight: nil Source")
	}

	if len(opts.Config.Tenants) > 0 && opts.Requirements == nil {
		return false, fmt.Errorf("preflight: nil Requirements for configured tenants")
	}

	allOK := true
	for _, t := range opts.Config.Tenants {
		reqs := opts.Requirements(t.TenantID)
		if len(reqs) == 0 {
			return false, fmt.Errorf("preflight: tenant %q: empty collector requirement inventory", t.TenantID)
		}
		granted, err := opts.Source.GrantedPermissions(ctx, t.TenantID)
		if err != nil {
			allOK = false
			fmt.Fprintf(opts.Out, "tenant %s: ERROR enumerating granted permissions: %v\n\n", t.TenantID, err)
			continue
		}

		report := Check(granted, reqs)
		WriteReport(opts.Out, t.TenantID, report)
		fmt.Fprintln(opts.Out)
		if !report.OK {
			allOK = false
		}
	}

	fmt.Fprintln(opts.Out, HelpText())
	return allOK, nil
}
