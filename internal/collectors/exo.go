package collectors

import (
	"context"
	"log/slog"

	"github.com/rknightion/graph2otel/internal/collector"
)

// EXOClient is the narrow Exchange Online cmdlet seam an EXO collector depends
// on. It is satisfied by *exoclient.Client. Collectors depend on this interface
// rather than the concrete client so each one is unit-testable against a fake
// returning canned records — no live tenant, no Exchange grants, no HTTP.
type EXOClient interface {
	// Invoke runs one Exchange Online cmdlet app-only and returns the decoded
	// `value` array. An empty result is (empty slice, nil error), never an
	// error: for quarantine, "nothing held" is the healthy steady state.
	Invoke(ctx context.Context, cmdlet string, params map[string]any) ([]map[string]any, error)
}

// EXODeps is everything an EXOFactory needs to construct an Exchange Online
// collector for one tenant (#233). It is the SIXTH construction path alongside
// Deps (snapshot), WindowDeps (logpipeline / jobpipeline), BlobDeps (Azure
// Storage), O365Deps (Management Activity API) and MDCADeps (the MDCA portal).
//
// It exists for the same reason MDCADeps does: none of the other five can carry
// an *exoclient.Client. The Exchange Online admin API is a fourth first-party
// API — its own audience (https://outlook.office365.com/.default; a Graph token
// is rejected), its own request shape (one POST per cmdlet carrying a
// CmdletInput envelope, not a paged GET), and an authorization model no other
// path has, needing BOTH an app role (Exchange.ManageAsApp) and an Entra
// directory role (Security Reader) where neither alone grants anything
// (live-measured 2026-07-23: 401 → 403 → 200).
//
// Why a separate path rather than a field on Deps: this transport is opt-in and
// most tenants will not have the two grants. A Deps field would register the
// collector for every tenant and let it fail on every cycle. A distinct path
// lets the composition root construct these collectors ONLY for tenants that
// configured Exchange Online, and record an explicit absent-with-a-reason skip
// for the rest — exactly what an unset blob_ingest.account_url or mdca.portal_url
// already does.
//
// Deliberately small, like BlobDeps/O365Deps/MDCADeps: no Graph client, no page
// fetcher, no checkpoint store (quarantine is a STATE snapshot, not a watermark
// stream, so there is nothing to resume), and no license capabilities — access
// is gated by the two grants, which either work or do not, with no tier to
// detect.
//
// NOTE — the #139/#100 gate-blindness trap, which this path is the sixth chance
// to fall into: a new registration path is INVISIBLE to every collectordoc gate
// until cmd/graph2otel/collectordoc_test.go registrySnapshot() is taught to walk
// EXOAll() and collectordoc.Rows is given the slice. Adding the path without
// that walk makes the doc gates pass because they cannot SEE the collector,
// which is worse than having no gate at all. See CLAUDE.md.
type EXODeps struct {
	// Client drives the tenant's Exchange Online admin API. Built once per
	// tenant by the composition root, and nil when the tenant has configured no
	// exchange_online block — in which case no EXO collectors are constructed.
	Client EXOClient
	// TenantID is the tenant this collector instance serves. For the collector's
	// own use only, never for labeling telemetry (telemetry.WithTenant owns
	// semconv.AttrTenantID — see Deps.TenantID).
	TenantID string
	// Logger is the process logger, for per-collector diagnostics.
	Logger *slog.Logger
}

// EXOFactory constructs one Exchange Online collector for a tenant. Registered
// from a collector subpackage's init() via RegisterEXO; the composition root
// calls it once per tenant that has Exchange Online configured, then gates the
// result through the same config/experimental gate as every other collector.
//
// It returns a SnapshotCollector — not the RegisteredWindow the MDCA path
// returns — because quarantine queue depth genuinely is a state snapshot: there
// is no watermark to advance and no [from, to] window to honor. Each tick asks
// "what is held right now" and answers in full.
type EXOFactory func(EXODeps) collector.SnapshotCollector

// registeredEXO accumulates every EXO-collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registeredEXO []EXOFactory

// RegisterEXO adds an EXO-collector factory. Call it from a collector
// subpackage's init(). Registration order is preserved by EXOAll().
func RegisterEXO(f EXOFactory) { registeredEXO = append(registeredEXO, f) }

// EXOAll returns every registered EXO-collector factory in registration order.
// The composition root calls each one per tenant with Exchange Online
// configured.
func EXOAll() []EXOFactory { return registeredEXO }
