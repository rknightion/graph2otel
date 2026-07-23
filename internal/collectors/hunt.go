package collectors

import (
	"context"
	"log/slog"

	"github.com/rknightion/graph2otel/internal/collector"
)

// HuntClient is the narrow advanced-hunting seam a hunting collector depends on.
// It is satisfied by *huntclient.Client. Collectors depend on this interface
// rather than the concrete client so each one is unit-testable against a fake
// returning canned query results — no live tenant, no ThreatHunting grant, no
// HTTP.
type HuntClient interface {
	// Query runs one advanced-hunting KQL query app-only and returns the decoded
	// result rows. label is a bounded, code-supplied name used only to attribute
	// self-observability metrics (never tenant data). An empty result is (empty
	// slice, nil error), never an error: a tenant with no onboarded devices, or a
	// filter with no hits, matches nothing, and that is the steady state.
	Query(ctx context.Context, label, kql string) ([]map[string]any, error)
}

// HuntDeps is everything a HuntFactory needs to construct an advanced-hunting
// collector for one tenant (#249). It is the SEVENTH construction path alongside
// Deps (snapshot), WindowDeps (logpipeline / jobpipeline), BlobDeps (Azure
// Storage), O365Deps (Management Activity API), MDCADeps (the MDCA portal) and
// EXODeps (the Exchange Online admin API).
//
// It exists for the same reason MDCADeps and EXODeps do: none of the other six
// can carry a *huntclient.Client. The advanced-hunting query API is a distinct
// Graph transport — a POST carrying a KQL query, whose response is a tabular
// schema+results set rather than a paged OData collection — so graphclient's
// paged-GET machinery (which Deps hands collectors) cannot express it. See
// internal/huntclient.
//
// Why a separate path rather than a field on Deps: this transport is opt-in
// (hunting.enabled) and needs a grant, ThreatHunting.Read.All, that most tenants
// will not have and that graph2otel cannot detect in advance — the query 403s
// only at runtime. A Deps field would register these collectors for every tenant
// and let them 403 on every cycle. A distinct path lets the composition root
// construct them ONLY for tenants that enabled hunting, and record an explicit
// absent-with-a-reason skip for the rest — exactly what an unset
// blob_ingest.account_url or a false exchange_online.enabled already does.
//
// Deliberately small, like BlobDeps/O365Deps/MDCADeps/EXODeps: no page fetcher
// and no checkpoint store. The DeviceTvm* tables are current-state snapshots with
// no Timestamp column to tail (#249), so there is nothing to resume — each tick
// asks "what is the posture right now" and answers in full.
//
// NOTE — the #139/#100 gate-blindness trap, which this path is the SEVENTH chance
// to fall into: a new registration path is INVISIBLE to every collectordoc gate
// until cmd/graph2otel/collectordoc_test.go registrySnapshot() is taught to walk
// HuntAll() and collectordoc.Rows is given the slice. Adding the path without
// that walk makes the doc gates pass because they cannot SEE the collector,
// which is worse than having no gate at all. Both were done in the same commit
// that added this file. See CLAUDE.md.
type HuntDeps struct {
	// Client drives the tenant's advanced-hunting queries. Built once per tenant
	// by the composition root, and nil when the tenant has not enabled hunting —
	// in which case no hunting collectors are constructed.
	Client HuntClient
	// TenantID is the tenant this collector instance serves. For the collector's
	// own use only, never for labeling telemetry (telemetry.WithTenant owns
	// semconv.AttrTenantID — see Deps.TenantID).
	TenantID string
	// Logger is the process logger, for per-collector diagnostics.
	Logger *slog.Logger
}

// HuntFactory constructs one advanced-hunting collector for a tenant. Registered
// from a collector subpackage's init() via RegisterHunt; the composition root
// calls it once per tenant that has enabled hunting, then gates the result
// through the same config/experimental gate as every other collector.
//
// It returns a SnapshotCollector — not the RegisteredWindow the MDCA path
// returns — because DeviceTvm* posture genuinely is a state snapshot: there is no
// watermark to advance and no [from, to] window to honor. Each tick asks "what is
// the current vulnerability / configuration / software posture" and answers in
// full.
type HuntFactory func(HuntDeps) collector.SnapshotCollector

// registeredHunt accumulates every hunting-collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registeredHunt []HuntFactory

// RegisterHunt adds a hunting-collector factory. Call it from a collector
// subpackage's init(). Registration order is preserved by HuntAll().
func RegisterHunt(f HuntFactory) { registeredHunt = append(registeredHunt, f) }

// HuntAll returns every registered hunting-collector factory in registration
// order. The composition root calls each one per tenant with hunting enabled.
func HuntAll() []HuntFactory { return registeredHunt }
