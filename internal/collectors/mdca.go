package collectors

import (
	"log/slog"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
)

// MDCADeps is everything an MDCAFactory needs to construct a Microsoft Defender
// for Cloud Apps (MDCA) Cloud-Discovery collector for one tenant (#145). It is
// the FIFTH construction path alongside Deps (snapshot), WindowDeps (logpipeline
// / jobpipeline), BlobDeps (Azure Storage) and O365Deps (Management Activity
// API).
//
// It exists because none of the other four can carry an *mdcaclient.Client: the
// MDCA portal API is a third first-party API with its own per-tenant host, its
// own static-token auth (Authorization: Token <secret>, NOT azidentity), its own
// 30 req/min ceiling, and no Graph equivalent. It is not Graph (WindowDeps.Fetcher
// cannot reach it), not Azure Storage (BlobDeps.Source cannot), and not the
// Management Activity API (O365Deps.Client is a different service and audience).
//
// Like BlobDeps and O365Deps it is deliberately small: this API needs no Graph
// client, no page fetcher and no license capabilities. Its access is gated by
// the static portal token, which either works or does not — there is no license
// tier to detect.
//
// NOTE — the #139/#100 gate-blindness trap: a fifth registration path is
// invisible to every collectordoc gate until cmd/graph2otel/collectordoc_test.go
// registrySnapshot() is taught to walk MDCAAll(). Adding this path without that
// walk makes the doc gates pass because they cannot SEE the collector, which is
// worse than no gate. See collectors/conflicts.go and CLAUDE.md.
type MDCADeps struct {
	// Client drives the tenant's MDCA portal API. Built once per tenant by the
	// composition root from the tenant's mdca.portal_url + token_file, and nil
	// when the tenant has configured no mdca block — in which case no MDCA
	// collectors are constructed at all, exactly as an unset blob_ingest.account_url
	// constructs no blob collectors.
	Client *mdcaclient.Client
	// TenantID is the tenant this collector instance serves: both the tenant
	// component of the checkpoint key and the rate-limiter bucket key.
	TenantID string
	// Logger is the process logger, for per-collector diagnostics.
	Logger *slog.Logger
	// Store persists each collector's checkpoint (watermark, overlap, seen ids and
	// parse-health) across restarts. The same checkpoint.Store every other engine
	// uses; the cursor kinds are namespaced apart on disk.
	Store *checkpoint.Store
}

// MDCAFactory constructs one MDCA collector for a tenant. Registered from a
// collector subpackage's init() via RegisterMDCA; the composition root calls it
// once per tenant that has MDCA configured, then gates the result through the
// same config/experimental gate as every other collector.
//
// It returns a RegisteredWindow — reusing the window path rather than inventing
// a sixth — because an MDCA governance-log collector genuinely is a
// WindowCollector: its progress is a time watermark over the record timestamp,
// so the scheduler's [from, to] contract fits. InitialLookback and MaxWindow
// therefore live on the schedule bounds, not on the collector.
type MDCAFactory func(MDCADeps) RegisteredWindow

// registeredMDCA accumulates every MDCA-collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registeredMDCA []MDCAFactory

// RegisterMDCA adds an MDCA-collector factory. Call it from a collector
// subpackage's init(). Registration order is preserved by MDCAAll().
func RegisterMDCA(f MDCAFactory) { registeredMDCA = append(registeredMDCA, f) }

// MDCAAll returns every registered MDCA-collector factory in registration order.
// The composition root calls each one per tenant with MDCA configured.
func MDCAAll() []MDCAFactory { return registeredMDCA }
