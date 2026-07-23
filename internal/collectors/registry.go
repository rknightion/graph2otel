// Package collectors is the self-registration hub for every data-source
// collector. Each collector lives in its own subpackage
// (internal/collectors/entra/<name>, internal/collectors/intune/<name>, ...)
// and registers a Factory from its init(); the composition root blank-imports
// those subpackages to populate the registry, then constructs, license/
// permission-gates, and schedules the collectors once per configured tenant.
//
// Depending on this package (rather than the composition root reaching into
// every subpackage) keeps "one file = one owner": a new collector is a new
// subpackage plus one blank-import line, never an edit to a shared wiring file.
package collectors

import (
	"context"
	"log/slog"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/license"
)

// GraphClient is the narrow Graph-fetch seam every collector depends on. It is
// satisfied by *graphclient.Client. Collectors depend on this interface, not
// the concrete client, so each one is unit-testable against a fake returning
// canned JSON — no live Graph, no msgraph-sdk mocking.
type GraphClient interface {
	// RawGet performs an authenticated GET against an absolute Graph URL and
	// returns the raw response body.
	RawGet(ctx context.Context, url string) ([]byte, error)
	// RawGetWithHeaders is RawGet with extra request headers — notably
	// "ConsistencyLevel: eventual", required by every directory $count segment
	// and advanced $filter operator.
	RawGetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error)
}

// ARMReader is the narrow Azure Resource Manager control-plane read seam. It is
// satisfied by *armclient.Client and used by exactly one collector — the
// blob-category census (#238), which reads the tenant's microsoft.aadiam
// diagnostic-settings object. A local interface keeps that collector unit-testable
// against a fake returning canned JSON.
type ARMReader interface {
	// RawGet performs an authenticated GET against an absolute ARM URL (the
	// management.azure.com audience) and returns the raw response body.
	RawGet(ctx context.Context, url string) ([]byte, error)
}

// Deps is everything a Factory needs to construct a collector for one tenant.
type Deps struct {
	// Graph is the per-tenant Graph client the collector polls through.
	Graph GraphClient
	// TenantID is the tenant this collector instance serves. It is for the
	// collector's OWN use — building per-tenant URLs, blob prefixes, checkpoint
	// keys — not for labeling telemetry.
	//
	// Do NOT put it on an emitted metric or log yourself: telemetry.WithTenant
	// stamps semconv.AttrTenantID on every record leaving the Scheduler's emitter
	// (#143), so a collector that also sets it is a second writer for a key the
	// emitter owns. entra/securityalerts and entra/securityincidents used to do
	// exactly that, from Microsoft's wire field, and both were removed.
	TenantID string
	// Logger is the process logger, for collector-side diagnostics.
	Logger *slog.Logger
	// Caps are the tenant's detected license capabilities. A collector that is
	// fully premium-gated should instead implement license.CapabilityRequirer
	// (the composition root then skips it entirely on an insufficient tier).
	// Caps is for collectors that PARTIALLY degrade — emit a base signal on
	// every tier and an extra premium-gated series only when the capability is
	// present (e.g. entra.users population counts always, stale-accounts only
	// under P1).
	Caps license.Capabilities
	// Export runs Intune reports export jobs (POST → poll → download → parse)
	// for the export-based report collectors (M5 #37/#38/#40/#41/#42). Only
	// those collectors use it; every other collector ignores it. The
	// composition root builds one per tenant.
	Export exportjob.Runner
	// Store is the per-tenant checkpoint store — the SAME *checkpoint.Store the
	// window/blob/job engines use (WindowDeps.Store et al.). It is OPTIONAL and
	// used by exactly one snapshot collector: intune.epm_elevation_events (#205),
	// an EVENT-stream export report that must dedupe across polls (watermark +
	// SeenIDs over the export transport) so it does not re-emit every elevation
	// on every 6h tick. Every other snapshot collector ignores it. nil (unit
	// tests) disables checkpointing and the owning collector skips rather than
	// dup-storming. Its checkpoint namespace never collides with exportjob's
	// in-flight JobRecord for the same report — jobFileKey prefixes those with
	// "jobrecord\x00" (internal/checkpoint), a separate file.
	Store *checkpoint.Store
	// Fleet is the shared /deviceManagement/managedDevices fetcher (#87). Only
	// intune.devices + intune.malware use it — both page the same fleet list
	// every cycle, so the composition root builds one CachingFleetFetcher per
	// tenant and injects it here so a single fetch serves both. When nil (unit
	// tests), each collector falls back to its own DirectFleetFetcher, so its
	// behavior is unchanged.
	Fleet FleetFetcher
	// ARM is the tenant's ARM control-plane reader (management.azure.com). It is
	// used by exactly one collector — the blob-category census (#238) — and is
	// non-nil ONLY when the tenant has blob ingest configured (there is nothing to
	// census otherwise). Every other collector ignores it; nil disables the census,
	// which then registers but no-ops. The composition root builds one per
	// blob-configured tenant over the tenant's own azidentity credential.
	ARM ARMReader
	// BlobContainerNames is the set of Azure Storage container names every
	// registered blob collector reads (#238), for the census to diff against the
	// enabled diagnostic-settings categories. Non-nil only when blob ingest is
	// configured (paired with ARM). The composition root fills it via
	// BlobContainers(); nil means "not applicable", the census no-ops.
	BlobContainerNames []string
	// SuppressedTwins names the per-entity log-twin EVENT names this collector
	// must NOT emit because a blob-sourced twin already owns them (#135-C). A
	// metric-emitting SnapshotCollector that also emits a per-entity twin (e.g.
	// entra.risk, intune.devices) keeps its gauges but skips a twin whose event
	// name is present here, so the blob and polled paths never double-ship the
	// same per-entity record. Populated by the composition root from
	// RegisterBlobTwinOwner declarations (see SuppressedTwins) — only when blob
	// ingest is configured AND the owning blob collector is enabled, so a twin is
	// never suppressed into a hole. nil/empty means suppress nothing.
	SuppressedTwins map[string]bool
}

// Factory constructs one snapshot collector instance for a tenant. Window
// collectors (the M3/M5 log pollers) get their own registration path when they
// land; M2's collectors are all SnapshotCollectors.
type Factory func(Deps) collector.SnapshotCollector

// Experimental is optionally implemented by a collector that polls a beta /
// preview Graph endpoint (schema-unstable). Such a collector is OPT-IN: the
// composition root registers it only when config explicitly enables it
// (config.CollectorExplicitlyEnabled), never on the default-enabled state, so a
// beta surface change can never break a default deployment.
type Experimental interface {
	// Experimental reports true to mark the collector as beta/opt-in.
	Experimental() bool
}

// registered accumulates every collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registered []Factory

// Register adds a collector factory. Call it from a collector subpackage's
// init(). Registration order is preserved by All().
func Register(f Factory) { registered = append(registered, f) }

// All returns every registered factory in registration order. The composition
// root calls each one per tenant.
func All() []Factory { return registered }
