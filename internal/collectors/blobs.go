package collectors

import (
	"log/slog"
	"reflect"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
)

// BlobDeps is everything a BlobFactory needs to construct a blob-sourced
// collector for one tenant (#89). It is the third construction path alongside
// Deps (snapshot collectors) and WindowDeps (window collectors), and it is
// deliberately the smallest of the three: a blob collector reads from Azure
// Storage, so it needs no Graph client, no page fetcher, and no license
// capabilities — the data has already left Microsoft's APIs by the time we see
// it.
type BlobDeps struct {
	// Source lists and reads the tenant's blobs. Built once per tenant by the
	// composition root over the tenant's own credential, and nil when the tenant
	// has configured no blob_ingest.account_url — in which case no blob
	// collectors are constructed at all.
	Source blobpipeline.Source
	// TenantID is the tenant this collector instance serves. It is both the
	// tenant component of the cursor key and, for tenant-level diagnostic
	// settings, the blob-name prefix each collector lists under.
	TenantID string
	// Logger is the process logger, for per-blob diagnostics.
	Logger *slog.Logger
	// Store persists each collector's blob cursor (its per-blob byte offsets)
	// across restarts. The same checkpoint.Store the window collectors use —
	// the two cursor kinds are namespaced apart on disk.
	Store *checkpoint.Store
	// ExcludeSelf mirrors the tenant's exclude_self flag (#154/#176): when true,
	// each blob collector whose records carry an appId drops the ones authored by
	// this tenant's own poller (SelfClientID). Default false — no filtering. A
	// factory copies it into its ContainerConfig; a category with no appId ignores
	// it by leaving ContainerConfig.SelfAppID nil.
	ExcludeSelf bool
	// SelfClientID is this tenant's poller client_id (config tenants[].client_id),
	// the value ExcludeSelf matches a record's appId against. Per-tenant, never a
	// global list: one deployment polling many tenants filters each against its own
	// identity. Empty means "self is unknown" and the filter no-ops even when
	// ExcludeSelf is true.
	SelfClientID string
	// MetricRecencyWindow is the tenant's blob_ingest.metric_recency_window (#128):
	// a factory that derives metrics copies it into ContainerConfig.RecencyWindow,
	// so a record older than the window takes the log path only and never a
	// counter. Zero here means "unset" — but the composition root sources it from
	// Config.BlobMetricRecencyWindow, which never returns zero (defaults to 20m).
	MetricRecencyWindow time.Duration
}

// BlobFactory constructs one blob-sourced collector for a tenant. Registered
// from a collector subpackage's init() via RegisterBlob; the composition root
// calls it once per tenant that has blob ingest configured, then gates the
// result through the same config/license gate as every other collector.
//
// It returns a SnapshotCollector rather than a dedicated interface because the
// scheduler's split is about the CURSOR shape, not the signal shape: a blob
// collector's progress is a byte offset per blob, so it cannot use a
// WindowCollector's [from, to] range, and SnapshotCollector's plain "here is a
// tick" contract is the exact fit. See blobpipeline.BlobCollector.
type BlobFactory func(BlobDeps) collector.SnapshotCollector

// registeredBlobs accumulates every blob-collector factory. Populated only from
// subpackage init() functions (single-threaded package initialization), so it
// needs no synchronization.
var registeredBlobs []BlobFactory

// RegisterBlob adds a blob-collector factory. Call it from a collector
// subpackage's init(). Registration order is preserved by BlobAll().
func RegisterBlob(f BlobFactory) { registeredBlobs = append(registeredBlobs, f) }

// BlobAll returns every registered blob-collector factory in registration
// order. The composition root calls each one per tenant with blob ingest
// configured.
func BlobAll() []BlobFactory { return registeredBlobs }

// BlobContainers returns the Azure Storage container name every registered blob
// collector reads, by constructing each factory with a minimal BlobDeps (no
// Source/Store needed — construction reads only the ContainerConfig) and
// recovering its blobpipeline.BlobCollector. Used by the blob-category census
// (#238) to diff what graph2otel consumes against the diagnostic-settings
// categories that are enabled and writing. The tenantID only shapes the listing
// prefix, which the census does not use; "" is fine but a real value keeps the
// stub honest. A collector whose container cannot be recovered is skipped — a
// census that silently mis-reads one container is worse than one that omits it,
// and the collectordoc gate already fails loudly on that case.
func BlobContainers(tenantID string, logger *slog.Logger) []string {
	out := make([]string, 0, len(registeredBlobs))
	for _, bf := range registeredBlobs {
		c := bf(BlobDeps{TenantID: tenantID, Logger: logger})
		if name := blobContainerName(c); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// blobContainerName recovers a blob collector's container. A collector either IS
// a *blobpipeline.BlobCollector or wraps one in a named struct (so collectordoc
// can recover the subpackage by reflection); this mirrors collectordoc.blobConfig
// so both read the container the same way.
func blobContainerName(c any) string {
	if b, ok := c.(*blobpipeline.BlobCollector); ok && b != nil {
		return b.Config.Container
	}
	v := reflect.ValueOf(c)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	for i := 0; i < v.NumField(); i++ {
		if b, ok := v.Field(i).Interface().(*blobpipeline.BlobCollector); ok && b != nil {
			return b.Config.Container
		}
	}
	return ""
}
