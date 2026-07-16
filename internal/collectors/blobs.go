package collectors

import (
	"log/slog"

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
