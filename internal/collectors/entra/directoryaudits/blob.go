package directoryaudits

// blob.go is the second TRANSPORT for the directory-audit signal this package
// owns: the `AuditLogs` Azure Monitor diagnostic-settings category, read out of
// Azure Storage, rather than polled from /auditLogs/directoryAudits (#135
// group D). It is NOT a different signal — the diagnostic-settings `properties`
// object IS the Graph directoryAudit resource (verified field-for-field against
// 28 live records, #135), so it reuses this package's mapDirectoryAudit and
// emits the identical entra.directory_audit records with the identical ids.
//
// # graph XOR blob — one collector, one transport
//
// Unlike the sign-in blob twins (which have Experimental polled twins, off by
// default, so blob-on + polled-off needs no operator action), the polled
// entra.directory_audits is DEFAULT-ON. So this twin does NOT register itself
// as a second always-on collector — it shares the SAME collector name
// ("entra.directory_audits") and the composition root activates exactly one of
// the two per tenant, selected by the `source: graph|blob` config (default
// graph). There is therefore no dual-ship to guard against with ConflictsWith:
// the two can never both register. Blob is the more scalable transport on a
// high-volume tenant (Graph's reporting endpoints throttle hard); graph is the
// default because a deployment with no blob ingest has no blob source.
//
// This is a log-only signal (a WindowCollector emits zero metrics), so source
// selection is a clean full swap: blob produces the same logs graph would, and
// nothing graph-unique is lost. The "graph for metrics, blob for logs" split
// only bites on a collector that emits BOTH (e.g. intune.devices — #132); it
// does not arise here.

import (
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// blobContainer is the Azure Monitor diagnostic-settings category for directory
// audit logs, lowercased into its fixed container name.
const blobContainer = "insights-logs-auditlogs"

// blobInterval is how often the container is re-listed. Records land minutes
// behind the event and the floor is Azure-side, so polling faster only bills
// list operations (#89).
const blobInterval = 5 * time.Minute

// blobCollector wraps the generic BlobCollector in a package-local named type so
// collectordoc can recover THIS package (and its signals golden) by reflection
// from the constructed value — a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package instead (see collectordoc.directBlobPackages, which its
// own comment says to avoid growing by wrapping, as entra/signins does).
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newBlobCollector builds the blob-sourced directory-audits collector. It shares
// the polled collector's name so `source: graph|blob` selects between them; the
// cursor namespace defaults to the container.
func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobContainer,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobDirectoryAudit,
		CollectorName: name,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(name, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// blobPrefix returns the listing prefix for a tenant's records: "tenantId=<guid>/"
// — the tenant-level (microsoft.aadiam) diagnostic-settings layout, NOT the
// subscription-scoped "resourceId=/…" form every Microsoft example shows, which
// would list zero blobs and report success forever (#89).
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// mapBlobDirectoryAudit turns one raw diagnostic-settings record into its OTLP
// log Event: unwrap the envelope, hand the inner directoryAudit object to the
// canonical mapDirectoryAudit, and set the timestamp the engine would otherwise
// have supplied from the endpoint's TimeField.
//
// The dedupe id mapDirectoryAudit returns is discarded — blobpipeline tracks
// progress by byte offset and has nowhere to put it. Azure's delivery is
// at-least-once (#138), so this transport can pass a duplicate through;
// properties.id equals the polled id, so downstream dedupe on `id` works.
func mapBlobDirectoryAudit(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := blobEventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}
	_, ev := mapDirectoryAudit(props)
	ev.Timestamp = ts
	return ev, true
}

// blobEventTime resolves the real event time from properties.activityDateTime —
// the same field the polled endpoint binds to (its TimeField). For AuditLogs the
// envelope top-level `time` happens to equal this as an INSTANT (verified live,
// #135 — they differ only in serialization: 7-digit-frac Z vs 6-digit +00:00),
// but binding to the resource field rather than the envelope keeps this correct
// even if that ever diverges, and matches the polled collector exactly. Parsed
// as an instant, never string-compared (the string test lies — #135). No
// fallback: an unparseable timestamp drops the record rather than mis-dating it.
func blobEventTime(props map[string]any) (time.Time, bool) {
	raw := str(props, "activityDateTime")
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func init() {
	collectors.RegisterBlob(newBlobCollector)
}
