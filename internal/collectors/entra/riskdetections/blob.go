package riskdetections

// blob.go is the second TRANSPORT for the risk-detection signal this package
// owns: the `UserRiskEvents` Azure Monitor diagnostic-settings category, read
// out of Azure Storage, rather than polled from /identityProtection/riskDetections
// (#135 group C). It is the SAME signal — the diagnostic-settings `properties`
// object is the riskDetection resource mapRiskDetection already reads, verified
// against a live m7kni sample (2026-07-18, #135, the #129 synthesized event) —
// so it reuses this package's mapRiskDetection and emits the identical
// entra.risk_detection records with the identical ids.
//
// # Why blob is worth having here — the IPC ceiling
//
// The polled endpoint sits in the Identity Protection workload, capped at 1
// req/s per tenant across ALL apps, with no Retry-After (graph2otel's tightest
// throttle). On a tenant with real risk volume that ceiling bites; the diagnostic
// container sidesteps it entirely. So on a high-risk tenant `source: blob` is the
// scalable transport; graph stays the default because a deployment with no blob
// ingest has no blob source.
//
// # graph XOR blob — one collector, one transport
//
// entra.risk_detections is a log-only WindowCollector (emits ZERO metrics), so
// source selection is a clean full swap exactly like entra.directory_audits
// (#135 group D): blob produces the same logs graph would, nothing graph-unique
// is lost, and the keep-gauges/suppress-twin guard that #135-C needs for
// entra.risk (a SnapshotCollector) does NOT arise here. This twin shares the
// polled collector's name, so it registers only when `source: blob` and the
// composition root activates exactly one transport per tenant — no ConflictsWith
// dual-ship to guard.
//
// The blob record carries one field the Graph v1.0 resource lacks — `riskType`,
// a duplicate of riskEventType (both "maliciousIPAddress" on the live sample) —
// which mapRiskDetection already accounts for, so nothing diverges. [live #135]

import (
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// blobContainer is the UserRiskEvents diagnostic-settings category's fixed
// container name (the category lowercased).
const blobContainer = "insights-logs-userriskevents"

// blobInterval is how often the container is re-listed. Records land minutes
// behind the event and the floor is Azure-side, so polling faster only bills
// list operations (#89).
const blobInterval = 5 * time.Minute

// blobCollector wraps the generic BlobCollector in a package-local named type so
// collectordoc can recover THIS package (and its signals golden) by reflection
// from the constructed value — a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package instead.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newBlobCollector builds the blob-sourced risk-detections collector. It shares
// the polled collector's name so `source: graph|blob` selects between them.
func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobContainer,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobRiskDetection,
		CollectorName: collectorName,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(collectorName, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// blobPrefix returns the listing prefix for a tenant's records: "tenantId=<guid>/"
// — the tenant-level (microsoft.aadiam) diagnostic-settings layout, NOT the
// subscription-scoped "resourceId=/…" form every Microsoft example shows, which
// would list zero blobs and report success forever (#89).
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// mapBlobRiskDetection turns one raw diagnostic-settings record into its OTLP log
// Event: unwrap the envelope, hand the inner riskDetection object to the
// canonical mapRiskDetection, and set the timestamp the engine would otherwise
// have supplied from the endpoint's TimeField (detectedDateTime).
//
// The dedupe id mapRiskDetection returns is discarded — blobpipeline tracks
// progress by byte offset. Azure's delivery is at-least-once (#138), so this
// transport can pass a duplicate through; properties.id equals the polled id, so
// downstream dedupe on `id` works.
func mapBlobRiskDetection(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := blobEventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}
	_, ev := mapRiskDetection(props)
	ev.Timestamp = ts
	return ev, true
}

// blobEventTime resolves the real event time from properties.detectedDateTime —
// the same field the polled endpoint binds to (its TimeField) and sorts by.
// Parsed as an instant; an unparseable timestamp drops the record rather than
// mis-dating it (the emitter must never stamp arrival time — CLAUDE.md).
func blobEventTime(props map[string]any) (time.Time, bool) {
	raw := str(props, "detectedDateTime")
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
