package provisioning

// blob.go is the second TRANSPORT for the provisioning signal this package
// owns: the `ProvisioningLogs` Azure Monitor diagnostic-settings category, read
// out of Azure Storage rather than polled from /auditLogs/provisioning (#135
// group D). Not a different signal — the diagnostic-settings `properties` object
// IS the Graph provisioning resource (verified live: provisioningAction,
// sourceIdentity, targetIdentity, servicePrincipal, statusInfo all present,
// #135), so it reuses this package's mapProvisioning and emits the identical
// entra.provisioning records with the identical ids.
//
// # graph XOR blob — one collector, one transport
//
// The polled entra.provisioning is DEFAULT-ON, so this twin shares its name and
// is selected against it by the `source: graph|blob` config (default graph); the
// composition root registers exactly one per tenant, so there is no dual-ship to
// guard with ConflictsWith. Blob is the more scalable transport on a high-volume
// tenant; graph is the default because a deployment with no blob ingest has no
// blob source. Log-only signal → source selection is a clean full swap (see the
// directoryaudits/blob.go doc for the reasoning; provisioning follows it).

import (
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// blobContainer is the ProvisioningLogs diagnostic-settings category's fixed
// container name.
const blobContainer = "insights-logs-provisioninglogs"

// blobInterval is how often the container is re-listed (#89).
const blobInterval = 5 * time.Minute

// blobCollector wraps the generic BlobCollector in a package-local named type so
// collectordoc can recover THIS package by reflection (see the twin note in
// directoryaudits/blob.go and collectordoc.directBlobPackages).
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newBlobCollector builds the blob-sourced provisioning collector, sharing the
// polled collector's name so `source: graph|blob` selects between them.
func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobContainer,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobProvisioning,
		CollectorName: name,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(name, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// blobPrefix returns the tenant-level listing prefix "tenantId=<guid>/" (#89).
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// mapBlobProvisioning unwraps the diagnostic-settings envelope, delegates the
// inner provisioning object to mapProvisioning, and sets the timestamp from
// properties.activityDateTime (the field the polled endpoint's TimeField binds
// to). The dedupe id is discarded (byte-offset cursor, #138). No timestamp
// fallback — an unparseable time drops the record rather than mis-dating it.
func mapBlobProvisioning(rec map[string]any) (telemetry.Event, bool) {
	props := nested(rec, "properties")
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := blobEventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}
	_, ev := mapProvisioning(props)
	ev.Timestamp = ts
	return ev, true
}

// blobEventTime resolves the event time from properties.activityDateTime, parsed
// as an instant, never string-compared (#135). No fallback to the envelope
// `time`.
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
