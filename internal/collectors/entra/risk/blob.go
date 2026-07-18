package risk

// blob.go adds a blob TRANSPORT for the risky-USER twin (#135-C): the RiskyUsers
// Azure Monitor diagnostic-settings category, read from Azure Storage. Unlike the
// log-only source: graph|blob swaps (#135-D), entra.risk is a SnapshotCollector
// whose GAUGES come from a current-state query the blob feed cannot reproduce. So
// this is NOT a full swap: the polled entra.risk keeps polling for its
// (riskLevel, riskState) counts, and only its per-entity twin is handed to blob.
//
// # keep-gauges, suppress-twin
//
// This is a SEPARATE, log-only collector ("entra.risky_users") that emits the
// SAME entra.risky_user records the polled twin would — reusing logTwin so the
// two are byte-identical in shape. It registers as a blob-twin OWNER of the
// entra.risky_user event; the composition root then sets Deps.SuppressedTwins so
// the polled entra.risk stops emitting that twin (but keeps its gauge) whenever
// this collector is active. blob twin XOR polled twin, gauges always.
//
// Why blob for the twin: the polled endpoint sits in the Identity Protection
// workload, capped at 1 req/s per tenant across all apps with no Retry-After
// (graph2otel's tightest throttle). The polled gauge query is one cheap request
// per 15m, so it stays; the per-entity stream is the part worth moving off that
// ceiling on a high-risk tenant.
//
// Timestamp: unlike the polled twin (deliberately stamped "now" because it
// RE-EMITS every risky user every cycle — a state feed), each blob record is a
// distinct append-only assessment emitted once, so it binds to the real event
// time (riskLastUpdatedDateTime). An unparseable time drops the record rather
// than mis-dating it (CLAUDE.md). Mapped against a live RiskyUsers sample
// (2026-07-18, #135).

import (
	"encoding/json"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// blobRiskyUsersCollector is this collector's stable config/self-obs key. It
	// is distinct from the polled "entra.risk" — it is a second, log-only
	// collector — but emits the same eventRiskyUser records.
	blobRiskyUsersCollector = "entra.risky_users"
	// blobRiskyUsersContainer is the RiskyUsers diagnostic-settings category's
	// fixed container name (the category lowercased).
	blobRiskyUsersContainer = "insights-logs-riskyusers"
	// blobInterval is how often the container is re-listed; the freshness floor
	// is Azure-side, so faster only bills list operations (#89).
	blobInterval = 5 * time.Minute
)

// blobCollector wraps the generic BlobCollector in a package-local named type so
// collectordoc can recover THIS package (and its signals golden) by reflection.
type blobCollector struct {
	*blobpipeline.BlobCollector
}

// newBlobRiskyUsers builds the blob-sourced risky-users collector.
func newBlobRiskyUsers(d collectors.BlobDeps) collector.SnapshotCollector {
	cfg := blobpipeline.ContainerConfig{
		Container:     blobRiskyUsersContainer,
		Prefix:        blobPrefix(d.TenantID),
		Map:           mapBlobRiskyUser,
		CollectorName: blobRiskyUsersCollector,
	}
	return &blobCollector{blobpipeline.NewBlobCollector(blobRiskyUsersCollector, blobInterval, d.TenantID, cfg, d.Source, d.Store, d.Logger)}
}

// blobPrefix is the tenant-level diagnostic-settings listing prefix (#89).
func blobPrefix(tenantID string) string {
	return "tenantId=" + tenantID + "/"
}

// mapBlobRiskyUser turns one RiskyUsers diagnostic-settings record into the
// entra.risky_user twin: unwrap the envelope, decode properties into the same
// riskyEntity the polled path uses, render it through the SAME logTwin (so the
// two transports are identical), then bind the timestamp to the event time.
func mapBlobRiskyUser(rec map[string]any) (telemetry.Event, bool) {
	propsAny, ok := rec["properties"].(map[string]any)
	if !ok {
		return telemetry.Event{}, false
	}
	ts, ok := blobRiskyUserTime(propsAny)
	if !ok {
		return telemetry.Event{}, false
	}
	// Re-marshal properties into riskyEntity via its json tags — the blob
	// `properties` object uses the same field names as the Graph riskyUser
	// resource (verified live 2026-07-18).
	raw, err := json.Marshal(propsAny)
	if err != nil {
		return telemetry.Event{}, false
	}
	var item riskyEntity
	if err := json.Unmarshal(raw, &item); err != nil {
		return telemetry.Event{}, false
	}
	ev := logTwin(item, usersHalf)
	ev.Timestamp = ts
	return ev, true
}

// blobRiskyUserTime resolves the event time from properties.riskLastUpdatedDateTime
// (the assessment instant). Parsed as an instant; an unparseable value drops the
// record rather than mis-dating it.
func blobRiskyUserTime(props map[string]any) (time.Time, bool) {
	raw, _ := props["riskLastUpdatedDateTime"].(string)
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
	collectors.RegisterBlob(newBlobRiskyUsers)
	// Declare that this blob collector owns the entra.risky_user twin, so the
	// composition root suppresses the polled entra.risk's copy when this runs.
	collectors.RegisterBlobTwinOwner(eventRiskyUser, blobRiskyUsersCollector)
}
