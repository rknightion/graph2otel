// Package deleteditems is the Entra directory recycle-bin census collector: a
// current-state inventory of the soft-deleted directory objects recoverable from
// /directory/deletedItems (the 30-day tombstone window). It answers "how many
// deleted objects of each type are recoverable right now, and which ones" — a
// question no other collector answers (#191).
//
// # Not the delete EVENT — the recoverable-object STATE
//
// Delete events already ship via entra.directory_audits ("Delete user", "Delete
// application", …). Those are the moment of deletion. This is different: the
// event can age out of the audit window while the object still sits in the bin,
// and a deleted-then-restored app/service principal is a known persistence
// technique. So this is a STATE feed — like entra.risk, a tombstoned object is
// re-counted every cycle for as long as it remains recoverable.
//
// # Both sides of the cardinality boundary, from one fetch
//
// Per type, one paged fetch produces:
//
//   - a bounded GAUGE (entra.deleted_items.count) counted by object_type x
//     near_purge — the aggregate, bounded by 5 types x 2 = 10 series;
//   - one LOG record per object (entra.deleted_item) carrying the per-entity
//     detail (id, display name, deletedDateTime, and the type's own identifier:
//     UPN / appId / deviceId) — never a metric label (#112/#114).
//
// near_purge marks an object within nearPurgeLead of its 30-day purge — an
// accumulation-near-expiry / mass-deletion-cleanup signal.
package deleteditems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key for config, self-observability, and the admin
// status page.
const collectorName = "entra.deleted_items"

// metricDeletedItems is the bounded census gauge. Cardinality = object_type (5)
// x near_purge (2), never entity population.
const metricDeletedItems = "entra.deleted_items.count"

// eventDeletedItem is the per-object log twin.
const eventDeletedItem = "entra.deleted_item"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// purgeWindow is Entra's soft-delete retention: a directory object is
// recoverable for 30 days after deletion, then permanently purged. Live-verified
// against the docs' stated window; graph2otel never mutates the bin.
const purgeWindow = 30 * 24 * time.Hour

// nearPurgeLead is how close to the 30-day purge an object is flagged near_purge.
// An object whose age exceeds purgeWindow-nearPurgeLead (i.e. ≥25 days deleted)
// is within 5 days of permanent loss — the window in which "recover it or lose
// it" matters.
const nearPurgeLead = 5 * 24 * time.Hour

// kind is one deletedItems object type: its OData cast segment, its stable
// object_type label, and the $select that fetches exactly the fields the census
// needs. deletedDateTime is explicitly selected because the deletedItems/user
// projection does NOT return it by default (live-verified 2026-07-19); the other
// types return it unprompted but selecting it uniformly is harmless.
type kind struct {
	segment  string
	typeName string
	selectQ  string
}

// kinds is the fixed set of directory object types the recycle bin holds. All
// five were live-verified reachable as graph2otel-poller (2026-07-19, #191).
var kinds = []kind{
	{"microsoft.graph.user", "user", "id,displayName,deletedDateTime,userPrincipalName"},
	{"microsoft.graph.group", "group", "id,displayName,deletedDateTime"},
	{"microsoft.graph.application", "application", "id,displayName,deletedDateTime,appId"},
	{"microsoft.graph.servicePrincipal", "servicePrincipal", "id,displayName,deletedDateTime,appId"},
	{"microsoft.graph.device", "device", "id,displayName,deletedDateTime,deviceId"},
}

// deletedObject is the union of the five projections. $select returns only the
// fields for each type, so the others decode empty and the twin omits them.
type deletedObject struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	DeletedDateTime   string `json:"deletedDateTime"`
	UserPrincipalName string `json:"userPrincipalName"` // user only
	AppID             string `json:"appId"`             // application / servicePrincipal
	DeviceID          string `json:"deviceId"`          // device only
}

// Collector polls the five /directory/deletedItems cast collections.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	now     func() time.Time
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Recycle-bin census is a
// slow-moving state signal — a 30-day window changes by minutes-to-hours, not
// seconds — and these are directory reads sharing the general Graph budget, so a
// conservative interval keeps it cheap.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// RequiredPermissions declares the least-privilege Graph scope. Directory.Read.All
// covers deletedItems reads across all five object types in one grant (the poller
// listed every type with it, 2026-07-19); the per-type read scopes
// (User/Group/Application/Device.Read.All) would each cover only their own cast.
func (c *Collector) RequiredPermissions() []string { return []string{"Directory.Read.All"} }

// Collect fetches every object type, emitting the bounded census gauge and one
// log twin per recoverable object. A per-type fetch error is logged and joined,
// never fatal to the other types (a missing scope on one cast must not blind the
// rest).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	now := c.now()
	// counts is keyed by (object_type, near_purge) so one GaugeSnapshot carries
	// every type. A (type) with an empty bin contributes no point — an empty
	// snapshot emits nothing, the tree-wide convention.
	counts := map[[2]string]int64{}
	var errs []error

	for _, k := range kinds {
		url := c.baseURL + "/directory/deletedItems/" + k.segment + "?$select=" + k.selectQ
		raws, err := collectors.GetAllValues(ctx, c.g, url, nil)
		if err != nil {
			c.logger.Warn("deleted-items census failed for a type",
				"collector", collectorName, "object_type", k.typeName, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", k.typeName, err))
			continue
		}
		for _, raw := range raws {
			var o deletedObject
			if err := json.Unmarshal(raw, &o); err != nil {
				return fmt.Errorf("decode %s: %w", k.typeName, err)
			}
			near := isNearPurge(o.DeletedDateTime, now)
			counts[[2]string{k.typeName, boolStr(near)}]++
			e.LogEvent(logTwin(o, k.typeName, near))
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for key, v := range counts {
		// near_purge is a STRING metric label ("true"/"false") — Prometheus labels
		// are strings, and the bounded (object_type x near_purge) pair keeps the
		// series count fixed. The log twin below carries the typed bool.
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrObjectType: key[0], semconv.AttrNearPurge: key[1]},
		})
	}
	e.GaugeSnapshot(metricDeletedItems, "{object}",
		"Current count of recoverable soft-deleted directory objects, by type and near-purge state (#191).", points)

	return errors.Join(errs...)
}

// isNearPurge reports whether an object has been deleted for at least
// purgeWindow-nearPurgeLead (≥25 days) — approaching OR already past the nominal
// 30-day purge. The "or past" matters: live-verified 2026-07-19, a deleted
// application sat recoverable in the bin 44 days after deletion, so the nominal
// window is not a hard ceiling; flagging everything ≥25 days captures "recover it
// or lose it" without asserting a purge time the wire contradicts. An unparseable
// or empty time is not near-purge — a missing timestamp must not read as
// imminently lost.
func isNearPurge(deletedDateTime string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, deletedDateTime)
	if err != nil {
		return false
	}
	return now.Sub(t) >= purgeWindow-nearPurgeLead
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// logTwin renders one deleted object as an OTLP log record. Timestamp is left
// zero (poll time) deliberately: this is a STATE feed, so stamping it with
// deletedDateTime would pile every re-emission onto the deletion instant and make
// "what was recoverable at 14:00" unanswerable. deletedDateTime is preserved as
// an attribute. near_purge is emitted as a bool (false is an answer, not an
// absence). Severity is Info: a full bin is normal directory hygiene, not an
// alert; near_purge is the queryable dimension.
func logTwin(o deletedObject, objectType string, near bool) telemetry.Event {
	attrs := telemetry.Attrs{
		semconv.AttrObjectType: objectType,
		semconv.AttrNearPurge:  near,
	}
	telemetry.SetStr(attrs, semconv.AttrId, o.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, o.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDeletedDateTime, o.DeletedDateTime)
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, o.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrAppId, o.AppID)
	telemetry.SetStr(attrs, semconv.AttrDeviceId, o.DeviceID)

	return telemetry.Event{
		Name:     eventDeletedItem,
		Body:     fmt.Sprintf("recoverable deleted %s %s (deleted %s)", objectType, displayOf(o), o.DeletedDateTime),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// displayOf picks the most human-readable identifier the object carries.
func displayOf(o deletedObject) string {
	for _, s := range []string{o.DisplayName, o.UserPrincipalName, o.AppID, o.DeviceID, o.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
