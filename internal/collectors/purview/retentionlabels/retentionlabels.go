// Package retentionlabels holds the Microsoft Purview retention-label
// inventory collector: bounded gauges over the tenant's retention-label catalog
// and its retention event types, PLUS a log twin of the same fetch — one OTEL
// log record per catalog row carrying the per-row detail the metrics never
// carry (name, id, descriptions).
//
// # One package, one collector (#140)
//
// This collector and its sensitivity-label sibling
// (internal/collectors/purview/sensitivitylabels) shared a package until #140.
// They emit DIFFERENT signals, and #140's per-package signal capture
// (internal/signalcapture, testdata/signals.json) is a UNION over everything a
// package's tests emit — so one package hosting both meant the capture could
// not attribute a signal to the collector that emits it, which is what blocks
// generating the signal columns of docs/collectors.md from real emissions.
// Measured 2026-07-17: this was the only package in the tree where that
// mattered. Keep it one collector per package.
//
// (entra/signins hosts seven collectors and is deliberately NOT split: all
// seven emit the same entra.signin event, so its union is unambiguous.)
//
// # Metric/log split, and why it is NOT a PII call
//
// A retention label's name is a tenant-wide POLICY name chosen by a handful of
// admins, not per-entity data — every document in the tenant that carries the
// label shares that one name, so it carries none of the per-user/per-device
// identifying weight CLAUDE.md's cardinality/PII rule is about. The reason the
// name and the free-text descriptions stay OFF the metrics is cardinality, not
// privacy: a per-label series would be one series per catalog row with every
// value == 1 — series count growing with the catalog and carrying no
// aggregation value, exactly what a bounded metric must not do. That argument
// says nothing about LOGS: a log record's cost is bounded by catalog size ×
// poll interval (hourly, and catalogs drift slowly), which is exactly where
// per-row detail belongs. So this collector decodes the bounded enum fields for
// the metrics AND the full per-row detail for the log twins from the SAME
// fetches, behind the same error gate — a tenant that can't reach an endpoint
// gets zero logs, not empty ones, same as it gets zero metric points.
//
// # Why the two label catalogs are two collectors
//
// The two catalogs sit behind two different premium entitlements: retention
// labels + retention event types need Records Management (service plan
// RECORDS_MANAGEMENT), sensitivity labels need Purview Information Protection
// (service plans MIP_S_CLP1/CLP2). A SnapshotCollector declares exactly one
// license.CapabilityRequirer, so these are TWO collectors rather than one
// partially-degrading collector — a tenant licensed for one but not the other
// then runs the collector it holds and the composition root skips the other
// cleanly (with a visible skip reason), instead of one collector silently
// half-failing on every tick.
//
// # API versions (verified against Microsoft Graph docs, 2026-07-16)
//
// Both endpoints are Graph v1.0 (GA), so this collector is not marked
// Experimental — following the entra.secure_score / entra.agreements precedent
// (license-gated, v1.0, not beta/opt-in):
//   - GET /security/labels/retentionLabels          (microsoft.graph.security.retentionLabel)
//   - GET /security/triggerTypes/retentionEventTypes (microsoft.graph.security.retentionEventType)
//
// # Error handling is asymmetric with the sensitivity collector, deliberately (#126)
//
// The two collectors do NOT share an error posture, because the two data planes
// do not share a reality (both live-verified 2026-07-16 under the poller's own
// identity):
//
//   - Retention labels / event types (here): the Exchange compliance data plane
//     refuses app-only outright (Microsoft: "Application: Not supported") and no
//     grant changes that, so the specific refusal signature skips-and-logs — the
//     defensive posture entra.recommendations uses.
//   - Sensitivity labels (the sibling package): the endpoint returns 200
//     app-only with the SensitivityLabel.Read application role, so EVERY fetch
//     error fails that collector — there is no skip path. A 403 there means
//     missing admin consent, which an operator can fix, so it must be loud.
//
// This asymmetry is the correction #126 made to #109, which had read a
// swallowed sensitivity 403 as proof of a permanent app-only gap. It is pinned
// by TestForbiddenSkipIsRetentionOnly; do not "restore symmetry" here.
package retentionlabels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// defaultBaseURL is the Graph v1.0 root shared by both sub-fetches.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector name (the stable config / self-observability / admin-status key)
// and the metrics it emits.
const (
	retentionName             = "purview.retention_labels"
	retentionLabelsMetric     = "purview.retention.labels.count"
	retentionEventTypesMetric = "purview.retention.event_types.count"
)

// Log-twin OTLP LogRecord EventNames, one per catalog row emitted alongside the
// metrics above (see the package doc's "Metric/log split" section).
const (
	retentionLabelEventName     = "purview.retention_label"
	retentionEventTypeEventName = "purview.retention_event_type"
)

// isRetentionUnavailable reports whether err is the RETENTION data plane being
// unavailable/unlicensed/app-only-unsupported on the tenant — an expected "no
// data here" condition, not a failure. Matches the graphclient error format
// ("...: status 403: ...").
//
// # Retention-only on purpose (#126)
//
// This predicate was once shared with the sensitivity-label collector (they
// shared a package until #140), which meant a sensitivity 403 — the signature
// of missing admin consent for SensitivityLabel.Read — was swallowed as
// "endpoint unavailable" and that collector reported success over zero data.
// #109 then read that silence as proof of a permanent app-only gap and closed
// the investigation on it. The endpoint is in fact GA and returns 200 app-only
// with SensitivityLabel.Read (live-verified 2026-07-16 under the poller's own
// cert, 5 labels). So the sensitivity collector has NO skip path at all: see
// internal/collectors/purview/sensitivitylabels. Do not re-widen this predicate
// back over it — the asymmetry is deliberate and TestForbiddenSkipIsRetentionOnly
// pins it.
//
// The retention half is a REAL permanent gap and keeps skipping. Signatures,
// all confirmed live (2026-07-16):
//   - status 500 wrapping DataInsightsRequestError "...FAILED - Forbidden": the
//     Exchange compliance data-plane blocks the app-only identity for retention
//     labels/event types, on both v1.0 and beta, even with
//     RecordsManagement.Read.All granted and in the token — Microsoft documents
//     these endpoints as "Application: Not supported", so no grant fixes it.
//     This is matched by the SPECIFIC DataInsights+Forbidden pair, NOT by
//     "status 500" alone — a generic 500 must still surface as a real failure.
//   - status 403 / 404: endpoint unavailable / unlicensed.
func isRetentionUnavailable(err error) bool {
	s := err.Error()
	if strings.Contains(s, "status 403") || strings.Contains(s, "status 404") {
		return true
	}
	return strings.Contains(s, "DataInsightsRequestError") && strings.Contains(s, "Forbidden")
}

// retentionLabel mirrors the retentionLabel fields this package uses: the
// three enums bucket the metric; ID/DisplayName/the two description fields
// feed only the purview.retention_label log twin, never a metric label
// (cardinality rule, see the package doc). createdBy/createdDateTime/
// lastModified* and everything else are not needed by either output.
type retentionLabel struct {
	ID                            string `json:"id"`
	DisplayName                   string `json:"displayName"`
	BehaviorDuringRetentionPeriod string `json:"behaviorDuringRetentionPeriod"`
	ActionAfterRetentionPeriod    string `json:"actionAfterRetentionPeriod"`
	RetentionTrigger              string `json:"retentionTrigger"`
	DescriptionForAdmins          string `json:"descriptionForAdmins"`
	DescriptionForUsers           string `json:"descriptionForUsers"`
}

// retentionEventType mirrors the retentionEventType fields this package
// uses. This catalog has no bounded categorical field to bucket a metric on
// (see collectEventTypes), so every field here feeds only the
// purview.retention_event_type log twin.
type retentionEventType struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

// RetentionCollector polls the retention-label catalog and the retention event
// types.
type RetentionCollector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
}

// The wire assumptions this collector watches at runtime (#233/#234).
//
// All three fields are METRIC LABELS, and all three normalizers send an
// unrecognized member to the SAME "unknown" bucket an absent field lands in —
// so a Microsoft addition is indistinguishable from a label that simply does
// not set the field, and the by-combination count moves with nothing saying
// why.
//
// The watched set is the set each normalizer NAMES: a value this collector
// explicitly handles is one it was built against, which is what makes the
// watchdog fire on a hole in the mapping rather than on correct data (the
// m365.message_trace precedent). The members are the LOWERCASED forms the
// switches match on, and the reported value is lowercased to match — the raw
// casing is not what the mapping keys on.
var (
	knownBehaviors = wirecheck.NewEnum("donotretain", "retain", "retainasrecord", "retainasregulatoryrecord")
	knownActions   = wirecheck.NewEnum("none", "delete", "startdispositionreview")
	knownTriggers  = wirecheck.NewEnum("datelabeled", "datecreated", "datemodified", "dateofevent")
)

// NewRetention builds the retention-label collector. A nil logger falls back
// to the slog default.
func NewRetention(g collectors.GraphClient, logger *slog.Logger) *RetentionCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionCollector{g: g, baseURL: defaultBaseURL, logger: logger, watch: wirecheck.New(retentionName, logger)}
}

// Name implements collector.Collector.
func (c *RetentionCollector) Name() string { return retentionName }

// DefaultInterval implements collector.Collector. Both catalogs drift slowly.
func (c *RetentionCollector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope both
// sub-fetches share.
func (c *RetentionCollector) RequiredPermissions() []string {
	return []string{"RecordsManagement.Read.All"}
}

// RequiredCapability implements license.CapabilityRequirer: retention labels
// require Purview Records Management. The composition root skips the whole
// collector, with a visible skip reason, on a tenant that lacks it.
func (c *RetentionCollector) RequiredCapability() license.Capability {
	return license.CapPurviewRecordsMgmt
}

// Collect fetches the retention-label catalog and the retention event types.
// The two sub-fetches are independent: a 403/404 (unavailable) on either is
// skipped-and-logged; a genuine failure on either is logged and joined into
// the returned error while the other still emits.
func (c *RetentionCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if err := c.collectLabels(ctx, e); err != nil {
		errs = append(errs, err)
	}
	if err := c.collectEventTypes(ctx, e); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// collectLabels emits purview.retention.labels.count bucketed by the three
// bounded retention-policy dimensions, and one purview.retention_label log per
// label carrying the per-row detail (id, name, the three enums — normalized
// to the SAME bucket values the metric uses — and both descriptions). Each
// label is a single combination, so the metric's series set is bounded by the
// enum product (not tenant size) and its sum equals the label count. A
// 403/404/DataInsights-Forbidden (endpoint unavailable) is skipped-and-logged
// before either the metric or the log twin emits anything.
func (c *RetentionCollector) collectLabels(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/labels/retentionLabels", nil)
	if err != nil {
		if isRetentionUnavailable(err) {
			c.logger.Info("retention labels endpoint unavailable on this tenant; skipping",
				"collector", retentionName, "error", err)
			return nil
		}
		return fmt.Errorf("%s: retention labels: %w", retentionName, err)
	}

	type combo struct{ behavior, action, trigger string }
	counts := map[combo]int64{}
	for _, raw := range raws {
		var l retentionLabel
		if err := json.Unmarshal(raw, &l); err != nil {
			c.logger.Warn("retention labels: skipping unparseable entry", "collector", retentionName, "error", err)
			continue
		}
		c.watch.Value(e, semconv.AttrBehaviorDuringRetention, strings.ToLower(l.BehaviorDuringRetentionPeriod), knownBehaviors)
		c.watch.Value(e, semconv.AttrActionAfterRetention, strings.ToLower(l.ActionAfterRetentionPeriod), knownActions)
		c.watch.Value(e, semconv.AttrRetentionTrigger, strings.ToLower(l.RetentionTrigger), knownTriggers)

		behavior := normalizeBehavior(l.BehaviorDuringRetentionPeriod)
		action := normalizeAction(l.ActionAfterRetentionPeriod)
		trigger := normalizeTrigger(l.RetentionTrigger)
		counts[combo{behavior: behavior, action: action, trigger: trigger}]++

		attrs := telemetry.Attrs{
			semconv.AttrBehaviorDuringRetention: behavior,
			semconv.AttrActionAfterRetention:    action,
			semconv.AttrRetentionTrigger:        trigger,
		}
		telemetry.SetStr(attrs, semconv.AttrId, l.ID)
		telemetry.SetStr(attrs, semconv.AttrName, l.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrDescriptionForAdmins, l.DescriptionForAdmins)
		telemetry.SetStr(attrs, semconv.AttrDescriptionForUsers, l.DescriptionForUsers)
		e.LogEvent(telemetry.Event{
			Name:  retentionLabelEventName,
			Body:  fmt.Sprintf("retention label: %s", l.DisplayName),
			Attrs: attrs,
		})
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrBehaviorDuringRetention: k.behavior,
				semconv.AttrActionAfterRetention:    k.action,
				semconv.AttrRetentionTrigger:        k.trigger,
			},
		})
	}
	e.GaugeSnapshot(retentionLabelsMetric, "{label}",
		"Purview retention labels, by retention behavior, post-retention action, and trigger.",
		points)
	return nil
}

// collectEventTypes emits a single purview.retention.event_types.count total,
// plus one purview.retention_event_type log per event type. The
// retentionEventType resource carries no bounded categorical field (only
// id/displayName/description/timestamps), so a bounded metric can only be a
// count — never a per-event-type series; the id/name/description detail goes
// entirely into the log twin instead.
func (c *RetentionCollector) collectEventTypes(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/triggerTypes/retentionEventTypes", nil)
	if err != nil {
		if isRetentionUnavailable(err) {
			c.logger.Info("retention event types endpoint unavailable on this tenant; skipping",
				"collector", retentionName, "error", err)
			return nil
		}
		return fmt.Errorf("%s: retention event types: %w", retentionName, err)
	}
	e.Gauge(retentionEventTypesMetric, "{event_type}",
		"Purview retention event types configured for the tenant.",
		float64(len(raws)), nil)

	for _, raw := range raws {
		var et retentionEventType
		if err := json.Unmarshal(raw, &et); err != nil {
			c.logger.Warn("retention event types: skipping unparseable entry", "collector", retentionName, "error", err)
			continue
		}
		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrId, et.ID)
		telemetry.SetStr(attrs, semconv.AttrName, et.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrDescription, et.Description)
		e.LogEvent(telemetry.Event{
			Name:  retentionEventTypeEventName,
			Body:  fmt.Sprintf("retention event type: %s", et.DisplayName),
			Attrs: attrs,
		})
	}
	return nil
}

// normalizeBehavior maps behaviorDuringRetentionPeriod to graph2otel's bounded
// set (the documented enum minus unknownFutureValue). Anything else → "unknown".
func normalizeBehavior(raw string) string {
	switch strings.ToLower(raw) {
	case "donotretain":
		return "do_not_retain"
	case "retain":
		return "retain"
	case "retainasrecord":
		return "retain_as_record"
	case "retainasregulatoryrecord":
		return "retain_as_regulatory_record"
	default:
		return "unknown"
	}
}

// normalizeAction maps actionAfterRetentionPeriod to graph2otel's bounded set.
// Anything else (including "") → "unknown".
func normalizeAction(raw string) string {
	switch strings.ToLower(raw) {
	case "none":
		return "none"
	case "delete":
		return "delete"
	case "startdispositionreview":
		return "start_disposition_review"
	default:
		return "unknown"
	}
}

// normalizeTrigger maps retentionTrigger to graph2otel's bounded set. Anything
// else → "unknown".
func normalizeTrigger(raw string) string {
	switch strings.ToLower(raw) {
	case "datelabeled":
		return "date_labeled"
	case "datecreated":
		return "date_created"
	case "datemodified":
		return "date_modified"
	case "dateofevent":
		return "date_of_event"
	default:
		return "unknown"
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return NewRetention(d.Graph, d.Logger)
	})
}
