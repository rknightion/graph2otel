// Package labels holds the Microsoft Purview label-inventory collectors:
// bounded gauges over the tenant's sensitivity-label and retention-label
// catalogs. Metrics only — label display names, tooltips, descriptions and
// per-label identifiers are PII-shaped and never become metric label
// dimensions (see CLAUDE.md's cardinality/PII rule); every series is bucketed
// by a bounded, documented enum.
//
// # Two collectors, not one
//
// The two catalogs sit behind two different premium entitlements: sensitivity
// labels need Purview Information Protection (service plans MIP_S_CLP1/CLP2),
// retention labels + retention event types need Records Management (service
// plan RECORDS_MANAGEMENT). A SnapshotCollector declares exactly one
// license.CapabilityRequirer, so this package registers TWO collectors rather
// than one partially-degrading collector — a tenant licensed for one but not
// the other then runs the collector it holds and the composition root skips
// the other cleanly (with a visible skip reason), instead of one collector
// silently half-failing on every tick.
//
// # API versions (verified against Microsoft Graph docs, 2026-07-16)
//
// All three endpoints are Graph v1.0 (GA), so neither collector is marked
// Experimental — following the entra.secure_score / entra.agreements
// precedent (license-gated, v1.0, not beta/opt-in). Endpoints and resources:
//   - GET /security/dataSecurityAndGovernance/sensitivityLabels  (microsoft.graph.security.sensitivityLabel)
//   - GET /security/labels/retentionLabels                       (microsoft.graph.security.retentionLabel)
//   - GET /security/triggerTypes/retentionEventTypes             (microsoft.graph.security.retentionEventType)
//
// Because these Purview security endpoints are relatively new and their
// application-permission support under app-only auth is not universally
// documented, both collectors treat a 403/404 (endpoint unavailable /
// unlicensed / app-only-unsupported on the tenant) as skip-and-log, not a
// failure — the same defensive posture as entra.recommendations.
//
// # Field-name deviation from issue #101's premise
//
// The issue asks for sensitivity labels bucketed by "applicableTo / rank".
// The live v1.0 sensitivityLabel resource has no "rank": its ordering field is
// `priority`, a dense per-label sequential integer. Bucketing a count by
// priority would mint one series per label (each value == 1) — per-entity
// cardinality that grows with the label count and carries no aggregation
// value, exactly what CLAUDE.md forbids. So the sensitivity collector emits
// purview.labels.count bucketed only by `applicableTo` (a bounded target
// enum) and deliberately drops the priority dimension.
package labels

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
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// defaultBaseURL is the Graph v1.0 root shared by both collectors.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector names (stable config / self-observability / admin-status keys) and
// the metric names each emits.
const (
	sensitivityName   = "purview.sensitivity_labels"
	sensitivityMetric = "purview.labels.count"

	retentionName             = "purview.retention_labels"
	retentionLabelsMetric     = "purview.retention.labels.count"
	retentionEventTypesMetric = "purview.retention.event_types.count"
)

// isUnavailable reports whether err is a Purview security endpoint being
// unavailable/unlicensed/app-only-unsupported on the tenant — an expected "no
// data here" condition, not a failure. Matches the graphclient error format
// ("...: status 403: ...").
//
// Three signatures, all confirmed live (2026-07-16):
//   - status 403 / 404: endpoint unavailable / unlicensed (sensitivity labels).
//   - status 500 wrapping DataInsightsRequestError "...FAILED - Forbidden": the
//     Exchange compliance data-plane blocks the app-only identity for retention
//     labels/event types, on both v1.0 and beta. This is matched by the SPECIFIC
//     DataInsights+Forbidden pair, NOT by "status 500" alone — a generic 500
//     must still surface as a real failure.
func isUnavailable(err error) bool {
	s := err.Error()
	if strings.Contains(s, "status 403") || strings.Contains(s, "status 404") {
		return true
	}
	return strings.Contains(s, "DataInsightsRequestError") && strings.Contains(s, "Forbidden")
}

// ---------------------------------------------------------------------------
// Sensitivity labels
// ---------------------------------------------------------------------------

// sensitivityLabel mirrors only the bounded field this collector buckets on.
// name, description, tooltip, color and every other display/identifier field
// are deliberately never decoded — they are PII-shaped and must never become
// metric labels (CLAUDE.md cardinality/PII rule).
type sensitivityLabel struct {
	// ApplicableTo is the microsoft.graph.security.sensitivityLabelTarget flags
	// value, serialized by Graph as a comma-separated string, e.g.
	// "email,file,teamwork".
	ApplicableTo string `json:"applicableTo"`
}

// SensitivityCollector polls the tenant's sensitivity-label catalog.
type SensitivityCollector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// NewSensitivity builds the sensitivity-label collector. A nil logger falls
// back to the slog default.
func NewSensitivity(g collectors.GraphClient, logger *slog.Logger) *SensitivityCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &SensitivityCollector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *SensitivityCollector) Name() string { return sensitivityName }

// DefaultInterval implements collector.Collector. The label catalog drifts
// slowly; an hourly poll is ample.
func (c *SensitivityCollector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *SensitivityCollector) RequiredPermissions() []string {
	return []string{"InformationProtectionPolicy.Read.All"}
}

// RequiredCapability implements license.CapabilityRequirer: sensitivity labels
// require Purview Information Protection. The composition root skips the whole
// collector, with a visible skip reason, on a tenant that lacks it.
func (c *SensitivityCollector) RequiredCapability() license.Capability {
	return license.CapPurviewInfoProtection
}

// Collect fetches the sensitivity-label catalog and emits purview.labels.count
// bucketed by applicableTo target. A label applicable to several targets is
// counted once per target, so the sum across the applicable_to dimension can
// exceed the label count — expected for a by-target breakdown. A 403/404
// (endpoint unavailable/unlicensed) is skipped-and-logged, not surfaced.
func (c *SensitivityCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/dataSecurityAndGovernance/sensitivityLabels", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("sensitivity labels endpoint unavailable on this tenant; skipping",
				"collector", sensitivityName, "error", err)
			return nil
		}
		return fmt.Errorf("%s: list: %w", sensitivityName, err)
	}

	byTarget := map[string]int64{}
	for _, raw := range raws {
		var l sensitivityLabel
		if err := json.Unmarshal(raw, &l); err != nil {
			c.logger.Warn("sensitivity labels: skipping unparseable entry", "collector", sensitivityName, "error", err)
			continue
		}
		for _, t := range applicableTargets(l.ApplicableTo) {
			byTarget[t]++
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(byTarget))
	for t, n := range byTarget {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"applicable_to": t},
		})
	}
	e.GaugeSnapshot(sensitivityMetric, "{label}",
		"Purview sensitivity labels, counted per applicability target (a multi-target label counts in each).",
		points)
	return nil
}

// sensitivityTargets is the bounded microsoft.graph.security.sensitivityLabelTarget
// enum this collector recognizes. Anything outside it collapses to "unknown"
// rather than becoming a fresh, unbounded label.
var sensitivityTargets = map[string]string{
	"email":           "email",
	"file":            "file",
	"teamwork":        "teamwork",
	"site":            "site",
	"schematizeddata": "schematized_data",
}

// applicableTargets splits the comma-separated applicableTo flags string into
// its bounded, deduplicated target buckets. An empty value yields "none"; an
// unrecognized target yields "unknown".
func applicableTargets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"none"}
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		key := strings.ToLower(strings.TrimSpace(part))
		if key == "" {
			continue
		}
		bucket, ok := sensitivityTargets[key]
		if !ok {
			bucket = "unknown"
		}
		if !seen[bucket] {
			seen[bucket] = true
			out = append(out, bucket)
		}
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

// ---------------------------------------------------------------------------
// Retention labels + retention event types
// ---------------------------------------------------------------------------

// retentionLabel mirrors only the bounded enum fields this collector buckets
// on. displayName, descriptionForUsers/Admins, createdBy and every other
// display/identifier field are deliberately never decoded (CLAUDE.md
// cardinality/PII rule).
type retentionLabel struct {
	BehaviorDuringRetentionPeriod string `json:"behaviorDuringRetentionPeriod"`
	ActionAfterRetentionPeriod    string `json:"actionAfterRetentionPeriod"`
	RetentionTrigger              string `json:"retentionTrigger"`
}

// RetentionCollector polls the retention-label catalog and the retention event
// types.
type RetentionCollector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// NewRetention builds the retention-label collector. A nil logger falls back
// to the slog default.
func NewRetention(g collectors.GraphClient, logger *slog.Logger) *RetentionCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionCollector{g: g, baseURL: defaultBaseURL, logger: logger}
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
// bounded retention-policy dimensions. Each label is a single combination, so
// the series set is bounded by the enum product (not tenant size) and its sum
// equals the label count.
func (c *RetentionCollector) collectLabels(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/labels/retentionLabels", nil)
	if err != nil {
		if isUnavailable(err) {
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
		counts[combo{
			behavior: normalizeBehavior(l.BehaviorDuringRetentionPeriod),
			action:   normalizeAction(l.ActionAfterRetentionPeriod),
			trigger:  normalizeTrigger(l.RetentionTrigger),
		}]++
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				"behavior_during_retention": k.behavior,
				"action_after_retention":    k.action,
				"retention_trigger":         k.trigger,
			},
		})
	}
	e.GaugeSnapshot(retentionLabelsMetric, "{label}",
		"Purview retention labels, by retention behavior, post-retention action, and trigger.",
		points)
	return nil
}

// collectEventTypes emits a single purview.retention.event_types.count total.
// The retentionEventType resource carries no bounded categorical field (only
// id/displayName/description/timestamps), so a bounded metric can only be a
// count — never a per-event-type series.
func (c *RetentionCollector) collectEventTypes(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/triggerTypes/retentionEventTypes", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("retention event types endpoint unavailable on this tenant; skipping",
				"collector", retentionName, "error", err)
			return nil
		}
		return fmt.Errorf("%s: retention event types: %w", retentionName, err)
	}
	e.Gauge(retentionEventTypesMetric, "{event_type}",
		"Purview retention event types configured for the tenant.",
		float64(len(raws)), nil)
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
		return NewSensitivity(d.Graph, d.Logger)
	})
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return NewRetention(d.Graph, d.Logger)
	})
}
