// Package labels holds the Microsoft Purview label-inventory collectors:
// bounded gauges over the tenant's sensitivity-label and retention-label
// catalogs, PLUS a log twin of the same fetch — one OTEL log record per
// catalog row carrying the per-label detail the metric never carries (name,
// id, priority, descriptions).
//
// # Metric/log split, and why it is NOT a PII call
//
// A sensitivity or retention label's name is a tenant-wide POLICY name
// ("Confidential", "Highly Confidential - Finance") chosen by a handful of
// admins, not per-entity data — every document in the tenant that carries the
// label shares that one name, so it carries none of the per-user/per-device
// identifying weight CLAUDE.md's cardinality/PII rule is about. The reason
// the name (and priority, and the free-text descriptions) stays OFF the
// metric is cardinality, not privacy: a per-label series would be one series
// per catalog label with every value == 1 (see the `priority` note below) —
// series count growing with the catalog and carrying no aggregation value,
// exactly what a bounded metric must not do. That argument says nothing about
// LOGS: a log record's cost is bounded by catalog size × poll interval
// (hourly, and catalogs drift slowly), which is exactly where per-row detail
// belongs. So each collector decodes the bounded enum fields for the metric
// AND the full per-row detail for the log twin from the SAME fetch, behind the
// same error gate — a tenant that can't reach an endpoint gets zero logs, not
// empty ones, same as it gets zero metric points. What that gate DOES with an
// error differs per collector; see "Error handling is asymmetric" below.
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
// # Error handling is asymmetric, and deliberately so (#126)
//
// The two collectors do NOT share an error posture, because the two data planes
// do not share a reality (both live-verified 2026-07-16 under the poller's own
// identity):
//
//   - Sensitivity labels: the endpoint returns 200 app-only with the
//     SensitivityLabel.Read application role. So EVERY fetch error fails the
//     collector — there is no skip path. A 403 means missing admin consent,
//     which an operator can fix, so it must be loud.
//   - Retention labels / event types: the Exchange compliance data plane refuses
//     app-only outright (Microsoft: "Application: Not supported") and no grant
//     changes that, so the specific refusal signature skips-and-logs — the
//     defensive posture entra.recommendations uses.
//
// This asymmetry is the correction #126 made to #109, which had read a
// swallowed sensitivity 403 as proof of a permanent app-only gap. It is pinned
// by TestForbiddenSkipIsRetentionOnly; do not "restore symmetry" here.
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
// enum) and keeps priority off the metric — it lands in the
// purview.sensitivity_label log twin instead (see above).
package labels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// Log-twin OTLP LogRecord EventNames, one per catalog row emitted alongside
// the metrics above (see the package doc's "Metric/log split" section).
const (
	sensitivityLabelEventName   = "purview.sensitivity_label"
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
// This predicate was once shared with the sensitivity-label collector, which
// meant a sensitivity 403 — the signature of missing admin consent for
// SensitivityLabel.Read — was swallowed as "endpoint unavailable" and the
// collector reported success over zero data. #109 then read that silence as
// proof of a permanent app-only gap and closed the investigation on it. The
// endpoint is in fact GA and returns 200 app-only with SensitivityLabel.Read
// (live-verified 2026-07-16 under the poller's own cert, 5 labels). So the
// sensitivity collector now has NO skip path at all: see
// SensitivityCollector.Collect. Do not re-widen this predicate back over it —
// the asymmetry is deliberate and TestForbiddenSkipIsRetentionOnly pins it.
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

// ---------------------------------------------------------------------------
// Sensitivity labels
// ---------------------------------------------------------------------------

// sensitivityLabel mirrors the sensitivityLabel fields this package uses:
// ApplicableTo buckets the metric; ID/Name/Priority/Description feed only the
// purview.sensitivity_label log twin, never a metric label (CLAUDE.md
// cardinality rule — see the package doc for why that's a cardinality
// argument, not a PII one). Every other Graph field (tooltip, color,
// isEnabled, actionSource, ...) is not needed by either output and stays
// undecoded.
type sensitivityLabel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// ApplicableTo is the microsoft.graph.security.sensitivityLabelTarget flags
	// value, serialized by Graph as a comma-separated string, e.g.
	// "email,file,teamwork".
	ApplicableTo string `json:"applicableTo"`
	// Priority is a dense per-label sequential integer (lower = higher
	// priority) — log-only, see the package doc's field-name-deviation note.
	Priority    int    `json:"priority"`
	Description string `json:"description"`
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
// RequiredPermissions declares the least-privilege Graph application scope.
//
// SensitivityLabel.Read, NOT InformationProtectionPolicy.Read.All: they are
// different permissions for different endpoints, and mistaking the two is what
// produced #109's wrong "app-only-blocked" verdict. Live-verified 2026-07-16
// (#126): SensitivityLabel.Read alone serves the full tenant catalog app-only,
// and SensitivityLabels.Read.All is not needed. Declaring the wrong scope here
// is not cosmetic — this feeds docs/collectors.md, so it told operators to grant
// a permission that does not unblock the endpoint.
func (c *SensitivityCollector) RequiredPermissions() []string {
	return []string{"SensitivityLabel.Read"}
}

// RequiredCapability implements license.CapabilityRequirer: sensitivity labels
// require Purview Information Protection. The composition root skips the whole
// collector, with a visible skip reason, on a tenant that lacks it.
func (c *SensitivityCollector) RequiredCapability() license.Capability {
	return license.CapPurviewInfoProtection
}

// Collect fetches the sensitivity-label catalog, emits purview.labels.count
// bucketed by applicableTo target, and emits one purview.sensitivity_label log
// per label carrying the per-row detail the metric can't (id, name, priority,
// applicable_to, description). A label applicable to several targets is
// counted once per target in the metric, so the sum across the applicable_to
// dimension can exceed the label count — expected for a by-target breakdown.
//
// # Every fetch error fails this collector (#126)
//
// There is deliberately NO skip path here, unlike the retention collector (see
// isRetentionUnavailable). This endpoint is GA and live-verified 200 under
// app-only auth with SensitivityLabel.Read, and the unlicensed tenant is
// already handled upstream by RequiredCapability — so nothing reaching this
// error branch is an expected steady state. A 403 in particular means missing
// admin consent, which is operator-fixable and must be loud: swallowing it is
// how #109 mistook a missing scope for a permanent product gap.
func (c *SensitivityCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/security/dataSecurityAndGovernance/sensitivityLabels", nil)
	if err != nil {
		if strings.Contains(err.Error(), "status 403") {
			// Name the fix in the error itself, so the next reader does not
			// re-run #109's investigation from a bare "status 403".
			return fmt.Errorf("%s: list: grant and admin-consent the SensitivityLabel.Read application permission (this endpoint is GA and app-only-capable; a 403 here is missing consent, not a product limitation): %w",
				sensitivityName, err)
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

		// priority is emitted as a string, matching every other log attribute in
		// this codebase: log attributes are Loki structured metadata (string-typed
		// on the wire regardless of OTEL attribute kind — see CLAUDE.md), so a
		// numeric OTEL kind buys nothing here and only this package's own log
		// twins would differ from house convention if it did.
		attrs := telemetry.Attrs{"priority": strconv.Itoa(l.Priority)}
		setStr(attrs, "id", l.ID)
		setStr(attrs, "name", l.Name)
		setStr(attrs, "applicable_to", l.ApplicableTo)
		setStr(attrs, "description", l.Description)
		e.LogEvent(telemetry.Event{
			Name:  sensitivityLabelEventName,
			Body:  fmt.Sprintf("sensitivity label: %s", l.Name),
			Attrs: attrs,
		})
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
		behavior := normalizeBehavior(l.BehaviorDuringRetentionPeriod)
		action := normalizeAction(l.ActionAfterRetentionPeriod)
		trigger := normalizeTrigger(l.RetentionTrigger)
		counts[combo{behavior: behavior, action: action, trigger: trigger}]++

		attrs := telemetry.Attrs{
			"behavior_during_retention": behavior,
			"action_after_retention":    action,
			"retention_trigger":         trigger,
		}
		setStr(attrs, "id", l.ID)
		setStr(attrs, "name", l.DisplayName)
		setStr(attrs, "description_for_admins", l.DescriptionForAdmins)
		setStr(attrs, "description_for_users", l.DescriptionForUsers)
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
		setStr(attrs, "id", et.ID)
		setStr(attrs, "name", et.DisplayName)
		setStr(attrs, "description", et.Description)
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

// setStr adds key=val to attrs only when val is non-empty, so an absent or
// empty decoded field is omitted from the log twin rather than emitted as ""
// (the same idiom internal/collectors/intune/auditevents.go uses over raw
// map[string]any — here adapted for this package's typed structs).
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
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
