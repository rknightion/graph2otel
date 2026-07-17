// Package sensitivitylabels holds the Microsoft Purview sensitivity-label
// inventory collector: a bounded gauge over the tenant's sensitivity-label
// catalog, PLUS a log twin of the same fetch — one OTEL log record per catalog
// row carrying the per-label detail the metric never carries (name, id,
// priority, description).
//
// # One package, one collector (#140)
//
// This collector and its retention-label sibling
// (internal/collectors/purview/retentionlabels) shared a package until #140.
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
// A sensitivity label's name is a tenant-wide POLICY name ("Confidential",
// "Highly Confidential - Finance") chosen by a handful of admins, not
// per-entity data — every document in the tenant that carries the label shares
// that one name, so it carries none of the per-user/per-device identifying
// weight CLAUDE.md's cardinality/PII rule is about. The reason the name (and
// priority, and the free-text description) stays OFF the metric is cardinality,
// not privacy: a per-label series would be one series per catalog label with
// every value == 1 (see the `priority` note below) — series count growing with
// the catalog and carrying no aggregation value, exactly what a bounded metric
// must not do. That argument says nothing about LOGS: a log record's cost is
// bounded by catalog size × poll interval (hourly, and catalogs drift slowly),
// which is exactly where per-row detail belongs. So this collector decodes the
// bounded enum field for the metric AND the full per-row detail for the log
// twin from the SAME fetch, behind the same error gate — a tenant that can't
// reach the endpoint gets zero logs, not empty ones, same as it gets zero
// metric points.
//
// # Why the two label catalogs are two collectors
//
// The two catalogs sit behind two different premium entitlements: sensitivity
// labels need Purview Information Protection (service plans MIP_S_CLP1/CLP2),
// retention labels + retention event types need Records Management (service
// plan RECORDS_MANAGEMENT). A SnapshotCollector declares exactly one
// license.CapabilityRequirer, so these are TWO collectors rather than one
// partially-degrading collector — a tenant licensed for one but not the other
// then runs the collector it holds and the composition root skips the other
// cleanly (with a visible skip reason), instead of one collector silently
// half-failing on every tick.
//
// # API version (verified against Microsoft Graph docs, 2026-07-16)
//
// GET /security/dataSecurityAndGovernance/sensitivityLabels is Graph v1.0 (GA),
// resource microsoft.graph.security.sensitivityLabel, so this collector is not
// marked Experimental — following the entra.secure_score / entra.agreements
// precedent (license-gated, v1.0, not beta/opt-in).
//
// # Error handling: every fetch error fails this collector (#126)
//
// This collector and the retention one do NOT share an error posture, because
// the two data planes do not share a reality (both live-verified 2026-07-16
// under the poller's own identity):
//
//   - Sensitivity labels (here): the endpoint returns 200 app-only with the
//     SensitivityLabel.Read application role. So EVERY fetch error fails the
//     collector — there is no skip path. A 403 means missing admin consent,
//     which an operator can fix, so it must be loud.
//   - Retention labels / event types (the sibling package): the Exchange
//     compliance data plane refuses app-only outright (Microsoft: "Application:
//     Not supported") and no grant changes that, so the specific refusal
//     signature skips-and-logs.
//
// This asymmetry is the correction #126 made to #109, which had read a
// swallowed sensitivity 403 as proof of a permanent app-only gap. It is pinned
// by TestSensitivityErrorsAlwaysFail here and by the retention package's
// TestForbiddenSkipIsRetentionOnly, which drives BOTH collectors with the one
// refusal string. Do not "restore symmetry".
//
// # Field-name deviation from issue #101's premise
//
// The issue asks for sensitivity labels bucketed by "applicableTo / rank". The
// live v1.0 sensitivityLabel resource has no "rank": its ordering field is
// `priority`, a dense per-label sequential integer. Bucketing a count by
// priority would mint one series per label (each value == 1) — per-entity
// cardinality that grows with the label count and carries no aggregation value,
// exactly what CLAUDE.md forbids. So this collector emits purview.labels.count
// bucketed only by `applicableTo` (a bounded target enum) and keeps priority
// off the metric — it lands in the purview.sensitivity_label log twin instead.
package sensitivitylabels

import (
	"context"
	"encoding/json"
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

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// Collector name (the stable config / self-observability / admin-status key)
// and the metric it emits.
const (
	sensitivityName   = "purview.sensitivity_labels"
	sensitivityMetric = "purview.labels.count"
)

// sensitivityLabelEventName is the log-twin OTLP LogRecord EventName, one per
// catalog row emitted alongside the metric above (see the package doc's
// "Metric/log split" section).
const sensitivityLabelEventName = "purview.sensitivity_label"

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
	Priority int `json:"priority"`
	// Description is the resource's nominal free-text field, but it is ""
	// on every live label (#175) — the human-readable text actually lives in
	// ToolTip. Kept only as the fallback source, in case a future tenant
	// populates it instead.
	Description string `json:"description"`
	ToolTip     string `json:"toolTip"`
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
// internal/collectors/purview/retentionlabels). This endpoint is GA and
// live-verified 200 under app-only auth with SensitivityLabel.Read, and the
// unlicensed tenant is already handled upstream by RequiredCapability — so
// nothing reaching this error branch is an expected steady state. A 403 in
// particular means missing admin consent, which is operator-fixable and must be
// loud: swallowing it is how #109 mistook a missing scope for a permanent
// product gap.
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
		// The human-readable text lives in toolTip on the live wire; description
		// is "" on every label there (#175). Fall back to description only for a
		// tenant that populates it instead.
		setStr(attrs, "description", firstNonEmpty(l.ToolTip, l.Description))
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

// setStr adds key=val to attrs only when val is non-empty, so an absent or
// empty decoded field is omitted from the log twin rather than emitted as ""
// (the same idiom internal/collectors/intune/auditevents.go uses over raw
// map[string]any — here adapted for this package's typed structs).
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// firstNonEmpty returns the first non-empty string among vals, or "" if all
// are empty.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return NewSensitivity(d.Graph, d.Logger)
	})
}
