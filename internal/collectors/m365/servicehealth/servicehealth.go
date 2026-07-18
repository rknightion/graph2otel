// Package servicehealth is the Microsoft 365 service-health collector (#119): it
// polls the tenant's own view of whether the Microsoft-side services graph2otel's
// other signals depend on are healthy, so "is this us or is this Microsoft?" is
// answerable on the same dashboard and in the same alert rules as the rest of the
// telemetry — instead of a human opening the admin portal outside the alerting
// path.
//
// Both shapes come from ONE request: healthOverviews?$expand=issues folds the
// service list and the issue list into a single response (live-verified
// 2026-07-18, #119 — 29 services + their issues, no paging). From it:
//
//   - a bounded GAUGE of service counts by health status (the alertable one:
//     > 0 on a degraded status fires regardless of which service broke);
//   - a bounded GAUGE of the numeric status enum per service;
//   - a bounded GAUGE of issue counts by classification x status;
//   - one LOG record per UNRESOLVED issue carrying the per-entity detail
//     (id/title/impactDescription/service/timestamps) a metric label must never
//     hold.
//
// Why the twin is unresolved-only. The API returns the tenant's whole retained
// issue history (232 issues on m7kni, 226 of them long-resolved — live 2026-07-18),
// and this is a SNAPSHOT collector that re-emits every cycle, so twinning all of
// them would re-ship hundreds of months-old resolved incidents every interval for
// no operational gain. The aggregate counts still cover the resolved ones (their
// status is serviceRestored/postIncidentReviewPublished); the per-issue twin is
// scoped to what is actually open, which is what "re-emits open issues every cycle"
// in the issue means. See docs/signals.md for the status enum mapping.
//
// No delta query and no time filter exist on either collection, so this is a
// snapshot read, not a WindowCollector; endDateTime is null on unresolved issues,
// so no duration is ever computed from it.
package servicehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config (enable/interval),
	// self-observability, and the admin status page.
	collectorName = "m365.servicehealth"
	// defaultBaseURL is the Graph v1.0 root; overridable for tests.
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	// overviewsPath folds services + their issues into one request.
	overviewsPath = "/admin/serviceAnnouncement/healthOverviews?$expand=issues"

	metricServicesTotal = "m365.service_health.services.total"
	metricStatus        = "m365.service_health.status"
	metricIssuesTotal   = "m365.service_health.issues.total"
	eventIssue          = "m365.service_health_issue"
)

// statusEnum maps a microsoftServiceHealthStatus value to a numeric severity
// ladder for the m365.service_health.status{service} gauge: 0 = healthy,
// increasing = worse, -1 = an unmapped/unknown status (so a new Microsoft enum
// value is visible as -1 rather than silently bucketed as healthy). The mapping
// is documented in docs/signals.md; do NOT add a companion mapping metric (#119).
var statusEnum = map[string]float64{
	"serviceOperational":          0,
	"falsePositive":               0,
	"serviceRestored":             1,
	"postIncidentReviewPublished": 1,
	"resolved":                    1,
	"resolvedExternal":            1,
	"mitigated":                   1,
	"mitigatedExternal":           1,
	"verifyingService":            2,
	"restoringService":            2,
	"extendedRecovery":            2,
	"investigationSuspended":      2,
	"reported":                    3,
	"investigating":               3,
	"confirmed":                   3,
	"serviceDegradation":          4,
	"serviceInterruption":         5,
}

// statusValue returns the numeric enum for a status, -1 when unmapped.
func statusValue(status string) float64 {
	if v, ok := statusEnum[status]; ok {
		return v
	}
	return -1
}

// overview is one healthOverviews entry with its expanded issues.
type overview struct {
	ID      string  `json:"id"`
	Service string  `json:"service"`
	Status  string  `json:"status"`
	Issues  []issue `json:"issues"`
}

// issue is one serviceHealthIssue. posts/details are intentionally not decoded:
// the twin carries the header fields, and the multi-KB posts array would be
// per-cycle re-emitted bulk with no aggregate value.
type issue struct {
	ID                   string `json:"id"`
	Title                string `json:"title"`
	Classification       string `json:"classification"`
	Status               string `json:"status"`
	Service              string `json:"service"`
	Feature              string `json:"feature"`
	FeatureGroup         string `json:"featureGroup"`
	Origin               string `json:"origin"`
	ImpactDescription    string `json:"impactDescription"`
	IsResolved           bool   `json:"isResolved"`
	StartDateTime        string `json:"startDateTime"`
	EndDateTime          string `json:"endDateTime"`
	LastModifiedDateTime string `json:"lastModifiedDateTime"`
}

// Collector polls the service-announcement health surface.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Both collections are small and
// change on the order of minutes-to-hours; 15m keeps the (unresolved-only) twin
// volume sane while still surfacing a new incident promptly.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares exactly ServiceHealth.Read.All — the only scope
// healthOverviews + issues need, and no broader one (#119). The message-center
// collector (ServiceMessage.Read.All) is a separate, deferred collector.
func (c *Collector) RequiredPermissions() []string {
	return []string{"ServiceHealth.Read.All"}
}

// Collect fetches the one folded request and emits the three bounded gauges plus
// one log per unresolved issue.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+overviewsPath, nil)
	if err != nil {
		return err
	}

	servicesByStatus := map[string]int64{}
	statusPoints := make([]telemetry.GaugePoint, 0, len(raws))
	issuesByClassStatus := map[[2]string]int64{}
	seenIssues := map[string]bool{}

	for _, raw := range raws {
		var ov overview
		if err := json.Unmarshal(raw, &ov); err != nil {
			return fmt.Errorf("decode healthOverview: %w", err)
		}
		servicesByStatus[ov.Status]++
		statusPoints = append(statusPoints, telemetry.GaugePoint{
			Value: statusValue(ov.Status),
			Attrs: telemetry.Attrs{semconv.AttrService: ov.Service},
		})

		for _, is := range ov.Issues {
			// Dedupe: an issue is nested under exactly one service today, but guard
			// against a future record appearing under two overviews.
			if seenIssues[is.ID] {
				continue
			}
			seenIssues[is.ID] = true
			issuesByClassStatus[[2]string{is.Classification, is.Status}]++
			if !is.IsResolved {
				e.LogEvent(issueTwin(is))
			}
		}
	}

	servicePoints := make([]telemetry.GaugePoint, 0, len(servicesByStatus))
	for status, n := range servicesByStatus {
		servicePoints = append(servicePoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrStatus: status},
		})
	}
	e.GaugeSnapshot(metricServicesTotal, "{service}", "Count of M365 services in each health status.", servicePoints)
	e.GaugeSnapshot(metricStatus, "1", "Numeric health-status enum per M365 service (0 = operational, higher = worse, -1 = unmapped). See docs/signals.md.", statusPoints)

	issuePoints := make([]telemetry.GaugePoint, 0, len(issuesByClassStatus))
	for k, n := range issuesByClassStatus {
		issuePoints = append(issuePoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrClassification: k[0], semconv.AttrStatus: k[1]},
		})
	}
	e.GaugeSnapshot(metricIssuesTotal, "{issue}", "Count of M365 service-health issues by classification and status.", issuePoints)
	return nil
}

// issueTwin renders one unresolved service-health issue as an OTLP log record.
//
// Timestamp is left zero ("now", i.e. poll time), not startDateTime: this is a
// snapshot twin re-emitted every cycle while the issue stays open, so stamping it
// with the incident start would pile every repeat onto one instant. The start /
// last-modified times are preserved as attributes. endDateTime is emitted only
// when present (SetStr omits it) — null on an unresolved issue, and no duration is
// derived from it.
func issueTwin(is issue) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, is.ID)
	telemetry.SetStr(attrs, semconv.AttrTitle, is.Title)
	telemetry.SetStr(attrs, semconv.AttrClassification, is.Classification)
	telemetry.SetStr(attrs, semconv.AttrStatus, is.Status)
	telemetry.SetStr(attrs, semconv.AttrService, is.Service)
	telemetry.SetStr(attrs, semconv.AttrFeature, is.Feature)
	telemetry.SetStr(attrs, semconv.AttrFeatureGroup, is.FeatureGroup)
	telemetry.SetStr(attrs, semconv.AttrOrigin, is.Origin)
	telemetry.SetStr(attrs, semconv.AttrImpactDescription, is.ImpactDescription)
	telemetry.SetStr(attrs, semconv.AttrStartDateTime, is.StartDateTime)
	telemetry.SetStr(attrs, semconv.AttrEndDateTime, is.EndDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, is.LastModifiedDateTime)
	telemetry.SetBool(attrs, semconv.AttrIsResolved, is.IsResolved)

	return telemetry.Event{
		Name:     eventIssue,
		Body:     fmt.Sprintf("%s [%s/%s]: %s", is.Title, is.Classification, is.Status, is.Service),
		Severity: severityFor(is),
		Attrs:    attrs,
	}
}

// severityFor ranks an unresolved incident above an unresolved advisory. Only
// unresolved issues are twinned, so both branches describe live problems; an
// incident (a confirmed service problem) is an error, an advisory (a warning of a
// narrower or potential impact) is a warning.
func severityFor(is issue) telemetry.Severity {
	if is.Classification == "incident" {
		return telemetry.SeverityError
	}
	return telemetry.SeverityWarn
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

var _ collector.SnapshotCollector = (*Collector)(nil)
