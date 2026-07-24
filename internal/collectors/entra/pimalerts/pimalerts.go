// Package pimalerts collects Microsoft's OWN pre-computed privileged-access
// findings for the tenant (BETA): stale accounts holding privileged roles,
// roles assigned outside PIM, roles activatable without MFA, too many global
// admins — each shipped with Microsoft's severity, security impact, mitigation
// steps and prevention guidance.
//
// entra.pim_role_policies covers what it TAKES to activate a role and
// entra.roles covers who holds one. Neither carries Microsoft's verdict on any
// of it; this collector is that verdict, and graph2otel re-derives none of it.
//
// # The $filter is MANDATORY, and its absence lies about why
//
// A bare list of any roleManagementAlerts segment answers
// (live-measured 2026-07-24 as graph2otel-poller, #256):
//
//	GET /beta/identityGovernance/roleManagementAlerts/alerts
//	400 {"errorCode":"MissingProvider","message":"The provider is missing."}
//
// That reads like the feature not being provisioned on the tenant, or the
// endpoint not existing. It is neither: the scope filter is not an optimization
// on this surface, it is part of the request. With it, all three segments
// answer 200:
//
//	?$filter=scopeId+eq+'/'+and+scopeType+eq+'DirectoryRole'
//
// The `+`-for-space encoding above is the exact URL form verified on the wire
// (200, 7 rows), matching the sibling entra/pimrolepolicies collector's filter.
// Same class of trap as the Intune EA `$top` rejected at every value: a query
// parameter whose absence produces an error naming something else entirely. See
// docs/graph-api-gotchas.md.
//
// v1.0 has no roleManagementAlerts segment at all (400), so this is beta-only →
// Experimental (#183).
//
// # Three segments, one record
//
// Joined on alertDefinitionId:
//
//   - alerts            — the STATE: isActive, incidentCount, scan timestamps.
//   - alertDefinitions  — the MEANING: displayName, description, severityLevel,
//     securityImpact, mitigationSteps, howToPrevent.
//   - alertConfigurations — whether the alert is even SWITCHED ON, plus its
//     per-type thresholds. A disabled alert reports isActive:false forever and
//     is indistinguishable from a healthy one unless this segment is read,
//     which is why it is read.
//
// alertIncidents — the per-entity detail behind incidentCount — 400s even with
// the mandatory filter ("Resource not found for the segment 'alertIncidents'",
// live-measured 2026-07-24). Per-incident entities are NOT reachable by this
// route, so incidentCount is the finest granularity this collector can offer,
// and it does not pretend otherwise.
//
// # Wire traps (live-measured 2026-07-24, n=1 tenant)
//
//   - lastModifiedDateTime is the .NET zero date, "0001-01-01T08:00:00Z", on
//     every alert that has never fired. It means ABSENT. Emitting it as a
//     timestamp would claim the finding last changed in year 1.
//   - The alert id embeds the tenant GUID
//     ("DirectoryRole_<tid>_StaleSignInAlert"), so the raw id is per-tenant
//     cardinality and can never be a metric label. The stripped type suffix is,
//     and it is a bounded set (7 on this tenant).
//   - alertDefinitionId is byte-identical to the row's own id on all three
//     segments, so it is used as the join key and deliberately not emitted
//     twice.
//   - The configuration's threshold fields are polymorphic per @odata.type and
//     absent on most rows. They decode through pointers so an absent threshold
//     stays absent rather than publishing a fabricated 0.
//
// # Cardinality (#112/#114)
//
// The three gauges carry only (alert_type, severity, is_active, is_enabled) —
// bounded by the alert-type catalog, not by tenant size. Microsoft's prose (the
// remediation worklist, which is the reason to collect this at all), the raw
// alert id, the scan timestamps and the per-alert incident count ride the
// entra.pim_alert twin: one record per alert, every cycle. Guard test.
package pimalerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "entra.pim_alerts"
	// The metric namespace follows the sibling PIM collector
	// (entra.pim.role_policy.*), not the collector name.
	//
	// alertsMetricName is one series per alert type carrying 1, so a sum over
	// alert_type gives the severity × active breakdown and the label gives the
	// per-finding detail. incidentsMetricName is the actionable number: how many
	// entities each finding covers. configurationsMetricName is the "is this
	// alert even switched on" axis, a separate metric rather than another
	// dimension so a naive sum over either one stays meaningful.
	alertsMetricName         = "entra.pim.alert.count"
	incidentsMetricName      = "entra.pim.alert.incidents"
	configurationsMetricName = "entra.pim.alert.configurations"
	eventName                = "entra.pim_alert"
	// defaultBaseURL is the Graph BETA root — see the package doc.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// scopeFilter is MANDATORY on every roleManagementAlerts segment; without it
	// Graph answers 400 MissingProvider. See the package doc. Spaces are `+`
	// encoded and the quotes/slash are left literal — the exact form verified
	// live (200, 7 rows), and the same encoding entra/pimrolepolicies uses on
	// the identically shaped roleManagementPolicies filter.
	scopeFilter = "?$filter=scopeId+eq+'/'+and+scopeType+eq+'DirectoryRole'"
	// The three segments. No $top: GetAllValues already asks for Graph's largest
	// page via the Prefer header, and an unverified $top is how a paged
	// collector earns a 400 (docs/graph-api-gotchas.md).
	alertsPath         = "/identityGovernance/roleManagementAlerts/alerts"
	definitionsPath    = "/identityGovernance/roleManagementAlerts/alertDefinitions"
	configurationsPath = "/identityGovernance/roleManagementAlerts/alertConfigurations"
	// unknownValue keeps a bounded gauge dimension stable when a row omits one
	// of its label fields, rather than emitting an empty label — or, for
	// is_enabled and is_active, rather than defaulting a missing boolean to
	// false and inventing a clean bill of health.
	unknownValue = "unknown"
	// guidLen/guidHyphens bound the alert-type label: an id whose last segment
	// is itself a GUID has not been stripped to a type name, so it is reported
	// as unknown rather than leaked onto a metric label.
	guidLen     = 36
	guidHyphens = 4
)

// Collector polls the three beta roleManagementAlerts segments.
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

func (c *Collector) Name() string { return collectorName }

// DefaultInterval matches the sibling entra.pim_role_policies: Microsoft
// recomputes these findings on its own multi-hour scan cycle
// (lastScannedDateTime moves a few times a day), so polling faster only
// re-reads the same verdicts.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental reports true: roleManagementAlerts exists only on Graph beta.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the single read-only least-privilege scope
// (granted on the verification tenant 2026-07-24, #251). No write scope is
// involved — graph2otel never remediates a PIM alert, it only reports one.
func (c *Collector) RequiredPermissions() []string {
	return []string{"RoleManagementAlert.Read.Directory"}
}

// alert is one roleManagementAlerts/alerts row: the STATE of a finding.
// IncidentCount is a pointer because absent and zero are different answers —
// "no entities are affected" versus "this row never said". scopeId/scopeType are
// deliberately not decoded: the mandatory filter pins both to constants, so
// emitting them would be emitting our own query back.
type alert struct {
	ID                   string `json:"id"`
	AlertDefinitionID    string `json:"alertDefinitionId"`
	IncidentCount        *int64 `json:"incidentCount"`
	IsActive             *bool  `json:"isActive"`
	LastModifiedDateTime string `json:"lastModifiedDateTime"`
	LastScannedDateTime  string `json:"lastScannedDateTime"`
}

// alertDefinition is one alertDefinitions row: the MEANING of a finding, and
// the reason this collector exists — Microsoft's own remediation worklist.
type alertDefinition struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	SeverityLevel   string `json:"severityLevel"`
	SecurityImpact  string `json:"securityImpact"`
	MitigationSteps string `json:"mitigationSteps"`
	HowToPrevent    string `json:"howToPrevent"`
	IsRemediatable  *bool  `json:"isRemediatable"`
	IsConfigurable  *bool  `json:"isConfigurable"`
}

// alertConfiguration is one alertConfigurations row: whether the alert is
// switched on, and the thresholds it trips at. Every threshold is a pointer and
// every one is absent on most rows — they are polymorphic per @odata.type, and
// a zero threshold is a very different claim from an unstated one.
type alertConfiguration struct {
	ID                                   string `json:"id"`
	AlertDefinitionID                    string `json:"alertDefinitionId"`
	IsEnabled                            *bool  `json:"isEnabled"`
	Duration                             string `json:"duration"`
	TimeIntervalBetweenActivations       string `json:"timeIntervalBetweenActivations"`
	SequentialActivationCounterThreshold *int64 `json:"sequentialActivationCounterThreshold"`
	GlobalAdminCountThreshold            *int64 `json:"globalAdminCountThreshold"`
	GlobalAdminPercentageThreshold       *int64 `json:"percentageOfGlobalAdminsOutOfRolesThreshold"`
}

// Collect reads all three segments, emits the three bounded gauges, and emits
// one twin per alert with its definition and configuration joined in.
//
// A 403 (missing scope) or a MissingProvider 400 (the tenant genuinely has no
// PIM provider — the request always carries the filter, so the other cause is
// impossible here) is a graceful info-level skip rather than a collection
// failure. Any other error is surfaced: all three segments come from one scope
// on one surface, so a failure on any of them means the cycle's picture is
// incomplete, and a partial picture of "what Microsoft thinks is wrong with your
// privileged access" is worse than a loud failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	alerts, err := fetch[alert](ctx, c, alertsPath)
	if err != nil {
		return c.skipOrFail("alerts", err)
	}
	definitions, err := fetch[alertDefinition](ctx, c, definitionsPath)
	if err != nil {
		return c.skipOrFail("alertDefinitions", err)
	}
	configurations, err := fetch[alertConfiguration](ctx, c, configurationsPath)
	if err != nil {
		return c.skipOrFail("alertConfigurations", err)
	}

	definitionByID := make(map[string]alertDefinition, len(definitions))
	for _, d := range definitions {
		definitionByID[d.ID] = d
	}
	configByID := make(map[string]alertConfiguration, len(configurations))
	for _, cfg := range configurations {
		configByID[cfg.joinKey()] = cfg
	}

	alertPoints := make([]telemetry.GaugePoint, 0, len(alerts))
	incidentPoints := make([]telemetry.GaugePoint, 0, len(alerts))
	for _, a := range alerts {
		typ := alertType(a.ID)
		def := definitionByID[a.AlertDefinitionID]
		cfg := configByID[a.AlertDefinitionID]

		alertPoints = append(alertPoints, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{
				semconv.AttrAlertType: typ,
				semconv.AttrSeverity:  orUnknown(def.SeverityLevel),
				semconv.AttrIsActive:  boolLabel(a.IsActive),
			},
		})
		// An alert that never stated an incidentCount contributes no series
		// rather than a zero one: "0 entities affected" is a claim, and this row
		// did not make it.
		if a.IncidentCount != nil {
			incidentPoints = append(incidentPoints, telemetry.GaugePoint{
				Value: float64(*a.IncidentCount),
				Attrs: telemetry.Attrs{
					semconv.AttrAlertType: typ,
					semconv.AttrSeverity:  orUnknown(def.SeverityLevel),
				},
			})
		}
		e.LogEvent(twin(a, typ, def, cfg))
	}
	e.GaugeSnapshot(alertsMetricName, "{alert}",
		"Microsoft's pre-computed PIM privileged-access findings, one series per alert type, labeled by Microsoft's severity and whether the finding is currently active. Microsoft's description, security impact and mitigation steps are on the entra.pim_alert log twin.",
		alertPoints)
	e.GaugeSnapshot(incidentsMetricName, "{incident}",
		"Entities each PIM alert covers (roles without MFA on activation, assignments made outside PIM, stale privileged accounts). The entities themselves are not reachable — the alertIncidents segment is not exposed — so this count is the finest granularity available.",
		incidentPoints)

	configPoints := make([]telemetry.GaugePoint, 0, len(configurations))
	for _, cfg := range configurations {
		configPoints = append(configPoints, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{
				semconv.AttrAlertType: alertType(cfg.joinKey()),
				semconv.AttrIsEnabled: boolLabel(cfg.IsEnabled),
			},
		})
	}
	e.GaugeSnapshot(configurationsMetricName, "{configuration}",
		"PIM alert configurations by whether the alert is switched ON. A disabled alert reports itself inactive forever and is otherwise indistinguishable from a healthy one, so is_enabled=false is itself a finding.",
		configPoints)

	return nil
}

// twin renders one alert as a log record, joining the definition's remediation
// text and the configuration's enabled state and thresholds.
//
// The timestamp is left zero ("now"): this is a re-emitted state snapshot, not
// an event stream, so "which findings were active at 14:00" stays answerable.
// lastScannedDateTime is when MICROSOFT last looked, which is not when this
// record was produced, and is carried as an attribute instead.
func twin(a alert, typ string, def alertDefinition, cfg alertConfiguration) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrAlertId, a.ID)
	telemetry.SetStr(attrs, semconv.AttrAlertType, typ)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, def.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, def.Description)
	telemetry.SetStr(attrs, semconv.AttrSeverity, def.SeverityLevel)
	telemetry.SetStr(attrs, semconv.AttrSecurityImpact, def.SecurityImpact)
	telemetry.SetStr(attrs, semconv.AttrMitigationSteps, def.MitigationSteps)
	telemetry.SetStr(attrs, semconv.AttrHowToPrevent, def.HowToPrevent)
	setBoolPtr(attrs, semconv.AttrIsRemediatable, def.IsRemediatable)
	setBoolPtr(attrs, semconv.AttrIsConfigurable, def.IsConfigurable)
	setBoolPtr(attrs, semconv.AttrIsActive, a.IsActive)
	setInt64Ptr(attrs, semconv.AttrIncidentCount, a.IncidentCount)
	telemetry.SetStr(attrs, semconv.AttrLastScannedDateTime, realTimestamp(a.LastScannedDateTime))
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, realTimestamp(a.LastModifiedDateTime))
	setBoolPtr(attrs, semconv.AttrIsEnabled, cfg.IsEnabled)
	telemetry.SetDurationSeconds(attrs, semconv.AttrAlertEvaluationWindowSeconds, cfg.Duration)
	telemetry.SetDurationSeconds(attrs, semconv.AttrTimeBetweenActivationsSeconds, cfg.TimeIntervalBetweenActivations)
	setInt64Ptr(attrs, semconv.AttrSequentialActivationCounterThreshold, cfg.SequentialActivationCounterThreshold)
	setInt64Ptr(attrs, semconv.AttrGlobalAdminCountThreshold, cfg.GlobalAdminCountThreshold)
	setInt64Ptr(attrs, semconv.AttrGlobalAdminPercentageThreshold, cfg.GlobalAdminPercentageThreshold)

	return telemetry.Event{
		Name:     eventName,
		Body:     body(typ, def, a),
		Severity: severity(a, def, cfg),
		Attrs:    attrs,
	}
}

// severity is the ladder: an ACTIVE high-severity finding is the thing to wake
// up for, an active medium/low one a warning, and an inactive finding is
// informational — whatever Microsoft's severity for it, because an alert that is
// not firing is not a finding.
//
// A switched-OFF configuration is its own warning even when the alert is
// inactive: an alert that cannot fire has been reporting "healthy" by
// construction, which is precisely the state nothing else in the record makes
// visible. An explicit isEnabled:false is required — an absent one is unknown,
// and unknown is not a finding.
func severity(a alert, def alertDefinition, cfg alertConfiguration) telemetry.Severity {
	if a.IsActive != nil && *a.IsActive {
		if strings.EqualFold(def.SeverityLevel, "high") {
			return telemetry.SeverityError
		}
		return telemetry.SeverityWarn
	}
	if cfg.IsEnabled != nil && !*cfg.IsEnabled {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// body is the human-readable one-liner. It leads with Microsoft's own
// displayName where there is one, because that sentence IS the finding.
func body(typ string, def alertDefinition, a alert) string {
	label := def.DisplayName
	if label == "" {
		label = typ
	}
	active := "inactive"
	if a.IsActive != nil && *a.IsActive {
		active = "active"
	}
	incidents := "unknown"
	if a.IncidentCount != nil {
		incidents = fmt.Sprintf("%d", *a.IncidentCount)
	}
	return fmt.Sprintf("PIM alert %s (%s): %s, severity=%s, incidents=%s",
		typ, label, active, orUnknown(def.SeverityLevel), incidents)
}

// joinKey is the id an alertConfiguration joins on. alertDefinitionId is
// byte-identical to the row's own id on every live row, so either works — id is
// the fallback for a row that omits the explicit join field.
func (cfg alertConfiguration) joinKey() string {
	if cfg.AlertDefinitionID != "" {
		return cfg.AlertDefinitionID
	}
	return cfg.ID
}

// fetch pages one segment with the mandatory scope filter attached and decodes
// its rows.
func fetch[T any](ctx context.Context, c *Collector, path string) ([]T, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+path+scopeFilter, nil)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(raws))
	for _, raw := range raws {
		var row T
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, fmt.Errorf("decode row: %w", err)
		}
		out = append(out, row)
	}
	return out, nil
}

// skipOrFail turns a fetch error into either a graceful skip (nil) or a wrapped
// collection failure. See Collect for which is which and why.
func (c *Collector) skipOrFail(segment string, err error) error {
	switch {
	case isForbidden(err):
		c.logger.Info("pimalerts: roleManagementAlerts forbidden (missing RoleManagementAlert.Read.Directory?); skipping",
			"collector", collectorName, "segment", segment, "error", graphclient.FormatODataError(err))
		return nil
	case isMissingProvider(err):
		c.logger.Info("pimalerts: tenant has no PIM alert provider; skipping",
			"collector", collectorName, "segment", segment, "error", graphclient.FormatODataError(err))
		return nil
	}
	return fmt.Errorf("%s: list %s: %w", collectorName, segment, err)
}

// alertType strips the "DirectoryRole_<tenant guid>_" prefix off an alert id and
// returns the bounded type suffix ("StaleSignInAlert"). The raw id is per-tenant
// cardinality; the suffix is a fixed catalog (7 values live).
//
// An id that does not have that shape — empty, or one whose last segment is
// itself a GUID — yields unknownValue rather than leaking an unbounded value
// onto a metric label. The raw id is still on the twin either way, so nothing is
// lost by refusing to guess.
func alertType(id string) string {
	typ := id
	if i := strings.LastIndex(id, "_"); i >= 0 {
		typ = id[i+1:]
	}
	if typ == "" || looksLikeGUID(typ) {
		return unknownValue
	}
	return typ
}

// looksLikeGUID reports whether s has the canonical 8-4-4-4-12 GUID shape by
// length and hyphen count. Deliberately cheap: this bounds a metric label, it
// does not validate a GUID.
func looksLikeGUID(s string) bool {
	return len(s) == guidLen && strings.Count(s, "-") == guidHyphens
}

// realTimestamp passes a wire timestamp through, unless it is the .NET zero date
// that roleManagementAlerts uses for "this alert has never fired"
// ("0001-01-01T08:00:00Z", live-measured). A sentinel is an ABSENT value: the
// caller omits the attribute rather than claiming the finding last changed in
// year 1. Anything unparseable is likewise treated as absent rather than
// forwarded as a timestamp nothing downstream can read.
func realTimestamp(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1 {
		return ""
	}
	return s
}

// boolLabel renders a tri-state boolean as a bounded METRIC label. A nil pointer
// is "unknown", never "false": defaulting a missing isEnabled/isActive to false
// would publish a switched-off alert or a clean bill of health that the wire
// never stated.
func boolLabel(v *bool) string {
	if v == nil {
		return unknownValue
	}
	if *v {
		return "true"
	}
	return "false"
}

// setBoolPtr sets a tri-state boolean twin attribute, omitting it when the wire
// did not state it.
func setBoolPtr(attrs telemetry.Attrs, key string, v *bool) {
	if v != nil {
		telemetry.SetBool(attrs, key, *v)
	}
}

// setInt64Ptr sets an integer twin attribute, omitting it when the wire did not
// state it — an absent threshold is not a zero threshold.
func setInt64Ptr(attrs telemetry.Attrs, key string, v *int64) {
	if v != nil {
		attrs[key] = *v
	}
}

// orUnknown keeps a bounded gauge dimension from ever carrying an empty label.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing
// scope) rather than a collection failure.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status 403") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "Authorization_RequestDenied"
	}
	return false
}

// isMissingProvider reports whether err is the 400 MissingProvider answer. Every
// request this collector issues carries the mandatory scope filter, so the
// "graph2otel built a bad URL" cause is excluded by construction and what is
// left is a tenant with no PIM alert provider — a skip, not a failure.
func isMissingProvider(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "MissingProvider") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "MissingProvider"
	}
	return false
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
