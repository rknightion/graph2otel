// Package settingscatalog is the Intune Settings Catalog / template-intents /
// security-baselines collector: policy inventory from the modern
// `configurationPolicies` (Settings Catalog) surface, template-based
// `intents` (the legacy mechanism Settings Catalog is replacing, including
// security baselines predating the dedicated templates surface below), and
// dedicated security-baseline `templates` inventory + compliance.
//
// All three endpoints are beta-only with no v1.0 fallback (verified against
// the tracking issue's API research) - this collector implements
// collectors.Experimental and is opt-in.
//
// Settings Catalog is Microsoft's forward direction; intents (including
// legacy security baselines) are migrating into it, flagged per-intent via
// isMigratingToConfigurationPolicy. A mid-migration tenant can expose the
// same underlying policy both as a configurationPolicy and as an intent, so
// Collect reconciles them by templateReference: an intent flagged as
// migrating whose templateId already appears among the configurationPolicies
// inventory is excluded from intune.intent.count (it is already counted
// there as a Settings Catalog policy), avoiding a double count across the
// two metrics. Its deviceStateSummary compliance gauge is still emitted
// regardless of reconciliation - migration state must flag double-counting
// risk without ever silently dropping compliance/baseline coverage.
//
// Settings Catalog and legacy intents have no per-device/per-setting status
// navigation property at fleet scale (that data is export-job-only:
// ConfigurationPolicyAggregate / DeviceIntentPerSettingStatus) - deferred to
// the M5 export-job subsystem. This collector only reads the entity and
// deviceStateSummary/overview endpoints.
package settingscatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.settings_catalog"

// Metric names this collector emits. Each is its own metric name so that
// summing a single metric always yields the true count for that breakdown -
// mixing independent dimensions under one metric name would mean a naive
// sum() over it silently multi-counts.
const (
	policyCountMetricName     = "intune.settings_catalog.policy.count"
	intentCountMetricName     = "intune.intent.count"
	intentDevicesMetricName   = "intune.intent.devices"
	baselineDevicesMetricName = "intune.security_baseline.devices"
)

// betaBaseURL is the Graph beta root. configurationPolicies, intents, and
// the security-baseline templates surface are all beta-only - no v1.0
// fallback exists for any of them (see the package doc and the tracking
// issue's API research table).
const betaBaseURL = "https://graph.microsoft.com/beta"

// securityBaselineFilter isolates security-baseline templates from the
// templates collection, which also holds non-baseline template types under
// the same templateType enum.
const securityBaselineFilter = "templateType eq 'securityBaseline'"

// Collector polls Settings Catalog configurationPolicies, template-based
// intents, and security-baseline templates.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the settings-catalog collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Policy/intent/baseline
// inventory and their compliance summaries drift slowly, and this collector
// fans out one deviceStateSummary call per intent/baseline on top of the
// three list calls, so it defaults to a longer cadence than the lighter
// single-call Entra collectors.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector - see the package doc.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Every endpoint this collector reads is documented under
// DeviceManagementConfiguration.Read.All. Endpoint-security-templated
// Settings Catalog policies may additionally require
// DeviceManagementEndpointSecurity.Read.All to read fully; that scope is
// deliberately not requested here since the entity/inventory fields this
// collector reads (platforms/technologies/templateReference) are documented
// under DeviceManagementConfiguration.Read.All alone - revisit if a tenant
// is observed 403ing on that subset specifically.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect polls all three surfaces. Each is independently resilient: a 403
// (missing scope) or 404 (beta endpoint unavailable on this tenant) is
// logged at Info and skipped rather than treated as a failure, since none of
// these beta surfaces are guaranteed present on every tenant/license
// combination; any other error is logged and joined into the returned error,
// but does not prevent the other two surfaces (or, within the intents/
// baselines fan-outs, any other item) from still emitting.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	policyTemplateIDs, err := c.collectConfigurationPolicies(ctx, e)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("settingscatalog: configurationPolicies unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("settingscatalog: configurationPolicies fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("configuration policies: %w", err))
		}
		policyTemplateIDs = map[string]struct{}{}
	}

	intents, err := c.listIntents(ctx)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("settingscatalog: intents unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("settingscatalog: intents list fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("intents: %w", err))
		}
	}
	if len(intents) > 0 {
		if err := c.emitIntentCountsAndDeviceStates(ctx, e, intents, policyTemplateIDs); err != nil {
			errs = append(errs, err)
		}
	} else {
		// Still emit an empty snapshot so a tenant with zero intents shows a
		// present-but-empty series set rather than no series at all.
		e.GaugeSnapshot(intentCountMetricName, "{intent}", "Intune template-based device management intents, by migration status.", nil)
		e.GaugeSnapshot(intentDevicesMetricName, "{device}", "Per-intent device compliance status from deviceStateSummary.", nil)
	}

	baselines, err := c.listSecurityBaselineTemplates(ctx)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("settingscatalog: security baseline templates unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("settingscatalog: security baseline templates fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("security baseline templates: %w", err))
		}
	}
	if len(baselines) > 0 {
		if err := c.emitSecurityBaselineDeviceStates(ctx, e, baselines); err != nil {
			errs = append(errs, err)
		}
	} else {
		e.GaugeSnapshot(baselineDevicesMetricName, "{device}", "Per-security-baseline device state from deviceStateSummary.", nil)
	}

	return errors.Join(errs...)
}

// configurationPolicyTemplateReference is the subset of a configurationPolicy's
// templateReference this collector reads: the family for bucketing, and the
// templateId used to reconcile against intents.
type configurationPolicyTemplateReference struct {
	TemplateID     string `json:"templateId"`
	TemplateFamily string `json:"templateFamily"`
}

// configurationPolicy is the subset of the beta deviceManagementConfigurationPolicy
// resource this collector reads. No id/name is emitted as a metric label -
// only the bounded platform/technology/template_family dimensions.
type configurationPolicy struct {
	ID                string                                `json:"id"`
	Platforms         string                                `json:"platforms"`
	Technologies      string                                `json:"technologies"`
	TemplateReference *configurationPolicyTemplateReference `json:"templateReference"`
}

// collectConfigurationPolicies fetches the Settings Catalog policy inventory,
// emits the bounded policy-count gauge, and returns the set of templateIds
// observed via templateReference - the reconciliation key emitIntentCountsAndDeviceStates
// uses to avoid double-counting a migrated intent against its Settings
// Catalog twin.
func (c *Collector) collectConfigurationPolicies(ctx context.Context, e telemetry.Emitter) (map[string]struct{}, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/configurationPolicies", nil)
	if err != nil {
		return nil, err
	}

	type bucketKey struct{ platform, technology, family string }
	counts := map[bucketKey]int64{}
	templateIDs := map[string]struct{}{}

	for _, r := range raw {
		var p configurationPolicy
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("settingscatalog: skipping unparseable configurationPolicy", "collector", collectorName, "error", err)
			continue
		}
		family := "none"
		if p.TemplateReference != nil {
			family = orUnknown(p.TemplateReference.TemplateFamily)
			if p.TemplateReference.TemplateID != "" {
				templateIDs[p.TemplateReference.TemplateID] = struct{}{}
			}
		}
		counts[bucketKey{orUnknown(p.Platforms), orUnknown(p.Technologies), family}]++
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrPlatform: k.platform, semconv.AttrTechnology: k.technology, semconv.AttrTemplateFamily: k.family},
		})
	}
	e.GaugeSnapshot(policyCountMetricName, "{policy}",
		"Intune Settings Catalog configuration policy count, by platform, technology, and template family.", points)
	return templateIDs, nil
}

// intent is the subset of the beta deviceManagementIntent resource this
// collector reads.
type intent struct {
	ID                               string `json:"id"`
	DisplayName                      string `json:"displayName"`
	TemplateID                       string `json:"templateId"`
	IsMigratingToConfigurationPolicy bool   `json:"isMigratingToConfigurationPolicy"`
}

// listIntents fetches the template-based intent inventory (unbounded by
// device/user count - bounded by admin-configured intent count).
func (c *Collector) listIntents(ctx context.Context) ([]intent, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/intents", nil)
	if err != nil {
		return nil, err
	}
	out := make([]intent, 0, len(raw))
	for _, r := range raw {
		var it intent
		if err := json.Unmarshal(r, &it); err != nil {
			c.logger.Warn("settingscatalog: skipping unparseable intent", "collector", collectorName, "error", err)
			continue
		}
		if it.ID == "" {
			c.logger.Warn("settingscatalog: skipping intent with empty id", "collector", collectorName)
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// intentDeviceStateSummary is the shape of GET .../intents/{id}/deviceStateSummary,
// mirroring the field naming of the v1.0 deviceCompliancePolicyDeviceStateSummary
// resource (Intune's summary singletons are consistently named across
// surfaces).
type intentDeviceStateSummary struct {
	UnknownDeviceCount       int64 `json:"unknownDeviceCount"`
	NotApplicableDeviceCount int64 `json:"notApplicableDeviceCount"`
	CompliantDeviceCount     int64 `json:"compliantDeviceCount"`
	RemediatedDeviceCount    int64 `json:"remediatedDeviceCount"`
	NonCompliantDeviceCount  int64 `json:"nonCompliantDeviceCount"`
	ErrorDeviceCount         int64 `json:"errorDeviceCount"`
	ConflictDeviceCount      int64 `json:"conflictDeviceCount"`
}

// points renders one intentDeviceStateSummary into its seven bounded
// (intent_name, compliance_status) gauge points.
func (s intentDeviceStateSummary) points(intentName string) []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(s.CompliantDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "compliant"}},
		{Value: float64(s.NonCompliantDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "non_compliant"}},
		{Value: float64(s.RemediatedDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "remediated"}},
		{Value: float64(s.ErrorDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "error"}},
		{Value: float64(s.ConflictDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "conflict"}},
		{Value: float64(s.NotApplicableDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "not_applicable"}},
		{Value: float64(s.UnknownDeviceCount), Attrs: telemetry.Attrs{semconv.AttrIntentName: intentName, semconv.AttrComplianceStatus: "unknown"}},
	}
}

// emitIntentCountsAndDeviceStates buckets intents by migration status
// (reconciled against policyTemplateIDs to avoid double-counting a policy
// already inventoried via configurationPolicies) and fans out to each
// intent's deviceStateSummary. A failure fetching one intent's
// deviceStateSummary is logged and joined into the returned error, but every
// other intent and both metrics still emit whatever succeeded.
func (c *Collector) emitIntentCountsAndDeviceStates(ctx context.Context, e telemetry.Emitter, intents []intent, policyTemplateIDs map[string]struct{}) error {
	var errs []error
	counts := map[string]int64{}
	devicePoints := make([]telemetry.GaugePoint, 0, len(intents)*7)

	for _, it := range intents {
		name := orUnknown(it.DisplayName)

		// Reconciliation: an intent flagged as migrating whose templateId
		// already has a twin in the configurationPolicies inventory is the
		// same underlying policy counted there - excluding it here avoids
		// double-counting across intune.settings_catalog.policy.count and
		// intune.intent.count. A migrating intent whose twin hasn't
		// appeared yet (migration in progress, not yet visible via
		// configurationPolicies) is still counted - this is a
		// best-effort reconciliation against the current snapshot, not a
		// guarantee against every possible migration timing race.
		_, hasPolicyTwin := policyTemplateIDs[it.TemplateID]
		alreadyCountedAsPolicy := it.IsMigratingToConfigurationPolicy && it.TemplateID != "" && hasPolicyTwin
		if !alreadyCountedAsPolicy {
			counts[strconv.FormatBool(it.IsMigratingToConfigurationPolicy)]++
		}

		// deviceStateSummary compliance coverage is emitted for every
		// intent regardless of reconciliation - migration status must never
		// silently drop compliance coverage, only flag count double-risk.
		summary, err := c.fetchIntentDeviceStateSummary(ctx, it.ID)
		switch {
		case err == nil:
			devicePoints = append(devicePoints, summary.points(name)...)
		case isUnavailable(err) || isSummaryUnavailable(err):
			c.logger.Info("settingscatalog: intent deviceStateSummary unavailable; skipping",
				"collector", collectorName, "intent_name", name, "error", err)
		default:
			c.logger.Warn("settingscatalog: intent deviceStateSummary fetch failed",
				"collector", collectorName, "intent_name", name, "error", err)
			errs = append(errs, fmt.Errorf("intent deviceStateSummary intent=%s: %w", name, err))
		}
	}

	countPoints := make([]telemetry.GaugePoint, 0, len(counts))
	for migrating, n := range counts {
		countPoints = append(countPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrMigrating: migrating},
		})
	}
	e.GaugeSnapshot(intentCountMetricName, "{intent}",
		"Intune template-based device management intents, by migration status. An intent already represented as a Settings Catalog configurationPolicy (migrating, matched by templateReference) is excluded here to avoid double-counting against intune.settings_catalog.policy.count.", countPoints)
	e.GaugeSnapshot(intentDevicesMetricName, "{device}",
		"Per-intent device compliance status from deviceStateSummary, by intent and compliance status.", devicePoints)
	return errors.Join(errs...)
}

// fetchIntentDeviceStateSummary GETs and decodes one intent's
// deviceStateSummary singleton.
func (c *Collector) fetchIntentDeviceStateSummary(ctx context.Context, id string) (intentDeviceStateSummary, error) {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/intents/"+id+"/deviceStateSummary")
	if err != nil {
		return intentDeviceStateSummary{}, err
	}
	var s intentDeviceStateSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return intentDeviceStateSummary{}, fmt.Errorf("decode intent deviceStateSummary: %w", err)
	}
	return s, nil
}

// baselineTemplate is the subset of the beta deviceManagementTemplate
// resource this collector reads, already filtered to templateType ==
// securityBaseline server-side.
type baselineTemplate struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// listSecurityBaselineTemplates fetches the security-baseline template
// inventory (bounded by Microsoft's published baseline catalog per
// platform/version, not tenant size).
func (c *Collector) listSecurityBaselineTemplates(ctx context.Context) ([]baselineTemplate, error) {
	u := c.baseURL + "/deviceManagement/templates?$filter=" + encodeFilter(securityBaselineFilter)
	raw, err := collectors.GetAllValues(ctx, c.g, u, nil)
	if err != nil {
		return nil, err
	}
	out := make([]baselineTemplate, 0, len(raw))
	for _, r := range raw {
		var t baselineTemplate
		if err := json.Unmarshal(r, &t); err != nil {
			c.logger.Warn("settingscatalog: skipping unparseable security baseline template", "collector", collectorName, "error", err)
			continue
		}
		if t.ID == "" {
			c.logger.Warn("settingscatalog: skipping security baseline template with empty id", "collector", collectorName)
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// baselineDeviceStateSummary is the shape of GET .../templates/{id}/deviceStateSummary
// for a security baseline template (securityBaselineDeviceStateSummary):
// secure/notSecure rather than compliant/nonCompliant, matching the
// dedicated baseline compliance vocabulary Microsoft documents for this
// resource.
type baselineDeviceStateSummary struct {
	UnknownDeviceCount       int64 `json:"unknownDeviceCount"`
	NotApplicableDeviceCount int64 `json:"notApplicableDeviceCount"`
	SecureDeviceCount        int64 `json:"secureDeviceCount"`
	NotSecureDeviceCount     int64 `json:"notSecureDeviceCount"`
	ErrorDeviceCount         int64 `json:"errorDeviceCount"`
	ConflictDeviceCount      int64 `json:"conflictDeviceCount"`
}

// points renders one baselineDeviceStateSummary into its six bounded
// (baseline_name, state) gauge points.
func (s baselineDeviceStateSummary) points(baselineName string) []telemetry.GaugePoint {
	return []telemetry.GaugePoint{
		{Value: float64(s.SecureDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "secure"}},
		{Value: float64(s.NotSecureDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "not_secure"}},
		{Value: float64(s.ErrorDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "error"}},
		{Value: float64(s.ConflictDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "conflict"}},
		{Value: float64(s.NotApplicableDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "not_applicable"}},
		{Value: float64(s.UnknownDeviceCount), Attrs: telemetry.Attrs{semconv.AttrBaselineName: baselineName, semconv.AttrState: "unknown"}},
	}
}

// emitSecurityBaselineDeviceStates fans out to each security-baseline
// template's deviceStateSummary and emits the bounded (baseline_name, state)
// gauge set. A failure fetching one baseline's summary is logged and joined
// into the returned error, but every other baseline still emits.
func (c *Collector) emitSecurityBaselineDeviceStates(ctx context.Context, e telemetry.Emitter, baselines []baselineTemplate) error {
	var errs []error
	points := make([]telemetry.GaugePoint, 0, len(baselines)*6)

	for _, b := range baselines {
		name := orUnknown(b.DisplayName)
		summary, err := c.fetchBaselineDeviceStateSummary(ctx, b.ID)
		switch {
		case err == nil:
			points = append(points, summary.points(name)...)
		case isUnavailable(err) || isSummaryUnavailable(err):
			c.logger.Info("settingscatalog: security baseline deviceStateSummary unavailable; skipping",
				"collector", collectorName, "baseline_name", name, "error", err)
		default:
			c.logger.Warn("settingscatalog: security baseline deviceStateSummary fetch failed",
				"collector", collectorName, "baseline_name", name, "error", err)
			errs = append(errs, fmt.Errorf("baseline deviceStateSummary baseline=%s: %w", name, err))
		}
	}

	e.GaugeSnapshot(baselineDevicesMetricName, "{device}",
		"Per-security-baseline device state from deviceStateSummary, by baseline and state.", points)
	return errors.Join(errs...)
}

// fetchBaselineDeviceStateSummary GETs and decodes one security baseline
// template's deviceStateSummary singleton.
func (c *Collector) fetchBaselineDeviceStateSummary(ctx context.Context, id string) (baselineDeviceStateSummary, error) {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceManagement/templates/"+id+"/deviceStateSummary")
	if err != nil {
		return baselineDeviceStateSummary{}, err
	}
	var s baselineDeviceStateSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return baselineDeviceStateSummary{}, fmt.Errorf("decode security baseline deviceStateSummary: %w", err)
	}
	return s, nil
}

// encodeFilter percent-encodes an OData $filter expression form-style
// (url.QueryEscape turns spaces into '+', which Graph doesn't accept in a
// query string - converted to '%20' instead), the same pattern used by every
// other collector's filterCountURL helper.
func encodeFilter(filter string) string {
	return strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
}

// isUnavailable reports whether err is a 4xx from a beta endpoint being
// unavailable/unlicensed on this tenant (403 forbidden - missing scope or
// license; 404 not found - the beta surface not yet rolled out to this
// tenant) - an expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

// isSummaryUnavailable reports whether err is a Graph response for a
// deviceStateSummary sub-fetch (per-intent or per-baseline-template) whose
// type simply doesn't expose that navigation property - observed live as
// HTTP 400 (not 404) with a segment-not-found message, e.g. `"Resource not
// found for the segment 'deviceStateSummary'."`. This is deliberately
// narrower than isUnavailable: a bare "status 400" is NOT enough (a
// genuinely malformed query must still surface as a failure) - the message
// must also name a missing/not-found segment or resource.
func isSummaryUnavailable(err error) bool {
	s := err.Error()
	if !strings.Contains(s, "status 400") && !strings.Contains(s, "status 404") {
		return false
	}
	lower := strings.ToLower(s)
	return strings.Contains(lower, "not found for the segment") ||
		strings.Contains(lower, "not found for segment") ||
		strings.Contains(lower, "resourcenotfound")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Compile-time interface assertions.
var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
