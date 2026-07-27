// Package recommendations is the Entra recommendations collector (BETA):
// Microsoft's own tenant-posture scoreboard from /beta/directory/recommendations,
// emitted as bounded counts by status/priority and by recommendation type, plus
// one entra.recommendation state twin per recommendation carrying the
// per-entity remediation detail the gauges cannot.
//
// Beta-only: the endpoint lives on /beta and its schema is unstable, so this
// collector implements collectors.Experimental (opt-in, off by default) and
// degrades cleanly — a 403/404 (endpoint unavailable or unlicensed on the
// tenant) is skipped-and-logged rather than treated as a failure.
//
// # The impacted-resources gauge and the omitted-relationship rule (#315)
//
// impactedResources is a Graph navigation property, requested inline via
// $expand=impactedResources on the single list request — the cheapest
// complete request shape, live-measured on the m7kni tenant 2026-07-26 (#315):
// one list page carrying the property beats either N+1 fan-out
// (per-recommendation /impactedResources or its $count) by 15 fewer requests
// for ~10KB more response body, with zero relationship-count mismatches
// against either fan-out.
//
// The property is OPTIONAL even when requested: Graph omits it on tenants/API
// versions where the relationship isn't populated. The collector distinguishes
// "omitted" (decodes to a nil pointer) from "present but empty" (decodes to a
// non-nil pointer to a zero-length slice): only a present relationship
// contributes to the impacted-resources gauge and the twin's
// impacted_resource_count attribute. An omitted relationship emits NEITHER —
// never a fabricated zero. The prior implementation read impactedResources as
// a bare (non-pointer) slice, so `len(nil) == 0` was indistinguishable from a
// genuinely empty relationship, and every impacted series on every real tenant
// was a fabricated zero (the #315 bug).
package recommendations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	collectorName  = "entra.recommendations"
	totalMetric    = "entra.recommendations.total"
	impactedMetric = "entra.recommendations.impacted_resources.total"
	betaBaseURL    = "https://graph.microsoft.com/beta"
	// recommendationsPath is the FROZEN request shape from the live-measured
	// decision on #315: one list request with $expand=impactedResources. See
	// the package doc for why this beats either per-recommendation fan-out.
	recommendationsPath = "/directory/recommendations?$expand=impactedResources"
	// eventRecommendation is the state-twin EventName: one record per
	// recommendation per poll, carrying the fields the two gauges above cannot
	// (#315 acceptance criterion 2).
	eventRecommendation = "entra.recommendation"
)

// status, priority and recommendationType are all METRIC LABELS passed RAW (the
// first two on the total gauge, the type on the impacted gauge), so a value
// Microsoft adds silently moves series membership with nothing saying why (#234).
// There is no in-repo bucket map to derive these from, so they are declared
// explicitly from the Graph BETA CSDL EnumType definitions
// (`GET /beta/$metadata`, recommendationBase's status/priority/recommendationType
// properties, fetched 2026-07-25). `unknownFutureValue` is EXCLUDED from every
// set: it is Microsoft's evolvable-enum sentinel, so its appearance is exactly
// the signal a new member exists and must fire the watchdog, not be accepted.
var (
	knownStatuses   = wirecheck.NewEnum("active", "completedBySystem", "completedByUser", "dismissed", "postponed", "riskAccepted", "thirdParty", "planned", "alternateMitigation")
	knownPriorities = wirecheck.NewEnum("low", "medium", "high")
	knownTypes      = wirecheck.NewEnum(
		"adfsAppsMigration", "enableDesktopSSO", "enablePHS", "enableProvisioning", "switchFromPerUserMFA",
		"tenantMFA", "thirdPartyApps", "turnOffPerUserMFA", "useAuthenticatorApp", "useMyApps", "staleApps",
		"staleAppCreds", "applicationCredentialExpiry", "servicePrincipalKeyExpiry", "adminMFAV2",
		"blockLegacyAuthentication", "integratedApps", "mfaRegistrationV2", "pwagePolicyNew", "passwordHashSync",
		"oneAdmin", "roleOverlap", "selfServicePasswordReset", "signinRiskPolicy", "userRiskPolicy",
		"insiderRiskPolicy",
		"verifyAppPublisher", "privateLinkForAAD", "appRoleAssignmentsGroups", "appRoleAssignmentsUsers",
		"managedIdentity", "overprivilegedApps", "longLivedCredentials", "aadConnectDeprecated",
		"adalToMsalMigration", "ownerlessApps", "inactiveGuests", "aadGraphDeprecationApplication",
		"aadGraphDeprecationServicePrincipal", "mfaServerDeprecation",
	)
)

// actionStep is one element of a recommendation's actionSteps array — the
// numbered remediation walkthrough. Only the human-readable text is decoded;
// see AttrActionStepTexts for why actionUrl/stepNumber are not carried.
type actionStep struct {
	Text string `json:"text"`
}

// recommendation is the beta recommendation resource this collector reads.
// Every field is one this endpoint already returns on the wire; before #315
// only RecommendationType/Status/Priority/ImpactedResources were decoded and
// everything else was fetched and discarded.
//
// ImpactedResources is requested inline via $expand=impactedResources
// (avoiding an N+1 call to the per-recommendation impactedResources endpoint)
// and decoded as a POINTER, deliberately: a plain slice cannot distinguish
// "Graph omitted the navigation property" (nil pointer) from "the
// relationship is genuinely empty" (non-nil pointer to a zero-length slice).
// Only the former must emit no series/attribute — see the package doc.
//
// CurrentScore/MaxScore are POINTERS for the same reason CLAUDE.md's
// absent-field-is-not-a-sentinel rule requires generally: a plain float64
// cannot tell "the wire said 0.0" from "the wire said nothing", and a nil
// pointer omits the twin attribute rather than publishing a fabricated 0.
type recommendation struct {
	ID                    string             `json:"id"`
	DisplayName           string             `json:"displayName"`
	Category              string             `json:"category"`
	RecommendationType    string             `json:"recommendationType"`
	Status                string             `json:"status"`
	Priority              string             `json:"priority"`
	CurrentScore          *float64           `json:"currentScore"`
	MaxScore              *float64           `json:"maxScore"`
	Benefits              string             `json:"benefits"`
	RemediationImpact     string             `json:"remediationImpact"`
	RequiredLicenses      string             `json:"requiredLicenses"`
	ReleaseType           string             `json:"releaseType"`
	ImpactType            string             `json:"impactType"`
	Insights              string             `json:"insights"`
	CreatedDateTime       string             `json:"createdDateTime"`
	LastModifiedDateTime  string             `json:"lastModifiedDateTime"`
	LastModifiedBy        string             `json:"lastModifiedBy"`
	ImpactStartDateTime   string             `json:"impactStartDateTime"`
	PostponeUntilDateTime string             `json:"postponeUntilDateTime"`
	FeatureAreas          []string           `json:"featureAreas"`
	ActionSteps           []actionStep       `json:"actionSteps"`
	ImpactedResources     *[]json.RawMessage `json:"impactedResources"`
}

// Collector polls /beta/directory/recommendations.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
}

// New builds the recommendations collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger, watch: wirecheck.New(collectorName, logger)}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The recommendation catalog
// drifts slowly; a longer cadence is fine.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DirectoryRecommendations.Read.All"}
}

// Collect fetches the recommendation list and emits status/priority counts plus
// per-type impacted-resource counts. Because coverage is license-dependent and
// the endpoint is beta, a 4xx (unavailable/unlicensed) is skipped-and-logged,
// not surfaced as an error.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raw, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+recommendationsPath, nil, outcomes)
	if err != nil {
		if isUnavailable(err) {
			if strings.Contains(err.Error(), "status 403") {
				outcomes.Cause(recordoutcome.CausePermissionDenied)
			}
			c.logger.Info("recommendations endpoint unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
			return nil
		}
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("recommendations: list: %w", err)
	}

	byStatusPriority := map[[2]string]int{}
	impactedByType := map[string]int{}
	for _, r := range raw {
		var rec recommendation
		if err := json.Unmarshal(r, &rec); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("recommendations: skipping unparseable entry", "collector", collectorName, "error", err)
			continue
		}
		// status/priority/recommendationType are metric labels passed raw — watch
		// each against its CSDL set so a new Microsoft member surfaces (#234).
		c.watch.Value(e, semconv.AttrStatus, rec.Status, knownStatuses)
		c.watch.Value(e, semconv.AttrPriority, rec.Priority, knownPriorities)
		c.watch.Value(e, semconv.AttrRecommendation, rec.RecommendationType, knownTypes)
		status := orUnknown(rec.Status)
		priority := orUnknown(rec.Priority)
		byStatusPriority[[2]string{status, priority}]++
		// Only a PRESENT navigation property contributes to the impacted-resources
		// gauge (#315): an omitted relationship (nil pointer) adds nothing, so a
		// type with no present relationship on any record gets no series at all,
		// rather than the fabricated zero the pre-#315 collector published.
		if rec.ImpactedResources != nil && rec.RecommendationType != "" {
			impactedByType[rec.RecommendationType] += len(*rec.ImpactedResources)
		}
		e.LogEvent(recommendationTwin(rec))
		entraoutcome.Emitted(outcomes, 1)
	}

	total := make([]telemetry.GaugePoint, 0, len(byStatusPriority))
	for k, v := range byStatusPriority {
		total = append(total, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrStatus: k[0], semconv.AttrPriority: k[1]},
		})
	}
	e.GaugeSnapshot(totalMetric, "{recommendation}", "Entra recommendations by status and priority.", total)

	impacted := make([]telemetry.GaugePoint, 0, len(impactedByType))
	for typ, n := range impactedByType {
		impacted = append(impacted, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrRecommendation: typ},
		})
	}
	e.GaugeSnapshot(impactedMetric, "{resource}", "Impacted resources per Entra recommendation type.", impacted)
	return nil
}

// isUnavailable reports whether err is a 4xx from the beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) — an
// expected "no data here" condition, not a failure.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// recommendationTwin renders one recommendation as the entra.recommendation
// state twin (#315 acceptance criterion 2): every field the response already
// returns, none of it a metric label. This is a STATE feed like
// entra/risk — the same recommendation is re-emitted every cycle for as long
// as it stays in scope, which is what makes "what did this recommendation say
// at 14:00" answerable; Timestamp is therefore left zero (poll time).
func recommendationTwin(r recommendation) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, r.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, r.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrCategory, r.Category)
	telemetry.SetStr(attrs, semconv.AttrStatus, r.Status)
	telemetry.SetStr(attrs, semconv.AttrPriority, r.Priority)
	telemetry.SetStr(attrs, semconv.AttrRecommendation, r.RecommendationType)
	if r.CurrentScore != nil {
		attrs[semconv.AttrScore] = *r.CurrentScore
	}
	if r.MaxScore != nil {
		attrs[semconv.AttrMaxScore] = *r.MaxScore
	}
	telemetry.SetStr(attrs, semconv.AttrBenefits, r.Benefits)
	telemetry.SetStr(attrs, semconv.AttrRemediationImpact, r.RemediationImpact)
	telemetry.SetStr(attrs, semconv.AttrRequiredLicenses, r.RequiredLicenses)
	telemetry.SetStr(attrs, semconv.AttrReleaseType, r.ReleaseType)
	telemetry.SetStr(attrs, semconv.AttrImpactType, r.ImpactType)
	telemetry.SetStr(attrs, semconv.AttrInsights, r.Insights)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, r.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, r.LastModifiedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedBy, r.LastModifiedBy)
	telemetry.SetStr(attrs, semconv.AttrImpactStartDateTime, r.ImpactStartDateTime)
	// postponeUntilDateTime is null on a non-postponed recommendation (JSON null
	// decodes to "" here); SetStr omits it rather than stamping a fabricated
	// blank.
	telemetry.SetStr(attrs, semconv.AttrPostponeUntilDateTime, r.PostponeUntilDateTime)
	telemetry.SetStrs(attrs, semconv.AttrFeatureAreas, r.FeatureAreas)
	if len(r.ActionSteps) > 0 {
		texts := make([]string, 0, len(r.ActionSteps))
		for _, s := range r.ActionSteps {
			if s.Text != "" {
				texts = append(texts, s.Text)
			}
		}
		telemetry.SetStrs(attrs, semconv.AttrActionStepTexts, texts)
	}
	// Mirrors the gauge's own present-vs-omitted rule (#315): the twin's count
	// is emitted only when the navigation property was present on this record,
	// never fabricated from a nil (omitted) relationship.
	if r.ImpactedResources != nil {
		attrs[semconv.AttrImpactedResourceCount] = len(*r.ImpactedResources)
	}

	return telemetry.Event{
		Name:     eventRecommendation,
		Body:     fmt.Sprintf("recommendation %s: %s (status=%s priority=%s)", orUnknown(r.RecommendationType), r.DisplayName, orUnknown(r.Status), orUnknown(r.Priority)),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
