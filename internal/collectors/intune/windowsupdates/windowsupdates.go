// Package windowsupdates is the Windows Update for Business DEPLOYMENT SERVICE
// collector (BETA): the tenant's update policies (what is auto-approved, under
// what filter, with what user experience) and its deployments (what is actually
// being offered to devices right now, and whether that matches what was asked
// for).
//
// Source (beta-only — v1.0 rejects the segment with
// "400 BadRequest — Resource not found for the segment 'windows'", live-measured
// 2026-07-24 as graph2otel-poller, which is why this collector is Experimental):
//
//	GET /beta/admin/windows/updates/updatePolicies
//	GET /beta/admin/windows/updates/deployments
//
// # Relationship to intune.updates
//
// intune.updates covers the CLASSIC Intune update surface — update rings under
// /deviceManagement/deviceConfigurations plus the windows*UpdateProfiles
// families. This collector covers the deployment SERVICE under
// /admin/windows/updates, which is a different API with a different object
// model and a different app role (WindowsUpdates.Read.All, not
// DeviceManagementConfiguration.Read.All). They are peers, not duplicates: a
// tenant can run one, the other, or both.
//
// Update deployment is the one Intune surface where "nothing happened" and "the
// update ring is broken" look identical from outside, which is what this
// collector is for.
//
// # Wire shape (live-captured 2026-07-24, all 3 m7kni rows, #259)
//
// This is the most polymorphic surface in the tree, and every trap below was
// observed on the wire rather than read in documentation.
//
//   - `state` is a THREE-part object — `effectiveValue`, `requestedValue`,
//     `reasons[]` — and on the live row the first two DISAGREE
//     (`effectiveValue: "offering"` under `requestedValue: "none"`). Collapsing
//     it to one value destroys the whole signal, so all three are mapped and the
//     mismatch drives severity. See deploymentTwin.
//   - `@odata.type` discriminators appear at four nesting levels
//     (`contentApprovalRule`, `qualityUpdateFilter` / `driverUpdateFilter`,
//     `catalogContent`, `qualityUpdateCatalogEntry`). Variant-specific fields are
//     read ONLY when the discriminator names their variant — a driver filter
//     carries neither `classification` nor `cadence`, and both live policies
//     prove it. See odataShortType, contentFilter and catalogEntry.
//   - The nested `catalogEntry` has `"id": ""` and `"displayName": null`. An
//     empty id is not an identifier, so it is omitted rather than emitted — the
//     twin never claims to name an update it cannot name.
//   - `lastEvaluatedDateTime: "0001-01-01T00:00:00Z"` is the .NET zero date
//     meaning "never evaluated". It is never emitted as a timestamp; the FACT it
//     encodes survives as the rules_never_evaluated count. Applied to EVERY
//     timestamp on these records, not just the one it was observed on — the same
//     serializer produces all of them. See realTime.
//   - `durationBeforeDeploymentStart: "PT0S"` is an ISO-8601 duration STRING,
//     carried verbatim. See semconv.AttrDeploymentStartDelays for why it is not
//     converted to seconds.
//   - `state.reasons` is EMPTY on the only live deployment, so its populated
//     shape is unverified — decoded defensively (objects with a `value`, bare
//     strings, or absent) so an unexpected shape can never fail a row.
//
// Deliberately NOT mapped, because they are null on every live row and mapping a
// field nobody has ever seen populated is mapping against documentation:
// `deploymentSettings.schedule`, `.monitoring`, the policy-side `.expedite`,
// `contentApplicability.safeguard`, and the catalog entry's `catalogName`,
// `shortName`, `deployableUntilDateTime` and `cveSeverityInformation`. Any of
// them becomes mappable the day a live row carries one.
//
// # products is deliberately NOT collected
//
// `GET /beta/admin/windows/updates/products` returns 17 rows on this tenant and
// would return the same 17 rows on every other one: it is Microsoft's global
// catalog of Windows product families ("Windows 11, version 24H2", id 1104),
// not tenant state. Nothing an operator does changes it.
//
//   - As a metric it is a constant: 17 series of the value 1, forever, per
//     tenant — cardinality spent on something that cannot move (#112).
//   - As logs it is 17 identical records re-emitted every poll into a billed log
//     store, answering a question nobody asks about their own tenant.
//   - Its only real use is as a LOOKUP TABLE, to resolve a product id appearing
//     on some other record. No record graph2otel maps carries one: a deployment
//     references a catalogEntry, not a product.
//
// So the request is not issued at all, and TestProductsCatalogueIsNeverFetched
// pins that. UNBLOCK CONDITION: if a future collector maps a record that carries
// a `products` id (an updatableAsset or a product-scoped audience), revisit — at
// that point the catalog becomes a join table and earns its keep.
//
// # Cardinality (#112/#114)
//
// The two gauges carry only bounded wire enums: (effective state, requested
// state, catalog entry type) and (auto-enrollment category). Policy and
// deployment ids, audience ids, catalog entry ids, rule evaluation timestamps
// and the whole filter/rule detail are per-entity and ride the twins — one
// intune.windows_update_policy per policy and one
// intune.windows_update_deployment per deployment, every cycle. Guard test.
package windowsupdates

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
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.windows_updates"
	// deploymentsMetricName counts deployments by the state pair plus the kind of
	// update being deployed. A state MISMATCH count falls straight out of it:
	// sum by (deployment_effective_state, deployment_requested_state).
	deploymentsMetricName = "intune.windows_updates.deployments"
	// policiesMetricName counts update policies by auto-enrollment category — a
	// separate metric name, not another dimension on the gauge above, because the
	// two count different entities entirely.
	policiesMetricName = "intune.windows_updates.update_policies"

	policyEventName     = "intune.windows_update_policy"
	deploymentEventName = "intune.windows_update_deployment"

	// defaultBaseURL is the Graph BETA root — see the package doc.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// updatePoliciesPath and deploymentsPath are the two collected segments. No
	// $top: GetAllValues already asks for Graph's largest page via the Prefer
	// header, and an unverified $top is how a paged collector earns a 400
	// (page-size ceilings, docs/graph-api-gotchas.md).
	updatePoliciesPath = "/admin/windows/updates/updatePolicies"
	deploymentsPath    = "/admin/windows/updates/deployments"

	// odataTypePrefix is the namespace every discriminator on this surface
	// carries. It is stripped so the emitted value is the variant name alone;
	// a type outside the namespace is emitted verbatim rather than mangled.
	odataTypePrefix = "#microsoft.graph.windowsUpdates."

	// unknownValue keeps a gauge dimension stable when a row omits one of the
	// bounded enums, rather than emitting an empty label.
	unknownValue = "unknown"
	// noneValue labels the policy gauge series for a policy enrolled in no
	// auto-enrollment category at all — it is still a policy and still counted.
	noneValue = "none"

	// qualityFilterType and qualityCatalogEntryType are the discriminator values
	// whose variant-specific classification/cadence fields exist. Compared
	// against, never assumed from field presence.
	qualityFilterType       = "qualityUpdateFilter"
	qualityCatalogEntryType = "qualityUpdateCatalogEntry"
)

// Collector polls the beta Windows Update for Business deployment service.
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

// DefaultInterval matches the other Intune configuration-posture collectors:
// update policies and deployments change on an administrator's timescale, not a
// minute one.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental reports true: the whole /admin/windows segment exists only on
// Graph beta (#183).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the single read-only least-privilege scope. No
// write scope is involved — both calls are plain GETs.
func (c *Collector) RequiredPermissions() []string {
	return []string{"WindowsUpdates.Read.All"}
}

// Collect reads both segments, aggregates one bounded gauge per segment, and
// emits one twin per row. The segments are INDEPENDENT: a hard failure on one
// still emits the other, and — critically — a failed segment is never
// snapshotted, because GaugeSnapshot replaces the whole series set and an empty
// snapshot would claim the tenant has none of them. A 403 (missing scope, or the
// deployment service not onboarded on this tenant) is a graceful info-level skip
// rather than a collection failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	if raws, ok, err := c.fetch(ctx, updatePoliciesPath); err != nil {
		errs = append(errs, err)
	} else if ok {
		if err := c.collectPolicies(e, raws); err != nil {
			errs = append(errs, err)
		}
	}

	if raws, ok, err := c.fetch(ctx, deploymentsPath); err != nil {
		errs = append(errs, err)
	} else if ok {
		if err := c.collectDeployments(e, raws); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// fetch pages one segment. ok=false with a nil error means "403, skip this
// segment" — the caller must then emit nothing for it, not an empty snapshot.
func (c *Collector) fetch(ctx context.Context, path string) ([]json.RawMessage, bool, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+path, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("windowsupdates: segment forbidden (missing scope?); skipping",
				"collector", collectorName, "path", path, "error", graphclient.FormatODataError(err))
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%s: list %s: %w", collectorName, path, err)
	}
	return raws, true, nil
}

// ---- update policies ----

// updatePolicy is one /admin/windows/updates/updatePolicies row.
type updatePolicy struct {
	ID                             string              `json:"id"`
	CreatedDateTime                string              `json:"createdDateTime"`
	AutoEnrollmentUpdateCategories []string            `json:"autoEnrollmentUpdateCategories"`
	ComplianceChangeRules          []complianceRule    `json:"complianceChangeRules"`
	DeploymentSettings             *deploymentSettings `json:"deploymentSettings"`
	Audience                       *audienceRef        `json:"audience"`
}

// complianceRule is one complianceChangeRules entry. ODataType is the
// discriminator; only contentApprovalRule is live-observed, and any other
// variant still emits its type so an operator sees what arrived.
type complianceRule struct {
	ODataType                     string         `json:"@odata.type"`
	LastEvaluatedDateTime         string         `json:"lastEvaluatedDateTime"`
	DurationBeforeDeploymentStart string         `json:"durationBeforeDeploymentStart"`
	ContentFilter                 *contentFilter `json:"contentFilter"`
}

// contentFilter is a rule's contentFilter. Classification and Cadence exist ONLY
// on the qualityUpdateFilter variant — a driverUpdateFilter carries neither
// (live-measured), and a featureUpdateFilter carries a version instead. They are
// therefore read only when ODataType says quality, never because the JSON
// happened to decode into the field.
type contentFilter struct {
	ODataType      string `json:"@odata.type"`
	Classification string `json:"classification"`
	Cadence        string `json:"cadence"`
}

// deploymentSettings is the policy's deploymentSettings (and a deployment's
// settings — the same type on the wire). Only the sub-objects live rows populate
// are modeled; see the package doc for the deliberate omissions.
type deploymentSettings struct {
	UserExperience       *userExperience       `json:"userExperience"`
	ContentApplicability *contentApplicability `json:"contentApplicability"`
	Expedite             *expediteSettings     `json:"expedite"`
}

// userExperience carries three NULLABLE fields. Every one is a pointer on
// purpose: daysUntilForcedReboot is 0 on the live deployment and null on the
// live policy, and a bare int would publish a fabricated 0 for the null.
type userExperience struct {
	DaysUntilForcedReboot *int  `json:"daysUntilForcedReboot"`
	OfferAsOptional       *bool `json:"offerAsOptional"`
	IsHotpatchEnabled     *bool `json:"isHotpatchEnabled"`
}

type contentApplicability struct {
	OfferWhileRecommendedBy []string `json:"offerWhileRecommendedBy"`
}

type expediteSettings struct {
	IsExpedited     *bool `json:"isExpedited"`
	IsReadinessTest *bool `json:"isReadinessTest"`
}

type audienceRef struct {
	ID string `json:"id"`
}

func (c *Collector) collectPolicies(e telemetry.Emitter, raws []json.RawMessage) error {
	counts := map[string]int64{}
	for _, raw := range raws {
		var p updatePolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("%s: decode update policy: %w", collectorName, err)
		}
		if len(p.AutoEnrollmentUpdateCategories) == 0 {
			counts[noneValue]++
		}
		for _, cat := range p.AutoEnrollmentUpdateCategories {
			counts[orUnknown(cat)]++
		}
		e.LogEvent(policyTwin(p))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrUpdateCategory: k},
		})
	}
	e.GaugeSnapshot(policiesMetricName, "{policy}",
		"Windows Update for Business deployment-service update policies by auto-enrollment update category (quality/driver/feature; `none` for a policy enrolled in none). A policy enrolled in SEVERAL categories counts once in each, so a sum over this metric is not the policy count; per-policy detail — approval rules, content filters, user experience and audience — on the intune.windows_update_policy log twin.",
		points)
	return nil
}

// policyTwin renders one update policy as a log record. The timestamp is left
// zero ("now"): this is a re-emitted configuration snapshot, not an event
// stream, so the policy's own createdDateTime rides as an attribute instead.
//
// Severity is INFO, always. The obvious candidate for a WARN — a rule that has
// never been evaluated — fires on 100% of this tenant's rules (every
// lastEvaluatedDateTime is the .NET zero date on a healthy tenant), so a warning
// there would be noise by construction rather than a signal. The count is
// emitted instead and an operator can alert on it if their tenant behaves
// differently.
func policyTwin(p updatePolicy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realTime(p.CreatedDateTime))
	telemetry.SetStrs(attrs, semconv.AttrAutoEnrollmentUpdateCategories, p.AutoEnrollmentUpdateCategories)
	if p.Audience != nil {
		telemetry.SetStr(attrs, semconv.AttrAudienceId, p.Audience.ID)
	}

	var ruleTypes, filterTypes, classifications, cadences, delays, evaluated []string
	neverEvaluated := 0
	for _, r := range p.ComplianceChangeRules {
		ruleTypes = append(ruleTypes, odataShortType(r.ODataType))
		if d := r.DurationBeforeDeploymentStart; d != "" {
			delays = append(delays, d)
		}
		if ts := realTime(r.LastEvaluatedDateTime); ts != "" {
			evaluated = append(evaluated, ts)
		} else {
			neverEvaluated++
		}
		if r.ContentFilter == nil {
			continue
		}
		ft := odataShortType(r.ContentFilter.ODataType)
		filterTypes = append(filterTypes, ft)
		// Discriminator, not field presence: only the quality variant HAS these.
		if ft == qualityFilterType {
			if v := r.ContentFilter.Classification; v != "" {
				classifications = append(classifications, v)
			}
			if v := r.ContentFilter.Cadence; v != "" {
				cadences = append(cadences, v)
			}
		}
	}
	telemetry.SetStrs(attrs, semconv.AttrComplianceChangeRuleTypes, ruleTypes)
	telemetry.SetStrs(attrs, semconv.AttrContentFilterTypes, filterTypes)
	telemetry.SetStrs(attrs, semconv.AttrContentFilterClassifications, classifications)
	telemetry.SetStrs(attrs, semconv.AttrContentFilterCadences, cadences)
	telemetry.SetStrs(attrs, semconv.AttrDeploymentStartDelays, delays)
	telemetry.SetStrs(attrs, semconv.AttrRuleLastEvaluatedDateTimes, evaluated)
	if len(p.ComplianceChangeRules) > 0 {
		attrs[semconv.AttrRulesNeverEvaluated] = int64(neverEvaluated)
	}

	setSettings(attrs, p.DeploymentSettings)

	return telemetry.Event{
		Name: policyEventName,
		Body: fmt.Sprintf("windows update policy %s: auto_enrollment=%s rules=%d",
			orUnknown(p.ID), strings.Join(p.AutoEnrollmentUpdateCategories, ","), len(p.ComplianceChangeRules)),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// ---- deployments ----

// deployment is one /admin/windows/updates/deployments row.
type deployment struct {
	ID                   string              `json:"id"`
	CreatedDateTime      string              `json:"createdDateTime"`
	LastModifiedDateTime string              `json:"lastModifiedDateTime"`
	State                *deploymentState    `json:"state"`
	Content              *deploymentContent  `json:"content"`
	Settings             *deploymentSettings `json:"settings"`
	Audience             *audienceRef        `json:"audience"`
}

// deploymentState is the three-part state object. Reasons is json.RawMessage
// because it is EMPTY on every live row — see stateReasons.
type deploymentState struct {
	EffectiveValue string          `json:"effectiveValue"`
	RequestedValue string          `json:"requestedValue"`
	Reasons        json.RawMessage `json:"reasons"`
}

type deploymentContent struct {
	ODataType    string        `json:"@odata.type"`
	CatalogEntry *catalogEntry `json:"catalogEntry"`
}

// catalogEntry is the polymorphic update being deployed. QualityUpdate* exist
// ONLY on the qualityUpdateCatalogEntry variant and are read only when the
// discriminator says so.
type catalogEntry struct {
	ODataType                   string `json:"@odata.type"`
	ID                          string `json:"id"`
	DisplayName                 string `json:"displayName"`
	ReleaseDateTime             string `json:"releaseDateTime"`
	IsExpeditable               *bool  `json:"isExpeditable"`
	QualityUpdateClassification string `json:"qualityUpdateClassification"`
	QualityUpdateCadence        string `json:"qualityUpdateCadence"`
}

func (c *Collector) collectDeployments(e telemetry.Emitter, raws []json.RawMessage) error {
	counts := map[[3]string]int64{}
	for _, raw := range raws {
		var d deployment
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("%s: decode deployment: %w", collectorName, err)
		}
		effective, requested := unknownValue, unknownValue
		if d.State != nil {
			effective = orUnknown(d.State.EffectiveValue)
			requested = orUnknown(d.State.RequestedValue)
		}
		entryType := unknownValue
		if d.Content != nil && d.Content.CatalogEntry != nil {
			entryType = orUnknown(odataShortType(d.Content.CatalogEntry.ODataType))
		}
		counts[[3]string{effective, requested, entryType}]++
		e.LogEvent(deploymentTwin(d))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrDeploymentEffectiveState: k[0],
				semconv.AttrDeploymentRequestedState: k[1],
				semconv.AttrCatalogEntryType:         k[2],
			},
		})
	}
	e.GaugeSnapshot(deploymentsMetricName, "{deployment}",
		"Windows Update for Business deployments by EFFECTIVE state, REQUESTED state and the kind of catalog entry being deployed. The two states are separate dimensions because they disagree in the interesting case — a series where they differ is a deployment not doing what was asked; per-deployment detail, including the reasons the effective state differs, on the intune.windows_update_deployment log twin.",
		points)
	return nil
}

// deploymentTwin renders one deployment as a log record, with the timestamp left
// zero for the same reason as policyTwin.
//
// Severity is WARN when the effective state and the requested state are both
// known and DISAGREE — the "the ring is not doing what you asked" case this
// collector exists for. When either side is absent the twin claims nothing:
// INFO, and the derived matches-request attribute is omitted entirely, because a
// missing value can prove neither agreement nor disagreement.
func deploymentTwin(d deployment) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeploymentId, d.ID)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realTime(d.CreatedDateTime))
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, realTime(d.LastModifiedDateTime))
	if d.Audience != nil {
		telemetry.SetStr(attrs, semconv.AttrAudienceId, d.Audience.ID)
	}

	effective, requested := "", ""
	severity := telemetry.SeverityInfo
	if d.State != nil {
		effective, requested = d.State.EffectiveValue, d.State.RequestedValue
		telemetry.SetStr(attrs, semconv.AttrDeploymentEffectiveState, effective)
		telemetry.SetStr(attrs, semconv.AttrDeploymentRequestedState, requested)
		telemetry.SetStrs(attrs, semconv.AttrDeploymentStateReasons, stateReasons(d.State.Reasons))
		if effective != "" && requested != "" {
			matches := strings.EqualFold(effective, requested)
			telemetry.SetBool(attrs, semconv.AttrDeploymentStateMatchesRequest, matches)
			if !matches {
				severity = telemetry.SeverityWarn
			}
		}
	}

	if d.Content != nil {
		telemetry.SetStr(attrs, semconv.AttrUpdateContentType, odataShortType(d.Content.ODataType))
		if ce := d.Content.CatalogEntry; ce != nil {
			entryType := odataShortType(ce.ODataType)
			telemetry.SetStr(attrs, semconv.AttrCatalogEntryType, entryType)
			// The live row sends "" here; SetStr omits it, which is the point.
			telemetry.SetStr(attrs, semconv.AttrCatalogEntryId, ce.ID)
			telemetry.SetStr(attrs, semconv.AttrDisplayName, ce.DisplayName)
			telemetry.SetStr(attrs, semconv.AttrUpdateReleaseDateTime, realTime(ce.ReleaseDateTime))
			if ce.IsExpeditable != nil {
				telemetry.SetBool(attrs, semconv.AttrIsExpeditable, *ce.IsExpeditable)
			}
			// Discriminator, not field presence.
			if entryType == qualityCatalogEntryType {
				telemetry.SetStr(attrs, semconv.AttrUpdateClassification, ce.QualityUpdateClassification)
				telemetry.SetStr(attrs, semconv.AttrUpdateCadence, ce.QualityUpdateCadence)
			}
		}
	}

	setSettings(attrs, d.Settings)

	return telemetry.Event{
		Name: deploymentEventName,
		Body: fmt.Sprintf("windows update deployment %s: effective=%s requested=%s",
			orUnknown(d.ID), orUnknown(effective), orUnknown(requested)),
		Severity: severity,
		Attrs:    attrs,
	}
}

// ---- shared mapping helpers ----

// setSettings maps the deploymentSettings sub-objects shared by a policy
// (deploymentSettings) and a deployment (settings) — the same wire type in both
// places. Every field is nullable and every absent one is omitted rather than
// defaulted, so "not configured" never renders as false or 0.
func setSettings(attrs telemetry.Attrs, s *deploymentSettings) {
	if s == nil {
		return
	}
	if ux := s.UserExperience; ux != nil {
		if ux.DaysUntilForcedReboot != nil {
			attrs[semconv.AttrDaysUntilForcedReboot] = int64(*ux.DaysUntilForcedReboot)
		}
		if ux.OfferAsOptional != nil {
			telemetry.SetBool(attrs, semconv.AttrOfferAsOptional, *ux.OfferAsOptional)
		}
		if ux.IsHotpatchEnabled != nil {
			telemetry.SetBool(attrs, semconv.AttrIsHotpatchEnabled, *ux.IsHotpatchEnabled)
		}
	}
	if ca := s.ContentApplicability; ca != nil {
		telemetry.SetStrs(attrs, semconv.AttrOfferWhileRecommendedBy, ca.OfferWhileRecommendedBy)
	}
	if ex := s.Expedite; ex != nil {
		if ex.IsExpedited != nil {
			telemetry.SetBool(attrs, semconv.AttrIsExpedited, *ex.IsExpedited)
		}
		if ex.IsReadinessTest != nil {
			telemetry.SetBool(attrs, semconv.AttrIsReadinessTest, *ex.IsReadinessTest)
		}
	}
}

// odataShortType strips the windowsUpdates namespace off a discriminator so the
// emitted value is the variant name alone ("qualityUpdateFilter"). A type from
// some other namespace is returned VERBATIM rather than half-parsed — an
// unrecognized discriminator is information, and mangling it would hide the one
// thing an operator needs to see when this surface grows a variant.
func odataShortType(t string) string {
	if s, ok := strings.CutPrefix(t, odataTypePrefix); ok {
		return s
	}
	return t
}

// stateReasons decodes state.reasons, which is EMPTY on every live row and whose
// populated shape is therefore unverified. Graph beta returns such collections
// both as objects carrying a `value` and as bare enum strings, so both decode,
// and ANY other shape yields nil (attribute omitted) rather than failing the
// row — which would drop the whole deployment collection on a tenant where the
// field is populated. The tolerance is deliberate: a field whose shape is known
// only from an EMPTY array is not a field whose shape is known.
func stateReasons(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var objs []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &objs); err == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.Value != "" {
				out = append(out, o.Value)
			}
		}
		return out
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	return nil
}

// zeroDateYear is the year of the .NET DateTime zero value. Graph serializes an
// unset timestamp on this surface as "0001-01-01T00:00:00Z" (and the same
// instant with a fractional part or an offset), which means "never", not an
// event in the year 1.
const zeroDateYear = 1

// realTime returns s when it parses as a timestamp AFTER the .NET zero date, and
// "" otherwise — so an unset, unparseable or zero timestamp omits its attribute
// instead of publishing a fabricated one. The check is on the PARSED year rather
// than a string compare, so every serialization of the zero instant is caught,
// not just the one shape this tenant happened to send.
func realTime(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	if t.UTC().Year() <= zeroDateYear {
		return ""
	}
	return s
}

// orUnknown keeps a bounded gauge dimension from ever carrying an empty label.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing
// scope, or the deployment service not onboarded on this tenant) rather than a
// collection failure.
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
