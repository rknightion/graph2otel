// Package accessreviews is the Entra ID Governance access-review DEFINITION
// inventory (#260). An access review that is created and then never completed is
// a governance control that looks present and does nothing — the same failure
// shape as a disabled alert rule — and nothing else graph2otel ships can see it.
//
// One fetch of /identityGovernance/accessReviews/definitions produces both sides
// of the cardinality boundary (#112/#114): a bounded gauge counting definitions
// by `status`, and one entra.access_review log twin per definition carrying the
// per-review detail — display name, descriptions, timestamps, the scope's shape
// and queries, reviewer identities, cadence, and the governance settings.
//
// # v1.0, deliberately, and what beta returns that v1.0 does not
//
// The endpoint answers on BOTH v1.0 and beta (200/200, live 2026-07-24), so this
// collector reads v1.0 and carries NO Experimental gate — that interface is
// reserved for genuine Graph beta surfaces (#183).
//
// The two responses are not identical, which matters more than it sounds. Beta
// additionally returns `backupReviewers`, `customData` and `customDataProvider`;
// v1.0 omits all three, and beta's `settings` carries an extra
// `isAgenticExperienceEnabled`. Nothing here maps them: a count derived from a
// field the chosen endpoint never sends would publish a fabricated zero, which is
// the "an absent field is not a sentinel" failure this repo has already shipped
// once.
//
// # The instances decision: RESOLVED (#319) — the non-inline route works
//
// #260 left the definition inventory as an explicit residual: the INLINE
// `instances` nav property on the definitions list came back an EMPTY ARRAY on
// both v1.0 and beta for a definition whose status was InProgress
// (live-measured 2026-07-24), so its length was never a fact about the review.
// That inline-array finding still holds and this collector still never reads
// `instances` off the definitions response.
//
// What has changed (live-probed 2026-07-28, read-only, `AccessReview.Read.All`,
// no new scope) is that the NON-inline, separately-fetched route answers fully:
//
//	GET .../definitions/{id}/instances                    -> 200
//	GET .../definitions/{id}/instances/{iid}/decisions    -> 200
//
// both around 0.2s per request. This collector now fans out into both: one
// `instances` fetch per definition, then one `decisions` fetch per instance —
// bounded by maxDefinitions/maxInstancesPerDefinition/maxDecisionsPerInstance
// below — and reports the bounded aggregate (entra.access_reviews.instances,
// entra.access_reviews.decisions) plus one twin per instance
// (entra.access_review_instance) and one per decision
// (entra.access_review_decision). This is what finally answers "is this review
// being completed" — the definition inventory alone never could.
//
// contactedReviewers (`.../instances/{iid}/contactedReviewers`) was ALSO
// probed live and answers 200, but is deliberately NOT fetched here: nothing in
// #319 named a metric or a twin attribute for it, so fetching it would be a
// request this collector pays for and then discards. Left for a future issue
// if a concrete signal is specified.
//
// # Three sentinels on a decision record (live-measured 2026-07-28, #319)
//
//   - `reviewedBy`/`appliedBy` arrive as a FULLY POPULATED object whose `id` is
//     the zero GUID (`00000000-0000-0000-0000-000000000000`) on an undecided
//     decision — not null, not absent. Treated as ABSENT: the id (and, for
//     reviewedBy, the display name) are omitted rather than mapped through,
//     because a real id would publish a reviewer that does not exist.
//   - `reviewedDateTime`/`appliedDateTime` are JSON `null` on an undecided
//     decision — omitted, never zero-stamped.
//   - `principal.lastUserSignInDateTime` is an EMPTY STRING when unknown, never
//     null — a presence (non-nil) check would miss it; telemetry.SetStr's own
//     empty-string omission is what actually protects this one.
//
// # Severity ladder — decisions and instances both now judge staleness
//
// Unlike the definition twin (still purely descriptive — see below), the
// instance and decision twins DO judge: an expired instance or an
// expired-and-never-reviewed decision is exactly the failure #319 exists to
// surface, and by this point real per-instance/per-decision state is fetched,
// so the judgement is honest.
//
//   - Decision twin: WARN when the owning instance's `endDateTime` is in the
//     past AND `decision` is still "NotReviewed" — the review expired without
//     being done. INFO otherwise.
//   - Instance twin: WARN when `status` is "InProgress" AND `endDateTime` is in
//     the past. INFO otherwise.
//
// "Now" comes from the Collector's `now` field (defaults to time.Now, overridden
// in tests) so severity is never wall-clock-dependent in a fixture.
//
// # Definition severity ladder (unchanged from #260)
//
//   - WARN — `settings.mailNotificationsEnabled` and
//     `settings.reminderNotificationsEnabled` are BOTH false. Reviewers are never
//     told the review exists and never reminded, so completion depends entirely
//     on someone remembering. This is the one "control exists but does nothing"
//     condition visible in the definition alone, with no instance data needed.
//   - INFO — everything else, including every status value. A status is reported,
//     never judged: see the wirecheck note below.
//
// A definition with no `settings` block at all stays INFO — a missing block is
// not evidence of a broken control — but it is announced through wirecheck,
// because otherwise the WARN rung would silently stop working the day Graph
// stopped sending settings.
//
// # Independent degradation and the #240 rule
//
// Each definition's `instances` fetch, and each instance's `decisions` fetch,
// can fail without losing the rest of the poll (errors.Join, same pattern the
// rest of this package already uses). A definition whose instances fetch fails
// is OMITTED from entra.access_reviews.instances entirely for that cycle — it
// is never counted as zero, because a failed read is a gap, not a measurement
// (#240). The same holds one level down: an instance whose decisions fetch
// fails still gets its instance twin (instance-level facts are known), but
// contributes nothing to entra.access_reviews.decisions and gets no decision
// twins that cycle.
//
// # Bounding the fan-out
//
// maxDefinitions/maxInstancesPerDefinition/maxDecisionsPerInstance (below) cap
// the fan-out breadth. A cap that truncates is logged, and where a twin exists
// to carry it also stamps semconv.AttrArraysTruncated:
//
//   - maxDecisionsPerInstance stamps the OWNING instance twin — "how many
//     decisions we processed for this instance" is a fact about that instance.
//   - maxInstancesPerDefinition has no single owning instance, so every
//     SURVIVING instance twin under the affected definition is stamped: each
//     one is a member of a set this collector knows was cut short.
//   - maxDefinitions is logged only. It bounds which DEFINITIONS get an
//     instances fetch at all, before any instance twin exists to carry the
//     mark, and the existing definition twin is frozen (see the top of this
//     file) — there is no entity left to stamp.
//
// # wirecheck: `scope_type` watched, three new closed enums NOT
//
// `scope` is polymorphic and its @odata.type is read as the discriminator (as is
// `settings.applyActions`), never decoded structurally. The watched Enum is
// derived from the exact set of discriminators this collector extracts queries
// from, so it can only fire on a hole in THIS collector's mapping — never on
// correct data (#234's rule). The same scope-reading code and Enum are reused
// for an instance's scope: it is the identical polymorphic shape.
//
// `status` (definition and instance), `decision`, `applied_result` and
// `recommendation` are all left UNWATCHED, for the same #234 reason: every
// value seen so far ("InProgress"; "NotReviewed"; "New"; "Deny"/"Approve") comes
// from ONE tenant's one review instance. A closed Enum needs evidence that the
// full value SET is known, and one tenant's sample — however many distinct
// values it happens to contain — is not that. Declare wirecheck coverage once a
// second tenant (or a value outside this set) has been seen live, not before.
package accessreviews

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
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.access_reviews"

// metricReviews counts access-review definitions by status. Bounded by the
// number of reviews a tenant configures, which is governance-config-shaped
// rather than tenant-size-shaped.
const metricReviews = "entra.access_reviews.total"

// eventReview is the per-definition log twin (#114).
const eventReview = "entra.access_review"

// metricInstances counts access-review INSTANCES (a definition's recurrences)
// by status (#319). Bounded by maxDefinitions x maxInstancesPerDefinition, a
// fan-out breadth this collector itself caps.
const metricInstances = "entra.access_reviews.instances"

// metricDecisions counts reviewer DECISIONS by decision x applied_result
// (#319) — both closed Graph enums. Deliberately not also broken out by
// recommendation: that would be a third label answering a question a LogQL
// `count by` over the twin already answers, tripling the series for it.
const metricDecisions = "entra.access_reviews.decisions"

// eventInstance is the per-instance log twin (#114, #319).
const eventInstance = "entra.access_review_instance"

// eventDecision is the per-decision log twin (#114, #319).
const eventDecision = "entra.access_review_decision"

// defaultBaseURL is the Graph v1.0 root — see the package doc on why this is
// not beta.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// definitionsPath lists the tenant's access-review definitions.
const definitionsPath = "/identityGovernance/accessReviews/definitions"

// zeroGUID is the sentinel Graph sends for reviewedBy/appliedBy on an
// undecided decision: a FULLY POPULATED identity object whose id is all
// zeroes rather than a null object or an absent key (live-measured
// 2026-07-28, #319). Treated as absent — see the package doc's sentinel
// section.
const zeroGUID = "00000000-0000-0000-0000-000000000000"

// The fan-out bounds for the instances/decisions walk (#319). Each is a
// breadth cap on requests fired, chosen against the live-measured ~0.2s cost
// per request (definitions, instances and decisions endpoints alike):
//
//   - maxDefinitions caps how many definitions get an instances fetch at all.
//     200 definitions x 0.2s = 40s worst case for this layer alone — far more
//     than any tenant's review-definition count (governance config, not
//     tenant-size-shaped), while still bounding a pathological tenant.
//   - maxInstancesPerDefinition caps how many instances of ONE definition get a
//     decisions fetch. 50 x 0.2s = 10s worst case per definition — an
//     absoluteMonthly review keeps at most ~4 open instances a year, so 50 is
//     over a decade of headroom.
//   - maxDecisionsPerInstance caps how many decision records ONE instance's
//     (already-paginated) decisions response contributes as twins. Unlike the
//     two above, this does not cost an extra request per unit — it bounds
//     memory/twin volume on a review scoped to a very large principal set.
//     5000 covers a large-tenant "review every user" instance with headroom.
const (
	maxDefinitions            = 200
	maxInstancesPerDefinition = 50
	maxDecisionsPerInstance   = 5000
)

// fieldSettings names the `settings` block in wirecheck findings. It is a wire
// field name, not an emitted attribute key, so it is a local const rather than a
// semconv constant.
const fieldSettings = "settings"

// odataPrefix is the namespace every @odata.type discriminator carries.
const odataPrefix = "#microsoft.graph."

// The scope discriminators this collector extracts queries from.
const (
	scopeTypePrincipalResourceMemberships = "principalResourceMembershipsScope"
	scopeTypeQuery                        = "accessReviewQueryScope"
)

// mappedScopeTypes is the wirecheck Enum for `scope_type`, DERIVED from the two
// constants the switch in scopeAttrs handles. Keeping the watched set and the
// mapped set the same thing means the watchdog fires exactly when a scope shape
// arrives that this collector does not extract queries from — a real hole — and
// can never fire on a shape it does handle (#234).
var mappedScopeTypes = wirecheck.NewEnum(scopeTypePrincipalResourceMemberships, scopeTypeQuery)

// accessReviewScheduleDefinition is the subset of a definition this collector
// reads.
//
// Scalars that are optional-but-meaningful are POINTERS so "the wire said false"
// stays distinct from "the wire said nothing": a bare bool would publish a
// fabricated false for a field Graph simply did not send.
type accessReviewScheduleDefinition struct {
	ID                               string            `json:"id"`
	DisplayName                      string            `json:"displayName"`
	Status                           string            `json:"status"`
	CreatedDateTime                  string            `json:"createdDateTime"`
	LastModifiedDateTime             string            `json:"lastModifiedDateTime"`
	DescriptionForAdmins             string            `json:"descriptionForAdmins"`
	DescriptionForReviewers          string            `json:"descriptionForReviewers"`
	CreatedBy                        *userIdentity     `json:"createdBy"`
	Scope                            *scope            `json:"scope"`
	Reviewers                        []reviewerScope   `json:"reviewers"`
	FallbackReviewers                []reviewerScope   `json:"fallbackReviewers"`
	AdditionalNotificationRecipients []json.RawMessage `json:"additionalNotificationRecipients"`
	StageSettings                    []json.RawMessage `json:"stageSettings"`
	Settings                         *settings         `json:"settings"`
}

// userIdentity is createdBy. Every string here can arrive EMPTY while ID is set
// (live-measured 2026-07-24) — Graph does not resolve the principal — so each is
// stamped through telemetry.SetStr, which omits an empty value.
type userIdentity struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Type              string `json:"type"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// scope is the polymorphic accessReviewScope. Every member of every known
// concrete shape is declared here, but which of them is READ is decided by
// ODataType alone — never by "whichever field happens to be non-empty".
type scope struct {
	ODataType       string          `json:"@odata.type"`
	Query           string          `json:"query"`
	PrincipalScopes []reviewerScope `json:"principalScopes"`
	ResourceScopes  []reviewerScope `json:"resourceScopes"`
}

// reviewerScope is an accessReviewReviewerScope / accessReviewQueryScope: a
// Graph URL naming a principal or a resource set. `queryType` and `queryRoot`
// are not read — the query string carries the meaning, and queryType was
// uniformly "MicrosoftGraph" on the wire.
type reviewerScope struct {
	Query string `json:"query"`
}

// settings is accessReviewScheduleSettings — the knobs that decide whether a
// review can change anything.
type settings struct {
	MailNotificationsEnabled        *bool             `json:"mailNotificationsEnabled"`
	ReminderNotificationsEnabled    *bool             `json:"reminderNotificationsEnabled"`
	JustificationRequiredOnApproval *bool             `json:"justificationRequiredOnApproval"`
	DefaultDecisionEnabled          *bool             `json:"defaultDecisionEnabled"`
	DefaultDecision                 string            `json:"defaultDecision"`
	InstanceDurationInDays          *int64            `json:"instanceDurationInDays"`
	AutoApplyDecisionsEnabled       *bool             `json:"autoApplyDecisionsEnabled"`
	RecommendationsEnabled          *bool             `json:"recommendationsEnabled"`
	Recurrence                      *recurrence       `json:"recurrence"`
	ApplyActions                    []applyActionType `json:"applyActions"`
}

// applyActionType is one accessReviewApplyAction — a polymorphic member whose
// ONLY interesting content is its discriminator (removeAccessApplyAction and
// friends carry no other fields).
type applyActionType struct {
	ODataType string `json:"@odata.type"`
}

// recurrence is the patternedRecurrence describing the review's cadence.
type recurrence struct {
	Pattern *struct {
		Type     string `json:"type"`
		Interval *int64 `json:"interval"`
	} `json:"pattern"`
	Range *struct {
		Type      string `json:"type"`
		StartDate string `json:"startDate"`
		// EndDate is deliberately NOT decoded: it is "9999-12-31" for a
		// never-ending recurrence, a sentinel rather than a date, and Type
		// already says "noEnd".
	} `json:"range"`
}

// accessReviewInstance is one recurrence of a definition (#319). Scope and
// reviewers reuse the exact same polymorphic shapes the definition already
// declares — Graph returns them identically on both endpoints.
type accessReviewInstance struct {
	ID                string          `json:"id"`
	StartDateTime     string          `json:"startDateTime"`
	EndDateTime       string          `json:"endDateTime"`
	Status            string          `json:"status"`
	Scope             *scope          `json:"scope"`
	Reviewers         []reviewerScope `json:"reviewers"`
	FallbackReviewers []reviewerScope `json:"fallbackReviewers"`
}

// accessReviewDecision is one reviewer decision on one principal within one
// instance (#319). ReviewedDateTime/AppliedDateTime are pointers because they
// arrive as JSON null on an undecided decision — a plain string would collapse
// "null" and "unparseable" into the same empty value; a pointer keeps "the
// wire sent null" honest and unambiguous to omit.
type accessReviewDecision struct {
	ID               string             `json:"id"`
	ReviewedDateTime *string            `json:"reviewedDateTime"`
	Decision         string             `json:"decision"`
	Justification    string             `json:"justification"`
	AppliedDateTime  *string            `json:"appliedDateTime"`
	ApplyResult      string             `json:"applyResult"`
	Recommendation   string             `json:"recommendation"`
	PrincipalLink    string             `json:"principalLink"`
	ResourceLink     string             `json:"resourceLink"`
	ReviewedBy       *userIdentity      `json:"reviewedBy"`
	AppliedBy        *userIdentity      `json:"appliedBy"`
	Resource         *decisionResource  `json:"resource"`
	Principal        *decisionPrincipal `json:"principal"`
}

// decisionResource is the access being reviewed (a directory role, in the
// live sample).
type decisionResource struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
}

// decisionPrincipal is the reviewed principal. LastUserSignInDateTime is an
// EMPTY STRING (never null) when unknown — telemetry.SetStr's own
// empty-string omission is what makes that safe to map without a special case
// (see the package doc's sentinel section).
type decisionPrincipal struct {
	ODataType              string `json:"@odata.type"`
	ID                     string `json:"id"`
	DisplayName            string `json:"displayName"`
	Type                   string `json:"type"`
	UserPrincipalName      string `json:"userPrincipalName"`
	LastUserSignInDateTime string `json:"lastUserSignInDateTime"`
}

// Collector polls the tenant's access-review definitions, instances and
// decisions.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
	// now returns the instant instance/decision expiry is judged against.
	// Defaults to time.Now; tests override it for a deterministic severity
	// ladder — see the package doc's "never wall-clock-dependent" note.
	now func() time.Time
}

// New builds the access-reviews collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, watch: wirecheck.New(collectorName, logger), now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. A review definition is
// governance configuration: it is created once and its status moves at the pace
// of a quarterly cadence, so an hourly read is already far faster than the thing
// it watches.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the single least-privilege application scope
// (granted on the live tenant 2026-07-24, #251).
//
// There is deliberately no license.CapabilityRequirer here. #251's scope table
// predicted this endpoint would need an Entra ID Governance license for any data
// to exist; the live tenant returned a review anyway, so gating the whole
// collector on a capability would skip it where it demonstrably works. A tenant
// that genuinely cannot use it 403s, which Collect treats as a graceful skip.
func (c *Collector) RequiredPermissions() []string {
	return []string{"AccessReview.Read.All"}
}

// Collect fetches every access-review definition and emits both halves from that
// one fetch: the bounded per-status gauge and one twin per definition. A 403 is a
// graceful info-skip (no governance feature, or the scope not consented); a bad
// row is skipped with its error aggregated rather than taking the poll down.
//
// It then fans out into each definition's instances, and each instance's
// decisions (#319), bounded by maxDefinitions/maxInstancesPerDefinition/
// maxDecisionsPerInstance and independently degrading per definition/instance
// — see the package doc for the #240 "a failed read is a gap, never a zero"
// rule this loop follows throughout.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+definitionsPath, nil, outcomes)
	if err != nil {
		if isForbidden(err) {
			outcomes.Cause(recordoutcome.CausePermissionDenied)
			c.logger.Info("skipping access reviews: endpoint returned 403 (governance feature or scope unavailable on this tenant)",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("fetch access review definitions: %w", err)
	}

	byStatus := map[string]int64{}
	var errs []error
	var definitionIDs []string
	for _, raw := range raws {
		var d accessReviewScheduleDefinition
		if err := json.Unmarshal(raw, &d); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			errs = append(errs, fmt.Errorf("decode access review definition: %w", err))
			continue
		}
		if d.ID == "" {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			c.logger.Warn("access reviews: skipping definition with empty id", "collector", collectorName)
			continue
		}
		byStatus[d.Status]++
		e.LogEvent(c.twin(e, d))
		entraoutcome.Emitted(outcomes, 1)
		definitionIDs = append(definitionIDs, d.ID)
	}

	points := make([]telemetry.GaugePoint, 0, len(byStatus))
	for status, n := range byStatus {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrStatus: status},
		})
	}
	e.GaugeSnapshot(metricReviews, "{review}",
		"Entra access-review definitions configured for the tenant, by review status.", points)

	fanoutIDs, defsTruncated := capSlice(definitionIDs, maxDefinitions)
	if defsTruncated {
		c.logger.Warn("access reviews: instances fan-out capped",
			"collector", collectorName, "limit", maxDefinitions, "definitions", len(definitionIDs))
	}

	instanceCounts := map[string]int64{}
	decisionCounts := map[[2]string]int64{}
	for _, definitionID := range fanoutIDs {
		if err := c.collectInstances(ctx, e, outcomes, definitionID, instanceCounts, decisionCounts); err != nil {
			errs = append(errs, err)
		}
	}

	instancePoints := make([]telemetry.GaugePoint, 0, len(instanceCounts))
	for status, n := range instanceCounts {
		instancePoints = append(instancePoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrStatus: status},
		})
	}
	e.GaugeSnapshot(metricInstances, "{instance}",
		"Entra access-review instances (recurrences), by instance status. A definition whose instances "+
			"fetch failed is omitted this cycle, never counted as zero.", instancePoints)

	decisionPoints := make([]telemetry.GaugePoint, 0, len(decisionCounts))
	for k, n := range decisionCounts {
		decisionPoints = append(decisionPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrDecision: k[0], semconv.AttrAppliedResult: k[1]},
		})
	}
	e.GaugeSnapshot(metricDecisions, "{decision}",
		"Entra access-review reviewer decisions, by decision and applied result. An instance whose "+
			"decisions fetch failed contributes nothing this cycle, never a fabricated zero.", decisionPoints)

	return errors.Join(errs...)
}

// collectInstances fetches one definition's instances, bounds them at
// maxInstancesPerDefinition, and for each surviving instance fetches its
// decisions and emits the instance twin. A fetch failure here means the
// definition contributes NOTHING to instanceCounts/decisionCounts this cycle
// (#240) — it is returned as an error so the caller's outcome/error surface
// sees it, but does not stop sibling definitions from being processed.
func (c *Collector) collectInstances(
	ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder,
	definitionID string, instanceCounts map[string]int64, decisionCounts map[[2]string]int64,
) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+definitionsPath+"/"+definitionID+"/instances", nil, outcomes)
	if err != nil {
		c.logger.Warn("access reviews: instances fetch failed, omitting definition from the instances gauge this cycle",
			"collector", collectorName, "definition_id", definitionID, "error", err)
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("fetch instances for definition %s: %w", definitionID, err)
	}

	var instances []accessReviewInstance
	for _, raw := range raws {
		var inst accessReviewInstance
		if err := json.Unmarshal(raw, &inst); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("access reviews: skipping unparseable instance",
				"collector", collectorName, "definition_id", definitionID, "error", err)
			continue
		}
		if inst.ID == "" {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			continue
		}
		instances = append(instances, inst)
	}

	capped, truncated := capSlice(instances, maxInstancesPerDefinition)
	if truncated {
		c.logger.Warn("access reviews: instances truncated for definition",
			"collector", collectorName, "definition_id", definitionID,
			"limit", maxInstancesPerDefinition, "total", len(instances))
	}

	var errs []error
	for _, inst := range capped {
		decisionsTruncated, err := c.collectDecisions(ctx, e, outcomes, definitionID, inst, decisionCounts)
		if err != nil {
			errs = append(errs, err)
		}
		instanceCounts[inst.Status]++
		// Every survivor is stamped when the INSTANCE LIST itself was
		// truncated (no single owning instance for that fact), OR'd with this
		// one instance's own decisions truncation.
		e.LogEvent(c.instanceTwin(e, definitionID, inst, truncated || decisionsTruncated))
		entraoutcome.Emitted(outcomes, 1)
	}
	return errors.Join(errs...)
}

// collectDecisions fetches one instance's decisions, bounds them at
// maxDecisionsPerInstance, and emits one decision twin per surviving row. A
// fetch failure means the instance contributes nothing to decisionCounts this
// cycle (#240) but the instance twin is still emitted by the caller — the
// instance's own facts are known even when its decisions are not.
func (c *Collector) collectDecisions(
	ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder,
	definitionID string, inst accessReviewInstance, decisionCounts map[[2]string]int64,
) (truncated bool, err error) {
	raws, err := collectors.GetAllValuesRecorded(
		ctx, c.g, c.baseURL+definitionsPath+"/"+definitionID+"/instances/"+inst.ID+"/decisions", nil, outcomes)
	if err != nil {
		c.logger.Warn("access reviews: decisions fetch failed, instance emitted without decisions this cycle",
			"collector", collectorName, "definition_id", definitionID, "instance_id", inst.ID, "error", err)
		entraoutcome.SourceError(outcomes)
		return false, fmt.Errorf("fetch decisions for instance %s: %w", inst.ID, err)
	}

	capped, truncated := capSlice(raws, maxDecisionsPerInstance)
	if truncated {
		c.logger.Warn("access reviews: decisions truncated for instance",
			"collector", collectorName, "instance_id", inst.ID,
			"limit", maxDecisionsPerInstance, "total", len(raws))
	}

	instanceExpired := c.isExpired(inst.EndDateTime)
	for _, raw := range capped {
		var dec accessReviewDecision
		if err := json.Unmarshal(raw, &dec); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("access reviews: skipping unparseable decision",
				"collector", collectorName, "instance_id", inst.ID, "error", err)
			continue
		}
		if dec.ID == "" {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			continue
		}
		decisionCounts[[2]string{dec.Decision, dec.ApplyResult}]++
		e.LogEvent(decisionTwin(definitionID, inst.ID, dec, instanceExpired))
		entraoutcome.Emitted(outcomes, 1)
	}
	return truncated, nil
}

// isExpired reports whether a Graph timestamp is unparseable-safe-false or in
// the past relative to c.now. An unparseable timestamp is treated as "not
// expired" — a WARN must never fire from a value this collector could not
// even read.
func (c *Collector) isExpired(raw string) bool {
	t, ok := parseGraphTime(raw)
	return ok && t.Before(c.now())
}

// parseGraphTime parses a Graph RFC3339 timestamp, trying the fractional-second
// form first (the shape every live sample here uses) and falling back to bare
// RFC3339.
func parseGraphTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// capSlice caps vals at maxLen, reporting whether it had to. Never mutates
// vals — the returned slice on the truncated path is a fresh subslice header
// (agentgovernance's capStrings pattern, generalized).
func capSlice[T any](vals []T, maxLen int) (out []T, truncated bool) {
	if len(vals) > maxLen {
		return vals[:maxLen:maxLen], true
	}
	return vals, false
}

// twin renders one definition as a log record. It takes the emitter because the
// wirecheck reporter counts through it — the scope discriminator is checked here,
// where the mapping decision is made.
func (c *Collector) twin(e telemetry.Emitter, d accessReviewScheduleDefinition) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, d.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, d.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrStatus, d.Status)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, d.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, d.LastModifiedDateTime)
	telemetry.SetStr(attrs, semconv.AttrDescriptionForAdmins, d.DescriptionForAdmins)
	telemetry.SetStr(attrs, semconv.AttrDescriptionForReviewers, d.DescriptionForReviewers)

	// The empty-identity trap: SetStr omits every empty string, so an unresolved
	// createdBy contributes its id and nothing else.
	if d.CreatedBy != nil {
		telemetry.SetStr(attrs, semconv.AttrCreatedById, d.CreatedBy.ID)
		telemetry.SetStr(attrs, semconv.AttrCreatedBy, d.CreatedBy.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrCreatedByUserPrincipalName, d.CreatedBy.UserPrincipalName)
		telemetry.SetStr(attrs, semconv.AttrCreatedByType, d.CreatedBy.Type)
	}

	c.scopeAttrs(e, attrs, d.Scope)

	telemetry.SetStrs(attrs, semconv.AttrReviewerQueries, queries(d.Reviewers))
	attrs[semconv.AttrReviewerCount] = int64(len(d.Reviewers))
	attrs[semconv.AttrFallbackReviewerCount] = int64(len(d.FallbackReviewers))
	attrs[semconv.AttrAdditionalNotificationRecipientCount] = int64(len(d.AdditionalNotificationRecipients))
	attrs[semconv.AttrStageCount] = int64(len(d.StageSettings))

	sev := telemetry.SeverityInfo
	reason := ""
	if d.Settings == nil {
		// An absent settings block blinds the whole posture read AND the WARN rung
		// below, so it announces itself rather than degrading in silence.
		c.watch.MissingField(e, fieldSettings)
	} else {
		settingsAttrs(attrs, d.Settings)
		if isFalse(d.Settings.MailNotificationsEnabled) && isFalse(d.Settings.ReminderNotificationsEnabled) {
			sev = telemetry.SeverityWarn
			reason = " (reviewers get neither notifications nor reminders)"
		}
	}

	return telemetry.Event{
		Name:     eventReview,
		Body:     fmt.Sprintf("access review %s: status=%s reviewers=%d%s", label(d), d.Status, len(d.Reviewers), reason),
		Severity: sev,
		Attrs:    attrs,
	}
}

// scopeAttrs reads the polymorphic scope BY ITS DISCRIMINATOR. An unmapped
// discriminator still contributes scope_type (so the twin names what arrived) and
// fires the wirecheck counter, but never drops the review.
func (c *Collector) scopeAttrs(e telemetry.Emitter, attrs telemetry.Attrs, s *scope) {
	if s == nil {
		return
	}
	scopeType := strings.TrimPrefix(s.ODataType, odataPrefix)
	telemetry.SetStr(attrs, semconv.AttrScopeODataType, scopeType)

	switch scopeType {
	case scopeTypePrincipalResourceMemberships:
		telemetry.SetStrs(attrs, semconv.AttrScopePrincipalQueries, queries(s.PrincipalScopes))
		telemetry.SetStrs(attrs, semconv.AttrScopeResourceQueries, queries(s.ResourceScopes))
	case scopeTypeQuery:
		telemetry.SetStr(attrs, semconv.AttrScopeQuery, s.Query)
	default:
		c.watch.Value(e, semconv.AttrScopeODataType, scopeType, mappedScopeTypes)
	}
}

// settingsAttrs stamps the governance-settings family. It is called only when the
// wire carried a settings block, so an absent block omits the whole family rather
// than publishing a row of fabricated falses.
func settingsAttrs(attrs telemetry.Attrs, s *settings) {
	setBoolPtr(attrs, semconv.AttrMailNotificationsEnabled, s.MailNotificationsEnabled)
	setBoolPtr(attrs, semconv.AttrReminderNotificationsEnabled, s.ReminderNotificationsEnabled)
	setBoolPtr(attrs, semconv.AttrJustificationRequiredOnApproval, s.JustificationRequiredOnApproval)
	setBoolPtr(attrs, semconv.AttrDefaultDecisionEnabled, s.DefaultDecisionEnabled)
	setBoolPtr(attrs, semconv.AttrAutoApplyDecisionsEnabled, s.AutoApplyDecisionsEnabled)
	setBoolPtr(attrs, semconv.AttrRecommendationsEnabled, s.RecommendationsEnabled)
	telemetry.SetStr(attrs, semconv.AttrDefaultDecision, s.DefaultDecision)
	if s.InstanceDurationInDays != nil {
		attrs[semconv.AttrInstanceDurationDays] = *s.InstanceDurationInDays
	}

	// applyActions is the second polymorphic member: only its discriminators
	// carry meaning, and they are read the same way scope's is.
	actions := make([]string, 0, len(s.ApplyActions))
	for _, a := range s.ApplyActions {
		if t := strings.TrimPrefix(a.ODataType, odataPrefix); t != "" {
			actions = append(actions, t)
		}
	}
	telemetry.SetStrs(attrs, semconv.AttrApplyActionTypes, actions)

	if s.Recurrence == nil {
		return
	}
	if p := s.Recurrence.Pattern; p != nil {
		telemetry.SetStr(attrs, semconv.AttrRecurrencePatternType, p.Type)
		if p.Interval != nil {
			attrs[semconv.AttrRecurrenceInterval] = *p.Interval
		}
	}
	if r := s.Recurrence.Range; r != nil {
		telemetry.SetStr(attrs, semconv.AttrRecurrenceRangeType, r.Type)
		telemetry.SetStr(attrs, semconv.AttrRecurrenceStartDate, r.StartDate)
	}
}

// queries flattens a scope list to its query strings, dropping entries with no
// query (a shape this collector cannot read anything out of).
func queries(scopes []reviewerScope) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s.Query != "" {
			out = append(out, s.Query)
		}
	}
	return out
}

// setBoolPtr stamps a tri-state wire bool: true/false are both real answers, nil
// omits the attribute rather than asserting a false Microsoft never sent.
func setBoolPtr(attrs telemetry.Attrs, key string, v *bool) {
	if v != nil {
		telemetry.SetBool(attrs, key, *v)
	}
}

// isFalse reports whether the wire explicitly said false. A nil (absent) value is
// NOT false — it is unknown, and must not trip a warning.
func isFalse(v *bool) bool { return v != nil && !*v }

// label is the human handle for the twin body, falling back to the id when a
// review has no display name.
func label(d accessReviewScheduleDefinition) string {
	if d.DisplayName != "" {
		return d.DisplayName
	}
	return d.ID
}

// instanceTwin renders one instance as a log record (#319). It takes the
// emitter and definitionID for the same reason twin does: the reused scope
// discriminator is checked here, and definitionID is the twin's foreign key to
// its parent. truncated marks semconv.AttrArraysTruncated on this twin when
// EITHER this instance's own decisions were capped, OR the definition's
// instance list itself was capped and this instance survived the cut (see the
// package doc's bounding section for why the latter has no single owning
// entity of its own).
func (c *Collector) instanceTwin(e telemetry.Emitter, definitionID string, inst accessReviewInstance, truncated bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, inst.ID)
	telemetry.SetStr(attrs, semconv.AttrDefinitionId, definitionID)
	telemetry.SetStr(attrs, semconv.AttrStatus, inst.Status)
	telemetry.SetStr(attrs, semconv.AttrStartDateTime, inst.StartDateTime)
	telemetry.SetStr(attrs, semconv.AttrEndDateTime, inst.EndDateTime)

	c.scopeAttrs(e, attrs, inst.Scope)

	telemetry.SetStrs(attrs, semconv.AttrReviewerQueries, queries(inst.Reviewers))
	attrs[semconv.AttrReviewerCount] = int64(len(inst.Reviewers))
	attrs[semconv.AttrFallbackReviewerCount] = int64(len(inst.FallbackReviewers))

	if truncated {
		attrs[semconv.AttrArraysTruncated] = true
	}

	sev := telemetry.SeverityInfo
	if inst.Status == "InProgress" && c.isExpired(inst.EndDateTime) {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventInstance,
		Body:     fmt.Sprintf("access review instance %s (definition %s): status=%s reviewers=%d", inst.ID, definitionID, inst.Status, len(inst.Reviewers)),
		Severity: sev,
		Attrs:    attrs,
	}
}

// decisionTwin renders one reviewer decision as a log record (#319).
// instanceExpired is passed in rather than recomputed so every decision under
// one instance judges expiry against the exact same clock read.
func decisionTwin(definitionID, instanceID string, dec accessReviewDecision, instanceExpired bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDecisionId, dec.ID)
	telemetry.SetStr(attrs, semconv.AttrInstanceId, instanceID)
	telemetry.SetStr(attrs, semconv.AttrDefinitionId, definitionID)
	telemetry.SetStr(attrs, semconv.AttrDecision, dec.Decision)
	telemetry.SetStr(attrs, semconv.AttrAppliedResult, dec.ApplyResult)
	telemetry.SetStr(attrs, semconv.AttrRecommendation, dec.Recommendation)
	telemetry.SetStr(attrs, semconv.AttrJustification, dec.Justification)
	telemetry.SetStr(attrs, semconv.AttrPrincipalLink, dec.PrincipalLink)
	telemetry.SetStr(attrs, semconv.AttrResourceLink, dec.ResourceLink)

	if dec.ReviewedDateTime != nil {
		telemetry.SetStr(attrs, semconv.AttrReviewedDateTime, *dec.ReviewedDateTime)
	}
	if dec.AppliedDateTime != nil {
		telemetry.SetStr(attrs, semconv.AttrAppliedDateTime, *dec.AppliedDateTime)
	}

	// The zero-GUID sentinel: a fully populated but meaningless identity on an
	// undecided decision. Treated as absent — see the package doc.
	setRealIdentity(attrs, semconv.AttrReviewedById, semconv.AttrReviewedByDisplayName, dec.ReviewedBy)
	setRealIdentity(attrs, semconv.AttrAppliedById, "", dec.AppliedBy)

	if dec.Resource != nil {
		telemetry.SetStr(attrs, semconv.AttrResourceId, dec.Resource.ID)
		telemetry.SetStr(attrs, semconv.AttrResourceDisplayName, dec.Resource.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrResourceType, dec.Resource.Type)
	}

	principalName := ""
	if dec.Principal != nil {
		principalName = dec.Principal.DisplayName
		telemetry.SetStr(attrs, semconv.AttrPrincipalId, dec.Principal.ID)
		telemetry.SetStr(attrs, semconv.AttrDisplayName, dec.Principal.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrPrincipalType, dec.Principal.Type)
		telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, dec.Principal.UserPrincipalName)
		// LastUserSignInDateTime arrives as an EMPTY STRING when unknown, never
		// null — SetStr's own empty-string omission is what makes this safe.
		telemetry.SetStr(attrs, semconv.AttrLastUserSignInDateTime, dec.Principal.LastUserSignInDateTime)
	}

	sev := telemetry.SeverityInfo
	if dec.Decision == "NotReviewed" && instanceExpired {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventDecision,
		Body: fmt.Sprintf("access review decision %s (instance %s): principal=%s decision=%s applied_result=%s",
			dec.ID, instanceID, displayOrID(principalName, dec.Principal), dec.Decision, dec.ApplyResult),
		Severity: sev,
		Attrs:    attrs,
	}
}

// setRealIdentity stamps id (and, when nameKey is non-empty, displayName) from
// u, unless u is nil or u.ID is the zero-GUID sentinel — in which case nothing
// is stamped at all. Reused for both reviewedBy (which gets a display name
// attribute) and appliedBy (which, per the frozen semconv contract, does not).
func setRealIdentity(attrs telemetry.Attrs, idKey, nameKey string, u *userIdentity) {
	if u == nil || u.ID == "" || u.ID == zeroGUID {
		return
	}
	telemetry.SetStr(attrs, idKey, u.ID)
	if nameKey != "" {
		telemetry.SetStr(attrs, nameKey, u.DisplayName)
	}
}

// displayOrID is the human handle for a decision's body line: the principal's
// display name when known, else its id, else "unknown" when Graph sent no
// principal object at all.
func displayOrID(name string, p *decisionPrincipal) string {
	if name != "" {
		return name
	}
	if p != nil && p.ID != "" {
		return p.ID
	}
	return "unknown"
}

// isForbidden reports whether err is a Graph 403 — the signal that this tenant
// may not use the endpoint, which is a graceful skip rather than a collection
// failure. The raw-REST path embeds the status in the error string
// ("status 403"); the OData path codes it Authorization_RequestDenied.
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

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
