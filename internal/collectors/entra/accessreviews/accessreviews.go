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
// # The instances decision: OUT of scope, and this collector says so
//
// A definition's `instances` are its recurrences, and per-instance state — how
// much has been reviewed, what was decided — is what would actually answer "is
// this review being done". They are NOT collected here, for a reason that is a
// wire fact rather than a preference:
//
//   - The list response DOES include an `instances` nav property, expanded, with
//     its own @odata.context — and on both v1.0 and beta it came back as an EMPTY
//     ARRAY for a definition whose status is InProgress (live-measured
//     2026-07-24). So the inline array is not merely incomplete, it is empty for
//     precisely the review whose progress a reader would want. Its length is
//     therefore not a fact about the review, and this collector never emits it as
//     an instance count.
//   - Real instance state needs a separate GET per definition
//     (/definitions/{id}/instances), and decision-level detail a further GET per
//     instance — an N x M fan-out on a workload that is rate-limited and sends no
//     Retry-After. That is a different collector with a different cost profile.
//
// The consequence is stated rather than papered over: **this collector cannot
// tell you whether a review is being completed.** It reports that a review
// exists, what it is scoped to, who is meant to review it, how often it recurs,
// and what its status field says — nothing about progress. There is deliberately
// no "stuck InProgress" or staleness warning, because the data that would make
// such a warning honest is not fetched. #260's shape note asked for exactly this
// choice to be explicit.
//
// # Severity ladder
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
// # wirecheck: `scope_type` watched, `status` deliberately NOT
//
// `scope` is polymorphic and its @odata.type is read as the discriminator (as is
// `settings.applyActions`), never decoded structurally. The watched Enum is
// derived from the exact set of discriminators this collector extracts queries
// from, so it can only fire on a hole in THIS collector's mapping — never on
// correct data (#234's rule).
//
// `status` is left UNWATCHED, and that is a recorded evidence gap rather than an
// oversight. Exactly one value has ever been observed on the wire —
// "InProgress", on one tenant, once. One observed value is not a value set, and
// #234 is explicit that an Enum is declared only from evidence in the repo or a
// live sample, never from Microsoft's documentation, because a watchdog that
// fires on correct data is worse than no watchdog. Declare it when a second
// value has been seen on the wire, and not before.
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

// defaultBaseURL is the Graph v1.0 root — see the package doc on why this is
// not beta.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// definitionsPath lists the tenant's access-review definitions.
const definitionsPath = "/identityGovernance/accessReviews/definitions"

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

// Collector polls the tenant's access-review definitions.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
}

// New builds the access-reviews collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, watch: wirecheck.New(collectorName, logger)}
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
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+definitionsPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("skipping access reviews: endpoint returned 403 (governance feature or scope unavailable on this tenant)",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("fetch access review definitions: %w", err)
	}

	byStatus := map[string]int64{}
	var errs []error
	for _, raw := range raws {
		var d accessReviewScheduleDefinition
		if err := json.Unmarshal(raw, &d); err != nil {
			errs = append(errs, fmt.Errorf("decode access review definition: %w", err))
			continue
		}
		if d.ID == "" {
			c.logger.Warn("access reviews: skipping definition with empty id", "collector", collectorName)
			continue
		}
		byStatus[d.Status]++
		e.LogEvent(c.twin(e, d))
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

	return errors.Join(errs...)
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
