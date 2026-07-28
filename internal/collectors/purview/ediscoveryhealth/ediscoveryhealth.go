// Package ediscoveryhealth is the Microsoft Purview eDiscovery case-HEALTH
// collector (#323): the legal holds, per-hold data sources, and long-running
// case operations hanging off each eDiscovery case that the sibling
// internal/collectors/purview/ediscoverycases counts but never inspects.
//
// # Opt-in for the SAME reason as ediscoverycases (#102), not a beta reason
//
// Every route this collector polls is Graph v1.0 (GA). It is Experimental
// (opt-in) because it needs the Security & Compliance data-plane registration
// a granted eDiscovery.Read.All scope does not provide on its own — see
// ediscoverycases' package doc and docs/data-plane-registration.md. A 401 here
// carries the same meaning and the same error message as that collector's.
//
// # Fetch shape and the cost gate (live-measured 2026-07-28, #323)
//
// Per case: GET legalHolds, then per hold GET userSources + siteSources, plus
// GET custodians, GET noncustodialDataSources, GET operations. That is
// 1 + 4C + 2H GETs with no batch form and no $expand, and these are among the
// slowest endpoints in the project — a single empty legalHolds list took
// 11-22s live. DefaultMaxCases bounds the per-cycle fan-out; cases_covered
// and cases_total are emitted every cycle so a shortfall is visible rather
// than silent.
//
// unifiedGroupSources is deliberately never fetched: the v1.0 EDM declares it
// only on ediscoveryCustodian, not on a legal hold, and fetching it per-hold
// is a guaranteed 400 (confirmed live in case2.json). searches, tags,
// reviewSets and caseMembers are out of scope for this issue (caseMembers
// 401s for the poller regardless).
//
// # Per-case, per-route degradation (#240)
//
// The ONLY fatal error is the top-level case-list fetch. Every child route
// (legalHolds, a hold's userSources/siteSources, custodians,
// noncustodialDataSources, operations) degrades independently: a fetch error
// is logged and that route/case pair contributes nothing to any metric or log
// — never a zero point, which per #240 would misrepresent a GAP as a measured
// zero. One live wire trap produces exactly this shape: while a case is an
// unmaterialized stub, its child routes return HTTP 500 with a body saying
// the compliance case doesn't exist — really a 404 on a listed case. It needs
// no special-casing beyond the generic per-route degrade path already
// described: it is treated as any other route failure, not as fatal and not
// as a reason to back off harder.
//
// # Wire traps this file's mapping exists to handle
//
// See internal/semconv/attrs_purview_ediscoveryhealth.go's package doc for the
// full detail (null hold status, non-GUID source ids, the three createdBy
// shapes, the .NET zero-date sentinel). This package additionally decides,
// where that doc leaves a choice open: a siteSource's log-twin
// created_date_time comes from the EMBEDDED site object's own createdDateTime
// (site.createdDateTime — the site's real creation time, and the field the
// live .NET zero-date sentinel was actually observed on) rather than the
// source row's own createdDateTime (when the source was added to the hold).
// A userSource has no such sub-object, so its created_date_time is the row's
// own createdDateTime. Both go through realDateTime.
//
// # custodians / noncustodialDataSources: counted, never decoded, never a log twin
//
// Both routes return 200 with zero rows on every case observed, and the
// semconv package doc's "deliberately no custodian field mapper" section
// explains why that is a closed question rather than a gap. This collector
// only counts rows on these two routes — no field mapper, no per-row log
// twin — and sums the count across every covered case into one aggregate
// gauge each (no case_id label, per #112). A per-case fetch failure on either
// route therefore contributes nothing to the sum rather than a zero, exactly
// like every other route, but because the metric has no per-case breakdown a
// reader cannot distinguish "this case truly has zero" from "this case's
// count is unknown" from the aggregate alone — an inherent consequence of the
// aggregate-only shape this issue specifies, not a bug.
package ediscoveryhealth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// DefaultMaxCases bounds how many eDiscovery cases this collector's child
// routes (legalHolds, custodians, noncustodialDataSources, operations, plus
// userSources/siteSources per hold) are polled against per cycle. Each case
// costs 4 GETs plus 2 GETs per hold with no batch form and no $expand
// (GETs are 1 + 4C + 2H), and these are among the slowest endpoints in the
// project — a single empty legalHolds list took 11-22s live
// [live-measured 2026-07-28, #323]. 50 keeps a worst-case cycle from
// stalling the poller on a tenant with many eDiscovery cases;
// cases_covered/cases_total make a shortfall visible instead of silent.
// There is deliberately no config key for this cap — the collector is
// already opt-in twice over (Experimental plus the S&C data-plane
// registration prerequisite).
const DefaultMaxCases = 50

// Collector name (the stable config / self-observability / admin-status
// key), the metrics it emits, and the log-twin EventNames.
const (
	healthName = "purview.ediscovery_case_health"

	metricLegalHolds     = "purview.ediscovery.legal_holds"
	metricHoldSources    = "purview.ediscovery.hold_sources"
	metricCaseOperations = "purview.ediscovery.case_operations"
	metricCustodians     = "purview.ediscovery.custodians"
	metricNoncustodial   = "purview.ediscovery.noncustodial_data_sources"
	metricCasesCovered   = "purview.ediscovery.case_health.cases_covered"
	metricCasesTotal     = "purview.ediscovery.case_health.cases_total"

	legalHoldEventName     = "purview.ediscovery_legal_hold"
	holdSourceEventName    = "purview.ediscovery_hold_source"
	caseOperationEventName = "purview.ediscovery_case_operation"

	unitHold      = "{hold}"
	unitSource    = "{source}"
	unitOperation = "{operation}"
	unitCustodian = "{custodian}"
	unitCase      = "{case}"
)

// ediscoveryCaseRef is the subset of the ediscoveryCase resource this
// collector needs to tie every child record back to its case (#112: case_id
// and case_display_name are log-twin only, never a metric label).
type ediscoveryCaseRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// holdBucket, sourceBucket and opBucket are the bounded gauge bucket keys for
// purview.ediscovery.legal_holds, .hold_sources and .case_operations
// respectively — package-level named types so Collect's accumulator maps and
// the per-case helper methods that populate them share exactly one type
// (Go's structural typing would otherwise make a same-shaped anonymous
// struct declared in two places two DIFFERENT types for map purposes only if
// their field names/order differ; naming them removes the risk entirely).
type (
	holdBucket   struct{ enabled, hasErrors bool }
	sourceBucket struct{ sourceType, holdStatus string }
	opBucket     struct{ action, status string }
)

// countingRoute accumulates a count-only child route (custodians,
// noncustodialDataSources) across every covered case, and — the part that
// matters — remembers whether ANY case's fetch on that route actually
// succeeded.
//
// Without that bit the two aggregate gauges violate #240. Their totals start
// at zero and only ever grow, so if every case's fetch fails the total is
// still 0 and publishing it asserts a confident "this tenant has no
// custodians" over what was really a total read failure — a GAP reported as a
// measured zero. `total == 0` cannot distinguish the two cases on its own,
// which is exactly why `any` is tracked separately rather than inferred.
//
// The inverse matters just as much: when at least one case answered 200 with
// an empty collection, zero IS the measurement and must be published. On this
// tenant that is the steady state for both routes, so a naive "never publish
// when the total is zero" would silently drop the collector's only honest
// answer.
type countingRoute struct {
	total int64
	any   bool
}

// add records one successful fetch of n rows. It is called ONLY on success,
// so `any` marks a real 200 rather than merely a non-zero count — a case that
// legitimately returns zero rows still makes the aggregate publishable.
func (r *countingRoute) add(n int) {
	r.any = true
	r.total += int64(n)
}

// points returns the single gauge point for this route, or nil when no case
// succeeded — nil yields no point at all, which is the honest representation
// of an unknown.
func (r *countingRoute) points() []telemetry.GaugePoint {
	if !r.any {
		return nil
	}
	return []telemetry.GaugePoint{{Value: float64(r.total)}}
}

// identityUser is the `user` half of a Graph identitySet, decoded uniformly
// across the three inconsistent createdBy shapes this API surfaces — see
// internal/semconv/attrs_purview_ediscoveryhealth.go's package doc. A JSON
// null on either field leaves the Go zero value (""), so no pointer is
// needed here.
type identityUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// identitySet mirrors the identitySet Graph wraps createdBy in. The
// `application` half is never needed by this collector and is left
// undecoded.
type identitySet struct {
	User identityUser `json:"user"`
}

// legalHold mirrors the legalHold fields this collector uses. Status is null
// on every hold observed live (log twin only, see AttrHoldState); IsEnabled
// and len(Errors)>0 bucket the metric instead.
type legalHold struct {
	ID                   string            `json:"id"`
	DisplayName          string            `json:"displayName"`
	Description          string            `json:"description"`
	IsEnabled            bool              `json:"isEnabled"`
	Errors               []json.RawMessage `json:"errors"`
	Status               string            `json:"status"`
	CreatedBy            identitySet       `json:"createdBy"`
	CreatedDateTime      string            `json:"createdDateTime"`
	LastModifiedDateTime string            `json:"lastModifiedDateTime"`
}

// siteInfo is the embedded `site` object on a siteSource row. WebUrl feeds
// AttrSiteWebUrl; CreatedDateTime is where the live .NET zero-date sentinel
// was observed (case2.json, deep.json) — see the package doc for why this
// collector uses it, not the row's own createdDateTime, as a siteSource's
// log-twin created_date_time.
type siteInfo struct {
	WebUrl          string `json:"webUrl"`
	CreatedDateTime string `json:"createdDateTime"`
}

// sourceRow mirrors both userSource and siteSource: they share every field
// this collector reads except Email (userSources only) and Site
// (siteSources only), so one struct decodes both. IncludedSources and Email
// are simply absent on a siteSource row and vice versa for Site.
type sourceRow struct {
	ID              string      `json:"id"`
	DisplayName     string      `json:"displayName"`
	HoldStatus      string      `json:"holdStatus"`
	IncludedSources string      `json:"includedSources"`
	Email           string      `json:"email"`
	CreatedDateTime string      `json:"createdDateTime"`
	CreatedBy       identitySet `json:"createdBy"`
	Site            *siteInfo   `json:"site"`
}

// caseOperation mirrors the caseOperation fields this collector uses.
// CreatedBy is null for system-generated actions (holdPolicySync) — see the
// package doc's trap 5 — so it is a pointer.
type caseOperation struct {
	ID                string       `json:"id"`
	Action            string       `json:"action"`
	Status            string       `json:"status"`
	PercentProgress   *float64     `json:"percentProgress"`
	CreatedDateTime   string       `json:"createdDateTime"`
	CompletedDateTime string       `json:"completedDateTime"`
	CreatedBy         *identitySet `json:"createdBy"`
}

// HealthCollector polls the tenant's eDiscovery case-health detail: legal
// holds, hold sources, custodians, non-custodial data sources, and case
// operations.
type HealthCollector struct {
	g        collectors.GraphClient
	baseURL  string
	logger   *slog.Logger
	maxCases int
	watch    *wirecheck.Reporter
}

// NewHealth builds the eDiscovery case-health collector. A nil logger falls
// back to the slog default.
func NewHealth(g collectors.GraphClient, logger *slog.Logger) *HealthCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &HealthCollector{
		g:        g,
		baseURL:  defaultBaseURL,
		logger:   logger,
		maxCases: DefaultMaxCases,
		watch:    wirecheck.New(healthName, logger),
	}
}

// Name implements collector.Collector.
func (c *HealthCollector) Name() string { return healthName }

// DefaultInterval implements collector.Collector. eDiscovery case health
// drifts slowly and every child route is expensive (see the package doc); an
// hourly poll is ample and keeps the per-cycle cost bounded.
func (c *HealthCollector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks this collector opt-in for the SAME reason as
// ediscoverycases — see the package doc.
func (c *HealthCollector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// eDiscovery.Read.All is necessary but NOT sufficient — see the package doc.
func (c *HealthCollector) RequiredPermissions() []string {
	return []string{"eDiscovery.Read.All"}
}

// Collect fetches the eDiscovery case-health detail across every covered
// case and emits the bounded gauges plus their log twins described in the
// package doc.
//
// # Every fetch error on the top-level case list fails this collector
//
// This mirrors ediscoverycases: a 401 in particular means the S&C
// registration is missing despite the scope being granted, and the error
// names that fix. Every CHILD route, by contrast, degrades independently —
// see the package doc's "#240" section.
func (c *HealthCollector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+"/security/cases/ediscoveryCases", nil, outcomes)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		if strings.Contains(err.Error(), "status 401") {
			return fmt.Errorf("%s: list cases: eDiscovery.Read.All is granted but the app's service principal must ALSO be registered in the Security & Compliance data plane (a 401 here is that missing registration, not a Graph scope gap) — see docs/data-plane-registration.md: %w",
				healthName, err)
		}
		return fmt.Errorf("%s: list cases: %w", healthName, err)
	}

	total := int64(len(raws))
	maxCases := c.maxCases
	if maxCases <= 0 {
		maxCases = DefaultMaxCases
	}
	covered := raws
	if int64(maxCases) < total {
		covered = raws[:maxCases]
	}

	var cases []ediscoveryCaseRef
	for _, raw := range covered {
		var ec ediscoveryCaseRef
		if err := json.Unmarshal(raw, &ec); err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, 1)
			outcomes.Cause(recordoutcome.CauseDecodeError)
			c.logger.Warn("ediscovery case health: skipping unparseable case entry", "collector", healthName, "error", err)
			continue
		}
		cases = append(cases, ec)
	}

	holdCounts := map[holdBucket]int64{}
	sourceCounts := map[sourceBucket]int64{}
	opCounts := map[opBucket]int64{}

	var custodians, noncustodial countingRoute

	for _, ec := range cases {
		c.collectCaseHolds(ctx, e, outcomes, ec, holdCounts, sourceCounts)
		c.collectCaseCustodians(ctx, outcomes, ec, &custodians)
		c.collectCaseNoncustodial(ctx, outcomes, ec, &noncustodial)
		c.collectCaseOperations(ctx, e, outcomes, ec, opCounts)
	}

	holdPoints := make([]telemetry.GaugePoint, 0, len(holdCounts))
	for b, n := range holdCounts {
		holdPoints = append(holdPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrEnabled:   strconv.FormatBool(b.enabled),
				semconv.AttrHasErrors: strconv.FormatBool(b.hasErrors),
			},
		})
	}
	e.GaugeSnapshot(metricLegalHolds, unitHold,
		"eDiscovery legal holds across every covered case, counted by isEnabled and whether the hold's errors array is non-empty. legalHold.status is null on every hold observed live, so it does not bucket this gauge — see AttrHoldState on the log twin. Never labeled by case or hold identity (#112).",
		holdPoints)

	sourcePoints := make([]telemetry.GaugePoint, 0, len(sourceCounts))
	for b, n := range sourceCounts {
		sourcePoints = append(sourcePoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrSourceType: b.sourceType,
				semconv.AttrHoldStatus: b.holdStatus,
			},
		})
	}
	e.GaugeSnapshot(metricHoldSources, unitSource,
		"eDiscovery legal-hold data sources (userSources + siteSources) across every covered case, counted by which collection the row came from and its dataSourceHoldStatus. Never labeled by case, hold or source identity (#112).",
		sourcePoints)

	opPoints := make([]telemetry.GaugePoint, 0, len(opCounts))
	for b, n := range opCounts {
		opPoints = append(opPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrAction: b.action,
				semconv.AttrStatus: b.status,
			},
		})
	}
	e.GaugeSnapshot(metricCaseOperations, unitOperation,
		"eDiscovery case operations across every covered case, counted by action and status. Never labeled by case or operation identity (#112).",
		opPoints)

	e.GaugeSnapshot(metricCustodians, unitCustodian,
		"eDiscovery custodians across every covered case — a plain count, no field mapper. Every case observed live returns zero rows; see the package doc for why no ediscoveryCustodian shape is mapped. Absent entirely when no case's fetch succeeded, so a total read failure never reads as a measured zero (#240).",
		custodians.points())
	e.GaugeSnapshot(metricNoncustodial, unitSource,
		"eDiscovery non-custodial data sources across every covered case — a plain count, no field mapper. Absent entirely when no case's fetch succeeded (#240).",
		noncustodial.points())

	e.GaugeSnapshot(metricCasesCovered, unitCase,
		"eDiscovery cases actually polled for case-health detail this cycle. Compare against purview.ediscovery.case_health.cases_total: covered < total means DefaultMaxCases left part of the tenant's case inventory unpolled this cycle, not that the tenant has few cases.",
		[]telemetry.GaugePoint{{Value: float64(len(covered))}})
	e.GaugeSnapshot(metricCasesTotal, unitCase,
		"Total eDiscovery cases this tenant has, per the case list. Always emitted alongside cases_covered so partial coverage is never indistinguishable from a genuinely small tenant.",
		[]telemetry.GaugePoint{{Value: float64(total)}})

	return nil
}

// caseBaseURL builds the absolute URL root for one case's child routes.
func (c *HealthCollector) caseBaseURL(caseID string) string {
	return c.baseURL + "/security/cases/ediscoveryCases/" + caseID
}

// collectCaseHolds fetches one case's legal holds, buckets and logs each,
// then fetches that hold's userSources/siteSources. A legalHolds fetch
// failure is logged and skipped — see the package doc's "#240" section; it
// never aborts the rest of Collect nor contributes a zero point.
func (c *HealthCollector) collectCaseHolds(
	ctx context.Context,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
	ec ediscoveryCaseRef,
	holdCounts map[holdBucket]int64,
	sourceCounts map[sourceBucket]int64,
) {
	url := c.caseBaseURL(ec.ID) + "/legalHolds"
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, url, nil, outcomes)
	if err != nil {
		c.logger.Warn("ediscovery case health: legalHolds fetch failed, skipping this case's holds",
			"collector", healthName, "case_id", ec.ID, "error", err)
		return
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))

	for _, raw := range raws {
		var lh legalHold
		if err := json.Unmarshal(raw, &lh); err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, 1)
			outcomes.Cause(recordoutcome.CauseDecodeError)
			c.logger.Warn("ediscovery case health: skipping unparseable legal hold entry", "collector", healthName, "case_id", ec.ID, "error", err)
			continue
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)

		hasErrors := len(lh.Errors) > 0
		holdCounts[holdBucket{enabled: lh.IsEnabled, hasErrors: hasErrors}]++

		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrCaseId, ec.ID)
		telemetry.SetStr(attrs, semconv.AttrCaseDisplayName, ec.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrId, lh.ID)
		telemetry.SetStr(attrs, semconv.AttrDisplayName, lh.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrDescription, lh.Description)
		telemetry.SetBool(attrs, semconv.AttrEnabled, lh.IsEnabled)
		telemetry.SetBool(attrs, semconv.AttrHasErrors, hasErrors)
		attrs[semconv.AttrErrorCount] = float64(len(lh.Errors))
		telemetry.SetStr(attrs, semconv.AttrHoldState, lh.Status)
		telemetry.SetStr(attrs, semconv.AttrCreatedByDisplayName, createdByName(lh.CreatedBy))
		telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realDateTime(lh.CreatedDateTime))
		telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, realDateTime(lh.LastModifiedDateTime))

		e.LogEvent(telemetry.Event{
			Name:  legalHoldEventName,
			Body:  fmt.Sprintf("eDiscovery legal hold: %s (case %s)", lh.DisplayName, ec.DisplayName),
			Attrs: attrs,
		})

		c.collectHoldSources(ctx, e, outcomes, ec, lh, sourceCounts)
	}
}

// collectHoldSources fetches one hold's userSources and siteSources. Each
// route degrades independently: a failure on one never blocks the other nor
// the rest of Collect.
func (c *HealthCollector) collectHoldSources(
	ctx context.Context,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
	ec ediscoveryCaseRef,
	lh legalHold,
	sourceCounts map[sourceBucket]int64,
) {
	routes := []struct{ path, sourceType string }{
		{"userSources", "user"},
		{"siteSources", "site"},
	}
	for _, route := range routes {
		url := c.caseBaseURL(ec.ID) + "/legalHolds/" + lh.ID + "/" + route.path
		raws, err := collectors.GetAllValuesRecorded(ctx, c.g, url, nil, outcomes)
		if err != nil {
			c.logger.Warn("ediscovery case health: hold source fetch failed, skipping this route",
				"collector", healthName, "case_id", ec.ID, "hold_id", lh.ID, "source_type", route.sourceType, "error", err)
			continue
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))

		for _, raw := range raws {
			var sr sourceRow
			if err := json.Unmarshal(raw, &sr); err != nil {
				outcomes.Add(recordoutcome.OutcomeErrored, 1)
				outcomes.Cause(recordoutcome.CauseDecodeError)
				c.logger.Warn("ediscovery case health: skipping unparseable hold source entry", "collector", healthName, "case_id", ec.ID, "hold_id", lh.ID, "error", err)
				continue
			}
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)

			c.watch.Value(e, semconv.AttrHoldStatus, sr.HoldStatus, knownHoldStatuses)
			holdStatus := bucketHoldStatus(sr.HoldStatus)
			sourceCounts[sourceBucket{sourceType: route.sourceType, holdStatus: holdStatus}]++

			attrs := telemetry.Attrs{}
			telemetry.SetStr(attrs, semconv.AttrCaseId, ec.ID)
			telemetry.SetStr(attrs, semconv.AttrCaseDisplayName, ec.DisplayName)
			telemetry.SetStr(attrs, semconv.AttrHoldId, lh.ID)
			telemetry.SetStr(attrs, semconv.AttrId, sr.ID)
			telemetry.SetStr(attrs, semconv.AttrDisplayName, sr.DisplayName)
			telemetry.SetStr(attrs, semconv.AttrSourceType, route.sourceType)
			telemetry.SetStr(attrs, semconv.AttrHoldStatus, holdStatus)
			telemetry.SetStr(attrs, semconv.AttrIncludedSources, sr.IncludedSources)
			telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, sr.Email)

			created := sr.CreatedDateTime
			if sr.Site != nil {
				telemetry.SetStr(attrs, semconv.AttrSiteWebUrl, sr.Site.WebUrl)
				created = sr.Site.CreatedDateTime
			}
			telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realDateTime(created))

			e.LogEvent(telemetry.Event{
				Name:  holdSourceEventName,
				Body:  fmt.Sprintf("eDiscovery hold source: %s (%s, case %s)", sr.DisplayName, route.sourceType, ec.DisplayName),
				Attrs: attrs,
			})
		}
	}
}

// collectCaseCustodians fetches one case's custodians and adds its row count
// to total. No field mapper, no log twin — see the package doc. It reports
// whether the fetch SUCCEEDED, which is not the same question as whether the
// count moved: see countingRoute's doc for why the caller needs that bit.
func (c *HealthCollector) collectCaseCustodians(ctx context.Context, outcomes *recordoutcome.Recorder, ec ediscoveryCaseRef, r *countingRoute) {
	url := c.caseBaseURL(ec.ID) + "/custodians"
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, url, nil, outcomes)
	if err != nil {
		c.logger.Warn("ediscovery case health: custodians fetch failed, skipping this case's count",
			"collector", healthName, "case_id", ec.ID, "error", err)
		return
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))
	r.add(len(raws))
}

// collectCaseNoncustodial fetches one case's non-custodial data sources and
// adds its row count to total. No field mapper, no log twin.
func (c *HealthCollector) collectCaseNoncustodial(ctx context.Context, outcomes *recordoutcome.Recorder, ec ediscoveryCaseRef, r *countingRoute) {
	url := c.caseBaseURL(ec.ID) + "/noncustodialDataSources"
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, url, nil, outcomes)
	if err != nil {
		c.logger.Warn("ediscovery case health: noncustodialDataSources fetch failed, skipping this case's count",
			"collector", healthName, "case_id", ec.ID, "error", err)
		return
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))
	r.add(len(raws))
}

// collectCaseOperations fetches one case's operations, buckets and logs
// each. A fetch failure is logged and skipped, same as every other route.
func (c *HealthCollector) collectCaseOperations(
	ctx context.Context,
	e telemetry.Emitter,
	outcomes *recordoutcome.Recorder,
	ec ediscoveryCaseRef,
	opCounts map[opBucket]int64,
) {
	url := c.caseBaseURL(ec.ID) + "/operations"
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, url, nil, outcomes)
	if err != nil {
		c.logger.Warn("ediscovery case health: operations fetch failed, skipping this case's operations",
			"collector", healthName, "case_id", ec.ID, "error", err)
		return
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))

	for _, raw := range raws {
		var op caseOperation
		if err := json.Unmarshal(raw, &op); err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, 1)
			outcomes.Cause(recordoutcome.CauseDecodeError)
			c.logger.Warn("ediscovery case health: skipping unparseable operation entry", "collector", healthName, "case_id", ec.ID, "error", err)
			continue
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)

		c.watch.Value(e, semconv.AttrAction, op.Action, knownActions)
		c.watch.Value(e, semconv.AttrStatus, op.Status, knownOperationStatuses)
		action := bucketAction(op.Action)
		status := bucketOperationStatus(op.Status)
		opCounts[opBucket{action: action, status: status}]++

		var createdBy string
		if op.CreatedBy != nil {
			createdBy = createdByName(*op.CreatedBy)
		}

		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrCaseId, ec.ID)
		telemetry.SetStr(attrs, semconv.AttrCaseDisplayName, ec.DisplayName)
		telemetry.SetStr(attrs, semconv.AttrId, op.ID)
		telemetry.SetStr(attrs, semconv.AttrAction, action)
		telemetry.SetStr(attrs, semconv.AttrStatus, status)
		// A POINTER, deliberately. percentProgress is declared nullable in the
		// v1.0 EDM (no Nullable="false"), so Graph may omit it entirely — and a
		// bare float64 would then publish a fabricated 0, which reads as "this
		// operation is 0% done" rather than "progress is unknown". Absent stays
		// absent.
		if op.PercentProgress != nil {
			attrs[semconv.AttrPercentProgress] = *op.PercentProgress
		}
		telemetry.SetStr(attrs, semconv.AttrCreatedByDisplayName, createdBy)
		telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, realDateTime(op.CreatedDateTime))
		telemetry.SetStr(attrs, semconv.AttrCompletedDateTime, realDateTime(op.CompletedDateTime))

		e.LogEvent(telemetry.Event{
			Name:  caseOperationEventName,
			Body:  fmt.Sprintf("eDiscovery case operation: %s %s (case %s)", action, status, ec.DisplayName),
			Attrs: attrs,
		})
	}
}

// realDateTime returns s only if it parses to a real (non-zero) RFC3339
// instant. Graph serializes an unset date as the .NET zero value
// 0001-01-01T00:00:00Z (live-measured on siteSource.site.createdDateTime,
// #323, and on the case object itself, #102); that must never be emitted as
// a year-0001 timestamp, so it — and any unparseable value — collapses to
// "". Same semantics as ediscoverycases' helper of the same name.
func realDateTime(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1 {
		return ""
	}
	return s
}

// looksLikeGUID reports whether s parses as a UUID/GUID. Used by
// createdByName to distinguish the legalHolds route's "id" field (which
// holds a human display name, not a GUID) from every other route's "id"
// (a real GUID that must never leak into AttrCreatedByDisplayName).
func looksLikeGUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// createdByName resolves the human who created a hold or operation across
// the three inconsistent createdBy shapes described in
// internal/semconv/attrs_purview_ediscoveryhealth.go's package doc: prefer
// displayName; fall back to id ONLY when id does not parse as a GUID (the
// legalHolds route puts the human name in the id field); otherwise "".
// There is deliberately no created_by_id attribute — see that doc.
func createdByName(is identitySet) string {
	if is.User.DisplayName != "" {
		return is.User.DisplayName
	}
	if is.User.ID != "" && !looksLikeGUID(is.User.ID) {
		return is.User.ID
	}
	return ""
}

// holdStatusBuckets is the bounded dataSourceHoldStatus enum this collector
// recognizes (v1.0 $metadata EDM). Identity-valued: the label IS the wire
// value when known. Anything outside it collapses to "unknown" rather than
// becoming a fresh, unbounded label.
var holdStatusBuckets = map[string]string{
	"notApplied":         "notApplied",
	"applied":            "applied",
	"applying":           "applying",
	"removing":           "removing",
	"partial":            "partial",
	"unknownFutureValue": "unknownFutureValue",
}

// bucketHoldStatus buckets a hold source's holdStatus: empty (null on the
// wire, per the semconv package doc) or unrecognized both collapse to
// "unknown".
func bucketHoldStatus(raw string) string {
	if b, ok := holdStatusBuckets[raw]; ok {
		return b
	}
	return "unknown"
}

// knownHoldStatuses is the wire assumption this collector watches at runtime
// (#233/#234): hold_status is a METRIC LABEL, and an unrecognized value
// collapses into "unknown" — a bucket nobody inspects. Derived from
// holdStatusBuckets' own keys rather than restated, so the watched set is
// exactly the set this collector maps.
var knownHoldStatuses = enumFromBuckets(holdStatusBuckets)

// caseActionBuckets is the bounded caseAction enum this collector recognizes
// (v1.0 $metadata EDM).
var caseActionBuckets = map[string]string{
	"contentExport":      "contentExport",
	"applyTags":          "applyTags",
	"convertToPdf":       "convertToPdf",
	"index":              "index",
	"estimateStatistics": "estimateStatistics",
	"addToReviewSet":     "addToReviewSet",
	"holdUpdate":         "holdUpdate",
	"unknownFutureValue": "unknownFutureValue",
	"purgeData":          "purgeData",
	"exportReport":       "exportReport",
	"exportResult":       "exportResult",
	"holdPolicySync":     "holdPolicySync",
}

// bucketAction buckets a case operation's action; empty or unrecognized
// collapses to "unknown".
func bucketAction(raw string) string {
	if b, ok := caseActionBuckets[raw]; ok {
		return b
	}
	return "unknown"
}

// knownActions is the wire assumption this collector watches at runtime
// (#233/#234) for the action label. Derived from caseActionBuckets' own
// keys.
var knownActions = enumFromBuckets(caseActionBuckets)

// caseOperationStatusBuckets is the bounded caseOperationStatus enum this
// collector recognizes (v1.0 $metadata EDM).
var caseOperationStatusBuckets = map[string]string{
	"notStarted":         "notStarted",
	"submissionFailed":   "submissionFailed",
	"running":            "running",
	"succeeded":          "succeeded",
	"partiallySucceeded": "partiallySucceeded",
	"failed":             "failed",
	"unknownFutureValue": "unknownFutureValue",
}

// bucketOperationStatus buckets a case operation's status; empty or
// unrecognized collapses to "unknown".
func bucketOperationStatus(raw string) string {
	if b, ok := caseOperationStatusBuckets[raw]; ok {
		return b
	}
	return "unknown"
}

// knownOperationStatuses is the wire assumption this collector watches at
// runtime (#233/#234) for the status label. Derived from
// caseOperationStatusBuckets' own keys.
var knownOperationStatuses = enumFromBuckets(caseOperationStatusBuckets)

// enumFromBuckets derives a wirecheck.Enum from a bucket map's own keys, so
// the watched set can never drift from the mapped set — the sensitivitylabels
// pattern (see its knownTargets).
func enumFromBuckets(buckets map[string]string) wirecheck.Enum {
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	return wirecheck.NewEnum(keys...)
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return NewHealth(d.Graph, d.Logger)
	})
}
