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
//
// # Service-health timeline posts (#367)
//
// Every issue (resolved or not — unlike the gauge twin above, a post is not
// scoped to open issues) carries an inline `posts` array: the timeline of
// updates Microsoft published against it. Because the ENTIRE retained history
// is re-served on every poll (the same trait that makes the issue twin
// unresolved-only), re-emitting the posts array verbatim every cycle would
// re-ship the same multi-KB HTML forever — so this collector checkpoints a
// watermark over each post's own createdDateTime (internal/checkpoint, the
// same store the WindowCollectors use) and emits one m365.service_health_post
// log record per post the FIRST time its createdDateTime clears the
// watermark, never again. A post has no id of its own (live-measured
// 2026-07-27, #367: exactly createdDateTime/description/postType on the
// wire), so its dedupe identity is derived — see postKey.
//
// The watermark, not a growing seen-set, is what survives the "full history
// re-served forever" trait: a post below the watermark is never even
// considered, so it never needs to be remembered to be correctly skipped. The
// seen-set only guards the boundary — the postOverlapWindow behind the
// watermark, where two polls could legitimately race — which is why it stays
// small regardless of how much issue history accumulates.
//
// A cold start (zero-valued checkpoint watermark) PRIMES: it records the
// newest post's createdDateTime as the watermark and emits nothing. Without
// this, every first run would try to emit the tenant's ENTIRE retained
// history (829 posts measured 2026-07-27) — nearly all older than the
// backend's 7-day accept window (b4fcaec) — as either a wall of loud
// per-entry rejections or, worse, records the ingest boundary silently
// discards. See TestFirstRunPrimesServiceHealthPostsWithoutEmitting.
package servicehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
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
	eventPost           = "m365.service_health_post"

	// postsEndpoint is the checkpoint namespace the post watermark/seen-set
	// persists under, distinct from any future use of overviewsPath itself as
	// a checkpoint key.
	postsEndpoint = overviewsPath + "#posts"
	// postOverlapWindow is how far behind the watermark a post is still
	// checked against the seen-set rather than skipped outright — 24h,
	// matching the widest source lateness measured elsewhere in this project.
	// It bounds the seen-set to a handful of entries regardless of how much
	// issue history the tenant retains (see the package doc).
	postOverlapWindow = 24 * time.Hour
	// postBodyCapBytes bounds description.content: 8192 bytes is 3.8x the
	// measured max (2176 B) and 4.6x the measured p95 (1792 B) across 829
	// live-sampled posts (2026-07-27, #367), so nothing observed on the wire
	// today is touched; a body over the cap is truncated, never dropped (see
	// the package doc).
	postBodyCapBytes = 8192
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

// issue is one serviceHealthIssue. `details` remains undecoded (still no
// aggregate or per-entity value); `posts` IS now decoded (#367) — see the
// package doc for why that is now safe: each post is checkpointed and
// emitted at most once, rather than re-shipped as per-cycle bulk.
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
	Posts                []post `json:"posts"`
}

// post is one serviceHealthIssuePost carried inline on an issue's posts
// array. It has NO id of its own — exactly three keys are observed on the
// wire (live-measured 2026-07-27, #367, probed as graph2otel-poller against
// m7kni: 829 posts across 100 issues) — so downstream dedupe derives its
// identity from (issue id, createdDateTime, postType) rather than a native
// one. See postKey.
type post struct {
	CreatedDateTime string          `json:"createdDateTime"`
	Description     postDescription `json:"description"`
	PostType        string          `json:"postType"`
}

// postDescription is a post's description object. ContentType was "html" on
// every live-measured sample; Content is carried verbatim in the emitted
// twin (never tag-stripped) and only ever length-capped — see the package
// doc's "RAW HTML, on purpose" note.
type postDescription struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"`
}

// Collector polls the service-announcement health surface.
type Collector struct {
	g        collectors.GraphClient
	baseURL  string
	logger   *slog.Logger
	store    *checkpoint.Store
	tenantID string
	// now is the priming fallback clock (see primePosts), overridable in tests.
	now func() time.Time
}

// New builds the collector. A nil logger falls back to slog.Default(). store
// and tenantID are OPTIONAL: when store is nil or tenantID is "" (unit tests,
// or a deployment that never wired collectors.Deps.Store), post processing is
// skipped entirely rather than emitted unchecked — posts would be
// undedupeable across restarts without a checkpoint, and dup-storming the
// backend is worse than skipping (the same contract dlppolicies and
// epmelevationevents follow for their own optional Store use). The existing
// gauge/twin behavior is unaffected either way.
func New(g collectors.GraphClient, store *checkpoint.Store, tenantID string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, store: store, tenantID: tenantID, now: time.Now}
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
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+overviewsPath, nil, outcomes)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return err
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))

	servicesByStatus := map[string]int64{}
	statusPoints := make([]telemetry.GaugePoint, 0, len(raws))
	issuesByClassStatus := map[[2]string]int64{}
	seenIssues := map[string]bool{}
	var postCandidates []postCandidate

	for i, raw := range raws {
		var ov overview
		if err := json.Unmarshal(raw, &ov); err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, uint64(len(raws))-uint64(i))
			outcomes.Cause(recordoutcome.CauseDecodeError)
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
			// Posts ride every issue regardless of resolution — a resolved
			// issue can still gain a final post (e.g. a PIR publication) — so
			// this is deliberately NOT gated on !is.IsResolved (#367).
			for _, p := range is.Posts {
				postCandidates = append(postCandidates, postCandidate{issueID: is.ID, raw: p})
			}
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}

	c.processPosts(e, outcomes, postCandidates)

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
		return New(d.Graph, d.Store, d.TenantID, d.Logger)
	})
}

var _ collector.SnapshotCollector = (*Collector)(nil)

// ---- service-health timeline posts (#367) ----

// postCandidate is one post extracted from an issue during this poll, with
// its parent issue id attached (a post carries no id of its own on the wire).
type postCandidate struct {
	issueID string
	raw     post
}

// postKey derives a post's dedupe identity. The wire carries no id, so
// issue id + createdDateTime + postType is the only combination it supports
// (live-measured 2026-07-27, #367) — and postType must be part of the key:
// two posts can share an issue and a createdDateTime and still be distinct
// (see TestPostDedupeKeyIncludesPostType).
func postKey(issueID string, raw post) string {
	return issueID + "|" + raw.CreatedDateTime + "|" + raw.PostType
}

// postTimeLayouts are tried in order to parse a post's createdDateTime.
var postTimeLayouts = []string{time.RFC3339, time.RFC3339Nano}

// parsePostTime parses a post's createdDateTime. ok is false for an empty or
// unparseable value — the caller drops the post rather than emit it stamped
// with arrival time (CLAUDE.md: a record with no parseable event time must be
// dropped, never stamped on arrival).
func parsePostTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range postTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// validPost is a postCandidate whose createdDateTime parsed successfully,
// carrying its derived dedupe key and parsed event time alongside.
type validPost struct {
	key     string
	issueID string
	raw     post
	t       time.Time
}

// processPosts is the entry point Collect calls once per cycle: it parses
// and validates every candidate, then either primes (cold start) or dedupes
// and emits (steady state). See the package doc for why a watermark, not a
// growing seen-set, survives the "full history re-served every poll" trait
// of the source endpoint.
func (c *Collector) processPosts(e telemetry.Emitter, outcomes *recordoutcome.Recorder, candidates []postCandidate) {
	if c.store == nil || c.tenantID == "" {
		return
	}

	cp, err := c.store.Load(c.tenantID, postsEndpoint)
	if err != nil {
		c.logger.Warn("servicehealth: post checkpoint load failed; starting from empty",
			"collector", collectorName, "error", err)
		cp = &checkpoint.Checkpoint{TenantID: c.tenantID, Endpoint: postsEndpoint, SeenIDs: checkpoint.NewSeenIDs()}
	}
	cp.TenantID, cp.Endpoint = c.tenantID, postsEndpoint
	if cp.SeenIDs == nil {
		cp.SeenIDs = checkpoint.NewSeenIDs()
	}

	valid := make([]validPost, 0, len(candidates))
	for _, cand := range candidates {
		t, ok := parsePostTime(cand.raw.CreatedDateTime)
		if !ok {
			outcomes.Add(recordoutcome.OutcomeFetched, 1)
			outcomes.Add(recordoutcome.OutcomeDropped, 1)
			outcomes.Cause(recordoutcome.CauseMissingEventTime)
			c.logger.Warn("servicehealth: post has missing/unparseable createdDateTime; dropping",
				"collector", collectorName, "issue_id", cand.issueID, "value", cand.raw.CreatedDateTime)
			continue
		}
		valid = append(valid, validPost{key: postKey(cand.issueID, cand.raw), issueID: cand.issueID, raw: cand.raw, t: t})
	}

	if cp.Watermark.IsZero() {
		c.primePosts(cp, valid)
	} else {
		c.emitNewPosts(e, outcomes, cp, valid)
	}

	if err := c.store.Save(cp); err != nil {
		c.logger.Warn("servicehealth: post checkpoint save failed", "collector", collectorName, "error", err)
	}
}

// primePosts runs on a cold-start checkpoint (zero watermark): it records the
// newest post's createdDateTime as the watermark, seeds the seen-set for the
// boundary immediately behind it, and emits NOTHING. See the package doc for
// why — the alternative is trying to emit the tenant's entire retained
// history on first run.
func (c *Collector) primePosts(cp *checkpoint.Checkpoint, valid []validPost) {
	newest := cp.Watermark
	sawAny := false
	for _, p := range valid {
		if !sawAny || p.t.After(newest) {
			newest = p.t
		}
		sawAny = true
	}
	if !sawAny {
		// Nothing to prime from (a healthy tenant with no posts yet, or an
		// all-unparseable set): still clear the cold-start marker so future
		// polls compare against a real watermark rather than priming forever.
		newest = c.now()
	}

	cutoff := newest.Add(-postOverlapWindow)
	for _, p := range valid {
		if !p.t.Before(cutoff) {
			cp.SeenIDs.Add(p.key, p.t)
		}
	}
	cp.Watermark = newest
	cp.OverlapWindow = postOverlapWindow
	cp.EvictStale()

	c.logger.Info("servicehealth: primed service-health post history on first run; emitting nothing this cycle",
		"collector", collectorName, "primed_posts", len(valid), "watermark", cp.Watermark)
}

// emitNewPosts runs on a warm checkpoint: it emits each post whose
// createdDateTime clears the watermark and has not already been seen within
// the overlap window, mirroring the watermark+SeenIDs shape
// intune.epm_elevation_events uses over its own (bounded) event stream.
func (c *Collector) emitNewPosts(e telemetry.Emitter, outcomes *recordoutcome.Recorder, cp *checkpoint.Checkpoint, valid []validPost) {
	cutoff := cp.Watermark.Add(-postOverlapWindow)
	newest := cp.Watermark
	sawAny := false

	for _, p := range valid {
		if p.t.Before(cutoff) {
			// Below the overlap window behind the watermark: already emitted
			// (or primed away) on a prior poll. Never needed in the seen-set
			// to be correctly skipped — see the package doc.
			outcomes.Add(recordoutcome.OutcomeFetched, 1)
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeDeduped, 1)
			continue
		}
		if cp.SeenIDs.Has(p.key) {
			outcomes.Add(recordoutcome.OutcomeFetched, 1)
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeDeduped, 1)
			continue
		}

		e.LogEvent(postTwin(p.issueID, p.raw, p.t))
		outcomes.Add(recordoutcome.OutcomeFetched, 1)
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		cp.SeenIDs.Add(p.key, p.t)
		if !sawAny || p.t.After(newest) {
			newest = p.t
		}
		sawAny = true
	}

	if sawAny && newest.After(cp.Watermark) {
		cp.Watermark = newest
	}
	cp.OverlapWindow = postOverlapWindow
	cp.EvictStale()
}

// postTwin renders one new service-health post as an OTLP log record,
// stamped with its OWN createdDateTime (never arrival time). The body is
// carried raw (no HTML stripping) and capped at postBodyCapBytes — truncated
// and flagged, never dropped, when it exceeds that cap. See the package doc
// and internal/semconv's attrs_m365_servicehealthpost.go for the full
// reasoning behind both decisions.
func postTwin(issueID string, p post, t time.Time) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrIssueId, issueID)
	telemetry.SetStr(attrs, semconv.AttrPostType, p.PostType)
	telemetry.SetStr(attrs, semconv.AttrContentType, p.Description.ContentType)

	content := p.Description.Content
	originalLen := len(content)
	truncated := originalLen > postBodyCapBytes
	if truncated {
		content = truncateUTF8(content, postBodyCapBytes)
	}
	telemetry.SetStr(attrs, semconv.AttrDescription, content)
	telemetry.SetBool(attrs, semconv.AttrBodyTruncated, truncated)
	if truncated {
		attrs[semconv.AttrDescriptionOriginalLength] = float64(originalLen)
	}

	return telemetry.Event{
		Name:      eventPost,
		Body:      fmt.Sprintf("Service-health post on issue %s (%s)", issueID, p.PostType),
		Severity:  telemetry.SeverityInfo,
		Timestamp: t,
		Attrs:     attrs,
	}
}

// truncateUTF8 returns s cut to at most maxBytes bytes, backing off at most a
// few bytes further so the result stays valid UTF-8 — the HTML body can
// contain multi-byte runes near the cut point, and an invalid partial rune
// would corrupt the OTLP attribute rather than just shorten it.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	return b
}
