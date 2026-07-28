// Package clouddiscovery is the Microsoft Defender for Cloud Apps (MDCA)
// Cloud Discovery APP INVENTORY collector (#361): what shadow-IT cloud
// services Cloud Discovery has DISCOVERED from a tenant's uploaded traffic
// logs, plus the health of the upload streams feeding that discovery.
//
// # The gap this closes
//
// mdca.discovery_parse (internal/collectors/mdca/discoveryparse) answers "is
// log parsing working" — it never names a single discovered app. Defender's
// OAuth-app posture (a different, unrelated signal) covers apps a user
// CONSENTED to; this collector covers apps discovered from network TRAFFIC,
// consented or not — the actual shadow-IT surface.
//
// # A DIFFERENT transport from mdca.discovery_parse
//
// discoveryparse reaches the legacy MDCA portal API with a static
// Authorization: Token credential — no azidentity, no Graph app role. This
// collector is ordinary Graph app-only auth against the Graph BETA surface
// GET /beta/security/dataDiscovery/cloudAppDiscovery/{uploadedStreams,
// aggregatedAppsDetails} — a genuine Graph beta endpoint (#183), hence
// Experimental()==true, gated on the CloudApp-Discovery.Read.All scope newly
// granted to graph2otel-poller. It shares the mdca.* domain namespace with
// discoveryparse (same product, same tenant-facing "MDCA" concept) but is a
// structurally unrelated fetch path — two collectors, two transports, one
// domain.
//
// # The fetch: 1+N per tenant, bounded by tenant CONFIGURATION not SIZE
//
// One GET lists the tenant's uploaded streams (6 live, #361); one further GET
// per stream fetches that stream's aggregated app details over the trailing
// 30 days, paging on @odata.nextLink. Stream count is bounded by how many log
// sources an admin has wired up, not by tenant population, so no HighVolume
// opt-in gate applies — same reasoning as the three-singleton fetch in
// entra/tenantpolicy. The aggregatedAppsDetails endpoint throttles (a live 429
// was observed 2026-07-28 mid-probe: `{"detail":"Request was throttled.
// Expected available in 1 second."}`); the shared graphclient transport owns
// backoff/retry, so this collector does not implement its own.
//
// Each stream's app list is capped at maxAppsPerStream, stopping the page walk
// (not merely truncating client-side) the moment the cap is reached — the cap
// is both a cost control against the throttle and a defensive backstop, same
// role as authmethodspolicy's maxTargetIdentifiers. A capped stream reports
// its own apps_truncated=true on its discovery_stream twin, and the tenant-wide
// mdca.cloud_discovery.apps_truncated metric counts how many streams hit it —
// a silent cap would report clean success over an unknown remainder.
//
// # Cardinality (#112/#114): metrics carry aggregates, logs carry entities
//
//   - mdca.cloud_discovery.apps{category} — discovered-app count per category.
//     category is a Graph-supplied enum (28 distinct values observed live on a
//     100-app sample, 2026-07-28, #361) — genuinely bounded by Microsoft's own
//     fixed taxonomy, unlike an admin-defined set. This is the metric this
//     collector exists for: "how many generativeAi apps is my traffic
//     reaching" is a question a log twin answers only via a slow `count by`.
//   - mdca.cloud_discovery.apps.by_risk{risk_band} — discovered-app count by
//     OUR banding of riskScore (low/medium/high/critical — see riskBand).
//     Banding, not the raw 1-10 score, is the deliberate choice: a raw score
//     as a label would be 10 series and defensible under the cardinality
//     rule, but nobody alerts on "risk_score=7"; an operator alerts on "the
//     high-risk bucket grew". The raw score still rides the discovered_app
//     twin via semconv.AttrRiskScore.
//   - mdca.cloud_discovery.streams{is_snapshot_report} — upload-stream count,
//     bucketed true/false/unknown (a stream lacking the field entirely — see
//     the absent-is-not-false note below).
//   - mdca.cloud_discovery.log_files.total — the SUM of logFileCount across
//     every returned stream, UNLABELED. A per-stream log-file gauge would key
//     a series by stream identity, which grows with how many log sources an
//     admin adds — exactly the shape the cardinality rule forbids; the total
//     is the bounded aggregate, the per-stream detail rides the
//     discovery_stream twin's AttrLogFileCount instead.
//   - mdca.cloud_discovery.apps_truncated — an UNLABELED count of streams
//     whose app list hit the cap (see above).
//
// App identity, display name, domains, tags, user/IP counts and traffic bytes
// are LOG-ONLY (mdca.discovered_app) — never a metric label. A series keyed
// by discovered-app name grows with the tenant's shadow-IT surface, exactly
// the unbounded shape #112 forbids. mdca.discovery_stream carries the
// per-stream detail a bounded gauge cannot (privacy switches, supported
// entity/traffic types, the raw log-file count).
//
// # Domains: capped, but the count is uncapped
//
// A discovered app's domains array is capped at maxDomains on the twin, with
// a true (uncapped) domain_count and a domains_truncated flag. The widest app
// observed live (#361, 2026-07-28) carries 355 domains — truncation is the
// NORMAL case here, not an edge case, which is why the true count must always
// ride alongside the capped list rather than only appearing when truncation
// happens. tags are NOT capped: this collector's live sample never observed a
// non-empty tags array, so there is no evidence yet that it needs the same
// treatment (the same "don't generalize an awkward-to-model field into an
// unsafe one" caution CLAUDE.md gives for content exclusions applies in
// reverse here — don't invent a cap against a shape nobody has seen).
//
// # Absent is not false
//
// anonymizeMachineData, anonymizeUserData, isSnapshotReport and every numeric
// field this collector reads are optional on the wire and decoded as
// pointers. A plain bool would fabricate `false` for a tenant/stream where
// Graph simply did not carry the field — the worst possible field to get
// wrong is a privacy setting. An absent value omits the attribute on the
// twin; on the streams metric, an absent isSnapshotReport buckets to
// "unknown" (a third bounded value) rather than silently joining "false".
//
// # wirecheck: category is watched, nothing else is
//
// category is the one field here with real evidence behind it (28 distinct
// live values on 100 rows) AND it keys a metric label, which is exactly what
// internal/wirecheck exists to guard: an unmapped category must never drop an
// app (report-only), but it must be visible if Microsoft adds a 29th. The
// watched set (categoryEnum) is built from knownCategories, the same map that
// documents what was actually observed — never restated as a second list —
// so the watched set cannot drift from the documented one. Every other field
// here (riskScore's exact bounds, tags' shape, domains' cardinality) has no
// comparable evidence of a closed value set and is deliberately left
// unwatched.
package clouddiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability and the admin status page.
const collectorName = "mdca.cloud_discovery"

// betaBaseURL is the Graph beta service root — dataDiscovery/cloudAppDiscovery
// has no v1.0 form.
const betaBaseURL = "https://graph.microsoft.com/beta"

// streamsPath lists the tenant's Cloud Discovery upload streams.
const streamsPath = "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"

// aggregationPeriod is the trailing window aggregatedAppsDetails aggregates
// over. Fixed at 30 days: the collector reports current discovery state each
// poll, not a rolling comparison across periods.
const aggregationPeriod = "P30D"

// maxAppsPerStream caps how many discovered-app rows one stream contributes
// per poll, stopping the page walk (not merely truncating after fetching
// everything) once reached — both a cost control against the endpoint's
// observed throttling and a defensive backstop against a runaway tenant.
const maxAppsPerStream = 500

// maxDomains bounds the domains array every discovered_app twin carries. See
// the package doc: 355 domains observed live means truncation is normal here.
const maxDomains = 50

// Risk-band boundaries. THESE ARE OUR OWN BANDING, not a scale Microsoft
// defines — riskScore is a raw 1-10 integer; an operator alerts on a bucket
// crossing, not a one-point wiggle in the raw score. Named consts so the
// boundary is asserted, not just implied by the switch in riskBand.
const (
	riskBandLowMax    = 3 // 1-3: low
	riskBandMediumMax = 6 // 4-6: medium
	riskBandHighMax   = 8 // 7-8: high
	// 9-10: critical
)

// Metric names this collector emits (mdca.* domain namespace).
const (
	metricApps          = "mdca.cloud_discovery.apps"
	metricAppsByRisk    = "mdca.cloud_discovery.apps.by_risk"
	metricStreams       = "mdca.cloud_discovery.streams"
	metricLogFilesTotal = "mdca.cloud_discovery.log_files.total"
	metricAppsTruncated = "mdca.cloud_discovery.apps_truncated"
)

// Log EventNames this collector emits. Both are LOG-ONLY.
const (
	eventApp    = "mdca.discovered_app"
	eventStream = "mdca.discovery_stream"
)

// knownCategories is every distinct discoveredCloudApp.category value observed
// live 2026-07-28 on a 100-app sample (#361). This is the SOLE declaration of
// that set — categoryEnum (below) derives from it, so the wirecheck watch list
// cannot drift from what this comment documents as observed.
var knownCategories = map[string]struct{}{
	"advertising":              {},
	"aiModelProvider":          {},
	"cloudComputingPlatform":   {},
	"cloudStorage":             {},
	"codeHosting":              {},
	"collaboration":            {},
	"communications":           {},
	"contentManagement":        {},
	"contentSharing":           {},
	"customerSupport":          {},
	"dataAnalytics":            {},
	"developmentTools":         {},
	"eCommerce":                {},
	"generativeAi":             {},
	"health":                   {},
	"hostingServices":          {},
	"internetOfThings":         {},
	"itServices":               {},
	"marketing":                {},
	"newsAndEntertainment":     {},
	"onlineMeetings":           {},
	"personalInstantMessaging": {},
	"productivity":             {},
	"security":                 {},
	"socialNetwork":            {},
	"transportationAndTravel":  {},
	"webAnalytics":             {},
	"websiteMonitoring":        {},
}

// categoryEnum is derived from knownCategories (never restated as a literal
// list) for internal/wirecheck to watch. See the package doc's wirecheck
// section.
var categoryEnum = wirecheck.NewEnum(categoryKeys()...)

func categoryKeys() []string {
	keys := make([]string, 0, len(knownCategories))
	for k := range knownCategories {
		keys = append(keys, k)
	}
	return keys
}

// uploadedStream mirrors the subset of a Graph uploadedStreams entry this
// collector reads. Privacy switches and every numeric are pointers: see the
// package doc's "absent is not false" section.
type uploadedStream struct {
	ID                       string   `json:"id"`
	DisplayName              string   `json:"displayName"`
	CreatedDateTime          string   `json:"createdDateTime"`
	LastDataReceivedDateTime string   `json:"lastDataReceivedDateTime"`
	LastModifiedDateTime     string   `json:"lastModifiedDateTime"`
	SupportedEntityTypes     []string `json:"supportedEntityTypes"`
	SupportedTrafficTypes    []string `json:"supportedTrafficTypes"`
	AnonymizeMachineData     *bool    `json:"anonymizeMachineData"`
	AnonymizeUserData        *bool    `json:"anonymizeUserData"`
	IsSnapshotReport         *bool    `json:"isSnapshotReport"`
	LogFileCount             *int64   `json:"logFileCount"`
}

// discoveredApp mirrors the subset of a Graph aggregatedAppsDetails entry this
// collector reads.
type discoveredApp struct {
	ID                            string   `json:"id"`
	DisplayName                   string   `json:"displayName"`
	Category                      string   `json:"category"`
	RiskScore                     *int64   `json:"riskScore"`
	Tags                          []string `json:"tags"`
	Domains                       []string `json:"domains"`
	UserCount                     *int64   `json:"userCount"`
	IPAddressCount                *int64   `json:"ipAddressCount"`
	TransactionCount              *int64   `json:"transactionCount"`
	UploadNetworkTrafficInBytes   *int64   `json:"uploadNetworkTrafficInBytes"`
	DownloadNetworkTrafficInBytes *int64   `json:"downloadNetworkTrafficInBytes"`
	LastSeenDateTime              string   `json:"lastSeenDateTime"`
}

// appsPage is the aggregatedAppsDetails collection envelope.
type appsPage struct {
	Value    []discoveredApp `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
}

// Collector polls Cloud Discovery's uploaded streams and each stream's
// aggregated app details.
type Collector struct {
	g         collectors.GraphClient
	baseURL   string
	logger    *slog.Logger
	wirecheck *wirecheck.Reporter
}

// New builds the cloud-discovery collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		g:         g,
		baseURL:   betaBaseURL,
		logger:    logger,
		wirecheck: wirecheck.New(collectorName, logger),
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Discovery aggregates update
// only when a stream ingests new log data, and the per-stream app fan-out is
// the expensive part of this poll (up to 1+maxAppsPerStream/pagesize requests
// per tenant) — an hourly cadence matches how often the underlying data can
// meaningfully change without over-polling a throttled endpoint.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks this collector beta/opt-in: dataDiscovery/
// cloudAppDiscovery exists only on the Graph beta surface (#183).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the Graph application scope newly granted to
// graph2otel-poller for this collector.
func (c *Collector) RequiredPermissions() []string {
	return []string{"CloudApp-Discovery.Read.All"}
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

// Collect fetches the tenant's upload streams, then each stream's aggregated
// app details, and emits the bounded gauges plus both log twins. Streams and
// apps degrade independently: a single stream's app fetch failing still emits
// every stream twin and every other stream's apps, aggregated into the
// returned error rather than aborting the whole poll.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+streamsPath, nil, outcomes)
	if err != nil {
		entraoutcome.SourceError(outcomes)
		return fmt.Errorf("clouddiscovery: fetch uploadedStreams: %w", err)
	}

	var errs []error
	categoryCounts := map[string]float64{}
	riskBandCounts := map[string]float64{}
	snapshotCounts := map[string]float64{}
	var logFilesTotal int64
	var streamsTruncated float64

	for _, raw := range raws {
		var s uploadedStream
		if err := json.Unmarshal(raw, &s); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			errs = append(errs, fmt.Errorf("decode uploadedStream: %w", err))
			continue
		}
		if s.ID == "" {
			entraoutcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			c.logger.Warn("clouddiscovery: skipping stream with empty id", "collector", collectorName)
			continue
		}

		snapshotCounts[snapshotBucket(s.IsSnapshotReport)]++
		if s.LogFileCount != nil {
			logFilesTotal += *s.LogFileCount
		}
		entraoutcome.Emitted(outcomes, 1)

		apps, truncated, err := c.fetchAppsForStream(ctx, s.ID, outcomes)
		if err != nil {
			entraoutcome.SourceError(outcomes)
			errs = append(errs, fmt.Errorf("fetch aggregatedAppsDetails for stream %s: %w", s.ID, err))
		}
		if truncated {
			streamsTruncated++
		}

		for _, app := range apps {
			c.emitApp(e, app, s)
			if app.Category != "" {
				categoryCounts[app.Category]++
			} else {
				categoryCounts["unknown"]++
			}
			if app.RiskScore != nil {
				riskBandCounts[riskBand(*app.RiskScore)]++
			}
		}
		entraoutcome.Emitted(outcomes, uint64(len(apps)))

		e.LogEvent(streamTwin(s, len(apps), truncated))
	}

	emitCountGauge(e, metricApps, "{app}",
		"Cloud Discovery apps discovered from uploaded traffic logs in the trailing 30 days, by category.",
		semconv.AttrCategory, categoryCounts)
	emitCountGauge(e, metricAppsByRisk, "{app}",
		"Cloud Discovery apps discovered in the trailing 30 days, by risk band (this collector's own low/medium/high/critical banding of riskScore).",
		semconv.AttrRiskBand, riskBandCounts)
	emitCountGauge(e, metricStreams, "{stream}",
		"Cloud Discovery upload streams configured for the tenant, by whether the stream is a one-off snapshot report.",
		semconv.AttrIsSnapshotReport, snapshotCounts)

	e.Gauge(metricLogFilesTotal, "{file}",
		"Sum of logFileCount across every Cloud Discovery upload stream. Unlabeled: a per-stream figure would key a series by stream identity, which grows with tenant configuration.",
		float64(logFilesTotal), nil)
	e.Gauge(metricAppsTruncated, "{stream}",
		"Count of Cloud Discovery upload streams whose discovered-app list hit the per-poll cap. Non-zero means some discovered apps for that stream were not processed this cycle.",
		streamsTruncated, nil)

	return errors.Join(errs...)
}

// emitCountGauge renders a bounded string->count map as a GaugeSnapshot, one
// point per key, labeled by attrKey. Emits nothing when counts is empty (a
// total upstream failure should not publish a hollow snapshot).
func emitCountGauge(e telemetry.Emitter, name, unit, desc, attrKey string, counts map[string]float64) {
	if len(counts) == 0 {
		return
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: v,
			Attrs: telemetry.Attrs{attrKey: k},
		})
	}
	e.GaugeSnapshot(name, unit, desc, points)
}

// snapshotBucket buckets an uploadedStream's IsSnapshotReport into the bounded
// three-value metric label set: "true", "false", or "unknown" when the field
// was absent from the wire (never silently folded into "false" — see the
// package doc's absent-is-not-false section).
func snapshotBucket(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "true"
	}
	return "false"
}

// riskBand maps a discovered app's raw 1-10 riskScore to this collector's own
// bounded band. See the package doc and the const block above for why this is
// a deliberate re-banding, not Microsoft's own scale.
func riskBand(score int64) string {
	switch {
	case score <= riskBandLowMax:
		return "low"
	case score <= riskBandMediumMax:
		return "medium"
	case score <= riskBandHighMax:
		return "high"
	default:
		return "critical"
	}
}

// fetchAppsForStream pages aggregatedAppsDetails for one stream, stopping
// (not just truncating after the fact) once maxAppsPerStream is reached so a
// capped stream costs no further requests against a throttled endpoint. A
// page-fetch or decode failure on any page returns the error and whatever was
// already accumulated is discarded by the caller (Collect logs the failure
// and moves on to the next stream) — a partially-paged stream is retried
// whole next poll rather than emitting an inconsistent partial app list.
func (c *Collector) fetchAppsForStream(ctx context.Context, streamID string, outcomes *recordoutcome.Recorder) ([]discoveredApp, bool, error) {
	next := c.baseURL + streamsPath + "/" + url.PathEscape(streamID) +
		fmt.Sprintf("/aggregatedAppsDetails(period=duration'%s')", aggregationPeriod)

	var out []discoveredApp
	for next != "" {
		body, err := c.g.RawGet(ctx, next)
		if err != nil {
			return nil, false, err
		}
		var page appsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, false, fmt.Errorf("decode aggregatedAppsDetails page: %w", err)
		}
		out = append(out, page.Value...)
		if len(out) >= maxAppsPerStream {
			return out[:maxAppsPerStream:maxAppsPerStream], true, nil
		}
		next = page.NextLink
	}
	return out, false, nil
}

// emitApp renders one discovered app as an mdca.discovered_app log record,
// reports its category to wirecheck, and records the app on e.
func (c *Collector) emitApp(e telemetry.Emitter, app discoveredApp, s uploadedStream) {
	c.wirecheck.Value(e, semconv.AttrCategory, app.Category, categoryEnum)

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, app.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, app.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrCategory, app.Category)
	if app.RiskScore != nil {
		attrs[semconv.AttrRiskScore] = float64(*app.RiskScore)
		telemetry.SetStr(attrs, semconv.AttrRiskBand, riskBand(*app.RiskScore))
	}
	telemetry.SetStrs(attrs, semconv.AttrTags, app.Tags)

	capped, truncated := capStrings(app.Domains, maxDomains)
	telemetry.SetStrs(attrs, semconv.AttrDomains, capped)
	if len(app.Domains) > 0 {
		attrs[semconv.AttrDomainCount] = float64(len(app.Domains))
	}
	telemetry.SetBool(attrs, semconv.AttrDomainsTruncated, truncated)

	if app.UserCount != nil {
		attrs[semconv.AttrUserCount] = float64(*app.UserCount)
	}
	if app.IPAddressCount != nil {
		attrs[semconv.AttrIpAddressCount] = float64(*app.IPAddressCount)
	}
	if app.TransactionCount != nil {
		attrs[semconv.AttrTransactionsCount] = float64(*app.TransactionCount)
	}
	if app.UploadNetworkTrafficInBytes != nil {
		attrs[semconv.AttrUploadBytes] = float64(*app.UploadNetworkTrafficInBytes)
	}
	if app.DownloadNetworkTrafficInBytes != nil {
		attrs[semconv.AttrDownloadBytes] = float64(*app.DownloadNetworkTrafficInBytes)
	}
	telemetry.SetStr(attrs, semconv.AttrLastSeenDateTime, app.LastSeenDateTime)
	telemetry.SetStr(attrs, semconv.AttrStreamId, s.ID)
	telemetry.SetStr(attrs, semconv.AttrStreamDisplayName, s.DisplayName)

	e.LogEvent(telemetry.Event{
		Name:     eventApp,
		Body:     fmt.Sprintf("Cloud Discovery app %s (%s): category=%s", app.ID, app.DisplayName, app.Category),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	})
}

// streamTwin renders one uploadedStream as an mdca.discovery_stream log
// record. appsDiscovered/truncated report what THIS poll saw for the stream,
// post-cap.
func streamTwin(s uploadedStream, appsDiscovered int, truncated bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, s.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, s.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, s.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastDataReceivedDateTime, s.LastDataReceivedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, s.LastModifiedDateTime)
	telemetry.SetStrs(attrs, semconv.AttrSupportedEntityTypes, s.SupportedEntityTypes)
	telemetry.SetStrs(attrs, semconv.AttrSupportedTrafficTypes, s.SupportedTrafficTypes)
	if s.AnonymizeMachineData != nil {
		telemetry.SetBool(attrs, semconv.AttrAnonymizeMachineData, *s.AnonymizeMachineData)
	}
	if s.AnonymizeUserData != nil {
		telemetry.SetBool(attrs, semconv.AttrAnonymizeUserData, *s.AnonymizeUserData)
	}
	if s.IsSnapshotReport != nil {
		telemetry.SetBool(attrs, semconv.AttrIsSnapshotReport, *s.IsSnapshotReport)
	}
	if s.LogFileCount != nil {
		attrs[semconv.AttrLogFileCount] = float64(*s.LogFileCount)
	}
	attrs[semconv.AttrAppsDiscovered] = float64(appsDiscovered)
	telemetry.SetBool(attrs, semconv.AttrAppsTruncated, truncated)

	return telemetry.Event{
		Name:     eventStream,
		Body:     fmt.Sprintf("Cloud Discovery upload stream %s (%s): %d apps discovered", s.ID, s.DisplayName, appsDiscovered),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// capStrings caps vals at max, reporting whether it had to. Never mutates
// vals — the returned slice on the truncated path is a fresh subslice header,
// matching the identical helper in authmethodspolicy/authstrength/etc (this
// codebase's convention is a local copy per package, not a shared exported
// helper).
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
