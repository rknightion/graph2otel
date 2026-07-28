// Package directoryrecovery is the Entra Backup and Recovery posture
// collector: GET /directory/recovery/snapshots and /directory/recovery/jobs
// (#334).
//
// It answers a question no other collector in this project can: is the
// directory actually recoverable right now. Every other Entra collector
// reports what the directory currently CONTAINS; this one reports whether a
// recent enough snapshot exists to put it back, and whether any recovery job
// has failed.
//
// # GA on v1.0 — deliberately NOT Experimental
//
// The issue was filed with a `beta-api` label and that label is wrong.
// Live-measured 2026-07-28 against m7kni as graph2otel-poller:
// GET /v1.0/directory/recovery/snapshots returns 200 with data identical to
// beta, and the entraRecoveryServices schema block is byte-identical in both
// $metadata documents. Per #183, Experimental is reserved for genuine Graph
// BETA surfaces, so this collector targets v1.0 and carries no opt-in gate.
//
// # Retention is 7 days, measured — and Microsoft's own docs disagree on it
//
// The Graph API overview page says snapshots are retained 5 days; the Entra
// admin-center page says 7. The wire says 7: exactly 7 snapshots, no
// @odata.nextLink, newest 2026-07-27T22:00:00Z, oldest 2026-07-21T22:00:00Z,
// taken daily at 22:00:00Z with no drift. Another wire-over-docs entry — the
// cadence here is measured, never inferred.
//
// # totalChangedObjects is declared in the EDM and never sent
//
// The snapshot EDM type declares createdDateTime, totalChangedObjects and
// nav properties recoveryJobs/recoveryPreviewJobs. The live response carries
// ONLY id and createdDateTime — and totalChangedObjects stays absent when
// named explicitly in $select and under $expand=recoveryJobs. Every numeric
// on both resources is therefore a POINTER: a bare int would publish a
// fabricated 0 for "objects changed since the last snapshot", which reads as
// a healthy quiet directory rather than as the missing field it is. This is
// the same correction #315 made for impactedResources earlier in this epic.
//
// # A snapshot id is not addressable
//
// GET /directory/recovery/snapshots/{id} returns 404 "Snapshot with
// identifier ... not found" for an id the collection returned one second
// earlier, with the trailing `==` both raw and percent-encoded. The
// collection is the only route, so this collector never fetches a snapshot
// individually. The id decodes as base64 of a unix epoch equal to the
// snapshot's own createdDateTime, which makes it a stable dedupe key but
// means it carries nothing the record does not already have.
//
// # Restore-capable surface, named here so it is never called
//
// The EDM binds a `cancel` action and `getChanges`/`getFailedChanges`
// functions to the job types, and recoveryAction includes softDelete, update
// and restore. #334 requires that none of these appear in runtime code. This
// collector issues exactly two requests, both plain GETs against the two
// collection URLs, and constructs no other URL anywhere.
//
// # An empty jobs collection is the healthy steady state
//
// GET /directory/recovery/jobs returns 200 with `value: []` on both API
// versions — a recovery job only exists once someone runs a restore. That
// makes this a "green tick is not evidence of data" collector, so the job
// gauge is split in two: jobs (a total, always emitted, 0 when the
// collection is empty) and jobs_by_status (points only for statuses actually
// observed). One gauge cannot say both "no job has ever run" and "we could
// not look", which is the same reasoning that gave #337 and #356 two gauges
// each.
//
// # Wirecheck
//
// The job status IS watched, derived from the bucket map the collector keys
// on so the watched set cannot drift from the mapped set. Note that the
// watched members come from the EDM's recoveryStatus enum rather than from
// observed rows — the jobs collection is empty here, so there are ZERO
// observed values. That is a stronger basis than the usual one-observed-value
// case this project refuses to watch on: the value set is Microsoft's own
// declared enum, not an inference from a single sample. Report-only, as
// always: an unexpected status buckets to "unknown" and is emitted verbatim
// on the twin, never dropped.
//
// Nothing on the snapshot resource is watched: it carries no enum at all,
// only an id and a timestamp.
package directoryrecovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
// self-observability, and the admin status page.
const collectorName = "entra.directory_recovery"

const (
	// snapshotsMetric is the count of retained directory snapshots. Bounded
	// by Microsoft's retention window (7 live-measured), never by tenant
	// size. Always emitted, including as 0 — a tenant with no snapshots at
	// all is the single most important thing this collector can report.
	snapshotsMetric = "entra.directory_recovery.snapshots"

	// newestSnapshotAgeMetric is how old the newest snapshot is, in seconds.
	// This is the actual posture signal: recoverability degrades with
	// staleness, and a snapshot count alone cannot express that. Emitted only
	// when at least one snapshot exists — a 0 on an empty collection would
	// claim a snapshot had just been taken.
	newestSnapshotAgeMetric = "entra.directory_recovery.newest_snapshot_age"

	// jobsMetric is the total number of recovery jobs. Always emitted, 0
	// included, so "no restore has ever run" is a measured zero rather than
	// an absent series indistinguishable from a disabled collector.
	jobsMetric = "entra.directory_recovery.jobs"

	// jobsByStatusMetric breaks the same jobs down by bucketed status. Points
	// exist only for statuses actually observed, so it is empty on a tenant
	// that has never run a recovery — which is why jobsMetric exists
	// separately.
	jobsByStatusMetric = "entra.directory_recovery.jobs_by_status"
)

const (
	// eventSnapshot is the log twin's EventName: one record per retained
	// snapshot.
	eventSnapshot = "entra.directory_recovery_snapshot"

	// eventJob is the log twin's EventName: one record per recovery job.
	eventJob = "entra.directory_recovery_job"
)

// defaultBaseURL is the Graph v1.0 root. See the package doc for why this is
// v1.0 and not beta.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

const (
	snapshotsPath = "/directory/recovery/snapshots"
	jobsPath      = "/directory/recovery/jobs"
)

// maxPages caps each hand-rolled nextLink loop. The live capture returns all
// 7 snapshots in one page with no nextLink and an empty jobs collection, so
// this is a runaway-loop backstop rather than a limit expected to bite.
const maxPages = 1000

// snapshot mirrors the entraRecoveryServices.snapshot resource. TotalChangedObjects
// is a POINTER because the field is declared in the EDM and never sent — see
// the package doc.
type snapshot struct {
	ID                  string `json:"id"`
	CreatedDateTime     string `json:"createdDateTime"`
	TotalChangedObjects *int64 `json:"totalChangedObjects"`
}

// recoveryJob mirrors the union of entraRecoveryServices.recoveryJobBase and
// recoveryJob. Every numeric is a POINTER: the jobs collection is empty on
// this tenant, so which of these Graph actually sends is UNMEASURED, and a
// bare int would fabricate a 0 for a count Graph never reported — including
// totalFailedChanges, where a fabricated 0 asserts a clean restore.
type recoveryJob struct {
	ID                            string `json:"id"`
	ODataType                     string `json:"@odata.type"`
	Status                        string `json:"status"`
	JobStartDateTime              string `json:"jobStartDateTime"`
	JobCompletionDateTime         string `json:"jobCompletionDateTime"`
	TargetStateDateTime           string `json:"targetStateDateTime"`
	TotalChangedObjectsCalculated *int64 `json:"totalChangedObjectsCalculated"`
	TotalChangedLinksCalculated   *int64 `json:"totalChangedLinksCalculated"`
	TotalObjectsModified          *int64 `json:"totalObjectsModified"`
	TotalLinksModified            *int64 `json:"totalLinksModified"`
	TotalFailedChanges            *int64 `json:"totalFailedChanges"`
}

// snapshotsPage / jobsPage are the collection envelopes.
type snapshotsPage struct {
	Value    []snapshot `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

type jobsPage struct {
	Value    []recoveryJob `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

// jobStatusBuckets maps the EDM's recoveryStatus members onto themselves.
// Identity-mapped rather than collapsed: every member is a distinct
// operational state and folding any pair together would hide a transition an
// operator cares about (calculating and running are not the same wait).
var jobStatusBuckets = map[string]string{
	"initialized":        "initialized",
	"running":            "running",
	"successful":         "successful",
	"failed":             "failed",
	"abandoned":          "abandoned",
	"calculating":        "calculating",
	"loadingData":        "loadingData",
	"unknownFutureValue": "unknownFutureValue",
}

// bucketJobStatus buckets a recovery job's status; empty or unrecognized
// collapses to "unknown".
func bucketJobStatus(raw string) string {
	if b, ok := jobStatusBuckets[raw]; ok {
		return b
	}
	return "unknown"
}

// knownJobStatuses is the wire assumption this collector watches at runtime
// (#233/#234) for the status label. Derived from jobStatusBuckets' OWN KEYS,
// so the watched set can never drift from the mapped set.
var knownJobStatuses = enumFromBuckets(jobStatusBuckets)

func enumFromBuckets(buckets map[string]string) wirecheck.Enum {
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	return wirecheck.NewEnum(keys...)
}

// previewODataType is the @odata.type discriminator for a preview job.
const previewODataType = "#microsoft.graph.entraRecoveryServices.recoveryPreviewJob"

// Collector polls the two directory-recovery collections.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	watch   *wirecheck.Reporter
	now     func() time.Time
}

// New builds the directory-recovery collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		g:       g,
		baseURL: defaultBaseURL,
		logger:  logger,
		watch:   wirecheck.New(collectorName, logger),
		now:     time.Now,
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Snapshots are taken once a
// day (live-measured, 22:00:00Z with no drift), so nothing here changes
// faster than that. An hourly poll keeps the newest-snapshot age gauge
// usefully current for a staleness alert without hammering a directory
// endpoint that has at most 7 rows to return.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"EntraBackup.Read.All"}
}

// Collect fetches both collections and emits the bounded gauges plus one log
// twin per snapshot and per job. A failure on either fetch aborts before
// emitting anything: a snapshot count built from a partial walk would read as
// "this tenant retains fewer snapshots now", which is precisely the alarm
// this collector exists to raise and must never raise falsely.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	snaps, err := c.fetchSnapshots(ctx, outcomes)
	if err != nil {
		return err
	}
	jobs, err := c.fetchJobs(ctx, outcomes)
	if err != nil {
		return err
	}

	now := c.now()

	e.GaugeSnapshot(snapshotsMetric, "{snapshot}",
		"Count of retained Entra directory recovery snapshots.",
		[]telemetry.GaugePoint{{Value: float64(len(snaps))}})

	// Newest-snapshot age: emitted only when a snapshot with a PARSEABLE
	// createdDateTime exists. An unparseable timestamp is not an age of zero.
	if age, ok := newestAge(snaps, now); ok {
		e.GaugeSnapshot(newestSnapshotAgeMetric, "s",
			"Age of the newest Entra directory recovery snapshot.",
			[]telemetry.GaugePoint{{Value: age.Seconds()}})
	} else {
		e.GaugeSnapshot(newestSnapshotAgeMetric, "s",
			"Age of the newest Entra directory recovery snapshot.", nil)
	}

	e.GaugeSnapshot(jobsMetric, "{job}",
		"Total count of Entra directory recovery jobs.",
		[]telemetry.GaugePoint{{Value: float64(len(jobs))}})

	buckets := map[string]int64{}
	for _, j := range jobs {
		buckets[bucketJobStatus(j.Status)]++
	}
	points := make([]telemetry.GaugePoint, 0, len(buckets))
	for status, count := range buckets {
		points = append(points, telemetry.GaugePoint{
			Value: float64(count),
			Attrs: telemetry.Attrs{semconv.AttrStatus: status},
		})
	}
	e.GaugeSnapshot(jobsByStatusMetric, "{job}",
		"Count of Entra directory recovery jobs, per status.", points)

	for _, s := range snaps {
		e.LogEvent(snapshotTwin(s, now))
	}
	for _, j := range jobs {
		c.watch.Value(e, semconv.AttrStatus, j.Status, knownJobStatuses)
		e.LogEvent(jobTwin(j))
	}
	entraoutcome.Emitted(outcomes, uint64(len(snaps)+len(jobs)))

	return nil
}

// newestAge returns the age of the newest snapshot with a parseable
// createdDateTime. Graph returns the collection newest-first (live-measured),
// but this scans every row rather than trusting that ordering: reading
// element 0 would silently report a stale age if Graph ever reversed the
// order, and a staleness signal that under-reports is worse than none.
func newestAge(snaps []snapshot, now time.Time) (time.Duration, bool) {
	var newest time.Time
	var found bool
	for _, s := range snaps {
		t, err := time.Parse(time.RFC3339, s.CreatedDateTime)
		if err != nil {
			continue
		}
		if !found || t.After(newest) {
			newest, found = t, true
		}
	}
	if !found {
		return 0, false
	}
	return now.Sub(newest), true
}

// fetchSnapshots pages through the snapshots collection.
func (c *Collector) fetchSnapshots(ctx context.Context, outcomes *recordoutcome.Recorder) ([]snapshot, error) {
	var out []snapshot
	url := c.baseURL + snapshotsPath
	for pages := 0; url != ""; pages++ {
		if pages >= maxPages {
			entraoutcome.SourceError(outcomes)
			return nil, fmt.Errorf("directoryrecovery: snapshot pagination exceeded %d pages", maxPages)
		}
		body, err := c.g.RawGet(ctx, url)
		if err != nil {
			entraoutcome.SourceError(outcomes)
			c.logger.Warn("recovery snapshots fetch failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("directoryrecovery: fetch snapshots: %w", err)
		}
		var page snapshotsPage
		if err := json.Unmarshal(body, &page); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("recovery snapshots decode failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("directoryrecovery: decode snapshots: %w", err)
		}
		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

// fetchJobs pages through the jobs collection.
func (c *Collector) fetchJobs(ctx context.Context, outcomes *recordoutcome.Recorder) ([]recoveryJob, error) {
	var out []recoveryJob
	url := c.baseURL + jobsPath
	for pages := 0; url != ""; pages++ {
		if pages >= maxPages {
			entraoutcome.SourceError(outcomes)
			return nil, fmt.Errorf("directoryrecovery: job pagination exceeded %d pages", maxPages)
		}
		body, err := c.g.RawGet(ctx, url)
		if err != nil {
			entraoutcome.SourceError(outcomes)
			c.logger.Warn("recovery jobs fetch failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("directoryrecovery: fetch jobs: %w", err)
		}
		var page jobsPage
		if err := json.Unmarshal(body, &page); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("recovery jobs decode failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("directoryrecovery: decode jobs: %w", err)
		}
		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

// snapshotTwin renders one snapshot as one entra.directory_recovery_snapshot
// record. Timestamp is deliberately left zero (emitter stamps "now"): this is
// a STATE twin reporting that a snapshot exists as of this poll, not an event
// that happened at createdDateTime. Backdating it would also push the oldest
// retained snapshot — exactly 7 days old at the retention edge — against the
// backend's 7-day accept horizon every single cycle.
func snapshotTwin(s snapshot, now time.Time) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, s.ID)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, s.CreatedDateTime)
	if t, err := time.Parse(time.RFC3339, s.CreatedDateTime); err == nil {
		attrs[semconv.AttrSnapshotAgeSeconds] = now.Sub(t).Seconds()
	}
	if s.TotalChangedObjects != nil {
		attrs[semconv.AttrTotalChangedObjects] = float64(*s.TotalChangedObjects)
	}
	return telemetry.Event{
		Name:     eventSnapshot,
		Body:     fmt.Sprintf("directory recovery snapshot %s taken %s", s.ID, s.CreatedDateTime),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// jobTwin renders one recovery job as one entra.directory_recovery_job
// record. The raw status is emitted VERBATIM (not the bucket), so an enum
// member Microsoft adds later is preserved on the record even while the gauge
// buckets it to "unknown".
func jobTwin(j recoveryJob) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, j.ID)
	telemetry.SetStr(attrs, semconv.AttrStatus, j.Status)
	telemetry.SetStr(attrs, semconv.AttrOdataType, j.ODataType)
	telemetry.SetStr(attrs, semconv.AttrJobStartDateTime, j.JobStartDateTime)
	telemetry.SetStr(attrs, semconv.AttrJobCompletionDateTime, j.JobCompletionDateTime)
	telemetry.SetStr(attrs, semconv.AttrTargetStateDateTime, j.TargetStateDateTime)
	if j.ODataType != "" {
		telemetry.SetBool(attrs, semconv.AttrIsPreview, j.ODataType == previewODataType)
	}
	setInt(attrs, semconv.AttrTotalChangedObjectsCalculated, j.TotalChangedObjectsCalculated)
	setInt(attrs, semconv.AttrTotalChangedLinksCalculated, j.TotalChangedLinksCalculated)
	setInt(attrs, semconv.AttrTotalObjectsModified, j.TotalObjectsModified)
	setInt(attrs, semconv.AttrTotalLinksModified, j.TotalLinksModified)
	setInt(attrs, semconv.AttrTotalFailedChanges, j.TotalFailedChanges)

	return telemetry.Event{
		Name:     eventJob,
		Body:     fmt.Sprintf("directory recovery job %s: %s", j.ID, j.Status),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// setInt writes a pointer-modeled numeric only when the wire carried it. An
// absent value emits NO key rather than a zero — see the package doc.
func setInt(attrs telemetry.Attrs, key string, v *int64) {
	if v != nil {
		attrs[key] = float64(*v)
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
