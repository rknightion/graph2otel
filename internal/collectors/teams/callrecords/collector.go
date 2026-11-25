// Package callrecords collects Teams call records over Microsoft Graph v1.0.
// Wire projections use docs and de-identified live evidence where noted.
// Call, roster and stream logs share the hydrated Call and tenant checkpoint
// with the first-version metrics.
package callrecords

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/teams/geoip"
	"github.com/rknightion/graph2otel/internal/teams/quality"
	"github.com/rknightion/graph2otel/internal/teams/sites"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// Name is the collector and checkpoint namespace.
	Name = "teams.call_records"
	// First notification bound, used as a polling design input, not a measured lag:
	// https://learn.microsoft.com/graph/change-notifications-overview#latency
	arrivalAllowance = 150 * time.Minute
	// Teams' documented meeting and event duration limit:
	// https://learn.microsoft.com/microsoftteams/limits-specifications-teams#meetings-and-calls
	maxCallDuration = 30 * time.Hour
	// https://learn.microsoft.com/graph/api/callrecords-cloudcommunications-list-callrecords
	retention = 30 * 24 * time.Hour
	interval  = 5 * time.Minute
	lag       = time.Minute
	maxWindow = 6 * time.Hour
	// Both bounds are per tenant. Retrying two calls can add at most two
	// detail reads and two sets of maxContinuationPages auxiliary reads.
	maxDeferred    = 64
	retriesPerPoll = 2
)

// Collector owns the hydrated call path. Window ownership, record keys and
// persistence remain in logpipeline.
type Collector struct {
	*logpipeline.LogCollector
	graph      collectors.GraphClient
	sitesFile  *sites.File
	domains    sites.Domains
	geoIP      *geoip.Reader
	thresholds quality.Thresholds
	logger     *slog.Logger
	now        func() time.Time
	permit     chan struct{}
	versions   versionWindow // shared by poll and direct ingestion under permit
}

func init() { collectors.RegisterWindow(newCollector) }

func newCollector(deps collectors.WindowDeps) collectors.RegisteredWindow {
	const overlap = maxCallDuration + arrivalAllowance
	cfg := logpipeline.EndpointConfig{
		Path: path, CheckpointKey: Name, TimeField: "startDateTime", PageSize: -1,
		CollectorName: Name, SafetyLag: lag, Overlap: overlap,
		Deferred: &logpipeline.DeferredPolicy{Capacity: maxDeferred, RetriesPerPoll: retriesPerPoll, ValidID: validID},
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	thresholds := quality.DefaultThresholds()
	if deps.TeamsQualityThresholds != nil {
		thresholds = *deps.TeamsQualityThresholds
	}
	return collectors.RegisteredWindow{
		Collector: &Collector{
			LogCollector: logpipeline.NewLogCollector(Name, interval, lag, deps.TenantID, cfg, listFetcher{deps.Graph}, deps.Store),
			graph:        deps.Graph, sitesFile: deps.TeamsSites, domains: deps.TeamsInternalDomains, geoIP: deps.TeamsGeoIP,
			thresholds: thresholds, logger: logger, now: time.Now, permit: make(chan struct{}, 1),
		},
		InitialLookback: overlap,
		MaxWindow:       maxWindow,
	}
}

// Profiles is constant, including in census-only construction.
func (*Collector) Profiles() collector.ProfileSet { return collector.ProfileTeams }

// HighVolume identifies a traffic-shaped feed rather than an inventory.
func (*Collector) HighVolume() bool { return true }

// HighVolumeDefaultProfiles opts in tenants that select the Teams profile.
func (*Collector) HighVolumeDefaultProfiles() collector.ProfileSet { return collector.ProfileTeams }

// RequiredPermissions declares the Graph application permission for every read.
func (*Collector) RequiredPermissions() []string { return []string{"CallRecords.Read.All"} }

// CollectWindow opens one enrichment snapshot for the whole poll before
// delegating the range and checkpoint to logpipeline.
func (c *Collector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
	if err := c.acquire(ctx); err != nil {
		return from, err
	}
	defer c.release()
	observedAt := c.now().UTC()
	poll := c.run(observedAt)
	hw, err := poll.CollectWindow(ctx, from, to, e, outcomes)
	c.versions.publish(e, c.now().UTC())
	return hw, err
}

// CollectCall ingests a call by ID without moving the polling watermark. A
// notification receiver uses the same tenant Collector instance and passes
// only the call ID, never a URL or a version from the notification. Poll
// and direct fetch share hydration, enrichment, emission and durable dedupe.
func (c *Collector) CollectCall(ctx context.Context, id string, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	observedAt := c.now().UTC()
	poll := c.run(observedAt)
	err := poll.CollectRecord(ctx, map[string]any{"id": id}, e, outcomes)
	c.versions.publish(e, c.now().UTC())
	return err
}

func (c *Collector) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.permit <- struct{}{}:
		return nil
	}
}

func (c *Collector) release() { <-c.permit }

func (c *Collector) run(observedAt time.Time) logpipeline.LogCollector {
	var table *sites.Table
	if c.sitesFile != nil {
		if err := c.sitesFile.Reload(); err != nil {
			c.logger.Warn("Teams sites reload failed; keeping the last good snapshot", "collector", Name, "error", err)
		}
		table = c.sitesFile.Snapshot()
	}
	poll := *c.LogCollector
	floor := observedAt.Add(-retention).Truncate(time.Second)
	poll.Config.NotBefore = floor
	poll.Config.MaintainCheckpoint = func(cp *checkpoint.Checkpoint) { maintainMetrics(cp, floor) }
	poll.Config.Prepare = c.prepare(table, floor)
	return poll
}

func (c *Collector) prepare(table *sites.Table, floor time.Time) logpipeline.PrepareRecord {
	return func(ctx context.Context, row map[string]any, seen func(string) bool) (logpipeline.PreparedRecord, error) {
		var result logpipeline.PreparedRecord
		id, _ := row["id"].(string)
		if !validID(id) {
			return result, errors.New("no valid call ID in Teams list or direct fetch")
		}
		hint, _ := row["version"].(int64)
		if hint > 0 {
			if key := versionKey(id, hint); seen(key) {
				return logpipeline.PreparedRecord{Key: key}, nil
			}
		}
		d, err := getDetail(ctx, c.graph, id)
		if err != nil {
			return result, fmt.Errorf("call detail: %w", err)
		}
		version, err := d.Version.Int64()
		if d.ID != id || err != nil || version <= 0 || version < hint {
			return result, errors.New("missing, mismatched or stale ID/version in Teams call detail")
		}
		result.Key = versionKey(id, version)
		result.SourceVersion = version
		result.Time = parseTime(d.Start)
		if seen(result.Key) || result.Time.IsZero() || result.Time.Before(floor) {
			return result, nil
		}
		sessions, people, err := hydrate(ctx, c.graph, d)
		if err != nil {
			return result, err
		}
		call := mapCall(d, version, sessions, people, table, c.domains)
		assessCall(&call, c.thresholds)
		result.Deliver = func(e telemetry.Emitter) { c.emitCall(e, call) }
		result.Stage = func(cp *checkpoint.Checkpoint, e telemetry.Emitter) func() {
			return c.stageMetrics(cp, e, call, c.now().UTC())
		}
		return result, nil
	}
}

func versionKey(id string, version int64) string { return id + ":" + strconv.FormatInt(version, 10) }

// An input ID must be a single safe path component; no notification URL or
// path syntax can reach the authenticated Graph request.
func validID(id string) bool {
	return id != "" && id != "." && id != ".." && len(id) <= 256 && !strings.ContainsAny(id, "/\\%?#\x00\r\n")
}
