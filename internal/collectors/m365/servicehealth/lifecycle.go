package servicehealth

import (
	"fmt"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// Poller read-back (#666): both the filtered issues list and
	// issues nested under healthOverviews return this exact service value.
	// The expanded Teams overview already carried 56 issues, 55 resolved
	// with an endDateTime. No second request or absence-based inference.
	teamsService           = "Microsoft Teams"
	teamsLifecycleEndpoint = overviewsPath + "#teams-lifecycle"
	// Forget issues absent for a week. At capacity, decline new opens rather
	// than evicting live completion markers and admitting resolution replay.
	teamsLifecycleRetention = 7 * 24 * time.Hour
	teamsLifecycleLimit     = 1024
)

// processTeamsLifecycle runs only after a fully decoded snapshot. The separate
// checkpoint holds observed opens and their completion markers, not every
// historical closure. An invalid closure leaves the issue pending. Absence
// does not resolve an issue; a pending ID can still resolve when it reappears
// before expiry. A completed ID cannot be re-armed while its marker is kept.
func (c *Collector) processTeamsLifecycle(e telemetry.Emitter, outcomes *recordoutcome.Recorder, issues []issue) error {
	cp, err := c.store.Load(c.tenantID, teamsLifecycleEndpoint)
	if err != nil {
		return fmt.Errorf("load Teams service-health lifecycle: %w", err)
	}
	state := cp.TeamsServiceHealth
	if state == nil {
		state = make(map[string]checkpoint.ServiceHealthIssueState)
	}
	previousLen := len(state)
	now := c.now().UTC()
	cutoff := now.Add(-teamsLifecycleRetention)
	for id, item := range state {
		if item.LastSeen.Before(cutoff) {
			delete(state, id)
		}
	}

	var skipped int
	for _, is := range issues {
		item, tracked := state[is.ID]
		switch {
		case !is.resolved():
			// Retain a completion marker even if a stale open row reappears.
			if !tracked && len(state) >= teamsLifecycleLimit {
				skipped++
				continue
			}
		case !tracked:
			continue // cold-start history is neither emitted nor remembered
		case !item.Resolved:
			if event, ok := resolutionTwin(is, now); ok {
				e.LogEvent(event)
				outcomes.Add(recordoutcome.OutcomeFetched, 1)
				outcomes.Add(recordoutcome.OutcomeMapped, 1)
				outcomes.Add(recordoutcome.OutcomeEmitted, 1)
				item.Resolved = true
			}
		}
		item.LastSeen = now
		state[is.ID] = item
	}

	if skipped > 0 {
		c.logger.Warn("servicehealth: Teams lifecycle checkpoint at capacity; not tracking new opens",
			"collector", collectorName, "skipped", skipped, "limit", teamsLifecycleLimit)
	}
	if previousLen == 0 && len(state) == 0 {
		return nil
	}
	cp.TeamsServiceHealth = state
	// Save after asking the emitter to enqueue. Normal restarts dedupe, but
	// a crash/save failure before this completes can replay a queued record;
	// saving here cannot attest that the backend has accepted it either.
	if err := c.store.Save(cp); err != nil {
		return fmt.Errorf("save Teams service-health lifecycle: %w", err)
	}
	return nil
}

// resolutionTwin keeps the same id, service and classification as the open
// issue event. Dashboards distinguish it by is_resolved=true, use the event
// timestamp for the end marker, and join to starts by tenant and id. The post's
// created_date_time describes the final update, not when the issue closed.
func resolutionTwin(is issue, now time.Time) (telemetry.Event, bool) {
	end, ok := parsePostTime(is.EndDateTime)
	if !ok || end.IsZero() || end.After(now) {
		return telemetry.Event{}, false
	}
	if start, ok := parsePostTime(is.StartDateTime); ok && end.Before(start) {
		return telemetry.Event{}, false
	}
	ev := issueTwin(is)
	ev.Severity = telemetry.SeverityInfo
	ev.Timestamp = end
	if p, ok := finalPost(is.Posts); ok {
		telemetry.SetStr(ev.Attrs, semconv.AttrCreatedDateTime, p.CreatedDateTime)
		addPostContent(ev.Attrs, p)
	}
	return ev, true
}

// finalPost finds the latest createdDateTime without assuming array order.
// Omit the post when ordering is ambiguous or the latest body is empty;
// a confirmed closure should not disappear because its post is unavailable.
func finalPost(posts []post) (post, bool) {
	var latest post
	var latestTime time.Time
	var ambiguous bool
	for _, p := range posts {
		t, ok := parsePostTime(p.CreatedDateTime)
		if !ok || t.IsZero() {
			return post{}, false
		}
		if latestTime.IsZero() || t.After(latestTime) {
			latest, latestTime, ambiguous = p, t, false
		} else if t.Equal(latestTime) && p != latest {
			ambiguous = true
		}
	}
	return latest, !ambiguous && strings.TrimSpace(latest.Description.Content) != ""
}
