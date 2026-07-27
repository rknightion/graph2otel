// Package privilegedgroups is the Entra allowlisted privileged-group
// member-count collector (#337, the surviving residual of #43 — see that
// issue's closing comment).
//
// # Why group_id is a metric label here, when it never is elsewhere
//
// Every other Entra group signal in this project (internal/collectors/entra/
// groups) is a strictly bounded population aggregate with no per-group
// dimension, because an unconstrained group_id label grows with tenant size —
// exactly the mistake CLAUDE.md's cardinality rule exists to prevent (#112).
// This collector is the deliberate, narrow exception: group_id is a label
// ONLY for groups an operator explicitly named in a per-tenant allowlist
// (config.PrivilegedGroupsConfig.GroupIDs), capped at
// config.MaxPrivilegedGroupAllowlist entries and validated at config load. The
// allowlist itself IS the cardinality bound — cardinality here is a config
// decision, not a runtime one, so it can never silently grow with the tenant.
//
// # Distinguishing "zero members" from "could not look"
//
// Two gauges are emitted per cycle from a per-group $count fetch:
//
//   - entra.privileged_groups.members.total — one point per group that was
//     SUCCESSFULLY read this cycle, value = the TRANSITIVE member count (0 is
//     a legitimate, measured value here — the group exists, was read, and is
//     empty). See memberCountURL for why membership is counted transitively.
//   - entra.privileged_groups.accessible — one point for EVERY configured
//     group, EVERY cycle, value 1 (read succeeded) or 0 (it did not). This is
//     the explicit "could graph2otel look" signal, decoupled from the count.
//
// A group that fails this cycle (deleted, 403, transient error) is therefore
// absent from members.total but always present in accessible=0 — an operator
// can never read silence on the first gauge as "zero members", because the
// second gauge is never silent about a configured group. This is the same
// shape as entra/risk's reconciled is_deleted (present/absent as fact, never a
// guessed value) applied to a metric instead of a log attribute, since a gauge
// point cannot itself express "unknown".
//
// The log twin (event entra.privileged_group, one per configured group per
// cycle) carries the accessible flag plus, on failure, a bounded reason
// (semconv.AttrReason: "not_found" / "forbidden" / "error") — the gauge cannot
// carry a reason string, only the twin can. It does NOT enumerate the group's
// members: the issue this collector implements is a COUNT gauge, not a
// membership listing, and per-member identity inside one of these groups is
// exactly the unbounded-entity-label shape the allowlist exists to avoid
// reaching for.
package privilegedgroups

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.privileged_groups"

// metricMembers is the per-group member-count gauge. Cardinality is bounded by
// the tenant's configured allowlist (<= config.MaxPrivilegedGroupAllowlist),
// never by tenant size — see the package doc.
const metricMembers = "entra.privileged_groups.members.total"

// metricAccessible is the per-group "could graph2otel read this group this
// cycle" gauge — see the package doc for why this exists as a second gauge
// rather than folding into metricMembers.
const metricAccessible = "entra.privileged_groups.accessible"

// eventPrivilegedGroup is the log twin's EventName, one record per configured
// group per cycle.
const eventPrivilegedGroup = "entra.privileged_group"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// memberCountURL builds a /groups/{id}/transitiveMembers/$count URL.
//
// TRANSITIVE membership, decided on #337 after both shapes were live-verified
// to work identically (same ConsistencyLevel + Accept headers, same response
// shape). Direct /members/$count was the initial default on cost grounds, but
// it undercounts: a principal nested inside another group is a full member of
// the privileged group for every authorization decision Entra makes, and
// omitting it makes this a security signal that reads LOW precisely when
// someone has expanded the blast radius by nesting. An over-count is a
// question; an under-count is a missed escalation.
//
// The count is therefore a TOTAL, not a floor — it includes members reached
// through any depth of nesting, and it counts every transitive member type
// (users, groups and service principals alike), not users only.
func memberCountURL(baseURL, groupID string) string {
	return baseURL + "/groups/" + url.PathEscape(groupID) + "/transitiveMembers/$count"
}

// var _ pins Collector to collector.SnapshotCollector at compile time — the
// interface the wiring pass's collectors.Register call must be able to return.
var _ collector.SnapshotCollector = (*Collector)(nil)

// Collector polls per-group member counts for a tenant's allowlisted
// privileged groups.
type Collector struct {
	g         collectors.GraphClient
	baseURL   string
	allowlist []string
	logger    *slog.Logger
}

// New builds the privileged-groups collector. allowlist is the tenant's
// configured group-id allowlist (config.PrivilegedGroupsConfig.GroupIDs,
// already validated against config.MaxPrivilegedGroupAllowlist at config
// load) — an empty allowlist makes Collect a no-op every cycle. A nil logger
// falls back to the slog default.
func New(g collectors.GraphClient, allowlist []string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, allowlist: allowlist, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Matches entra/groups'
// cadence: privileged-group population drifts slowly, and up to
// config.MaxPrivilegedGroupAllowlist (50) cheap $count calls per tick is
// trivially inside the directory-objects RU budget at five-minute intervals.
func (c *Collector) DefaultInterval() time.Duration { return 5 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Group.Read.All covers both reading the allowlisted groups' existence and
// their /members/$count, mirroring entra/groups' own scope declaration.
func (c *Collector) RequiredPermissions() []string { return []string{"Group.Read.All"} }

// Collect fetches /members/$count for every allowlisted group and emits both
// gauges plus one log twin per group. A per-group failure never drops that
// group from metricAccessible (it is reported there as inaccessible) and never
// fabricates a zero on metricMembers; every other group still emits normally.
// The aggregated error is returned so a partial failure is visible in scrape
// self-obs without hiding the data that did succeed.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	if len(c.allowlist) == 0 {
		return nil
	}

	memberPoints := make([]telemetry.GaugePoint, 0, len(c.allowlist))
	accessiblePoints := make([]telemetry.GaugePoint, 0, len(c.allowlist))
	var errs []error

	for _, id := range c.allowlist {
		n, err := collectors.Count(ctx, c.g, memberCountURL(c.baseURL, id))
		if err != nil {
			reason := classifyFailure(err)
			entraoutcome.SourceError(outcomes)
			c.logger.Warn("privileged group member count failed", "collector", collectorName, "group_id", id, "reason", reason, "error", err)
			errs = append(errs, fmt.Errorf("group %s: %w", id, err))

			accessiblePoints = append(accessiblePoints, telemetry.GaugePoint{
				Value: 0,
				Attrs: telemetry.Attrs{semconv.AttrGroupId: id},
			})
			e.LogEvent(logTwin(id, nil, reason))
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseForError(err))
			continue
		}

		memberPoints = append(memberPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrGroupId: id},
		})
		accessiblePoints = append(accessiblePoints, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{semconv.AttrGroupId: id},
		})
		e.LogEvent(logTwin(id, &n, ""))
		entraoutcome.Emitted(outcomes, 1)
	}

	e.GaugeSnapshot(metricMembers, "{member}", "Member count for allowlisted privileged Entra groups. Only groups explicitly configured in privileged_groups.group_ids ever appear here.", memberPoints)
	e.GaugeSnapshot(metricAccessible, "1", "Whether graph2otel could read each allowlisted privileged group this cycle (1) or not (0) — present for every configured group every cycle, so a missing member count is never mistaken for zero members.", accessiblePoints)

	return errors.Join(errs...)
}

// classifyFailure maps a /members/$count failure to a bounded reason string
// for the log twin. The raw-REST transport (collectors.Count) embeds the HTTP
// status in the error text ("status 404" / "status 403"); the OData fallback
// covers a typed-SDK-shaped error for robustness, mirroring entra/risk's
// isForbidden.
func classifyFailure(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "status 404"):
		return "not_found"
	case strings.Contains(msg, "status 403"):
		return "forbidden"
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		switch code {
		case "Request_ResourceNotFound":
			return "not_found"
		case "Authorization_RequestDenied":
			return "forbidden"
		}
	}
	return "error"
}

// logTwin renders one allowlisted group as an OTLP log record. memberCount is
// non-nil on success (the measured count); reason is non-empty on failure
// (never both). Never carries member identities — see the package doc.
func logTwin(groupID string, memberCount *int64, reason string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrGroupId, groupID)

	accessible := memberCount != nil
	telemetry.SetBool(attrs, semconv.AttrAccessible, accessible)

	sev := telemetry.SeverityInfo
	var body string
	if accessible {
		attrs[semconv.AttrMemberCount] = float64(*memberCount)
		body = fmt.Sprintf("privileged group %s: member_count=%d", groupID, *memberCount)
	} else {
		telemetry.SetStr(attrs, semconv.AttrReason, reason)
		sev = telemetry.SeverityWarn
		body = fmt.Sprintf("privileged group %s: inaccessible this cycle (reason=%s)", groupID, reason)
	}

	return telemetry.Event{
		Name:     eventPrivilegedGroup,
		Body:     body,
		Severity: sev,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.PrivilegedGroupAllowlist, d.Logger)
	})
}
