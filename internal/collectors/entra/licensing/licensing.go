// Package licensing is the Entra licensing collector: tenant-wide
// subscribedSku inventory emitted as per-SKU gauges (entra.license.consumed,
// entra.license.enabled, entra.license.units, entra.license.capability_status)
// plus a bounded group-level license-assignment-error signal
// (entra.license.groups_with_errors.total + entra.license_group_error log
// twins).
//
// # entra.license.enabled vs entra.license.units{state="enabled"}
//
// entra.license.enabled{sku} is kept emitting unchanged for backward
// compatibility with dashboards/alerts already built against it.
// entra.license.units{sku,state="enabled"} duplicates exactly the same value
// under the new, more general state-sliced gauge. This duplication is
// DELIBERATE, not an oversight: entra.license.units is the one gauge that also
// carries suspended/warning/locked_out (subscription HEALTH, #122), and a
// consumer who only ever cared about enabled prepaid units should not have to
// migrate off entra.license.enabled to get it.
//
// # entra.license.capability_status
//
// One series per SKU, value always 1, with the SKU's current Graph
// capabilityStatus (lowercased: enabled/warning/suspended/deleted/lockedout)
// as the label — the standard enum-as-label "info gauge" shape: a `sum by
// (status) (entra_license_capability_status)` or a straight label filter
// answers "which SKUs are in what state" without scanning logs.
//
// # Assignment-error detection: two different, both bounded, paths
//
// Per-user assignment-error detection is deliberately NOT implemented. The
// traditional (non-preview) license model exposes assignment failures only as
// a per-user property (`licenseAssignmentStates` on the user resource, state
// == "Error"), which has no v1.0 tenant-level aggregate — detecting it would
// mean paging every user in the tenant just to produce one counter, which is
// exactly the per-entity-scan-for-an-aggregate anti-pattern this collector
// framework exists to avoid. Microsoft Graph beta does have a newer
// `assignmentError` entity (see the beta-only "cloud licensing" / allotments
// API), but that API models an entirely different, opt-in licensing paradigm
// (allotments, not classic direct/group-based subscribedSkus licensing) and is
// beta-only, so it isn't a safe v1.0 substitute. See issue #45 and this
// collector's final implementation brief for the full reasoning; revisit if
// Microsoft ships a v1.0, tenant-level assignment-error aggregate for classic
// licensing. #45's objection stands unchanged.
//
// Issue #122 adds a DIFFERENT, bounded, group-level path rather than
// reversing #45: GET /groups?$filter=hasMembersWithLicenseErrors eq true
// returns only the (typically small) set of groups that have at least one
// member with a license assignment error — a single filtered, paged fetch of
// groups, never a per-user scan. hasMembersWithLicenseErrors does not support
// $count, so the filtered collection is paged and counted client-side instead
// of via the $count-segment helper. Groups, not users, become the log twin's
// subject: entra.license_group_error carries the group id and display name,
// never a user identifier.
package licensing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.licensing"

// Metric names this collector emits. consumed/enabled/units are per-SKU
// (bounded, tenant-shaped: cardinality grows with the number of purchased
// SKUs, tens at most, never with tenant size). capabilityStatus is likewise
// one series per SKU. groupsWithErrors is a single scalar.
const (
	consumedMetricName         = "entra.license.consumed"
	enabledMetricName          = "entra.license.enabled"
	unitsMetricName            = "entra.license.units"
	capabilityStatusMetricName = "entra.license.capability_status"
	groupsWithErrorsMetricName = "entra.license.groups_with_errors.total"
)

// eventLicenseGroupError is the log twin EventName for one group with at
// least one member whose license assignment failed. See the package doc.
const eventLicenseGroupError = "entra.license_group_error"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// groupsWithLicenseErrorsFilter selects groups that have at least one member
// whose license assignment failed. hasMembersWithLicenseErrors does NOT
// support $count (per issue #122's brief), so the filtered collection below
// is paged via GetAllValues and counted client-side rather than via
// collectors.Count.
const groupsWithLicenseErrorsFilter = "hasMembersWithLicenseErrors eq true"

// prepaidUnits mirrors the Graph licenseUnitsDetail complex type in full:
// enabled, suspended, warning, and locked-out prepaid unit counts. All four
// feed entra.license.units (#122) — this is subscription HEALTH, not just the
// enabled pool this struct used to limit itself to.
type prepaidUnits struct {
	Enabled   int64 `json:"enabled"`
	Suspended int64 `json:"suspended"`
	Warning   int64 `json:"warning"`
	LockedOut int64 `json:"lockedOut"`
}

// unitState pairs one prepaidUnits field with the state label
// entra.license.units uses for it.
type unitState struct {
	name  string
	value int64
}

// states returns the four (state, value) pairs entra.license.units emits per
// SKU, in a fixed order.
func (p prepaidUnits) states() []unitState {
	return []unitState{
		{"enabled", p.Enabled},
		{"suspended", p.Suspended},
		{"warning", p.Warning},
		{"locked_out", p.LockedOut},
	}
}

// subscribedSku mirrors the fields of the Graph subscribedSku resource this
// collector reads. skuPartNumber is the bounded, tenant-shaped label value
// ("sku") — never skuId (an opaque GUID, less operator-readable) and never
// any per-assignment/per-user field. capabilityStatus feeds
// entra.license.capability_status (#122).
type subscribedSku struct {
	SkuPartNumber    string       `json:"skuPartNumber"`
	ConsumedUnits    int64        `json:"consumedUnits"`
	PrepaidUnits     prepaidUnits `json:"prepaidUnits"`
	CapabilityStatus string       `json:"capabilityStatus"`
}

// erroredGroup mirrors the /groups?$select=id,displayName shape this
// collector reads for the hasMembersWithLicenseErrors filter (#122). Only id
// and displayName are decoded — never any per-member/per-user field, keeping
// this a group-level signal.
type erroredGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// Collector polls /subscribedSkus and the hasMembersWithLicenseErrors
// /groups filter.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the licensing collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. License consumption drifts
// slowly and subscribedSkus has no delta/filter support (a full read every
// cycle), so a longer interval than the directory counts is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scopes.
// Per current Microsoft Graph docs (learn.microsoft.com/graph/api/subscribedsku-list),
// LicenseAssignment.Read.All is the least-privileged permission for
// GET /subscribedSkus — Directory.Read.All/Organization.Read.All (named in
// issue #45) are listed there as higher-privileged alternatives, so this
// deliberately deviates from the issue text toward the narrower scope per the
// authoring guide's "prefer the specific scope" rule. Group.Read.All is added
// for #122's GET /groups?$filter=hasMembersWithLicenseErrors query.
func (c *Collector) RequiredPermissions() []string {
	return []string{"LicenseAssignment.Read.All", "Group.Read.All"}
}

// Collect fetches the full subscribedSkus collection and emits the per-SKU
// gauge snapshots (consumed units, enabled/prepaid units, all-state prepaid
// units, capability status), one point (or four, for units) per SKU.
// subscribedSkus is a small, tenant-wide collection with no $filter or delta
// support, so GetAllValues (not Count) is the right helper here. It then
// fetches the bounded hasMembersWithLicenseErrors group filter (#122) and
// emits its scalar count plus one log twin per affected group.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/subscribedSkus", nil)
	if err != nil {
		return fmt.Errorf("licensing: fetch subscribedSkus: %w", err)
	}

	consumed := make([]telemetry.GaugePoint, 0, len(raw))
	enabled := make([]telemetry.GaugePoint, 0, len(raw))
	units := make([]telemetry.GaugePoint, 0, len(raw)*4)
	capabilityStatus := make([]telemetry.GaugePoint, 0, len(raw))
	for _, r := range raw {
		var sku subscribedSku
		if err := json.Unmarshal(r, &sku); err != nil {
			c.logger.Warn("licensing: skipping unparseable subscribedSku", "collector", collectorName, "error", err)
			continue
		}
		if sku.SkuPartNumber == "" {
			c.logger.Warn("licensing: skipping subscribedSku with empty skuPartNumber", "collector", collectorName)
			continue
		}
		skuAttrs := telemetry.Attrs{semconv.AttrSku: sku.SkuPartNumber}
		consumed = append(consumed, telemetry.GaugePoint{Value: float64(sku.ConsumedUnits), Attrs: skuAttrs})
		enabled = append(enabled, telemetry.GaugePoint{Value: float64(sku.PrepaidUnits.Enabled), Attrs: skuAttrs})

		for _, st := range sku.PrepaidUnits.states() {
			units = append(units, telemetry.GaugePoint{
				Value: float64(st.value),
				Attrs: telemetry.Attrs{semconv.AttrSku: sku.SkuPartNumber, semconv.AttrState: st.name},
			})
		}

		capabilityStatus = append(capabilityStatus, telemetry.GaugePoint{
			Value: 1,
			Attrs: telemetry.Attrs{semconv.AttrSku: sku.SkuPartNumber, semconv.AttrStatus: strings.ToLower(sku.CapabilityStatus)},
		})
	}

	e.GaugeSnapshot(consumedMetricName, "{unit}", "Consumed license units per Entra subscribed SKU.", consumed)
	e.GaugeSnapshot(enabledMetricName, "{unit}", "Enabled (prepaid) license units per Entra subscribed SKU.", enabled)
	e.GaugeSnapshot(unitsMetricName, "{unit}", "Prepaid license units per Entra subscribed SKU, by unit state (enabled/suspended/warning/locked_out).", units)
	e.GaugeSnapshot(capabilityStatusMetricName, "{sku}", "Current Graph capabilityStatus per Entra subscribed SKU (value is always 1; status is the label).", capabilityStatus)

	if err := c.collectGroupsWithErrors(ctx, e); err != nil {
		c.logger.Warn("licensing: groups-with-license-errors collection failed", "collector", collectorName, "error", err)
		return fmt.Errorf("licensing: fetch groups with license errors: %w", err)
	}
	return nil
}

// collectGroupsWithErrors fetches the (small) set of groups with at least one
// member whose license assignment failed and emits both the bounded scalar
// count (explicit 0 when none) and one log twin per affected group (none when
// the count is 0 — see the package doc for why this is a different, bounded
// path from the per-user detection #45 rejected).
func (c *Collector) collectGroupsWithErrors(ctx context.Context, e telemetry.Emitter) error {
	groupsURL := c.baseURL + "/groups?$filter=" + url.QueryEscape(groupsWithLicenseErrorsFilter) + "&$select=id,displayName"
	raw, err := collectors.GetAllValues(ctx, c.g, groupsURL, collectors.EventualHeaders())
	if err != nil {
		return err
	}

	var affected int64
	for _, r := range raw {
		var g erroredGroup
		if err := json.Unmarshal(r, &g); err != nil {
			c.logger.Warn("licensing: skipping unparseable errored group", "collector", collectorName, "error", err)
			continue
		}
		affected++

		attrs := telemetry.Attrs{}
		telemetry.SetStr(attrs, semconv.AttrId, g.ID)
		telemetry.SetStr(attrs, semconv.AttrDisplayName, g.DisplayName)

		name := g.DisplayName
		if name == "" {
			name = g.ID
		}
		e.LogEvent(telemetry.Event{
			Name:     eventLicenseGroupError,
			Body:     fmt.Sprintf("group %s has members with license assignment errors", name),
			Severity: telemetry.SeverityWarn,
			Attrs:    attrs,
		})
	}

	e.Gauge(groupsWithErrorsMetricName, "{group}", "Total Entra groups with at least one member whose license assignment failed.", float64(affected), nil)
	return nil
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
