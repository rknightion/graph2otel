// Package roledefinitions is the Entra directory ROLE DEFINITION catalog
// collector: GET /roleManagement/directory/roleDefinitions (#320).
//
// entra.roles (a separate collector) answers "who currently holds a
// privileged role" — standing membership plus PIM assignments. This
// collector answers a different question: "what roles EXIST, and what can
// each one actually do", independent of whether anyone is currently assigned
// to it. A custom role with zero assignments, or a built-in role an admin has
// disabled, is invisible to entra.roles by construction (nobody holds it) but
// is exactly the kind of posture gap a SIEM feed exists to surface.
//
// # No pagination helper, and never $top
//
// Live-measured 2026-07-28 against m7kni as graph2otel-poller:
// GET .../roleDefinitions returns all 145 definitions in ONE page with no
// @odata.nextLink, and `$top` at ANY value (100, 999) 400s with
// Request_UnsupportedQuery — a real endpoint-specific ceiling, not a
// tenant-size limit this collector could page around. Collect therefore never
// sends $top and does its OWN nextLink loop (mirroring the shape of
// internal/collectors.GetAllValues but not calling it): that helper also sends
// a `Prefer: odata.maxpagesize=999` request header on every page to ask Graph
// for its largest page size, and this endpoint's tolerance for that header is
// UNVERIFIED — nothing in the #320 probe exercised it. Given the endpoint
// already rejects one page-shaping mechanism outright, sending a second,
// untested one for a collection that already arrives in a single page (145
// rows, no pagination in practice) buys nothing and risks a second 400. A
// hand-rolled loop keeps every request to a bare RawGet against the base URL
// or a returned nextLink, nothing else on the wire.
//
// # Definitions vs. assignments: no principal identity here
//
// A role DEFINITION carries no principal id — that is the whole point of the
// split with entra.roles. So the "log-only, never a metric label" boundary
// here is about the definition's own identity (id, name) and the actions it
// grants, not about a person or service principal.
//
// # Wirecheck: deliberately none
//
// This collector declares nothing to internal/wirecheck. is_built_in and
// is_enabled are gauge dimensions, but both are booleans this collector reads
// directly off the wire and reports as-is — it does not classify a Graph
// ENUM into a bounded value set the way, say, a risk level or account status
// collector does. There is no Graph-supplied value set here for an unexpected
// member to arrive in, so there is nothing for a watchdog to watch.
package roledefinitions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	entraoutcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.role_definitions"

// definitionsMetric is the bounded per-(is_built_in,is_enabled) count of
// directory role definitions. Cardinality is at most 4 regardless of tenant
// size — the catalog is bounded by Microsoft's built-in set plus whatever
// custom roles a tenant has defined, and neither dimension is per-entity.
const definitionsMetric = "entra.role_definitions.definitions"

// eventDefinition is the log twin's EventName: one record per returned
// roleDefinition, carrying the per-entity detail (id, name, granted actions)
// the bounded gauge cannot.
const eventDefinition = "entra.role_definition"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// definitionsPath is the roleDefinitions collection endpoint. `$top` is
// deliberately never appended anywhere this path is used — see the package
// doc's live-measured note.
const definitionsPath = "/roleManagement/directory/roleDefinitions"

// maxAllowedActions bounds the flattened allowed_actions array. The live
// 2026-07-28 m7kni capture's widest role (Global Administrator) carries 262
// allowedResourceActions in a single rolePermissions element; 300 clears that
// with headroom while still being a defensive backstop rather than a limit
// any observed role is near.
const maxAllowedActions = 300

// maxResourceScopes bounds both resourceScopes and
// inheritsPermissionsFrom[].id — both are admin/Microsoft-configured
// collections (which scopes a role applies to; which other definition a role
// inherits from), not per-entity data, so they share one cap rather than each
// coining their own. Every live row's resourceScopes is exactly ["/"] and
// inheritsPermissionsFrom is at most one element, so 50 is comfortable
// headroom, not a ceiling any observed row approaches.
const maxResourceScopes = 50

// rolePermission mirrors one element of a roleDefinition's rolePermissions
// array. Graph documents further fields on this object (condition,
// excludedResourceActions) that this collector does not read: #320 asks only
// for what a role can DO (allowedResourceActions), not the full permission
// grammar.
type rolePermission struct {
	AllowedResourceActions []string `json:"allowedResourceActions"`
}

// inheritsRef mirrors one element of inheritsPermissionsFrom: only the id of
// the definition being inherited from, not its expanded content (Graph does
// not return one without an explicit $expand, and this collector does not
// request it — a definition's own record, fetched independently, already
// carries everything this collector would otherwise have to re-derive from an
// expansion).
type inheritsRef struct {
	ID string `json:"id"`
}

// roleDefinition mirrors the subset of the Graph unifiedRoleDefinition
// resource this collector reads.
type roleDefinition struct {
	ID          string `json:"id"`
	TemplateID  string `json:"templateId"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	// IsBuiltIn and IsEnabled are POINTERS: both are gauge dimensions, and a
	// plain bool would fabricate `false` for a hypothetical response where
	// either key is absent, asserting Graph said something it never said.
	// Every one of the 145 live rows carries both keys, but the pointer costs
	// nothing and matches this project's standing convention for a
	// gauge-dimension boolean (see authmethodspolicy's keyRestrictions.IsEnforced).
	IsBuiltIn *bool  `json:"isBuiltIn"`
	IsEnabled *bool  `json:"isEnabled"`
	Version   string `json:"version"`

	ResourceScopes          []string         `json:"resourceScopes"`
	RolePermissions         []rolePermission `json:"rolePermissions"`
	InheritsPermissionsFrom []inheritsRef    `json:"inheritsPermissionsFrom"`
}

// roleDefinitionsPage is the collection envelope this collector pages
// through by hand (see package doc for why it does not use
// collectors.GetAllValues).
type roleDefinitionsPage struct {
	Value    []roleDefinition `json:"value"`
	NextLink string           `json:"@odata.nextLink"`
}

// maxPages caps the hand-rolled nextLink loop below. The live capture returns
// all 145 rows in one page (no nextLink at all), so this is a defensive
// backstop against a runaway pagination loop, not a limit expected to bite —
// the same role internal/collectors.maxPages plays for the shared helper this
// collector deliberately does not use.
const maxPages = 1000

// Collector polls GET /roleManagement/directory/roleDefinitions.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the role-definitions collector. A nil logger falls back to the
// slog default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Role definitions change
// very rarely (145 built-in roles, a handful of custom ones at most), so an
// hourly poll is ample and cheap on the directory/roleManagement throttle
// bucket.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *Collector) RequiredPermissions() []string {
	return []string{"RoleManagement.Read.Directory"}
}

// Collect fetches every directory role definition, emits the bounded
// (is_built_in, is_enabled) count gauge, and emits one entra.role_definition
// log twin per definition. A fetch/decode failure on any page aborts before
// emitting anything — a partial gauge built from only the pages that
// succeeded would read as "the tenant has fewer roles now", which is worse
// than reporting nothing this cycle.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	defs, err := c.fetchAll(ctx, outcomes)
	if err != nil {
		return err
	}

	buckets := map[[2]bool]int64{}
	for _, d := range defs {
		if d.IsBuiltIn == nil || d.IsEnabled == nil {
			// Not present on this row (never observed live, but see the
			// pointer rationale on roleDefinition) - skip rather than
			// fabricate a bucket membership Graph didn't report.
			c.logger.Debug("roledefinitions: definition missing isBuiltIn/isEnabled", "collector", collectorName, "id", d.ID)
			continue
		}
		buckets[[2]bool{*d.IsBuiltIn, *d.IsEnabled}]++
	}

	points := make([]telemetry.GaugePoint, 0, len(buckets))
	for key, count := range buckets {
		points = append(points, telemetry.GaugePoint{
			Value: float64(count),
			Attrs: telemetry.Attrs{
				semconv.AttrIsBuiltIn: strconv.FormatBool(key[0]),
				semconv.AttrIsEnabled: strconv.FormatBool(key[1]),
			},
		})
	}
	e.GaugeSnapshot(definitionsMetric, "{definition}",
		"Count of Entra directory role definitions, per (is_built_in, is_enabled).",
		points)

	for _, d := range defs {
		e.LogEvent(definitionTwin(d))
	}
	entraoutcome.Emitted(outcomes, uint64(len(defs)))

	return nil
}

// fetchAll pages through GET /roleManagement/directory/roleDefinitions by
// hand, following @odata.nextLink until exhausted (or, per the live capture,
// not following one at all - the response has none). `$top` is never
// appended: see the package doc's live-measured note. A failure on any page
// discards everything buffered so far rather than returning a partial list -
// the caller must not build a gauge from an incomplete walk.
func (c *Collector) fetchAll(ctx context.Context, outcomes *recordoutcome.Recorder) ([]roleDefinition, error) {
	var out []roleDefinition
	url := c.baseURL + definitionsPath
	for pages := 0; url != ""; pages++ {
		if pages >= maxPages {
			err := fmt.Errorf("roledefinitions: pagination exceeded %d pages (unbounded collection?)", maxPages)
			entraoutcome.SourceError(outcomes)
			return nil, err
		}

		body, err := c.g.RawGet(ctx, url)
		if err != nil {
			entraoutcome.SourceError(outcomes)
			c.logger.Warn("roleDefinitions fetch failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("roledefinitions: fetch roleDefinitions: %w", err)
		}

		var page roleDefinitionsPage
		if err := json.Unmarshal(body, &page); err != nil {
			entraoutcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			c.logger.Warn("roleDefinitions decode failed", "collector", collectorName, "error", err)
			return nil, fmt.Errorf("roledefinitions: decode roleDefinitions: %w", err)
		}

		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

// capStrings caps vals at max, reporting whether it had to. Never mutates
// vals - the returned slice on the truncated path is a fresh subslice header,
// not vals itself, so callers can't accidentally reuse the full backing array
// past the cap. Copied verbatim (same behavior, same reasoning) from
// authmethodspolicy.capStrings.
func capStrings(vals []string, max int) (out []string, truncated bool) {
	if len(vals) > max {
		return vals[:max:max], true
	}
	return vals, false
}

// definitionTwin renders one roleDefinition as one entra.role_definition log
// record (#320). allowedActions is flattened across EVERY rolePermissions
// element in order (a definition can carry more than one - observed live as
// 2 and 3 elements) - both getting this wrong by under-flattening (only the
// first element) and by over-flattening (double-counting) are real failure
// modes, which is why the true count is read once, independently of the
// capped array.
func definitionTwin(d roleDefinition) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, d.ID)
	telemetry.SetStr(attrs, semconv.AttrTemplateId, d.TemplateID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, d.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, d.Description)
	if d.IsBuiltIn != nil {
		telemetry.SetBool(attrs, semconv.AttrIsBuiltIn, *d.IsBuiltIn)
	}
	if d.IsEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrIsEnabled, *d.IsEnabled)
	}
	telemetry.SetStr(attrs, semconv.AttrVersion, d.Version)

	if len(d.ResourceScopes) > 0 {
		capped, truncated := capStrings(d.ResourceScopes, maxResourceScopes)
		telemetry.SetStrs(attrs, semconv.AttrResourceScopes, capped)
		telemetry.SetBool(attrs, semconv.AttrResourceScopesTruncated, truncated)
	}

	if len(d.InheritsPermissionsFrom) > 0 {
		ids := make([]string, 0, len(d.InheritsPermissionsFrom))
		for _, r := range d.InheritsPermissionsFrom {
			if r.ID != "" {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) > 0 {
			capped, truncated := capStrings(ids, maxResourceScopes)
			telemetry.SetStrs(attrs, semconv.AttrInheritsPermissionsFromIds, capped)
			telemetry.SetBool(attrs, semconv.AttrInheritsPermissionsFromTruncated, truncated)
		}
	}

	attrs[semconv.AttrRolePermissionCount] = float64(len(d.RolePermissions))

	var allActions []string
	var trueCount int
	for _, rp := range d.RolePermissions {
		trueCount += len(rp.AllowedResourceActions)
		allActions = append(allActions, rp.AllowedResourceActions...)
	}
	attrs[semconv.AttrAllowedActionCount] = float64(trueCount)
	if len(allActions) > 0 {
		capped, truncated := capStrings(allActions, maxAllowedActions)
		telemetry.SetStrs(attrs, semconv.AttrAllowedActions, capped)
		telemetry.SetBool(attrs, semconv.AttrAllowedActionsTruncated, truncated)
	}

	return telemetry.Event{
		Name:     eventDefinition,
		Body:     fmt.Sprintf("role definition %s (%s): %d allowed actions across %d permission block(s)", d.DisplayName, d.ID, trueCount, len(d.RolePermissions)),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
