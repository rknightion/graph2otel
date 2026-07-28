// Package exposuregraph is the Microsoft Defender Exposure Management graph
// collector (#350): a census-and-twin read of the advanced-hunting
// ExposureGraphNodes and ExposureGraphEdges tables, deliberately bounded.
//
// # What this deliberately is NOT
//
// It does not fabricate attack paths, choke points or centrality from raw
// nodes and edges. A label census is a census, not a graph analysis — that
// is a binding non-goal from #350, not an oversight. Building a real path
// analysis would need the graph's full topology in memory, which is exactly
// the unbounded shape the rest of this package doc explains why graph2otel
// cannot afford.
//
// # The bounding problem, live-measured (2026-07-28, m7kni, #350)
//
//   - ExposureGraphNodes has 993,292 rows; `summarize count()` over it took
//     77s.
//   - ExposureGraphEdges cannot be counted whole: an unpruned
//     `summarize count()` returned HTTP 504 at 150s. Every edge query in
//     this package MUST carry a `where` predicate that prunes BEFORE any
//     aggregation runs — that predicate is the fix for the 504, not an
//     optimization.
//   - The node label census is dominated by two labels: mdcSecurityRecommen-
//     dation (618,032) and Cve (372,330) are 99.7% of the graph. The next
//     largest label, baseModel, is 1,057 — a ~350x empty band. Excluding the
//     top two leaves 2,932 nodes across 19 labels, and a pruned edge query
//     (excluding those two on BOTH endpoints) completes in 72s, yielding 337
//     edges across 13 edge labels.
//
// # The bounding rule: data-driven, no hardcoded label names
//
// A node label whose population exceeds twinThreshold (10,000) is bulk
// inventory: it is COUNTED (twinned="false" on metricNodes) and never
// twinned. Every other label is twinned (twinned="true"). The 350x gap
// between the largest bounded label (1,057) and the smallest excluded one
// (372,330 on this tenant) means a threshold anywhere in that band separates
// bulk inventory from investigable entities on ANY tenant, with no
// hardcoded label list, no sampling, no top-N and no centrality heuristic —
// the bounded subset falls out of the data. metricExcludedLabels reports how
// many labels were excluded this way, split by entity_type ("node"/"edge") —
// they are different operational facts about different label ontologies, so
// both series are always seeded (a zero is a real zero, not an absent
// series). An over-threshold label is never a silent truncation:
// twinned="false" IS the
// report.
//
// The same rule applies independently to edge labels, using the edge
// census's own per-label counts (computed AFTER pruning by the excluded node
// labels, since an edge touching an excluded node is edge noise the census
// would otherwise have to describe by hand).
//
// # Four queries per cycle, degrading independently
//
//  1. Node census: bounded — one row per NodeLabel, cheap (measured 77s
//     across the whole 993k-node graph).
//  2. Node twins: either one query (`NodeLabel !in (excluded)`) or, when the
//     sum of to-be-twinned node counts would exceed totalTwinCap, one query
//     PER twinned label. Since every twinned label is by construction under
//     twinThreshold (10,000), a single per-label query can never hit the
//     hard 100,000-row cap (huntclient's transport ceiling) — that is why no
//     hash-sharding is needed here, unlike defender.vulnerabilities.
//  3. Edge census: pruned by the excluded node labels on BOTH endpoints,
//     grouped by EdgeLabel.
//  4. Edge twins: the same node-label prune, plus an EdgeLabel exclusion when
//     an edge label itself exceeds twinThreshold, with the same
//     per-edge-label fallback under totalTwinCap.
//
// The node census is a genuine prerequisite: without it there is no excluded
// set, and running the edge queries with no prune is precisely the request
// shape that returned the 504. A node census failure is therefore FATAL to
// the tick, mirroring defender.vulnerabilities' summary-query fatality. The
// other three queries degrade independently — a twin-fetch or edge-side
// failure is logged, aggregated with errors.Join, and does not prevent the
// other queries' results from being emitted, the defender.vulnerabilities
// shape rather than defender.quarantine's single-query fail-fast.
//
// # Both sides of the cardinality boundary
//
//   - bounded GAUGES from the two census queries: node and edge counts by
//     their respective label plus whether the label was twinned. Both label
//     ontologies are Microsoft's own (a closed vocabulary), not tenant-sized,
//     so series count is bounded by the ontology, not by tenant size.
//   - one LOG twin per bounded-label node/edge carrying the per-entity detail
//     the gauges collapse. "Not a metric label" means "log twin", never
//     "dropped" (#114).
//
// # Wire, not docs
//
// Every field mapped here was read off a VERBATIM live capture of the m7kni
// tenant as graph2otel-poller, 2026-07-28 (testdata/*.json). Two wire facts
// drive the mapper and are not obvious from documentation:
//
//   - NodeProperties/EdgeProperties are a `dynamicColumnValue` — an
//     arbitrarily deep object shaped per label, with the actual payload
//     nested one level down under a "rawData" key. The mapper attempts every
//     mapped field on every node/edge, omitting the ones the wire did not
//     send, the same one-builder-many-shapes pattern defender.mdo_policies
//     uses for its seven policy shapes. That is what makes "an unknown
//     label still produces a twin" true by construction.
//   - Every map key containing "@" is an OData sidecar
//     ("taskCapabilities@odata.type", "@odata.type") interleaved next to the
//     real keys. This mapper never iterates a properties map generically —
//     every field is looked up by its exact name from a fixed table — so a
//     sidecar key can never collide with a real one; there is nothing extra
//     to filter.
//   - EntityIds elements are JSON STRINGS, not objects:
//     "{\"type\":\"AadObjectId\",\"id\":\"tenantid=...;objectid=...\"}", and
//     need a SECOND decode. A failed decode publishes the raw element as the
//     id and the literal "unparsed" as its type, at the same index, so
//     alignment holds and the failure is visible instead of dropped. THE SAME
//     TRAP recurs on three edge property shapes (a follow-up finding, #350):
//     `delegatedPermissions.permissions`, `applicationPermissions.permissions`
//     and `roles.rolePermissions` are each a collection of wrapped
//     {"permissionValue":"..."} / {"roleValue":"..."} JSON-string elements.
//     decodeWrappedValues generalizes the same second-decode discipline
//     (failed decode keeps the raw text rather than dropping the element),
//     and an empty array — applicationPermissions.permissions is [] on the
//     live sample — correctly omits the attribute rather than publishing an
//     empty list.
//   - Booleans arrive as a genuine JSON bool in the dynamic rawData object
//     here (unlike the typed hunting columns internal/tvm's collectors read,
//     which get SByte 0/1 numbers) — boolFrom accepts bool, float64 AND
//     json.Number defensively, so a wire-shape drift in either direction
//     still decodes.
//   - depricationDate is MICROSOFT'S TYPO, on the wire (aiModelMetadata).
//     The mapper reads their spelling and publishes
//     semconv.AttrDeprecationDate, spelled correctly.
//
// # What is deliberately NOT emitted
//
// `description` never appears in any twin attribute. Every finding-shaped
// label (mdcManagementRecommendation, mde-healthFinding, ...) and ai-agent
// carry multi-paragraph HTML remediation prose that reads identically on
// every tenant — it is not a fact about THIS tenant's graph, and shipping it
// would put an unbounded, unreviewed blob on every twin. AttrSeverity and
// AttrRecommendationCategory carry the parts of a finding an operator can
// act on. semconv.AttrDescription must never be set by this package.
//
// # wirecheck: deliberately not used here
//
// NodeLabel and EdgeLabel are passed through to metric label values
// VERBATIM — there is no map bucketing an unrecognized value to "unknown",
// so there is no mapped set for internal/wirecheck to derive an Enum from.
// Per #234, a watchdog with no map behind it is exactly what must not be
// built: it would fire on every genuinely new label Microsoft adds to the
// ontology, trained on nothing, and the reader would learn to ignore it.
//
// # A STATE feed with no wire timestamp
//
// Neither ExposureGraphNodes nor ExposureGraphEdges carries a Timestamp
// column — this is a current-state snapshot, re-emitted in full every
// cycle. Twins are stamped at POLL time (Event.Timestamp left zero), the
// same shape as defender.vulnerabilities, defender.quarantine and
// entra/risk.
package exposuregraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "defender.exposure_graph"
	eventNode     = "defender.exposure_graph_node"
	eventEdge     = "defender.exposure_graph_edge"

	// interval matches the other advanced-hunting collectors: a current-state
	// snapshot with no Timestamp to tail shares a per-tenant advanced-hunting
	// CPU budget with humans in the Defender portal (#106), so polling it a
	// few times a day is ample. Do NOT shorten without re-reading #106/#249.
	interval = 6 * time.Hour

	metricNodes          = "defender.exposure_graph.nodes"
	metricEdges          = "defender.exposure_graph.edges"
	metricExcludedLabels = "defender.exposure_graph.excluded_labels"

	unitNode  = "{node}"
	unitEdge  = "{edge}"
	unitLabel = "{label}"

	// twinThreshold is the per-label bulk-inventory cutoff (#350): a node or
	// edge label whose population exceeds this is counted, not twinned. See
	// the package doc for why this sits safely inside the observed 350x gap.
	twinThreshold = 10_000

	// totalTwinCap is the sum-of-twinned-counts ceiling this collector aims to
	// stay under with a single combined twin query, held under huntclient's
	// hard 100,000-row-per-query ceiling. Above it, the twin fetch falls back
	// to one query per label (safe because every twinned label is, by
	// construction, under twinThreshold). Overridable in tests to force the
	// fallback on small fixtures.
	totalTwinCap = 90_000

	// maxListItems caps every list-shaped attribute (entity ids, categories,
	// tags, user rights, ...). Longest observed live is 6 (userRights); this
	// is a ceiling, not a normal case.
	maxListItems = 100
)

const nodeCensusQuery = `ExposureGraphNodes | summarize n=count() by NodeLabel=tostring(NodeLabel)`

// Collector reads the Defender Exposure Management graph over the
// advanced-hunting query API.
type Collector struct {
	c       collectors.HuntClient
	logger  *slog.Logger
	twinCap int
}

// New builds the exposure-graph collector. A nil logger falls back to
// slog.Default().
func New(d collectors.HuntDeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger, twinCap: totalTwinCap}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// RequiredPermissions is the Graph app role the advanced-hunting query needs.
func (c *Collector) RequiredPermissions() []string {
	return []string{"ThreatHunting.Read.All"}
}

// Collect runs the node census, derives the excluded (bulk-inventory) label
// set, then fetches node twins, the edge census (pruned by that set) and edge
// twins.
//
// The node census is fatal to the tick: everything downstream depends on the
// excluded set it produces, and running the edge queries with no prune is the
// exact request shape that returned HTTP 504 on this table (#350). The other
// three queries degrade independently and are aggregated with errors.Join —
// the defender.vulnerabilities shape.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	census, err := c.c.Query(ctx, "eg_node_census", nodeCensusQuery)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("%s: node census: %w", collectorName, err)
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(census)))

	nodeCounts := map[string]int64{}
	for _, r := range census {
		label := str(r, "NodeLabel")
		if label == "" {
			outcomes.Add(recordoutcome.OutcomeDropped, 1)
			outcomes.Cause(recordoutcome.CauseMappingError)
			continue
		}
		n, _ := r["n"].(float64)
		nodeCounts[label] = int64(n)
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}

	excludedNode, twinnedNode := splitByThreshold(nodeCounts)
	emitLabelGauge(e, metricNodes, unitNode,
		"ExposureGraphNodes rows, by node label and whether the label was twinned.",
		nodeCounts, excludedNode, semconv.AttrNodeLabel)

	var errs []error

	if len(twinnedNode) > 0 {
		if err := c.fetchNodeTwins(ctx, e, outcomes, excludedNode, twinnedNode, nodeCounts); err != nil {
			errs = append(errs, err)
		}
	}

	excludedEdgeCount := 0
	edgeCensus, err := c.c.Query(ctx, "eg_edge_census", edgeCensusQuery(excludedNode))
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		c.logger.Warn("exposure graph edge census failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("edge census: %w", err))
	} else {
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(edgeCensus)))
		edgeCounts := map[string]int64{}
		for _, r := range edgeCensus {
			label := str(r, "EdgeLabel")
			if label == "" {
				outcomes.Add(recordoutcome.OutcomeDropped, 1)
				outcomes.Cause(recordoutcome.CauseMappingError)
				continue
			}
			n, _ := r["n"].(float64)
			edgeCounts[label] = n2int(n)
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}

		excludedEdge, twinnedEdge := splitByThreshold(edgeCounts)
		excludedEdgeCount = len(excludedEdge)
		emitLabelGauge(e, metricEdges, unitEdge,
			"ExposureGraphEdges rows (pruned of bulk-inventory node labels), by edge label and whether the label was twinned.",
			edgeCounts, excludedEdge, semconv.AttrEdgeLabel)

		if len(twinnedEdge) > 0 {
			if err := c.fetchEdgeTwins(ctx, e, outcomes, excludedNode, excludedEdge, twinnedEdge, edgeCounts); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// Both series are ALWAYS seeded, even when a count is zero: an entity_type
	// with nothing excluded is a real "0", not an absent series, so a reader
	// can tell "no edge labels crossed the threshold" apart from "we never
	// checked" (#350 follow-up).
	e.GaugeSnapshot(metricExcludedLabels, unitLabel,
		"Node and edge labels excluded from twinning as bulk inventory (population over the twin threshold), by entity type.",
		[]telemetry.GaugePoint{
			{Value: float64(len(excludedNode)), Attrs: telemetry.Attrs{semconv.AttrEntityType: "node"}},
			{Value: float64(excludedEdgeCount), Attrs: telemetry.Attrs{semconv.AttrEntityType: "edge"}},
		})

	return errors.Join(errs...)
}

// n2int truncates a float64 row count to int64, matching the census-mapping
// convention used for node counts above.
func n2int(n float64) int64 { return int64(n) }

// splitByThreshold partitions a label->count map into the excluded
// (over-threshold, bulk-inventory) and twinned (under-threshold) label sets,
// in deterministic sorted order.
func splitByThreshold(counts map[string]int64) (excluded, twinned []string) {
	for label, n := range counts {
		if n > twinThreshold {
			excluded = append(excluded, label)
		} else {
			twinned = append(twinned, label)
		}
	}
	sort.Strings(excluded)
	sort.Strings(twinned)
	return excluded, twinned
}

// emitLabelGauge emits one gauge point per label in counts, tagged with
// labelAttr and AttrTwinned ("false" for a label in excluded, "true"
// otherwise).
func emitLabelGauge(e telemetry.Emitter, name, unit, desc string, counts map[string]int64, excluded []string, labelAttr string) {
	isExcluded := make(map[string]bool, len(excluded))
	for _, l := range excluded {
		isExcluded[l] = true
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for label, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				labelAttr:           label,
				semconv.AttrTwinned: fmtBool(!isExcluded[label]),
			},
		})
	}
	e.GaugeSnapshot(name, unit, desc, points)
}

// fetchNodeTwins fetches and emits the per-node twins for every label in
// twinned. If the sum of their counts fits under c.twinCap, one combined query
// runs; otherwise one query per label runs — safe because every twinned label
// is, by construction, under twinThreshold (far under the hard 100,000-row
// cap), so a per-label query can never truncate.
func (c *Collector) fetchNodeTwins(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder, excluded, twinned []string, counts map[string]int64) error {
	var sum int64
	for _, l := range twinned {
		sum += counts[l]
	}

	var errs []error
	emit := func(label, query string) {
		rows, err := c.c.Query(ctx, "eg_node_twin_"+label, query)
		if err != nil {
			outcomes.Cause(recordoutcome.CauseSourceError)
			c.logger.Warn("exposure graph node twin fetch failed",
				"collector", collectorName, "label", label, "error", err)
			errs = append(errs, fmt.Errorf("node twin %s: %w", label, err))
			return
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
		for _, r := range rows {
			e.LogEvent(nodeTwin(r))
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}
	}

	if sum <= int64(c.twinCap) {
		emit("all", nodeTwinQuery(excluded))
		return errors.Join(errs...)
	}
	for _, label := range twinned {
		emit(label, nodeTwinLabelQuery(label))
	}
	return errors.Join(errs...)
}

// fetchEdgeTwins mirrors fetchNodeTwins for edges: same combined-vs-per-label
// fallback, plus the node-label prune every edge query must carry.
func (c *Collector) fetchEdgeTwins(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder, excludedNode, excludedEdge, twinnedEdge []string, counts map[string]int64) error {
	var sum int64
	for _, l := range twinnedEdge {
		sum += counts[l]
	}

	var errs []error
	emit := func(label, query string) {
		rows, err := c.c.Query(ctx, "eg_edge_twin_"+label, query)
		if err != nil {
			outcomes.Cause(recordoutcome.CauseSourceError)
			c.logger.Warn("exposure graph edge twin fetch failed",
				"collector", collectorName, "label", label, "error", err)
			errs = append(errs, fmt.Errorf("edge twin %s: %w", label, err))
			return
		}
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
		for _, r := range rows {
			e.LogEvent(edgeTwin(r))
			outcomes.Add(recordoutcome.OutcomeMapped, 1)
			outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		}
	}

	if sum <= int64(c.twinCap) {
		emit("all", edgeTwinQuery(excludedNode, excludedEdge))
		return errors.Join(errs...)
	}
	for _, label := range twinnedEdge {
		emit(label, edgeTwinLabelQuery(excludedNode, label))
	}
	return errors.Join(errs...)
}

func init() {
	collectors.RegisterHunt(func(d collectors.HuntDeps) collector.SnapshotCollector { return New(d) })
}

// --- KQL query construction ---

// kqlString renders s as a double-quoted KQL string literal, escaping the two
// characters KQL string literals are sensitive to. Label values come straight
// from Microsoft's ontology and at least one live value contains a space
// ("Microsoft Entra OAuth App"); this helper (never fmt.Sprintf("%q"), which
// is Go-string escaping, not KQL) is what keeps such a value a single literal
// rather than broken KQL.
func kqlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// kqlStringList renders labels as a comma-separated list of KQL string
// literals, suitable for a KQL `!in (...)` / `in (...)` operand.
func kqlStringList(labels []string) string {
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = kqlString(l)
	}
	return strings.Join(parts, ", ")
}

// nodeTwinQuery returns the combined per-node-label twin query, omitting the
// `where` clause entirely when excluded is empty (nothing to prune).
func nodeTwinQuery(excluded []string) string {
	if len(excluded) == 0 {
		return "ExposureGraphNodes"
	}
	return fmt.Sprintf("ExposureGraphNodes | where NodeLabel !in (%s)", kqlStringList(excluded))
}

// nodeTwinLabelQuery returns the per-label fallback twin query for one node
// label. Safe unsharded: every twinned label is, by construction, under
// twinThreshold (10,000), far under huntclient's hard 100,000-row cap.
func nodeTwinLabelQuery(label string) string {
	return fmt.Sprintf("ExposureGraphNodes | where NodeLabel == %s", kqlString(label))
}

// edgeNodeLabelPredicate returns the `where` fragment that prunes edges whose
// EITHER endpoint carries an excluded (bulk-inventory) node label. Returns ""
// only when excluded is empty (nothing to prune) — every edge query in this
// package calls this so the 504-causing unpruned shape can never be built.
func edgeNodeLabelPredicate(excluded []string) string {
	if len(excluded) == 0 {
		return ""
	}
	list := kqlStringList(excluded)
	return fmt.Sprintf(" | where SourceNodeLabel !in (%s) and TargetNodeLabel !in (%s)", list, list)
}

// edgeCensusQuery returns the pruned edge census query, grouped by EdgeLabel.
func edgeCensusQuery(excludedNode []string) string {
	return fmt.Sprintf("ExposureGraphEdges%s | summarize n=count() by EdgeLabel=tostring(EdgeLabel)",
		edgeNodeLabelPredicate(excludedNode))
}

// edgeTwinQuery returns the combined edge twin query: the node-label prune,
// plus an EdgeLabel exclusion when any edge label itself exceeded
// twinThreshold.
func edgeTwinQuery(excludedNode, excludedEdge []string) string {
	q := "ExposureGraphEdges" + edgeNodeLabelPredicate(excludedNode)
	if len(excludedEdge) > 0 {
		q += fmt.Sprintf(" | where EdgeLabel !in (%s)", kqlStringList(excludedEdge))
	}
	return q
}

// edgeTwinLabelQuery returns the per-edge-label fallback query, still carrying
// the node-label prune.
func edgeTwinLabelQuery(excludedNode []string, edgeLabel string) string {
	return "ExposureGraphEdges" + edgeNodeLabelPredicate(excludedNode) +
		fmt.Sprintf(" | where EdgeLabel == %s", kqlString(edgeLabel))
}

// --- wire decode helpers ---

// str reads a string column, "" when absent or non-string.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolFrom decodes a boolean that may arrive as a genuine JSON bool (the
// dynamic rawData object, live-observed), an SByte-style float64 0/1 (the
// typed hunting-column encoding internal/tvm's collectors handle), or a
// json.Number (defensive: this package's own json.Unmarshal calls never
// produce one, since none sets UseNumber, but a caller constructing a fixture
// directly might). Returns ok=false for anything else, including absence.
func boolFrom(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case float64:
		return x != 0, true
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return false, false
		}
		return f != 0, true
	default:
		return false, false
	}
}

// fmtBool renders a bool as "true"/"false", matching telemetry.SetBool's
// encoding, for use as a bounded metric-label value.
func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// toStringSlice decodes a dynamic column's array value ([]any of strings) into
// a []string. Non-string elements are skipped rather than causing a panic; a
// non-array value returns nil.
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// capList caps list at maxListItems, reporting whether it truncated.
func capList(list []string) ([]string, bool) {
	if len(list) > maxListItems {
		return list[:maxListItems], true
	}
	return list, false
}

// rawDataOf reads row[col].rawData as a map, the actual payload one level
// under the dynamicColumnValue envelope. Returns nil when either level is
// absent or not an object (e.g. a label whose properties carry nothing but
// the envelope's own @odata.type).
func rawDataOf(row map[string]any, col string) map[string]any {
	outer, _ := row[col].(map[string]any)
	if outer == nil {
		return nil
	}
	rd, _ := outer["rawData"].(map[string]any)
	return rd
}

// cappedRawElements normalizes a dynamic column's array value into []any,
// capped at maxListItems, reporting whether it truncated. Shared by every
// decoder below that reads a collection of wrapped JSON-string elements
// (EntityIds, and the permission/role collections following the same wire
// pattern).
func cappedRawElements(v any) (elems []any, truncated bool) {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return nil, false
	}
	if len(arr) > maxListItems {
		return arr[:maxListItems], true
	}
	return arr, false
}

// entityIDWire is the shape of one decoded EntityIds element.
type entityIDWire struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// decodeEntityIDs decodes the EntityIds column (a []any of JSON-string
// elements, each "{\"type\":...,\"id\":...}") into two index-aligned slices:
// the id values and their type names. An element that fails to decode as JSON
// contributes its raw string as the id and the literal "unparsed" as its
// type, so alignment holds and the failure is visible rather than silently
// dropped.
func decodeEntityIDs(v any) (ids, types []string, truncated bool) {
	arr, truncated := cappedRawElements(v)
	if len(arr) == 0 {
		return nil, nil, truncated
	}
	ids = make([]string, 0, len(arr))
	types = make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			ids = append(ids, fmt.Sprintf("%v", e))
			types = append(types, "unparsed")
			continue
		}
		var w entityIDWire
		if err := json.Unmarshal([]byte(s), &w); err != nil {
			ids = append(ids, s)
			types = append(types, "unparsed")
			continue
		}
		ids = append(ids, w.ID)
		types = append(types, w.Type)
	}
	return ids, types, truncated
}

// decodeWrappedValues decodes a collection of wrapped JSON-string elements —
// the SAME trap as EntityIds, in a different place: `delegatedPermissions.
// permissions` and `applicationPermissions.permissions` each hold elements
// like `{"permissionValue":"DeviceManagementApps.ReadWrite.All"}`, and
// `roles.rolePermissions` holds `{"roleValue":"Owner"}` — a single-key wrapper
// around the fact that actually matters. valueKey names that one key
// ("permissionValue"/"roleValue"). The wrapper is discarded; only the decoded
// value is published. An element that fails to decode, or decodes with the
// key absent or empty, keeps its raw text rather than being dropped — there
// is no aligned "type" slice here (unlike EntityIds), so there is nothing to
// mark "unparsed" against; the raw text IS the fallback.
func decodeWrappedValues(v any, valueKey string) (values []string, truncated bool) {
	arr, truncated := cappedRawElements(v)
	if len(arr) == 0 {
		return nil, truncated
	}
	values = make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			values = append(values, fmt.Sprintf("%v", e))
			continue
		}
		var w map[string]any
		if err := json.Unmarshal([]byte(s), &w); err != nil {
			values = append(values, s)
			continue
		}
		val, ok := w[valueKey].(string)
		if !ok || val == "" {
			values = append(values, s)
			continue
		}
		values = append(values, val)
	}
	return values, truncated
}
