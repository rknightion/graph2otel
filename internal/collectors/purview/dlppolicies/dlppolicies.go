// Package dlppolicies is the Purview Data Loss Prevention policy-inventory
// collector (BETA): the tenant's DLP policy DEFINITIONS and their enforcement
// mode, over GET /beta/security/dataSecurityAndGovernance/policyFiles (#246).
// It answers "which DLP policies exist, are they ENFORCING or only auditing,
// which workloads are they bound to, and which sensitive-info types do their
// rules match" — the "someone quietly downgraded enforcement" posture signal.
//
// # The wire shape (measured, not documented)
//
// policyFiles returns a small fixed set of "file" rows, one per policy category
// (id=DataCollectionPolicy, id=DlpPolicy, id=CustomClassifications on the m7kni
// tenant). Only the DlpPolicy row is consumed here. Each row carries a
// fileType, a status in {modified, notModified, noContent}, a version hash, and
// a `content` (Edm.Binary) field. The DlpPolicy content is base64 of a
// UTF-16LE-encoded XML document (root <Content xmlns=".../hygienews/">), ~76KB
// on this tenant. The wire returned fileType "customClassifications" — a value
// NOT in the beta EDM's declared fileType enum — so this collector matches the
// DlpPolicy row by fileType/id and never switches exhaustively on the enum.
//
// The XML is decoded verbatim from the live sample (docs/../samples/246): a
// <policies> list, each <policy id mode name whenChangedUtc whenRulesChangedUtc>
// with <rules> (each <rule> carries an id, managementRuleId, a comma-joined
// workload string, per-rule <action> elements, and — for classification rules —
// a <condition> of <containsDataClassification><keyValues> sensitive-info-type
// entries) and policy-level <bindings> (each <binding workload type>). Two rule
// shapes appear: a "simple" rule with no mode/enabled attributes (mode inherited
// from the policy) and an "advanced" rule carrying its own mode/enabled/severity.
// Advanced rules carry BOTH `Workload` and `workload` attributes with identical
// values; encoding/xml binds the exact-case `workload` tag, so the duplicate is
// harmless here.
//
// # Cardinality (#112/#114): metrics count, logs name
//
// All metrics are bounded by policy/rule/binding SHAPE, never by tenant size:
//
//   - purview.dlp.policies{enforcement_mode}      — policy count by mode
//   - purview.dlp.rules{workload, action}         — rule count by workload x action
//   - purview.dlp.policy_bindings{workload, binding_type}
//   - purview.dlp.policy.last_changed_age (s)     — one gauge, age of the most
//     recently changed policy (NOT keyed by policy id — that would grow with the
//     policy count and pin an age per series).
//
// Per-policy / per-rule identity (ids, names, bound workloads, the matched
// sensitive-info-type ids, confidence/count bands) rides the log twins
// purview.dlp_policy and purview.dlp_rule — never a metric label. "Not a metric
// label" means LOG TWIN, not dropped (#114).
//
// # The one content boundary: DEFINITION is safe, matched VALUES are not
//
// A DLP policy DEFINITION — rule names, sensitive-info-type GUIDs, confidence
// thresholds, the enforcement mode — is safe to emit in full and is the whole
// point of this collector. What must NEVER be emitted is a rule CONDITION's
// value text: the notify-recipient addresses, custom-group GUIDs, file-type
// GUIDs and free-text embedded in <condition>/<argument><value> elements (for a
// credential-style condition the value could BE a secret). This collector's XML
// structs have no field that binds any <value> element text; it reads only the
// structured keyValue ATTRIBUTES (the sensitive-info-type id and its numeric
// count/confidence bounds). A guard test (TestNoConditionValuesEmitted) pins
// that no known condition value from the live sample reaches any emitted signal.
//
// # Beta, Experimental, opt-in
//
// The dataSecurityAndGovernance surface exists only under
// https://graph.microsoft.com/beta, so baseURL points at beta and the collector
// implements collectors.Experimental (an operator opts in explicitly). A 403 is
// a graceful info-skip (the tenant lacks the surface / scope), not a failure.
//
// # Checkpoint parse-skip (#246)
//
// The ~76KB base64/UTF-16/XML decode is skipped when the policy set is
// unchanged: the collector caches the parsed policies in memory keyed by the
// row's version hash and re-emits from that cache when the hash is unchanged, so
// the snapshot gauges are still re-emitted every cycle (a snapshot gauge must
// not vanish between policy edits) without re-parsing. The version hash is ALSO
// persisted to the per-tenant checkpoint.Store (collectors.Deps.Store) so a
// process restart can recognize an unchanged-since-last-run set and log it; the
// Store never gates emission (a restart's cold cache always re-parses whatever
// content is present). Deps.Store is OPTIONAL: when nil (unit tests) the
// collector degrades to always-parse and does not persist.
//
// # Permission (docs-only — NOT live-verified for this endpoint)
//
// RequiredPermissions returns InformationProtectionPolicy.Read.All, the
// information-protection policy READ scope the poller already holds and the
// closest documented match to "read DLP policy definitions". The precise scope
// the dataSecurityAndGovernance/policyFiles endpoint demands was NOT verified on
// the live tenant from this lane; treat the scope as `docs-only` until probed as
// graph2otel-poller (the poller token also carries RecordsManagement.Read.All
// and SecurityEvents.Read.All, either of which could be the true requirement).
package dlppolicies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "purview.dlp_policies"

	// betaBaseURL is the Graph beta service root — dataSecurityAndGovernance has
	// no v1.0 form.
	betaBaseURL = "https://graph.microsoft.com/beta"
	// policyFilesPath is the beta path this collector polls.
	policyFilesPath = "/security/dataSecurityAndGovernance/policyFiles"
	// dlpFileType is the fileType (and, redundantly, the id "DlpPolicy") of the
	// one policyFiles row this collector consumes.
	dlpFileType = "dlpPolicy"
	// endpoint is this collector's checkpoint namespace (the endpoint component
	// of the (tenant, endpoint) key).
	endpoint = "beta/security/dataSecurityAndGovernance/policyFiles"
	// enforceMode is the enforcement mode that means "actively blocking". Any
	// other mode (AuditAndNotify, test, disabled) is a non-enforcing posture and
	// escalates its policy twin to WARN.
	enforceMode = "Enforce"

	metricPolicies    = "purview.dlp.policies"
	metricRules       = "purview.dlp.rules"
	metricBindings    = "purview.dlp.policy_bindings"
	metricLastChanged = "purview.dlp.policy.last_changed_age"

	eventPolicy = "purview.dlp_policy"
	eventRule   = "purview.dlp_rule"
)

// whenChangedLayout is the timestamp format of a policy's whenChangedUtc
// attribute on the wire ("2026-07-14 21:53:27Z": space separator, trailing Z
// for UTC).
const whenChangedLayout = "2006-01-02 15:04:05Z07:00"

// Collector polls the Purview DLP policy inventory.
type Collector struct {
	g        collectors.GraphClient
	baseURL  string
	store    *checkpoint.Store
	tenantID string
	logger   *slog.Logger
	now      func() time.Time

	// In-memory parse cache: the actual parse-skip. When the fetched version hash
	// matches cachedVersion, the previous cycle's parsed policies are re-emitted
	// without re-running the base64/UTF-16/XML decode.
	cachedVersion string
	cached        []policy
	// parseCount counts how many times the expensive decode ran — a test hook for
	// the parse-skip.
	parseCount int
}

// New builds the DLP-policies collector. A nil logger falls back to
// slog.Default(); a nil store disables cross-restart version persistence
// (Collect then always parses on a version change and never persists).
func New(g collectors.GraphClient, store *checkpoint.Store, tenantID string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, store: store, tenantID: tenantID, logger: logger, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. DLP policy definitions change
// rarely (an admin edit), so an hourly poll is ample; the parse-skip makes the
// unchanged cycles cheap.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks this collector beta/opt-in: the dataSecurityAndGovernance
// surface exists only on the Graph beta endpoint.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the Graph application scope. See the package doc:
// this is the closest documented match the poller holds, NOT live-verified for
// this endpoint.
func (c *Collector) RequiredPermissions() []string {
	return []string{"InformationProtectionPolicy.Read.All"}
}

// policyFilesResp is the GET /policyFiles envelope.
type policyFilesResp struct {
	Value []policyFileRow `json:"value"`
}

// policyFileRow is one policyFiles "file" row. Content is base64 of UTF-16LE XML
// (or "" when status is noContent/notModified).
type policyFileRow struct {
	ID       string `json:"id"`
	FileType string `json:"fileType"`
	Version  string `json:"version"`
	Status   string `json:"status"`
	Content  string `json:"content"`
}

// Collect fetches the policyFiles set, decodes the DlpPolicy content (skipping
// the parse when the version hash is unchanged), and emits the bounded posture
// gauges plus one log twin per policy and per rule.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	body, err := c.g.RawGet(ctx, c.baseURL+policyFilesPath)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("skipping DLP policies: endpoint returned 403 (surface/scope not available on this tenant)",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return err
	}

	var resp policyFilesResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode policyFiles response: %w", err)
	}

	row, ok := dlpRow(resp.Value)
	if !ok {
		// No DlpPolicy row at all: nothing to inventory.
		c.logger.Info("no DlpPolicy row in policyFiles response; nothing to emit", "collector", collectorName)
		return nil
	}

	policies, err := c.policiesFor(row)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		// The row carried no parseable/present content and we have no cache: a
		// tenant with DLP configured but no policy payload this cycle.
		return nil
	}

	c.emit(e, policies)
	return nil
}

// dlpRow returns the DlpPolicy row from the policyFiles set, matched by fileType
// (falling back to id) — never by exhaustively switching the declared enum,
// which the wire has already been observed to exceed (customClassifications).
func dlpRow(rows []policyFileRow) (policyFileRow, bool) {
	for _, r := range rows {
		if strings.EqualFold(r.FileType, dlpFileType) || strings.EqualFold(r.ID, "DlpPolicy") {
			return r, true
		}
	}
	return policyFileRow{}, false
}

// policiesFor returns the parsed policies for a DlpPolicy row, using the
// in-memory version cache to skip the expensive decode when the version is
// unchanged. When the content must be parsed, the new version is persisted to
// the checkpoint store (best-effort).
func (c *Collector) policiesFor(row policyFileRow) ([]policy, error) {
	// Unchanged version and a warm cache: re-emit without re-parsing.
	if row.Version != "" && row.Version == c.cachedVersion && c.cached != nil {
		return c.cached, nil
	}
	if row.Content == "" {
		// No payload this cycle. Reuse the cache if we have one (server said
		// notModified); otherwise there is nothing to emit.
		if c.cached != nil {
			return c.cached, nil
		}
		return nil, nil
	}

	policies, err := parseContent(row.Content)
	if err != nil {
		return nil, err
	}
	c.parseCount++

	if prev := c.storedVersion(); prev != "" && prev != row.Version {
		c.logger.Info("DLP policy set changed since last run", "collector", collectorName,
			"previous_version", prev, "version", row.Version, "policies", len(policies))
	}
	c.cached, c.cachedVersion = policies, row.Version
	c.persistVersion(row.Version)
	return policies, nil
}

// parseContent decodes a DlpPolicy content field: base64 -> UTF-16LE bytes ->
// XML -> the collector's policy model.
func parseContent(content string) ([]policy, error) {
	raw, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("base64-decode DlpPolicy content: %w", err)
	}
	xmlText, err := decodeUTF16LE(raw)
	if err != nil {
		return nil, fmt.Errorf("utf-16le-decode DlpPolicy content: %w", err)
	}
	var doc xmlContent
	if err := xml.Unmarshal([]byte(xmlText), &doc); err != nil {
		return nil, fmt.Errorf("xml-decode DlpPolicy content: %w", err)
	}
	return doc.toPolicies(), nil
}

// decodeUTF16LE decodes little-endian UTF-16 bytes to a Go string, stripping a
// leading BOM if present. It is stdlib-only (encoding/binary is unnecessary — a
// two-byte little-endian read is a shift-or), so it adds no module dependency.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("odd byte length %d", len(b))
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if len(u16) > 0 && u16[0] == 0xFEFF {
		u16 = u16[1:]
	}
	return string(utf16.Decode(u16)), nil
}

// emit renders the bounded posture gauges and the per-policy / per-rule twins.
func (c *Collector) emit(e telemetry.Emitter, policies []policy) {
	byMode := map[string]int64{}
	byBinding := map[[2]string]int64{}
	byRule := map[[2]string]int64{}
	var newest time.Time
	haveNewest := false

	for _, p := range policies {
		byMode[p.Mode]++
		for _, b := range p.Bindings {
			byBinding[[2]string{b.Workload, b.Type}]++
		}
		for _, r := range p.Rules {
			for _, w := range r.Workloads {
				for _, a := range r.Actions {
					byRule[[2]string{w, a}]++
				}
			}
			e.LogEvent(ruleTwin(p, r))
		}
		if t, ok := parseWhenChanged(p.WhenChangedUtc); ok {
			if !haveNewest || t.After(newest) {
				newest, haveNewest = t, true
			}
		}
		e.LogEvent(policyTwin(p))
	}

	e.GaugeSnapshot(metricPolicies, "{policy}",
		"DLP policies, by enforcement mode (Enforce vs audit/test/disabled).", modePoints(byMode))
	e.GaugeSnapshot(metricRules, "{rule}",
		"DLP rules, by target workload and action.", ruleActionPoints(byRule))
	e.GaugeSnapshot(metricBindings, "{binding}",
		"DLP policy bindings, by workload and binding type.", bindingPoints(byBinding))

	if haveNewest {
		age := c.now().Sub(newest).Seconds()
		if age < 0 {
			age = 0
		}
		e.Gauge(metricLastChanged, semconv.UnitSeconds,
			"Seconds since the most recently changed DLP policy (max over whenChangedUtc).", age, nil)
	}
}

func modePoints(byMode map[string]int64) []telemetry.GaugePoint {
	pts := make([]telemetry.GaugePoint, 0, len(byMode))
	for mode, n := range byMode {
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrEnforcementMode: mode},
		})
	}
	return pts
}

func ruleActionPoints(byRule map[[2]string]int64) []telemetry.GaugePoint {
	pts := make([]telemetry.GaugePoint, 0, len(byRule))
	for k, n := range byRule {
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrWorkload: k[0], semconv.AttrAction: k[1]},
		})
	}
	return pts
}

func bindingPoints(byBinding map[[2]string]int64) []telemetry.GaugePoint {
	pts := make([]telemetry.GaugePoint, 0, len(byBinding))
	for k, n := range byBinding {
		pts = append(pts, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrWorkload: k[0], semconv.AttrBindingType: k[1]},
		})
	}
	return pts
}

// policyTwin renders one policy as a log record. It escalates to WARN when the
// policy is NOT enforcing (mode != Enforce): an audit-only / test / disabled DLP
// policy is the "enforcement quietly downgraded" posture signal (#246).
func policyTwin(p policy) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrPolicyName, p.Name)
	telemetry.SetStr(attrs, semconv.AttrEnforcementMode, p.Mode)
	telemetry.SetStr(attrs, semconv.AttrWhenChangedUtc, p.WhenChangedUtc)
	telemetry.SetStr(attrs, semconv.AttrWhenRulesChangedUtc, p.WhenRulesChangedUtc)
	telemetry.SetStr(attrs, semconv.AttrBoundWorkloads, strings.Join(p.BoundWorkloads(), ","))

	sev := telemetry.SeverityInfo
	if !strings.EqualFold(p.Mode, enforceMode) {
		sev = telemetry.SeverityWarn
	}

	name := p.Name
	if name == "" {
		name = p.ID
	}
	return telemetry.Event{
		Name:     eventPolicy,
		Body:     fmt.Sprintf("DLP policy %s: mode=%s", name, p.Mode),
		Severity: sev,
		Attrs:    attrs,
	}
}

// ruleTwin renders one rule as a log record: the per-rule definition detail the
// bounded gauges cannot carry — its id, management id, name, the comma-joined
// workload/action lists, and the sensitive-info-type ids + confidence/count
// bands its condition matches. It never carries a condition VALUE (see the
// package doc). Emitted at Info, except a rule explicitly disabled (enabled
// attribute == "false") which is inert and escalates to WARN.
func ruleTwin(p policy, r rule) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRuleId, r.ID)
	telemetry.SetStr(attrs, semconv.AttrManagementRuleId, r.ManagementRuleID)
	telemetry.SetStr(attrs, semconv.AttrRuleName, r.Name)
	telemetry.SetStr(attrs, semconv.AttrPolicyId, p.ID)
	telemetry.SetStr(attrs, semconv.AttrEnforcementMode, r.EffectiveMode(p))
	telemetry.SetStr(attrs, semconv.AttrWorkload, strings.Join(r.Workloads, ","))
	telemetry.SetStr(attrs, semconv.AttrActions, strings.Join(r.Actions, ","))
	telemetry.SetStr(attrs, semconv.AttrLastModifiedUtc, r.LastModifiedTimeUTC)
	if r.Enabled != "" {
		telemetry.SetStr(attrs, semconv.AttrEnabled, r.Enabled)
	}
	if r.Severity != "" {
		telemetry.SetStr(attrs, semconv.AttrSeverity, r.Severity)
	}
	if len(r.SensitiveInfoTypeIDs) > 0 {
		telemetry.SetStrs(attrs, semconv.AttrSensitiveInfoTypeIds, r.SensitiveInfoTypeIDs)
		if r.MinConfidence != nil {
			attrs[semconv.AttrMinConfidence] = *r.MinConfidence
		}
		if r.MaxConfidence != nil {
			attrs[semconv.AttrMaxConfidence] = *r.MaxConfidence
		}
		if r.MinCount != nil {
			attrs[semconv.AttrMinCount] = *r.MinCount
		}
		if r.MaxCount != nil {
			attrs[semconv.AttrMaxCount] = *r.MaxCount
		}
	}

	sev := telemetry.SeverityInfo
	if strings.EqualFold(r.Enabled, "false") {
		sev = telemetry.SeverityWarn
	}

	name := r.Name
	if name == "" {
		name = r.ID
	}
	return telemetry.Event{
		Name:     eventRule,
		Body:     fmt.Sprintf("DLP rule %s (policy %s): mode=%s", name, p.Name, r.EffectiveMode(p)),
		Severity: sev,
		Attrs:    attrs,
	}
}

// parseWhenChanged parses a policy whenChangedUtc value; ok is false when empty
// or unparseable (the age gauge then ignores that policy).
func parseWhenChanged(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(whenChangedLayout, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// storedVersion returns the version hash persisted on the last successful parse,
// or "" when no store is configured or none is stored.
func (c *Collector) storedVersion() string {
	if c.store == nil || c.tenantID == "" {
		return ""
	}
	cp, err := c.store.Load(c.tenantID, endpoint)
	if err != nil {
		return ""
	}
	for v := range cp.SeenIDs {
		return v
	}
	return ""
}

// persistVersion records the current version hash in the checkpoint store as the
// sole SeenIDs entry (the struct has no generic string field, and SeenIDs is a
// string->time set — a natural fit for "the one version we last parsed").
// Best-effort: a failure degrades to re-detecting the change next restart.
func (c *Collector) persistVersion(v string) {
	if c.store == nil || c.tenantID == "" || v == "" {
		return
	}
	cp := &checkpoint.Checkpoint{
		TenantID: c.tenantID,
		Endpoint: endpoint,
		SeenIDs:  checkpoint.SeenIDs{v: c.now()},
	}
	if err := c.store.Save(cp); err != nil {
		c.logger.Warn("dlppolicies: checkpoint save failed", "collector", collectorName, "error", err)
	}
}

// isForbidden reports whether err is a Graph 403 — the signal that this tenant
// cannot reach the surface (feature/scope missing), a graceful skip rather than
// a failure.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status 403") {
		return true
	}
	if code, _, ok := graphclient.UnwrapODataError(err); ok {
		return code == "Authorization_RequestDenied"
	}
	return false
}

// ---- the collector's policy model (decoupled from the raw XML) ----

type policy struct {
	ID                  string
	Mode                string
	Name                string
	WhenChangedUtc      string
	WhenRulesChangedUtc string
	Rules               []rule
	Bindings            []binding
}

// BoundWorkloads returns the distinct workloads this policy is bound to, in
// binding order.
func (p policy) BoundWorkloads() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range p.Bindings {
		if b.Workload == "" || seen[b.Workload] {
			continue
		}
		seen[b.Workload] = true
		out = append(out, b.Workload)
	}
	return out
}

type binding struct {
	Workload string
	Type     string
}

type rule struct {
	ID                   string
	Name                 string
	ManagementRuleID     string
	Mode                 string // "" on a simple rule (inherits the policy mode)
	Enabled              string
	Severity             string
	LastModifiedTimeUTC  string
	Workloads            []string // distinct, from the comma-joined workload attr
	Actions              []string // distinct action names, first-seen order
	SensitiveInfoTypeIDs []string
	MinConfidence        *int64
	MaxConfidence        *int64
	MinCount             *int64
	MaxCount             *int64
}

// EffectiveMode is the rule's own mode when it declares one, else the policy's.
func (r rule) EffectiveMode(p policy) string {
	if r.Mode != "" {
		return r.Mode
	}
	return p.Mode
}

// ---- raw XML binding (only the fields consumed; NO <value> element text) ----

type xmlContent struct {
	XMLName  xml.Name    `xml:"Content"`
	Policies []xmlPolicy `xml:"policies>policy"`
}

type xmlPolicy struct {
	ID                  string       `xml:"id,attr"`
	Mode                string       `xml:"mode,attr"`
	Name                string       `xml:"name,attr"`
	WhenChangedUtc      string       `xml:"whenChangedUtc,attr"`
	WhenRulesChangedUtc string       `xml:"whenRulesChangedUtc,attr"`
	Rules               []xmlRule    `xml:"rules>rule"`
	Bindings            []xmlBinding `xml:"bindings>binding"`
}

type xmlRule struct {
	ID                  string `xml:"id,attr"`
	Name                string `xml:"name,attr"`
	ManagementRuleID    string `xml:"managementRuleId,attr"`
	Mode                string `xml:"mode,attr"`
	Enabled             string `xml:"enabled,attr"`
	Severity            string `xml:"severity,attr"`
	Workload            string `xml:"workload,attr"`
	LastModifiedTimeUTC string `xml:"lastModifiedTimeUTC,attr"`
	// KeyValues binds ONLY the structured sensitive-info-type entries of a
	// classification condition (containsDataClassification). It deliberately does
	// NOT bind any <value> element text of the condition (is / equal /
	// IsMemberOfCustomGroups / notify arguments) — those can carry matched values.
	KeyValues []xmlKeyValues `xml:"version>condition>and>containsDataClassification>keyValues"`
	Actions   []xmlAction    `xml:"version>action"`
}

type xmlKeyValues struct {
	KeyValue []xmlKeyValue `xml:"keyValue"`
}

type xmlKeyValue struct {
	Key   string `xml:"key,attr"`
	Value string `xml:"value,attr"`
}

type xmlAction struct {
	Name string `xml:"name,attr"`
}

type xmlBinding struct {
	Workload string `xml:"workload,attr"`
	Type     string `xml:"type,attr"`
}

// toPolicies maps the raw XML into the collector's model.
func (d xmlContent) toPolicies() []policy {
	out := make([]policy, 0, len(d.Policies))
	for _, xp := range d.Policies {
		p := policy{
			ID:                  xp.ID,
			Mode:                xp.Mode,
			Name:                xp.Name,
			WhenChangedUtc:      xp.WhenChangedUtc,
			WhenRulesChangedUtc: xp.WhenRulesChangedUtc,
		}
		for _, xb := range xp.Bindings {
			p.Bindings = append(p.Bindings, binding(xb))
		}
		for _, xr := range xp.Rules {
			p.Rules = append(p.Rules, xr.toRule())
		}
		out = append(out, p)
	}
	return out
}

func (xr xmlRule) toRule() rule {
	r := rule{
		ID:                  xr.ID,
		Name:                xr.Name,
		ManagementRuleID:    xr.ManagementRuleID,
		Mode:                xr.Mode,
		Enabled:             xr.Enabled,
		Severity:            xr.Severity,
		LastModifiedTimeUTC: xr.LastModifiedTimeUTC,
		Workloads:           splitDistinct(xr.Workload),
		Actions:             distinctActions(xr.Actions),
	}
	r.applySensitiveInfoTypes(xr.KeyValues)
	return r
}

// applySensitiveInfoTypes pulls the sensitive-info-type ids and the confidence /
// count bands out of a classification condition's keyValues. Only the structured
// id/minConfidence/maxConfidence/minCount/maxCount keys are read; the band is the
// widest span over the rule's types.
func (r *rule) applySensitiveInfoTypes(kvs []xmlKeyValues) {
	for _, kv := range kvs {
		var id string
		var minConf, maxConf, minCnt, maxCnt *int64
		for _, e := range kv.KeyValue {
			switch e.Key {
			case "id":
				id = e.Value
			case "minConfidence":
				minConf = parseIntPtr(e.Value)
			case "maxConfidence":
				maxConf = parseIntPtr(e.Value)
			case "minCount":
				minCnt = parseIntPtr(e.Value)
			case "maxCount":
				maxCnt = parseIntPtr(e.Value)
			}
		}
		if id == "" {
			continue
		}
		r.SensitiveInfoTypeIDs = append(r.SensitiveInfoTypeIDs, id)
		r.MinConfidence = minPtr(r.MinConfidence, minConf)
		r.MaxConfidence = maxPtr(r.MaxConfidence, maxConf)
		r.MinCount = minPtr(r.MinCount, minCnt)
		r.MaxCount = maxPtr(r.MaxCount, maxCnt)
	}
}

// splitDistinct splits a comma-joined attribute (e.g. the rule workload string)
// into distinct, trimmed, non-empty values in first-seen order.
func splitDistinct(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

// distinctActions returns the distinct action names of a rule in first-seen
// order (a rule may repeat an action, e.g. EndpointRestrictAccess per channel).
func distinctActions(actions []xmlAction) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range actions {
		if a.Name == "" || seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		out = append(out, a.Name)
	}
	return out
}

func parseIntPtr(s string) *int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func minPtr(cur, v *int64) *int64 {
	if v == nil {
		return cur
	}
	if cur == nil || *v < *cur {
		return v
	}
	return cur
}

func maxPtr(cur, v *int64) *int64 {
	if v == nil {
		return cur
	}
	if cur == nil || *v > *cur {
		return v
	}
	return cur
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Store, d.TenantID, d.Logger)
	})
}

// Compile-time interface checks.
var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)
