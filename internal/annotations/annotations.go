// Package annotations publishes a curated, closed set of Microsoft domain
// events into Grafana as annotations, so a dashboard can answer "what changed
// at 14:00" from graph2otel itself instead of an external automation (#400).
//
// # THE ONE AUTHORIZED SECOND EGRESS PATH — READ THIS BEFORE ADDING ANYTHING
//
// graph2otel is OTLP-push-only: no Prometheus endpoint, no generic listener or
// output framework, no Event Hub, no Log Analytics pipeline. #310 recorded a
// NARROW amendment to that invariant, on explicit maintainer instruction, for
// annotations and NOTHING else. This package is the whole of that amendment. It
// speaks exactly one HTTP call to exactly one destination —
// POST /api/annotations on the operator's Grafana — and metrics and logs do not
// gain a second path. Do not add another egress here, and do not read this
// package as precedent for one; the narrowness is carried by the token's scope
// (annotations:create and nothing else) and by this package boundary.
//
// # It publishes what collectors already emit; it polls nothing
//
// There is no Graph call, no new endpoint and no new scope anywhere in this
// package. Annotations are derived by teeing the telemetry.Emitter the
// collectors already emit through (see Tee), which is the same chokepoint
// telemetry.WithTenant and telemetry.WithTransport use and for the same reason:
// it is the only boundary with nothing behind it, so a collector added later is
// covered for free and cannot escape it.
//
// # Failure is isolated, always
//
// Nothing in here can block or fail collection. Enqueue never blocks: a full
// queue drops and counts. A Grafana outage, an expired token or a 429 is
// counted and surfaced through graph2otel.annotation.degraded — the same
// unrecovered-failure shape as telemetry's graph2otel.otlp.delivery.degraded —
// and is otherwise invisible to the poller. The ONE place a failure is fatal is
// startup: Preflight writes a real annotation before any collector runs, so a
// token that cannot write is reported at start rather than discovered at the
// first real event, when an operator is looking for context that was never
// there.
//
// # No secret and no raw configuration ever reaches annotation text
//
// Annotation text is built from a per-rule ALLOW-LIST of attribute keys, never
// from the whole attribute map, so a field added to a source record later cannot
// silently ride out to Grafana. The startup annotation carries #310's
// version + one-way configuration fingerprint contract
// (startupevent.Fingerprint), never the effective configuration.
package annotations

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Category is the closed set of annotation categories. Four of them are the
// curated domain categories the maintainer selected on #400; Lifecycle is
// graph2otel's own start marker, which doubles as the startup write probe.
type Category string

const (
	// CategoryConfigPosture is "what changed at 14:00": Conditional Access
	// policy changes, Intune compliance/configuration policy changes, admin
	// consent grants, app credential additions.
	CategoryConfigPosture Category = "config_posture"
	// CategorySecurityIncident is medium/high security alerts and incidents
	// becoming active. Timeline context, deliberately not a page.
	CategorySecurityIncident Category = "security_incident"
	// CategoryServiceHealth is Microsoft 365 service-health incidents opening
	// and closing — the annotation that explains collector degradation which is
	// not graph2otel's fault.
	CategoryServiceHealth Category = "service_health"
	// CategoryLicense is subscribed-SKU set changes and license exhaustion,
	// which explain a collector flipping to limited/partial_license.
	CategoryLicense Category = "license"
	// CategoryLifecycle is graph2otel's own process start marker.
	CategoryLifecycle Category = "lifecycle"
)

// Categories returns every category in a stable order. It exists so a test can
// enumerate the closed set instead of restating it.
func Categories() []Category {
	return []Category{
		CategoryConfigPosture,
		CategorySecurityIncident,
		CategoryServiceHealth,
		CategoryLicense,
		CategoryLifecycle,
	}
}

// Annotation is one annotation ready to publish.
type Annotation struct {
	// Category is the curated category this annotation belongs to.
	Category Category
	// TenantID is the Entra tenant the annotated event belongs to. Empty only
	// for a process-wide lifecycle annotation in a no-tenant (stdout) deploy.
	TenantID string
	// RuleID names the curated rule that produced it. It is part of the dedupe
	// key and is published as a tag, so an operator can tell two rules of one
	// category apart without parsing the text.
	RuleID string
	// Time is the annotation's event time. It is the SOURCE record's event time
	// wherever the source carries one — never arrival time, because an
	// annotation whose whole job is lining up against a metric step is worthless
	// misdated (#226 is the same rule for log records).
	Time time.Time
	// TimeEnd, when non-zero, makes this a REGION annotation spanning
	// [Time, TimeEnd]. Rollups use it so the marker covers the interval it
	// summarizes rather than pretending everything happened at one instant.
	TimeEnd time.Time
	// Text is the annotation body. Built from an allow-list; never a secret and
	// never the raw effective configuration.
	Text string
	// DedupeKey is the stable identity of the underlying occurrence. Two
	// deliveries of one event derive the same key, so the second is dropped.
	DedupeKey string
	// Severity is an optional bounded severity from the source record, published
	// as a tag when present.
	Severity string
}

// Tags returns the annotation's Grafana tag set — THE PUBLIC CONTRACT a
// dashboard annotation query selects on. It is deliberately a small, closed,
// low-cardinality set: Grafana indexes annotation tags, so a tag carrying an
// entity id or a hash would grow the tag store without ever being queried.
//
// Every annotation carries, in this order:
//
//	graph2otel                 — the root selector; present on every annotation
//	tenant_id:<guid>           — omitted only when no tenant is configured
//	category:<category>        — one of Categories()
//	rule:<rule id>             — the curated rule that produced it
//	severity:<severity>        — only when the source record carries one
//	rollup                     — only on a rolled-up interval annotation
//
// TagRoot is what a dashboard query should filter on; the rest narrow it.
func (a Annotation) Tags() []string {
	tags := []string{TagRoot}
	if a.TenantID != "" {
		tags = append(tags, TagTenantPrefix+a.TenantID)
	}
	tags = append(tags,
		TagCategoryPrefix+string(a.Category),
		TagRulePrefix+a.RuleID,
	)
	if a.Severity != "" {
		tags = append(tags, TagSeverityPrefix+a.Severity)
	}
	if !a.TimeEnd.IsZero() {
		tags = append(tags, TagRollup)
	}
	return tags
}

// The annotation tag contract. These are consumed by a Grafana dashboard's
// annotation query, so they are a published interface: renaming one silently
// stops every existing annotation query from matching, which looks exactly like
// "graph2otel stopped publishing annotations".
const (
	// TagRoot is on EVERY annotation graph2otel writes and is the selector a
	// dashboard annotation query should use.
	TagRoot = "graph2otel"
	// TagTenantPrefix + the tenant GUID. tenant_id is on every graph2otel
	// signal (#143) and this is its annotation form, so a marker follows the
	// tenant dropdown instead of appearing on every tenant's axes.
	TagTenantPrefix = "tenant_id:"
	// TagCategoryPrefix + one of Categories().
	TagCategoryPrefix = "category:"
	// TagRulePrefix + a curated rule id.
	TagRulePrefix = "rule:"
	// TagSeverityPrefix + a bounded severity from the source record.
	TagSeverityPrefix = "severity:"
	// TagRollup marks an interval rollup rather than a single occurrence.
	TagRollup = "rollup"
)

// dedupeDomain domain-separates and VERSIONS the dedupe hash, for the same two
// reasons startupevent's fingerprint domain exists: a dedupe key can never
// collide with a hash computed elsewhere, and changing what the key covers is a
// breaking change for a deployment mid-flight. Bumping /v1 makes every key move
// once — which republishes recent annotations exactly once, the honest cost of
// redefining identity.
const dedupeDomain = "graph2otel/annotation-dedupe/v1\x00"

// dedupeHexLen is how many hex characters of the digest form the key. 32 hex
// characters is 128 bits: collision-free at any rate a tenant can produce, and
// short enough that the persisted key set stays small.
const dedupeHexLen = 32

// DedupeKey derives the stable identity of one annotatable occurrence.
//
// It is a pure function of (tenant, rule, source identity) and NOTHING else — no
// clock, no counter, no process identity. That is the whole property being
// bought: the same source record re-delivered by an overlapping poll window, or
// re-seen after a restart, derives the same key and is dropped. A key that
// varied with arrival time would make every duplicate look like a second real
// event, which is indistinguishable from the truth once it is in Grafana.
func DedupeKey(tenantID, ruleID string, identity ...string) string {
	h := sha256.New()
	h.Write([]byte(dedupeDomain))
	// Length-prefix every component so ("a","bc") and ("ab","c") cannot collide.
	for _, part := range append([]string{tenantID, ruleID}, identity...) {
		_, _ = fmt.Fprintf(h, "%d:", len(part))
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:dedupeHexLen]
}

// summaryLimit bounds how many distinct titles a rolled-up annotation names.
// Beyond it the text says how many more there were. A rollup exists to keep a
// dashboard readable; an unbounded list in the tooltip defeats it.
const summaryLimit = 5

// summarize renders a bounded "N x title" summary from a title histogram, in
// descending count order with the title as a stable tiebreak.
func summarize(counts map[string]int) string {
	type entry struct {
		title string
		n     int
	}
	entries := make([]entry, 0, len(counts))
	for title, n := range counts {
		entries = append(entries, entry{title: title, n: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].n != entries[j].n {
			return entries[i].n > entries[j].n
		}
		return entries[i].title < entries[j].title
	})

	var b strings.Builder
	for i, e := range entries {
		if i == summaryLimit {
			_, _ = fmt.Fprintf(&b, "; +%d more", len(entries)-summaryLimit)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		if e.n > 1 {
			b.WriteString(strconv.Itoa(e.n) + "x ")
		}
		b.WriteString(e.title)
	}
	return b.String()
}
