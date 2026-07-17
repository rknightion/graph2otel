// Package securityincidents is the Entra security-incidents log source: a
// single WindowCollector over GET /security/incidents (v1.0, GA), emitting one
// OTLP log record per incident through the generic logpipeline engine (#92).
//
// An incident groups related security alerts into one correlated object
// carrying SecOps workflow state — severity, status, classification,
// determination, an ML-derived priorityScore, assignedTo, and tags — that is
// genuinely new signal, not derivable by aggregating the flat
// entra.security_alerts stream client-side. It is read-only via
// SecurityIncident.Read.All (a read scope exists independently of
// SecurityIncident.ReadWrite.All — verified live 2026-07-16, so this is NOT a
// "write scope for a read-only consumer" exception like the Intune
// reports-export one). It polls the security workload (moderate throttle
// limits, classified by the transport off the /security/ path prefix), not the
// Identity Protection 1 req/s bucket, so it wires no dedicated limiter.
//
// # Update-aware watermark (re-emit on change)
//
// Incidents MUTATE after creation — status, assignment, and tags change and
// bump lastUpdateDateTime. Watermarking on createdDateTime would emit each
// incident once and never again, missing every subsequent workflow change. So
// this collector watermarks on lastUpdateDateTime (TimeField) and makes the
// logpipeline dedupe id a COMPOSITE of the incident id plus its
// lastUpdateDateTime (mapIncident returns "<id>#<lastUpdateDateTime>"). When an
// incident's lastUpdateDateTime advances past the watermark, the next window
// re-fetches it and its composite id is NEW to SeenIDs, so it re-emits; an
// unchanged incident keeps the same composite id and is deduped away. This
// gives "re-emit on change" for free on the existing engine, with no
// logpipeline change.
//
// # Server-side $filter, client-side ordering
//
// GET /security/incidents supports $filter on lastUpdateDateTime (verified
// against the Microsoft Graph v1.0 "List incidents" reference), so the window
// is bounded on the wire — NoServerFilter is NOT needed. It does NOT support
// $orderby, so OrderByReliable is false: the engine omits $orderby and sorts
// the drained window client-side by lastUpdateDateTime before computing the
// watermark. $expand=alerts (to carry grouped alert ids inline) is not sent by
// default because the logpipeline engine has no $expand hook and this
// collector deliberately does not modify it; mapIncident still reads an
// `alerts` array if one is ever present, so the wiring is forward-compatible.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — the incident id, assignedTo (a UPN), custom/system tags,
// grouped alert ids — belongs here as structured log attributes. That same
// data must NEVER become a metric label; this package emits no metrics.
//
// See GitHub issue #92 (part of #86).
package securityincidents

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// path is the Graph v1.0 path this collector polls.
	path = "/security/incidents"
	// name is the stable collector key.
	name = "entra.security_incidents"
	// eventName is the OTLP LogRecord EventName every incident record carries.
	eventName = "entra.security_incident"
)

// Schedule tuning: incidents mutate less often than raw alerts arrive, so a
// 12-minute cadence (the 10-15 min range the issue suggests) with a generous
// safety lag is ample. The cold-start lookback reaches back a day to pick up
// incidents updated shortly before startup; maxWindow caps a post-outage
// catch-up to a week per tick.
const (
	interval        = 12 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = 24 * time.Hour
	maxWindow       = 7 * 24 * time.Hour
)

// collectorImpl is the security-incidents WindowCollector: the generic
// LogCollector plus the permission declaration the composition root's preflight
// check reads. No license gate — the endpoint itself needs only
// SecurityIncident.Read.All; a tenant on a lower Defender tier (rich incident
// correlation is effectively an MDE P2 feature) simply yields fewer/less-
// enriched incidents, not a hard failure, mirroring securityalerts.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the least-privilege Graph application scope. A
// read-only scope exists (SecurityIncident.Read.All) — verified live — so this
// is a plain read scope, not a write-for-read exception.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"SecurityIncident.Read.All"}
}

// newCollector builds the security-incidents WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:      path,
		TimeField: "lastUpdateDateTime",
		// $orderby is unsupported on /security/incidents, so use strict gt/lt
		// bounds paired with client-side ordering (OrderByReliable=false): the
		// engine omits $orderby and sorts the drained window by
		// lastUpdateDateTime itself.
		Flavor:          logpipeline.FlavorGtLt,
		OrderByReliable: false,
		// /security/incidents caps $top at 50 (live: $top=1000 -> HTTP 400 "The
		// limit of '50' for Top query has been exceeded"). The engine defaults
		// PageSize to 1000, so pin it to 50 or every cycle 400s.
		PageSize: 50,
		Map:      mapIncident,
	}
	lc := logpipeline.NewLogCollector(name, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapIncident turns one raw security.incident record into its dedupe id and the
// OTLP log Event.
//
// The dedupe id is the COMPOSITE "<id>#<lastUpdateDateTime>" — NOT the bare
// incident id — so that an incident whose lastUpdateDateTime advances (a status
// / assignment / tag change) presents a new id to the engine's SeenIDs dedupe
// and re-emits, while an unchanged incident is deduped. The clean incident id
// is still emitted verbatim in attrs["id"] for downstream correlation.
//
// It sets only attributes actually present, so an incident with no assignedTo,
// customTags/systemTags, or priorityScore simply omits those attributes rather
// than emitting empty/zero ones.
func mapIncident(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	lastUpdate := str(rec, "lastUpdateDateTime")
	displayName := str(rec, "displayName")
	severity := str(rec, "severity")
	status := str(rec, "status")

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "display_name", displayName)
	setStr(attrs, "severity", severity)
	setStr(attrs, "status", status)
	setStr(attrs, "classification", str(rec, "classification"))
	setStr(attrs, "determination", str(rec, "determination"))
	setStr(attrs, "assigned_to", str(rec, "assignedTo"))
	setStr(attrs, "created_time", str(rec, "createdDateTime"))
	setStr(attrs, "last_update_time", lastUpdate)

	// The record's own `tenantId` is deliberately NOT emitted — it is OURS, not
	// Microsoft's, and telemetry.WithTenant already stamps it on every record from
	// this Scheduler (#143). See entra/securityalerts's mapAlert for the live
	// measurement and the full reasoning. Do not re-add it.

	if score, ok := intField(rec, "priorityScore"); ok {
		attrs["priority_score"] = score
	}
	// `tags` is not a real field on this endpoint (#169, live-measured
	// 2026-07-17: 0/5 rows carried it — see TestLiveRecordCarriesNoWireTagsKey).
	// The wire's real tag fields are customTags (operator-set) and systemTags
	// (Defender-set); they are distinct fields with different semantics, so each
	// gets its own attribute rather than being collapsed into one.
	if tags := strSlice(rec, "customTags"); len(tags) > 0 {
		attrs["custom_tags"] = tags
	}
	if tags := strSlice(rec, "systemTags"); len(tags) > 0 {
		attrs["system_tags"] = tags
	}
	// Grouped alert ids, only present when $expand=alerts was applied. Not sent
	// by default (see the package doc), so this is normally a no-op; kept so the
	// Map is forward-compatible if $expand support is ever wired.
	if ids := alertIDs(rec); len(ids) > 0 {
		attrs["alert_ids"] = ids
		attrs["alert_count"] = len(ids)
	}

	dedupeID := id + "#" + lastUpdate
	return dedupeID, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("%s [%s/%s]", displayName, severity, status),
		Severity: severityFor(severity),
		Attrs:    attrs,
	}
}

// severityFor maps the incident's own severity string (kept verbatim in
// attrs["severity"]) to the OTLP log record's Severity: "high" incidents are
// errors, "medium"/"low" are warnings, anything else (including
// "informational", "unknownFutureValue", absent) stays Info.
func severityFor(incidentSeverity string) telemetry.Severity {
	switch incidentSeverity {
	case "high":
		return telemetry.SeverityError
	case "medium", "low":
		return telemetry.SeverityWarn
	default:
		return telemetry.SeverityInfo
	}
}

// --- small defensive accessors for untyped Graph JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// setStr adds key=val only when val is non-empty, so absent fields don't emit
// empty attributes.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// intField reads a whole-number field. JSON numbers decode as float64, so it
// accepts float64 (and int, defensively) and reports ok=false when absent or
// non-numeric.
func intField(m map[string]any, key string) (int, bool) {
	switch v := m[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

// strSlice reads a JSON array of strings (as decoded: []any of string),
// returning the string elements and skipping any non-string entries.
func strSlice(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// alertIDs extracts the ids of the incident's grouped alerts when an `alerts`
// array is present (only when $expand=alerts was requested). Each element is a
// security.alert object; its "id" is collected.
func alertIDs(m map[string]any) []string {
	raw, ok := m["alerts"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if am, ok := e.(map[string]any); ok {
			if id := str(am, "id"); id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       newCollector(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the security-incidents collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
)
