package annotations

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// Kind distinguishes the two shapes of source stream a rule reads, because they
// need opposite cold-start behavior.
type Kind int

const (
	// KindEvent is a WindowCollector event stream: each record is one
	// occurrence, delivered at least once. Duplicates come from the overlap
	// window and from restarts, and are handled entirely by the persisted dedupe
	// set.
	KindEvent Kind = iota
	// KindState is a SnapshotCollector log twin: the WHOLE current set is
	// re-emitted every tick, so "a record arrived" does not mean "something
	// happened". Only an identity that was not in the previous set is an
	// occurrence — and on the very first observed set there IS no previous set,
	// so that set PRIMES silently. Publishing it would annotate every consent
	// grant and every app credential that already existed, at once, which is the
	// picket-fence failure #400 exists to avoid.
	KindState
)

// Rule is one curated annotatable event: which emitted signal it reads, which
// records of that signal qualify, and exactly which attributes may reach the
// annotation text.
//
// The set of rules is CLOSED and lives in Rules(). Adding one is a deliberate
// product decision about dashboard readability, not a drive-by.
type Rule struct {
	// ID is the stable rule identity. It is part of every dedupe key and is
	// published as a `rule:` tag, so renaming one republishes recent annotations
	// and breaks any dashboard query filtering on it. Treat it as frozen.
	ID string
	// Category gates the rule and decides whether it rolls up.
	Category Category
	// EventName is the OTEL event name of the source signal.
	EventName string
	// Kind selects the cold-start behavior. See KindEvent / KindState.
	Kind Kind
	// Match reports whether this record qualifies. It must never panic on a
	// missing or unexpectedly-typed attribute: an unmatched record is simply not
	// annotated, and a record is NEVER dropped from the telemetry pipeline by
	// anything in this package.
	Match func(attrs telemetry.Attrs) bool
	// Identity names the attribute keys whose values form the source identity
	// fed to DedupeKey. It must be enough to tell two real occurrences apart and
	// no more — including a field that changes on re-delivery (a poll timestamp,
	// a lastModified) would defeat dedupe entirely.
	Identity []string
	// Detail is the ALLOW-LIST of attribute keys rendered into the annotation
	// text, in order. Anything not named here never reaches Grafana, so a field
	// added to the source record later cannot silently ride out.
	Detail []string
	// Title renders the short human label used in a rolled-up summary and as the
	// text prefix. It reads only Detail-allow-listed values.
	Title func(attrs telemetry.Attrs) string
	// SeverityAttr, when set, names the attribute whose value becomes the
	// `severity:` tag. It must be a bounded value set.
	SeverityAttr string
}

// Rules returns the curated, closed rule set: the four categories the
// maintainer selected on #400, mapped onto the signals graph2otel already
// emits.
//
// # Evidence classes for the match predicates, stated because they differ
//
// Every predicate below is REPORT-ONLY: a value the predicate does not
// recognize means "no annotation", never a dropped or altered record. That is
// what makes a docs-only predicate safe to ship — the cost of it being wrong is
// a missing marker, not corrupted telemetry (the same asymmetry that makes
// internal/wirecheck report-only).
//
//   - entra.security_alert / entra.security_incident severity and status:
//     `docs-only`, keyed on Graph's documented alertSeverity / incidentStatus
//     enums, matched case-insensitively because Graph's casing has differed
//     between v1.0 and beta on other enums.
//   - m365.service_health_issue is_resolved: derived from the boolean the
//     collector already emits, so it cannot drift from the mapped value.
//   - intune.audit_event category: "DeviceConfiguration" is
//     `live-measured (2026-07-27, #400)` — 543 records over 30d on m7kni, every
//     one with activity_result "Success" (capital S; the comparison is
//     case-insensitive and needs to stay that way). "Compliance" and
//     "DeviceCompliancePolicy" remain `docs-only`: neither occurred in that
//     window, which is absence of evidence, not evidence of absence. All three
//     are matched, and an unrecognized category is simply not annotated.
//     Read-shaped verbs within a matched category are excluded — see
//     readOnlyActivityVerbs.
//   - entra.directory_audit Conditional Access:
//     `live-measured (2026-07-27, #400)`, and the previous note here was WRONG.
//     It said there is no CA-specific attribute to key on. There is:
//     `logged_by_service` is literally "Conditional Access" on every record from
//     that surface (69 over 30d on m7kni). The substring-only predicate that
//     belief produced missed "Update named location" — a real CA posture change,
//     because named locations are CA conditions, so a policy's meaning changes
//     without its own record moving. Both predicates are now matched as a union.
//     The conditionalaccess collector is still metrics-only and still leaves
//     policy CHANGES to this audit stream.
//   - entra.consent_grant consent_type: `docs-only`. "AllPrincipals" is
//     tenant-wide admin consent on an oauth2PermissionGrant; "Principal" is one
//     user consenting for themselves, which is not a posture change worth a
//     dashboard marker.
//   - entra.app_credential: no predicate at all. Every credential on an app is
//     annotatable when it APPEARS, which KindState already means.
func Rules() []Rule {
	return []Rule{
		{
			ID:        "entra.conditional_access_policy_changed",
			Category:  CategoryConfigPosture,
			EventName: "entra.directory_audit",
			Kind:      KindEvent,
			Match: func(a telemetry.Attrs) bool {
				if !strings.EqualFold(attrString(a, "result"), "success") {
					return false
				}
				// The service attribute is the primary predicate; the activity
				// substring is kept as a union so a CA change logged by another
				// service still lands. Either alone is sufficient.
				if strings.EqualFold(attrString(a, "logged_by_service"), "Conditional Access") {
					return true
				}
				return strings.Contains(
					strings.ToLower(attrString(a, "activity_display_name")),
					"conditional access",
				)
			},
			Identity:     []string{"id"},
			Detail:       []string{"activity_display_name", "logged_by_service", "initiator_app_display_name", "target_display_names", "modified_property_names"},
			Title:        func(a telemetry.Attrs) string { return attrString(a, "activity_display_name") },
			SeverityAttr: "",
		},
		{
			ID:        "intune.policy_changed",
			Category:  CategoryConfigPosture,
			EventName: "intune.audit_event",
			Kind:      KindEvent,
			Match: func(a telemetry.Attrs) bool {
				if !strings.EqualFold(attrString(a, "activity_result"), "success") {
					return false
				}
				switch strings.ToLower(attrString(a, "category")) {
				case "deviceconfiguration", "compliance", "devicecompliancepolicy":
					return !isReadOnlyActivity(attrString(a, "activity_type"))
				default:
					return false
				}
			},
			Identity: []string{"id"},
			Detail: []string{
				"category", "activity_type", "display_name",
				"actor_user_principal_name", "actor_application_display_name",
				"modified_property_names",
			},
			Title: func(a telemetry.Attrs) string {
				activity := attrString(a, "activity_type")
				if activity == "" {
					activity = attrString(a, "activity")
				}
				return strings.TrimSpace(attrString(a, "category") + " " + activity)
			},
		},
		{
			ID:        "entra.admin_consent_granted",
			Category:  CategoryConfigPosture,
			EventName: "entra.consent_grant",
			Kind:      KindState,
			Match: func(a telemetry.Attrs) bool {
				return strings.EqualFold(attrString(a, "consent_type"), "allprincipals")
			},
			Identity: []string{"id"},
			Detail:   []string{"client_id", "resource_display_name", "scope", "privilege"},
			Title: func(a telemetry.Attrs) string {
				resource := attrString(a, "resource_display_name")
				if resource == "" {
					resource = attrString(a, "resource_id")
				}
				return "admin consent granted on " + resource
			},
			SeverityAttr: "privilege",
		},
		{
			ID:        "entra.app_credential_added",
			Category:  CategoryConfigPosture,
			EventName: "entra.app_credential",
			Kind:      KindState,
			Match:     nil,
			Identity:  []string{"app_object_id", "key_id"},
			Detail: []string{
				"display_name", "credential_type", "credential_display_name",
				"end_date_time", "expiry_bucket",
			},
			Title: func(a telemetry.Attrs) string {
				return "app credential added to " + attrString(a, "display_name")
			},
		},
		{
			ID:        "entra.security_alert_active",
			Category:  CategorySecurityIncident,
			EventName: "entra.security_alert",
			Kind:      KindEvent,
			Match: func(a telemetry.Attrs) bool {
				return activeSeverity(attrString(a, "severity")) &&
					activeAlertStatus(attrString(a, "status"))
			},
			// status participates in identity on purpose: an alert that closes and
			// reopens is a second occurrence, and the identity must be able to say
			// so. It is safe here because the status VALUE is what the predicate
			// already gates on, so no unrelated churn can enter the key.
			Identity:     []string{"id", "status"},
			Detail:       []string{"title", "severity", "status", "category", "service_source", "detection_source", "incident_id"},
			Title:        func(a telemetry.Attrs) string { return attrString(a, "title") },
			SeverityAttr: "severity",
		},
		{
			ID:        "entra.security_incident_active",
			Category:  CategorySecurityIncident,
			EventName: "entra.security_incident",
			Kind:      KindEvent,
			Match: func(a telemetry.Attrs) bool {
				return activeSeverity(attrString(a, "severity")) &&
					strings.EqualFold(attrString(a, "status"), "active")
			},
			Identity:     []string{"id", "status"},
			Detail:       []string{"display_name", "severity", "status", "classification", "determination", "assigned_to"},
			Title:        func(a telemetry.Attrs) string { return attrString(a, "display_name") },
			SeverityAttr: "severity",
		},
		{
			ID:        "m365.service_health_issue_open",
			Category:  CategoryServiceHealth,
			EventName: "m365.service_health_issue",
			Kind:      KindState,
			Match:     func(a telemetry.Attrs) bool { return !attrBool(a, "is_resolved") },
			// The resolved flag is in the identity so the SAME issue produces one
			// marker when it opens and a second when it closes, through the two
			// rules below, without either deduping the other away.
			Identity:     []string{"id", "is_resolved"},
			Detail:       []string{"title", "service", "classification", "status", "feature", "start_date_time"},
			Title:        func(a telemetry.Attrs) string { return attrString(a, "service") + ": " + attrString(a, "title") },
			SeverityAttr: "classification",
		},
		{
			ID:        "m365.service_health_issue_resolved",
			Category:  CategoryServiceHealth,
			EventName: "m365.service_health_issue",
			Kind:      KindState,
			Match:     func(a telemetry.Attrs) bool { return attrBool(a, "is_resolved") },
			Identity:  []string{"id", "is_resolved"},
			Detail:    []string{"title", "service", "classification", "status", "feature", "last_modified_date_time"},
			Title: func(a telemetry.Attrs) string {
				return "resolved — " + attrString(a, "service") + ": " + attrString(a, "title")
			},
			SeverityAttr: "classification",
		},
	}
}

// LicenseRuleIDs are the license/entitlement rule ids. They are declared here
// rather than in Rules() because they are derived from METRIC snapshots rather
// than from a log record: entra.license.consumed / entra.license.enabled are
// gauge snapshots, and "the SKU set changed" is a comparison between two
// snapshots, not a field on either. See licenseWatcher.
const (
	// RuleLicenseSKUAdded fires when a subscribed SKU appears that was not in
	// the previous snapshot.
	RuleLicenseSKUAdded = "entra.license_sku_added"
	// RuleLicenseSKURemoved fires when a subscribed SKU disappears.
	RuleLicenseSKURemoved = "entra.license_sku_removed"
	// RuleLicenseUnitsChanged fires when a SKU's prepaid (enabled) unit count
	// changes — a subscription resize.
	RuleLicenseUnitsChanged = "entra.license_units_changed"
	// RuleLicenseExhausted fires on the TRANSITION into exhaustion: consumed
	// units reaching or exceeding enabled units, which is what makes a
	// license-gated collector report limited/partial_license.
	RuleLicenseExhausted = "entra.license_exhausted"
)

// LicenseRuleIDs returns the license rule ids in a stable order.
func LicenseRuleIDs() []string {
	return []string{
		RuleLicenseSKUAdded,
		RuleLicenseSKURemoved,
		RuleLicenseUnitsChanged,
		RuleLicenseExhausted,
	}
}

// activeSeverity reports whether a Graph alert/incident severity counts as
// "worth a dashboard marker". Low and informational deliberately do not: a
// healthy tenant produces a steady trickle of them and a picket fence of
// low-severity markers is what stops operators reading annotations at all.
func activeSeverity(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "medium", "high":
		return true
	default:
		return false
	}
}

// activeAlertStatus reports whether an alertStatus means the alert is live.
// "resolved" is excluded and "unknown" is excluded — an unknown status is not
// evidence that anything became active.
func activeAlertStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "new", "inprogress":
		return true
	default:
		return false
	}
}

// readOnlyActivityVerbs are the Intune audit verbs that CHANGE NOTHING. Intune
// audits reads into the same categories it audits changes into, so without this
// a "what changed at 14:00" marker lands for someone merely looking: `Search
// CloudCertificationAuthorityLeafCertificate`, `Search CloudCertificationAuthority`
// and `Get CloudCertificationAuthority` were 38 of 543 DeviceConfiguration
// records over 30 days on m7kni (live-measured 2026-07-27, #400).
//
// It is a DENY list on purpose. Intune's verb vocabulary is open — the same 30
// days carried `assignDeviceManagementScript`, `patchDeviceCustomAttributeShellScript`
// and `createDeviceShellScript` — so an allow list would silently stop
// annotating real changes the first time Microsoft adds a verb. An unrecognized
// verb therefore still annotates: a spare marker is recoverable, a missing one
// is the failure this feature exists to prevent.
var readOnlyActivityVerbs = map[string]bool{
	"search": true,
	"get":    true,
	"list":   true,
	"export": true,
	"read":   true,
}

// isReadOnlyActivity reports whether an Intune `activity_type` names a read.
// The wire form is verb-first with the entity after a space ("Patch
// DeviceConfiguration", "Search CloudCertificationAuthority"), and the verb's
// casing varies between Pascal and camel on the same tenant, so only the leading
// word is compared and it is compared case-insensitively.
func isReadOnlyActivity(activityType string) bool {
	verb, _, _ := strings.Cut(strings.TrimSpace(activityType), " ")
	return readOnlyActivityVerbs[strings.ToLower(verb)]
}

// attrString renders one attribute value as a string for matching and for text.
// telemetry.Attrs is map[string]any over a documented value set (string, bool,
// int, int64, float64, []string), so this covers all of it; anything else
// renders with %v rather than panicking, because a rule must never be able to
// take the process down.
func attrString(attrs telemetry.Attrs, key string) string {
	v, ok := attrs[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []string:
		return strings.Join(t, ",")
	default:
		return fmt.Sprintf("%v", t)
	}
}

// attrBool reads a boolean attribute, tolerating the string form. A missing or
// unparseable value reads as false.
func attrBool(attrs telemetry.Attrs, key string) bool {
	switch t := attrs[key].(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(t)
		return err == nil && b
	default:
		return false
	}
}

// renderText builds the annotation body from the rule's title plus its
// allow-listed detail attributes. Empty values are skipped so the text does not
// carry a wall of "key=" for attributes this record happens not to have.
func renderText(rule Rule, attrs telemetry.Attrs) string {
	var b strings.Builder
	title := strings.TrimSpace(rule.Title(attrs))
	if title == "" {
		title = rule.ID
	}
	b.WriteString(title)
	for _, key := range rule.Detail {
		value := strings.TrimSpace(attrString(attrs, key))
		if value == "" {
			continue
		}
		_, _ = fmt.Fprintf(&b, " | %s=%s", key, value)
	}
	return b.String()
}
