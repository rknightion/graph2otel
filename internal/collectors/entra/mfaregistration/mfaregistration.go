// Package mfaregistration is the Entra MFA / authentication-methods
// registration-posture collector: tenant-wide counts of users registered
// for/capable of MFA, SSPR, and passwordless auth, plus per-method
// registration counts and an admin-vs-non-admin MFA-capable split — the
// compliance-KPI signal from issue #69 — PLUS a log twin of the same fetch,
// one entra.user_registration OTEL log record per user per cycle carrying
// the per-user identity the metrics can never carry. See "Log twin" below.
//
// # Why userRegistrationDetails, not the two summary functions
//
// The issue's original API table names
// GET /reports/authenticationMethods/usersRegisteredByFeatureSummary and
// .../usersRegisteredByMethodSummary. Validating against the current
// Microsoft Graph v1.0 docs (learn.microsoft.com/graph/api/
// authenticationmethodsroot-usersregisteredbyfeature and
// -usersregisteredbymethod, both fetched 2026-07-15) found two premise
// deviations:
//
//  1. The v1.0 function names are usersRegisteredByFeature and
//     usersRegisteredByMethod (no "Summary" suffix) — they return a
//     userRegistrationFeatureSummary / userRegistrationMethodSummary object,
//     but the function names themselves don't carry that suffix.
//  2. Critically, both functions' Permissions tables list "Application: Not
//     supported" — only a delegated (signed-in work/school user) token can
//     call them. graph2otel is an unattended, app-only exporter
//     (azidentity.DefaultAzureCredential, client secret/certificate, no
//     interactive user), so neither summary function is reachable at all.
//
// The only Graph v1.0 endpoint in this API family that supports the
// Application permission type is
// GET /reports/authenticationMethods/userRegistrationDetails (Application:
// AuditLog.Read.All), which returns one record per user. This collector
// therefore pages that per-user endpoint and aggregates client-side into the
// same bounded, feature/method-shaped counts the summary functions would
// have produced — never emitting a per-user series. This is the documented
// fallback the authoring guide anticipates ("if only per-user detail is
// available, aggregate it into bounded counts and do not emit per-user
// series").
//
// # A known scaling limitation of this fallback
//
// collectors.GetAllValues's own doc comment says it must never be used to
// page a full users/devices collection, specifically because tenant-size
// pagination can exceed its 1000-page defensive cap. userRegistrationDetails
// is inherently one row per (non-disabled) user, so it has exactly that
// shape. There is no alternative Graph v1.0 endpoint that both aggregates
// server-side AND supports application permissions, so this collector
// deliberately accepts that tradeoff rather than leaving the whole signal
// unimplemented — flagged here for the coordinating thread/maintainer:
// extremely large tenants (roughly above the 1000-page x page-size ceiling)
// could see this collector's fetch fail with GetAllValues' pagination-exceeded
// error. Revisit if Microsoft ships an application-permission-compatible
// aggregate for this report.
//
// The log twin below (per-user identity) does not change this: it decodes
// and emits from the SAME fetch, adding zero Graph calls and zero additional
// pages — the pagination-exceeded risk is a function of user count alone,
// unaffected by what this collector does with each row once fetched.
//
// # Log twin: per-user identity, and its volume cost
//
// userRegistrationDetails' per-user identity fields (userPrincipalName,
// userDisplayName, id, lastUpdatedDateTime) were previously excluded at the
// $select level and never crossed the wire at all — so this collector could
// answer "how many admins lack MFA" but never "WHICH admins", arguably the
// single most-asked identity-posture question there is. That was a bug
// (#112's framing issue, not a deliberate privacy control — see below), so
// $select now also requests those four fields, and each decoded row is
// additionally emitted as an entra.user_registration OTEL log record
// carrying them plus every posture flag (mfa/sspr/passwordless
// registered/capable/enabled, methodsRegistered).
//
// Per the maintainer decision on #114, EVERY user row is twinned each
// cycle, not just posture failures: graph2otel's log pipeline is the
// surviving SIEM record for this signal, and filtering to "problem rows
// only" would break the correlation a SIEM exists to do ("did this user
// have MFA registered last month"). This is a STATE feed, like the metrics
// above: a user is re-emitted every cycle regardless of posture.
//
// This makes the volume characteristic explicit, so an operator knows what
// they are signing up for: log volume scales LINEARLY with tenant user
// count, at DefaultInterval's cadence (15 minutes) — one record per user
// per cycle. A 1,000-user tenant emits roughly 1,000 records every 15
// minutes (~4,000/hour); a 50,000-user tenant emits roughly 200,000/hour.
// This is orthogonal to the pagination-exceeded risk noted above (both scale
// with user count, but the log twin adds no extra fetches), and is a
// materially higher volume than the entra.risk log twin (which only emits
// for the, typically small, currently-risky population).
//
// Identity is never a metric label here (CLAUDE.md's cardinality rule):
// the three status/method/admin-split gauges above stay bounded by their
// fixed enum/method dimensions regardless of tenant size — see
// TestNoPerEntitySeries.
package mfaregistration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.mfa_registration"

// Metric names this collector emits, all namespaced entra.mfa.registration.*
// per CLAUDE.md's metric namespace convention.
const (
	statusMetricName          = "entra.mfa.registration.users.total"
	methodMetricName          = "entra.mfa.registration.methods.total"
	adminMfaCapableMetricName = "entra.mfa.registration.admin_mfa_capable.total"
)

// eventUserRegistration is the log-twin OTLP LogRecord EventName, one per
// user per cycle — see the package doc's "Log twin" section. Frozen by #114.
const eventUserRegistration = "entra.user_registration"

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// requestURL is the userRegistrationDetails read this collector issues. The
// $select trims the response to exactly the fields this collector reads:
// the seven posture booleans + methodsRegistered feed the bounded metrics
// below, and id/userPrincipalName/userDisplayName/lastUpdatedDateTime feed
// ONLY the per-user log twin (see the package doc) — never a metric label.
const requestPath = "/reports/authenticationMethods/userRegistrationDetails" +
	"?$select=isAdmin,isMfaRegistered,isMfaCapable,isSsprRegistered,isSsprEnabled,isSsprCapable,isPasswordlessCapable,methodsRegistered," +
	"id,userPrincipalName,userDisplayName,lastUpdatedDateTime"

var requestURL = defaultBaseURL + requestPath

// registrationStatus pairs a bounded `status` attribute value with the
// userRegistrationDetails boolean field it reads. This is the fixed,
// exhaustive set mirroring (and, since it's read off the per-user detail
// resource rather than the delegated-only summary function, actually
// exceeding) the fields the real userRegistrationFeatureSummary would
// report — cardinality of the status metric is always exactly
// len(registrationStatuses), zero-filled every tick regardless of tenant
// size.
type registrationStatus struct {
	attr string
	get  func(userRegistrationDetail) bool
}

var registrationStatuses = []registrationStatus{
	{"mfa_registered", func(u userRegistrationDetail) bool { return u.IsMfaRegistered }},
	{"mfa_capable", func(u userRegistrationDetail) bool { return u.IsMfaCapable }},
	{"sspr_registered", func(u userRegistrationDetail) bool { return u.IsSsprRegistered }},
	{"sspr_enabled", func(u userRegistrationDetail) bool { return u.IsSsprEnabled }},
	{"sspr_capable", func(u userRegistrationDetail) bool { return u.IsSsprCapable }},
	{"passwordless_capable", func(u userRegistrationDetail) bool { return u.IsPasswordlessCapable }},
}

// userRegistrationDetail mirrors the fields of the Graph
// userRegistrationDetails resource this collector reads. The seven posture
// fields feed the bounded metrics (see registrationStatuses / Collect);
// ID/UserPrincipalName/UserDisplayName/LastUpdatedDateTime feed ONLY the
// entra.user_registration log twin (logTwin) — CLAUDE.md's cardinality rule
// means they must never reach a metric label, but "not a metric label"
// means "log twin", not "dropped" (see the package doc's Log-twin section
// and TestNoPerEntitySeries, which pins the metric side of that boundary).
// Field names/casing verified against learn.microsoft.com/graph/api/
// resources/userregistrationdetails (v1.0), 2026-07-16.
type userRegistrationDetail struct {
	IsAdmin               bool     `json:"isAdmin"`
	IsMfaRegistered       bool     `json:"isMfaRegistered"`
	IsMfaCapable          bool     `json:"isMfaCapable"`
	IsSsprRegistered      bool     `json:"isSsprRegistered"`
	IsSsprEnabled         bool     `json:"isSsprEnabled"`
	IsSsprCapable         bool     `json:"isSsprCapable"`
	IsPasswordlessCapable bool     `json:"isPasswordlessCapable"`
	MethodsRegistered     []string `json:"methodsRegistered"`

	// Log-twin-only identity fields — never read into a metric attribute.
	ID                  string `json:"id"`
	UserPrincipalName   string `json:"userPrincipalName"`
	UserDisplayName     string `json:"userDisplayName"`
	LastUpdatedDateTime string `json:"lastUpdatedDateTime"`
}

// Collector polls the MFA/auth-methods registration report.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the MFA registration collector. A nil logger falls back to the
// slog default. This collector takes no license.Capabilities: it is a
// WHOLE-collector, Entra ID P1-gated feature (see RequiredCapability), so the
// composition root skips constructing/registering it entirely for a tenant
// that lacks P1, rather than this collector degrading internally.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Registration posture
// drifts slowly and userRegistrationDetails has no delta query support (a
// full read every cycle), so a longer interval matches this exporter's other
// slow-drifting posture collectors (e.g. conditional access, licensing).
func (c *Collector) DefaultInterval() time.Duration { return 15 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Per current Microsoft Graph docs, AuditLog.Read.All is the (only)
// supported application permission for
// GET /reports/authenticationMethods/userRegistrationDetails — the two
// summary functions the issue named do not support application permissions
// at all (see the package doc), so no other scope is needed or requested.
func (c *Collector) RequiredPermissions() []string { return []string{"AuditLog.Read.All"} }

// RequiredCapability implements license.CapabilityRequirer. The registration
// report requires Entra ID P1 or P2; a P2 tenant normally also holds the P1
// capability, so gating on P1 alone covers both tiers. The composition root
// uses this to skip the whole collector, and show the skip reason on the
// admin page, for a tenant that lacks P1.
func (c *Collector) RequiredCapability() license.Capability { return license.CapEntraP1 }

// Collect fetches every userRegistrationDetails record and aggregates it
// into three bounded gauge snapshots: registration/capability status counts,
// per-method registration counts, and an admin-vs-non-admin MFA-capable
// split. No advanced $filter/$search/$count is used (a $select-trimmed full
// read, aggregated client-side), so no ConsistencyLevel header is required.
//
// It ALSO emits one entra.user_registration log record per user, from the
// same decoded rows, carrying the per-user identity the metrics above can
// never carry — see the package doc's "Log twin" section. Every row is
// twinned, not just posture failures (the #114 maintainer decision).
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+requestPath, nil)
	if err != nil {
		return fmt.Errorf("mfa registration: fetch userRegistrationDetails: %w", err)
	}

	statusCounts := make(map[string]int64, len(registrationStatuses))
	methodCounts := map[string]int64{}
	var adminMfaCapable, nonAdminMfaCapable int64

	for _, r := range raw {
		var u userRegistrationDetail
		if err := json.Unmarshal(r, &u); err != nil {
			c.logger.Warn("mfa registration: skipping unparseable user registration record", "collector", collectorName, "error", err)
			continue
		}

		for _, rs := range registrationStatuses {
			if rs.get(u) {
				statusCounts[rs.attr]++
			}
		}

		for _, m := range u.MethodsRegistered {
			methodCounts[m]++
		}

		if u.IsMfaCapable {
			if u.IsAdmin {
				adminMfaCapable++
			} else {
				nonAdminMfaCapable++
			}
		}

		e.LogEvent(logTwin(u))
	}

	statusPoints := make([]telemetry.GaugePoint, 0, len(registrationStatuses))
	for _, rs := range registrationStatuses {
		statusPoints = append(statusPoints, telemetry.GaugePoint{
			Value: float64(statusCounts[rs.attr]),
			Attrs: telemetry.Attrs{"status": rs.attr},
		})
	}
	e.GaugeSnapshot(statusMetricName, "{user}",
		"Entra users by MFA/SSPR/passwordless registration and capability status.", statusPoints)

	methodPoints := make([]telemetry.GaugePoint, 0, len(methodCounts))
	for method, n := range methodCounts {
		methodPoints = append(methodPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{"method": method},
		})
	}
	e.GaugeSnapshot(methodMetricName, "{user}",
		"Entra users registered for each authentication method (a user may count toward several methods).", methodPoints)

	e.GaugeSnapshot(adminMfaCapableMetricName, "{user}",
		"Entra users capable of MFA, split by admin role membership.", []telemetry.GaugePoint{
			{Value: float64(adminMfaCapable), Attrs: telemetry.Attrs{"is_admin": true}},
			{Value: float64(nonAdminMfaCapable), Attrs: telemetry.Attrs{"is_admin": false}},
		})

	return nil
}

// logTwin renders one userRegistrationDetails row as an OTLP log record.
//
// Timestamp is deliberately left zero ("now", i.e. poll time) rather than
// set to LastUpdatedDateTime — this is a STATE feed like entra.risk's, and
// every user is re-emitted every cycle regardless of posture, so stamping
// each record with Graph's last-assessment time would pile every repeat
// onto one instant. The assessment time is preserved as the last_updated
// attribute instead.
func logTwin(u userRegistrationDetail) telemetry.Event {
	attrs := telemetry.Attrs{}
	setStr(attrs, "id", u.ID)
	setStr(attrs, "user_principal_name", u.UserPrincipalName)
	setStr(attrs, "user_display_name", u.UserDisplayName)
	setStr(attrs, "last_updated", u.LastUpdatedDateTime)
	setStr(attrs, "methods_registered", strings.Join(u.MethodsRegistered, ","))

	// The seven posture booleans are always decoded (never legitimately
	// absent), so they're direct string assignments rather than
	// setStr-omitted — house convention is string-typed log attributes
	// (Loki structured metadata is string on the wire), not omission of a
	// real false value.
	attrs["is_admin"] = strconv.FormatBool(u.IsAdmin)
	attrs["mfa_registered"] = strconv.FormatBool(u.IsMfaRegistered)
	attrs["mfa_capable"] = strconv.FormatBool(u.IsMfaCapable)
	attrs["sspr_registered"] = strconv.FormatBool(u.IsSsprRegistered)
	attrs["sspr_enabled"] = strconv.FormatBool(u.IsSsprEnabled)
	attrs["sspr_capable"] = strconv.FormatBool(u.IsSsprCapable)
	attrs["passwordless_capable"] = strconv.FormatBool(u.IsPasswordlessCapable)

	// Only an admin who cannot currently complete a policy-compliant MFA
	// challenge escalates: IsMfaCapable (not IsMfaRegistered) is the
	// operationally meaningful "can this admin actually MFA right now"
	// signal — a user can have IsMfaRegistered true with IsMfaCapable false
	// when their registered method is no longer allowed by the
	// authentication methods policy, which is still a real gap for an
	// admin. Every other combination, including a non-admin with no MFA at
	// all, stays Info — routine background posture on any real tenant, and
	// warning on it would make the severity dimension useless for
	// filtering (same reasoning as entra/risk's "only high escalates").
	sev := telemetry.SeverityInfo
	if u.IsAdmin && !u.IsMfaCapable {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventUserRegistration,
		Body:     fmt.Sprintf("user registration status: %s mfa_capable=%t mfa_registered=%t", displayOf(u), u.IsMfaCapable, u.IsMfaRegistered),
		Severity: sev,
		Attrs:    attrs,
	}
}

// displayOf picks the most human-readable identifier a user row carries,
// falling back to the id (never returning empty).
func displayOf(u userRegistrationDetail) string {
	for _, s := range []string{u.UserPrincipalName, u.UserDisplayName, u.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// setStr adds key=val to attrs only when val is non-empty, so an absent
// field (e.g. an identity field on a sparse row) emits no attribute rather
// than an empty one.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
