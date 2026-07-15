// Package mfaregistration is the Entra MFA / authentication-methods
// registration-posture collector: tenant-wide counts of users registered
// for/capable of MFA, SSPR, and passwordless auth, plus per-method
// registration counts and an admin-vs-non-admin MFA-capable split — the
// compliance-KPI signal from issue #69.
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
package mfaregistration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// defaultBaseURL is the Graph v1.0 root.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// requestURL is the userRegistrationDetails read this collector issues. A
// $select trims the response to only the fields this collector aggregates —
// every per-user identifier (id, userPrincipalName, userDisplayName) is
// deliberately left off the wire, never merely dropped after decoding.
const requestPath = "/reports/authenticationMethods/userRegistrationDetails" +
	"?$select=isAdmin,isMfaRegistered,isMfaCapable,isSsprRegistered,isSsprEnabled,isSsprCapable,isPasswordlessCapable,methodsRegistered"

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

// userRegistrationDetail mirrors only the fields of the Graph
// userRegistrationDetails resource this collector reads. userPrincipalName,
// userDisplayName, id, lastUpdatedDateTime and every other per-user field are
// deliberately never decoded here — see the package doc and CLAUDE.md's
// cardinality rule.
type userRegistrationDetail struct {
	IsAdmin               bool     `json:"isAdmin"`
	IsMfaRegistered       bool     `json:"isMfaRegistered"`
	IsMfaCapable          bool     `json:"isMfaCapable"`
	IsSsprRegistered      bool     `json:"isSsprRegistered"`
	IsSsprEnabled         bool     `json:"isSsprEnabled"`
	IsSsprCapable         bool     `json:"isSsprCapable"`
	IsPasswordlessCapable bool     `json:"isPasswordlessCapable"`
	MethodsRegistered     []string `json:"methodsRegistered"`
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

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
