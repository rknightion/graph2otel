// Package syncerrors is the Entra hybrid directory-sync ERROR collector: it
// answers "is the sync engine SUCCEEDING", which entra.organization's sync
// freshness/age gauges cannot. Entra Connect can run on schedule, report a fresh
// last-sync timestamp, and still fail to provision individual objects — usually a
// UPN or proxy-address conflict between the on-prem object and an existing cloud
// object. The sync cycle completes, the age metric stays green, and a subset of
// users silently do not sync. Graph exposes this per-object as
// onPremisesProvisioningErrors; this collector surfaces it (#123).
//
// # Both sides of the cardinality boundary, from one fetch
//
//   - a bounded GAUGE counted by (object_type, category, property_causing_error)
//     — the aggregate ("11 users are not syncing"); and
//   - one LOG record per errored object (entra.directory_sync_error) carrying the
//     per-entity detail the gauge cannot: object id, UPN, and — the actionable
//     field — the conflicting value that has to be resolved. "Not a metric label"
//     means "log twin", never "dropped" (#112/#114).
//
// # Cost, opt-in, and the free cloud-only skip
//
// onPremisesProvisioningErrors is NOT $filter-able and has no $count shortcut, so
// the only path is paging the full /users collection with a trimmed $select and
// filtering client-side. That page-walk is the cost, so this collector is
// OPT-IN / default-off (via the Experimental gate — the only default-off lever
// the framework has). The endpoint itself is Graph v1.0 STABLE: the opt-in is for
// COST, not API instability, unlike a true beta collector. A cheap
// /organization probe gates the whole thing — when the tenant is cloud-only
// (onPremisesSyncEnabled is false/null, the default for most tenants) the
// collector no-ops without paging anything.
//
// v1 sweeps USERS only. Group provisioning conflicts are rarer than user ones and
// the user sweep delivers most of the value; a group sweep can follow (#123).
package syncerrors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "entra.syncerrors"

// metricSyncErrors is the bounded aggregate: directory-sync provisioning errors
// counted by object type, error category, and the conflicting property. Bounded
// by three small closed enums, never by tenant size.
const metricSyncErrors = "entra.directory.sync.errors.total"

// eventSyncError is the per-object log twin carrying the identity + the
// conflicting value the gauge cannot.
const eventSyncError = "entra.directory_sync_error"

// defaultBaseURL is the Graph v1.0 root — both endpoints are v1.0.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// orgSelectPath probes only the one field that gates the whole collector.
const orgSelectPath = "/organization?$select=onPremisesSyncEnabled"

// usersSelectPath trims the full-user page-walk to the three fields the
// aggregate + twin need. onPremisesProvisioningErrors is returned by default but
// named explicitly so the $select stays minimal.
const usersSelectPath = "/users?$select=id,userPrincipalName,onPremisesProvisioningErrors"

// provisioningError mirrors the Graph onPremisesProvisioningError resource. All
// four fields are per-object detail; category and propertyCausingError are the
// two small closed enums that bucket the gauge.
type provisioningError struct {
	Category             string `json:"category"`
	PropertyCausingError string `json:"propertyCausingError"`
	OccurredDateTime     string `json:"occurredDateTime"`
	Value                string `json:"value"`
}

// userRecord is the trimmed user shape this collector decodes.
type userRecord struct {
	ID                           string              `json:"id"`
	UserPrincipalName            string              `json:"userPrincipalName"`
	OnPremisesProvisioningErrors []provisioningError `json:"onPremisesProvisioningErrors"`
}

// orgSync decodes the single gate field. A pointer distinguishes Graph's null
// (cloud-only, never synced) from a real false — both mean "not hybrid-synced".
type orgSync struct {
	OnPremisesSyncEnabled *bool `json:"onPremisesSyncEnabled"`
}

// Collector pages /users for directory-sync provisioning errors, gated behind a
// cheap /organization sync-state probe.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the sync-errors collector. A nil logger falls back to slog.Default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Sync conflicts are resolved by
// a human editing on-prem AD, not in minutes, and the full-user page-walk is not
// cheap — six hours is ample and keeps this a negligible share of the directory
// throttle bucket.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this collector OPT-IN / default-off. The gate is the only
// default-off lever the framework exposes; here it guards COST (the full /users
// page-walk), not a beta/preview endpoint — /users and /organization are both
// Graph v1.0 stable. See the package doc.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares least-privilege scopes: User.Read.All for the user
// sweep, Organization.Read.All for the sync-state probe.
func (c *Collector) RequiredPermissions() []string {
	return []string{"User.Read.All", "Organization.Read.All"}
}

// Collect probes the tenant's on-prem sync state and, only if hybrid sync is
// enabled, pages /users for provisioning errors — emitting the bounded gauge and
// one log twin per errored object. A cloud-only tenant no-ops without paging.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	enabled, err := c.syncEnabled(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		c.logger.Info("skipping directory sync-errors sweep: on-premises sync not enabled (cloud-only tenant)", "collector", collectorName)
		return nil
	}

	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+usersSelectPath, nil)
	if err != nil {
		return fmt.Errorf("syncerrors: page users: %w", err)
	}

	// Object-count semantics: one bucket increment and one log per errored
	// OBJECT (not per error), keyed by the object's PRIMARY (first) error. A
	// single object almost always carries exactly one provisioning error (a UPN
	// or proxy-address conflict); the rare multi-error object surfaces its first
	// error and is counted once — matching "N users are not syncing".
	counts := map[[3]string]int64{}
	for _, raw := range raws {
		var u userRecord
		if err := json.Unmarshal(raw, &u); err != nil {
			return fmt.Errorf("syncerrors: decode user: %w", err)
		}
		if len(u.OnPremisesProvisioningErrors) == 0 {
			continue
		}
		pe := u.OnPremisesProvisioningErrors[0]
		counts[[3]string{"user", pe.Category, pe.PropertyCausingError}]++
		e.LogEvent(logTwin(u, pe))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts)+1)
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrObjectType:           k[0],
				semconv.AttrCategory:             k[1],
				semconv.AttrPropertyCausingError: k[2],
			},
		})
	}
	// Explicit zero: a healthy hybrid tenant emits a single zero-valued sentinel
	// so "no errors" is never indistinguishable from "collector did not run". The
	// sentinel drops out the moment any real bucket exists (GaugeSnapshot only
	// keeps the points it is given), so it never inflates a sum.
	if len(points) == 0 {
		points = append(points, telemetry.GaugePoint{
			Value: 0,
			Attrs: telemetry.Attrs{
				semconv.AttrObjectType:           "user",
				semconv.AttrCategory:             "none",
				semconv.AttrPropertyCausingError: "none",
			},
		})
	}
	e.GaugeSnapshot(metricSyncErrors, "{object}",
		"Directory-sync provisioning errors, counted by object type, error category, and the conflicting property. An explicit zero means the sweep ran and found none.",
		points)
	return nil
}

// syncEnabled reports whether the tenant is currently synced from on-premises AD.
// The probe is one small request (a single-element collection) and is the free
// guard that skips the whole user page-walk for cloud-only tenants.
func (c *Collector) syncEnabled(ctx context.Context) (bool, error) {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+orgSelectPath, nil)
	if err != nil {
		return false, fmt.Errorf("syncerrors: probe organization sync state: %w", err)
	}
	if len(raws) == 0 {
		c.logger.Warn("syncerrors: /organization returned an empty collection; skipping this cycle", "collector", collectorName)
		return false, nil
	}
	var org orgSync
	if err := json.Unmarshal(raws[0], &org); err != nil {
		return false, fmt.Errorf("syncerrors: decode organization: %w", err)
	}
	return org.OnPremisesSyncEnabled != nil && *org.OnPremisesSyncEnabled, nil
}

// logTwin renders one errored object as an OTLP log record.
//
// Timestamp is left zero ("now", i.e. poll time), not occurredDateTime: this is a
// STATE feed — the same conflict is re-emitted every cycle for as long as it
// persists, so stamping it with the assessment time would pile every repeat onto
// one instant. occurredDateTime is preserved as an attribute instead (mirrors
// entra/risk).
func logTwin(u userRecord, pe provisioningError) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, u.ID)
	telemetry.SetStr(attrs, semconv.AttrObjectType, "user")
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, u.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrCategory, pe.Category)
	telemetry.SetStr(attrs, semconv.AttrPropertyCausingError, pe.PropertyCausingError)
	telemetry.SetStr(attrs, semconv.AttrOccurredDateTime, pe.OccurredDateTime)
	telemetry.SetStr(attrs, semconv.AttrConflictingValue, pe.Value)

	id := u.UserPrincipalName
	if id == "" {
		id = u.ID
	}
	return telemetry.Event{
		Name:     eventSyncError,
		Body:     fmt.Sprintf("directory sync error: user %s — %s conflict on %s", id, pe.Category, pe.PropertyCausingError),
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
