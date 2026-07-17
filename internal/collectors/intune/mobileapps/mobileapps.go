// Package mobileapps is the Intune mobile-app-catalog and app-configuration
// collector: bounded aggregate gauges over the tenant's `mobileApps` catalog
// (a small, device-independent collection - counts by app type and
// publishing state) plus per-policy device-status counts for
// `mobileAppConfigurations`, read from each policy's `deviceStatusSummary`
// singleton.
//
// Per-app, per-device install status (which app is installed on which
// device) is a deprecated/broken nav-prop surface on this abstract resource
// and fundamentally an export-job product (DeviceInstallStatusByApp,
// AppInstallStatusAggregate) - fleet-wide per-device install detail is
// deferred to the M5 export-job subsystem. This collector covers only the
// catalog and config-policy summary endpoints (issue #55).
package mobileapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.mobile_apps"

// Metric names this collector emits.
const (
	appsMetricName         = "intune.mobile_apps.count"
	configStatusMetricName = "intune.mobile_app_config.status"
)

// defaultBaseURL is the Graph v1.0 root. Both endpoints this collector polls
// are v1.0-documented (not beta), so this collector is not Experimental.
const defaultBaseURL = "https://graph.microsoft.com/v1.0"

// odataTypePrefix is stripped off a mobileApp's @odata.type to produce the
// bounded app_type attribute value (e.g. "#microsoft.graph.win32LobApp" ->
// "win32LobApp"). The set of subtypes is Microsoft-defined (an abstract
// resource hierarchy), not tenant-scaling, so using the type name directly
// as a label stays bounded.
const odataTypePrefix = "#microsoft.graph."

// mobileApp is the subset of the abstract microsoft.graph.mobileApp resource
// this collector reads. publishingState is documented on the mobileLobApp
// subtype (not every subtype sets it), so it is read as a plain optional
// string and mapped to "unknown" when absent - see publishingStateOf.
type mobileApp struct {
	ODataType       string `json:"@odata.type"`
	PublishingState string `json:"publishingState"`
}

// mobileAppConfiguration is the subset of the abstract
// microsoft.graph.managedDeviceMobileAppConfiguration resource this
// collector reads to drive the per-policy deviceStatusSummary fetch.
type mobileAppConfiguration struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// deviceStatusSummaryFields are the bounded device-status-count fields on
// microsoft.graph.managedDeviceMobileAppConfigurationDeviceSummary, per
// https://learn.microsoft.com/en-us/graph/api/intune-apps-manageddevicemobileappconfigurationdevicesummary-get
// (verified live against the docs 2026-07-15). Note this is the
// deviceConfiguration-style status enum (pending/notApplicable/success/
// error/failed), not the compliance-policy-style enum
// (compliant/nonCompliant/remediated/conflict) - the two Intune "status
// summary" resource families use different field names, so do not copy one
// shape onto the other without checking the specific resource's docs.
type deviceStatusSummaryFields struct {
	PendingCount       int `json:"pendingCount"`
	NotApplicableCount int `json:"notApplicableCount"`
	SuccessCount       int `json:"successCount"`
	ErrorCount         int `json:"errorCount"`
	FailedCount        int `json:"failedCount"`
}

// deviceStatusSummaryResponse decodes the deviceStatusSummary GET
// permissively against two possible shapes. Microsoft's own worked example
// for this endpoint shows the fields wrapped in a {"value": {...}} envelope
// - unusual for a singleton (non-collection) GET, and not independently
// live-verified by this lane (see the issue's "verify live" gotcha for this
// status sub-path) - so this decodes both the bare-object shape and the
// enveloped shape rather than trusting either one alone.
type deviceStatusSummaryResponse struct {
	deviceStatusSummaryFields
	Value *deviceStatusSummaryFields `json:"value"`
}

// fields returns whichever shape actually carries the data: the enveloped
// Value if present, otherwise the bare top-level fields.
func (r deviceStatusSummaryResponse) fields() deviceStatusSummaryFields {
	if r.Value != nil {
		return *r.Value
	}
	return r.deviceStatusSummaryFields
}

// statusBuckets pairs each bounded status attribute value with the field it
// reads off a decoded deviceStatusSummaryFields.
var statusBuckets = []struct {
	attr string
	get  func(deviceStatusSummaryFields) int
}{
	{"pending", func(f deviceStatusSummaryFields) int { return f.PendingCount }},
	{"not_applicable", func(f deviceStatusSummaryFields) int { return f.NotApplicableCount }},
	{"success", func(f deviceStatusSummaryFields) int { return f.SuccessCount }},
	{"error", func(f deviceStatusSummaryFields) int { return f.ErrorCount }},
	{"failed", func(f deviceStatusSummaryFields) int { return f.FailedCount }},
}

// Collector polls the Intune mobile app catalog and app-configuration
// device-status summaries.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the mobile apps collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. The app catalog and its
// configuration policies are small, device-independent, and cheap to poll
// fully (per issue #55), and both drift slowly, so a longer cadence than the
// per-device inventory collectors is appropriate.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// RequiredPermissions declares the least-privilege Graph application scope.
// Both mobileApps and mobileAppConfigurations (including their
// deviceStatusSummary sub-resource) are covered by DeviceManagementApps.Read.All.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementApps.Read.All"}
}

// Collect fetches the mobile app catalog and app-configuration
// device-status summaries and emits two independent gauge snapshots. The
// two are fetched and emitted independently so a failure in one never
// suppresses the other. A 403 (missing scope, or Intune not licensed on the
// tenant) is skipped-and-logged, not treated as a failure; any other error
// is logged, aggregated via errors.Join, and returned so partial failure
// stays visible in scrape self-observability.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error

	appPoints, err := c.appsSnapshot(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	e.GaugeSnapshot(appsMetricName, "{app}",
		"Intune mobile app catalog entries, by app type and publishing state.", appPoints)

	configPoints, err := c.configStatusSnapshot(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	e.GaugeSnapshot(configStatusMetricName, "{device}",
		"Intune mobile app configuration policy device-status counts, by policy and status.", configPoints)

	return errors.Join(errs...)
}

// appsSnapshot lists the full mobileApps catalog (bounded - hundreds to low
// thousands of admin-configured apps, never per-device) and aggregates it
// into (app_type, publishing_state) counts. Deliberately does not
// $expand=assignments on the list, which Microsoft's docs mark deprecated
// for this collection.
func (c *Collector) appsSnapshot(ctx context.Context) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceAppManagement/mobileApps", nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("mobile apps: catalog endpoint forbidden (missing DeviceManagementApps.Read.All or unlicensed); skipping",
				"collector", collectorName, "error", err)
			return nil, nil
		}
		c.logger.Warn("mobile apps: list mobileApps failed", "collector", collectorName, "error", err)
		return nil, fmt.Errorf("list mobileApps: %w", err)
	}

	type bucket struct{ appType, state string }
	counts := map[bucket]int{}
	for _, r := range raw {
		var a mobileApp
		if err := json.Unmarshal(r, &a); err != nil {
			c.logger.Warn("mobile apps: skipping unparseable app", "collector", collectorName, "error", err)
			continue
		}
		counts[bucket{appTypeOf(a.ODataType), publishingStateOf(a.PublishingState)}]++
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for b, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrAppType: b.appType, semconv.AttrPublishingState: b.state},
		})
	}
	return points, nil
}

// configStatusSnapshot lists the (small, admin-configured) app-configuration
// policies, then fetches each one's deviceStatusSummary singleton and emits
// its bounded per-status device counts. Each policy's summary fetch is
// independently resilient - a failure on one policy is logged and that
// policy is dropped from the snapshot, but every other policy still emits.
func (c *Collector) configStatusSnapshot(ctx context.Context) ([]telemetry.GaugePoint, error) {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceAppManagement/mobileAppConfigurations", nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("mobile app config: policies endpoint forbidden (missing DeviceManagementApps.Read.All or unlicensed); skipping",
				"collector", collectorName, "error", err)
			return nil, nil
		}
		c.logger.Warn("mobile app config: list mobileAppConfigurations failed", "collector", collectorName, "error", err)
		return nil, fmt.Errorf("list mobileAppConfigurations: %w", err)
	}

	var errs []error
	var points []telemetry.GaugePoint
	for _, r := range raw {
		var cfg mobileAppConfiguration
		if err := json.Unmarshal(r, &cfg); err != nil {
			c.logger.Warn("mobile app config: skipping unparseable policy", "collector", collectorName, "error", err)
			continue
		}
		if cfg.ID == "" {
			c.logger.Warn("mobile app config: skipping policy with empty id", "collector", collectorName)
			continue
		}
		policyName := cfg.DisplayName
		if policyName == "" {
			policyName = cfg.ID
		}

		summaryPoints, err := c.deviceStatusSummaryPoints(ctx, cfg.ID, policyName)
		if err != nil {
			c.logger.Warn("mobile app config: deviceStatusSummary failed",
				"collector", collectorName, "policy", cfg.ID, "error", err)
			errs = append(errs, fmt.Errorf("policy %s deviceStatusSummary: %w", cfg.ID, err))
			continue
		}
		points = append(points, summaryPoints...)
	}
	return points, errors.Join(errs...)
}

// deviceStatusSummaryPoints fetches one policy's deviceStatusSummary
// singleton and returns its five bounded (policy_name, status) gauge
// points. A 403 on an individual policy is skipped-and-logged like the
// list-level 403 case, rather than surfaced as an error.
func (c *Collector) deviceStatusSummaryPoints(ctx context.Context, id, policyName string) ([]telemetry.GaugePoint, error) {
	body, err := c.g.RawGet(ctx, c.baseURL+"/deviceAppManagement/mobileAppConfigurations/"+id+"/deviceStatusSummary")
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("mobile app config: deviceStatusSummary forbidden; skipping policy",
				"collector", collectorName, "policy", id, "error", err)
			return nil, nil
		}
		return nil, err
	}

	var resp deviceStatusSummaryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode deviceStatusSummary: %w", err)
	}
	fields := resp.fields()

	points := make([]telemetry.GaugePoint, 0, len(statusBuckets))
	for _, b := range statusBuckets {
		points = append(points, telemetry.GaugePoint{
			Value: float64(b.get(fields)),
			Attrs: telemetry.Attrs{semconv.AttrPolicyName: policyName, semconv.AttrStatus: b.attr},
		})
	}
	return points, nil
}

// appTypeOf strips the Graph @odata.type namespace prefix down to the bare
// subtype name (e.g. "win32LobApp"), or "unknown" if empty/unrecognized.
func appTypeOf(odataType string) string {
	t := strings.TrimPrefix(odataType, odataTypePrefix)
	if t == "" {
		return "unknown"
	}
	return t
}

// publishingStateOf maps an empty publishingState (subtypes that don't set
// it) to the bounded "unknown" bucket rather than an empty-string label.
func publishingStateOf(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// isForbidden reports whether err is an HTTP 403 from Graph - missing scope
// or Intune not licensed on the tenant - which this collector treats as an
// expected "no data here" condition, not a failure, per the graceful-skip
// rule (M1 #9).
func isForbidden(err error) bool {
	return strings.Contains(err.Error(), "status 403")
}

// Compile-time interface assertion.
var _ collector.SnapshotCollector = (*Collector)(nil)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
