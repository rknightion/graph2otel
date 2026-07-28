// Package featureupdatedevices is the Intune Windows feature-update
// per-device residual collector (#351): the FeatureUpdateDeviceState export
// report, one row per (policy, device). intune.feature_update_summary
// (sibling package) ships Microsoft's pre-aggregated
// FeatureUpdatePolicyStatusSummary counts — "how many devices are stuck per
// policy". That report structurally cannot name one, which #38/#193 named
// explicitly as this collector's job when they closed: "which device, and
// why".
//
// # Fan-out shape
//
// There is no tenant-wide feature-update-device-state endpoint. The flow is:
//
//  1. GET (beta) /deviceManagement/windowsFeatureUpdateProfiles — the
//     tenant's feature-update policies (id, displayName,
//     featureUpdateVersion). Bounded by admin CONFIGURATION, not tenant size:
//     live-measured 2026-07-28 on m7kni, 2 profiles.
//  2. One export job per profile, POST (beta)
//     /deviceManagement/reports/exportJobs with
//     reportName=FeatureUpdateDeviceState and
//     filter=(PolicyId eq '<profileId>'), through the shared exportjob
//     subsystem (internal/exportjob, #17).
//
// So fan-out is 1 + N, N the profile count — never the device count. Budget
// math against the measured numbers: 2 profiles x ~8s per export job
// (live-measured 2026-07-28: create -> 3 inProgress polls -> completed,
// ~8s wall clock) is comfortably inside the shared 48 req/min Intune-export
// rate budget (internal/exportjob's Poster goes through
// graphclient's WorkloadIntuneExport limiter) even before the 6h default
// interval is accounted for.
//
// The list call uses /beta — windowsFeatureUpdateProfiles is a genuine Graph
// beta surface (live-measured 2026-07-28), so this collector implements
// collectors.Experimental per #183.
//
// # Every status column ships TWICE, and only the bare one may be a label
//
// See internal/semconv/attrs_intune_featureupdatedevices.go for the full
// rationale. Short version: AggregateState / CurrentDeviceUpdateStatus /
// LatestAlertMessage are the stable machine values and key the three bounded
// gauges below; their `_loc` twins are tenant-locale-dependent display
// strings and ride the log twin ONLY, never a metric attribute.
//
// # Cardinality (#112/#114)
//
// DeviceId, DeviceName and UPN are per-entity and are TWIN-ONLY — never a
// metric label (fleet size is unbounded from this collector's point of
// view). policy_name is a metric label: it is bounded by the same profile
// count intune.feature_update_summary already keys its gauge on, so the two
// collectors' cardinality stays consistent. Every fetched device outcome gets
// a log twin (#114): a collector that counts per-entity rows and discards
// the rest can answer "how many" but never "which one", which is the whole
// reason this collector exists alongside the summary report.
//
// # Failure isolation
//
// A profile whose export job fails must not blank the others: each
// profile's export is independently resilient (errors.Join), mirroring
// internal/collectors/intune/configprofiles's per-profile fan-out. A failed
// profile contributes NO points to the three gauges — a failed read is a gap,
// not a measured zero (#240) — while every other profile still emits
// whatever it successfully fetched. Export failure modes are classified and
// logged exactly as intune.feature_update_summary does: a job that reports
// failed, a SAS url that expired before download, and a 403 on job creation
// (likely a missing write scope, or the report unavailable on this tenant)
// are all expected-shaped outcomes, not surprises; a 403 is logged at Info
// (not Warn) and never joined into the returned error, since it is
// indistinguishable from "this tenant does not use this feature" rather than
// a bug.
//
// Zero profiles, and a profile with zero enrolled devices, are both real,
// healthy states: the fan-out simply produces no points for that iteration,
// not an error.
//
// # wirecheck: nothing declared
//
// AggregateState is a bounded metric dimension in principle, but the only
// evidence available (live-measured 2026-07-28, m7kni, 9 device rows across
// one profile) shows both "Success" and "InProgress" — a two-member sample,
// not Microsoft's documented value set for this report (undocumented). One
// tenant's live sample is not a value set (#233/#234): declaring an Enum
// from it would assert a boundary this collector has no evidence for, so
// CurrentDeviceUpdateStatus and LatestAlertMessage are left unwatched here
// too, for the identical reason. Nothing in this package calls
// internal/wirecheck.
//
// # Timestamps
//
// Event.Timestamp is left zero (poll time) on every twin. This is a
// current-state report re-emitted every cycle, not an event stream with a
// per-row event time on the wire — inventing one would misdate a record
// that never carried a timestamp, which internal/telemetry's emitter
// contract treats as strictly worse than the poll-time default.
package featureupdatedevices

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
	"github.com/rknightion/graph2otel/internal/exportjob"
	outcome "github.com/rknightion/graph2otel/internal/outcomehelper"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.feature_update_devices"

// eventName is the log twin's OTEL EventName — one record per fetched device
// row, every cycle (#114).
const eventName = "intune.feature_update_device"

// reportName is the export report catalog name. The job id Microsoft returns
// does NOT echo it (live-measured 2026-07-28: requesting
// "FeatureUpdateDeviceState" returned a job id and a poll-response
// "reportName" both prefixed "WindowsUpdatePerPolicyPerDeviceStatus_..." /
// "WindowsUpdatePerPolicyPerDeviceStatus") — do not assume the two match.
const reportName = "FeatureUpdateDeviceState"

// Metric names this collector emits. Each is its own metric name (rather than
// one metric with a "kind" dimension) for the same reason
// intune.feature_update_summary's three states are: summing any one of them
// must yield a true total, which stuffing independent breakdowns under one
// name would silently break.
const (
	metricStates       = "intune.feature_update_devices.states"
	metricUpdateStatus = "intune.feature_update_devices.update_status"
	metricAlerts       = "intune.feature_update_devices.alerts"
)

// betaBaseURL is the Graph beta root. windowsFeatureUpdateProfiles is a
// genuine beta surface (live-measured 2026-07-28) — see Experimental.
const betaBaseURL = "https://graph.microsoft.com/beta"

// selectColumns pins the export columns explicitly (Microsoft's default
// column set can change without notice, and the localized/bare column pairing
// this collector depends on is exactly the kind of detail an unpinned export
// could silently drop).
var selectColumns = []string{
	"PolicyId", "DeviceId", "DeviceName", "UPN",
	"AggregateState", "AggregateState_loc",
	"CurrentDeviceUpdateStatus", "CurrentDeviceUpdateStatus_loc",
	"LatestAlertMessage", "LatestAlertMessage_loc",
}

// Collector fans out one FeatureUpdateDeviceState export job per feature-update
// profile through the shared export-job subsystem (internal/exportjob, #17).
type Collector struct {
	g       collectors.GraphClient
	export  exportjob.Runner
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, export: export, baseURL: betaBaseURL, logger: logger}
}

func (c *Collector) Name() string { return collectorName }

func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportReportExport
}

// DefaultInterval implements collector.Collector. Fan-out is 1 + N (N the
// tenant's feature-update-profile count), so 6h keeps this collector a small
// share of the shared 48 req/min Intune-export budget regardless — see the
// package doc's budget math.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this collector as beta/opt-in: the profile-listing
// endpoint (windowsFeatureUpdateProfiles) lives on /beta — see the package
// doc and #183.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scopes:
// DeviceManagementConfiguration.Read.All lists the feature-update profiles
// (the same permission intune.config_profiles documents for the sibling
// deviceConfigurations collection); DeviceManagementManagedDevices.ReadWrite.All
// is the write scope that creates the export job — the same documented break
// intune.feature_update_summary already uses for the same subsystem.
func (c *Collector) RequiredPermissions() []string {
	return []string{
		"DeviceManagementConfiguration.Read.All",
		"DeviceManagementManagedDevices.ReadWrite.All",
	}
}

// profileRef is the bounded (id, name, feature update version) tuple this
// collector carries from the profile listing into the per-profile export
// fan-out and the per-row attribute mapping.
type profileRef struct {
	id      string
	name    string
	version string
}

// featureUpdateProfile is the subset of the windowsFeatureUpdateProfile
// resource this collector reads.
type featureUpdateProfile struct {
	ID                   string `json:"id"`
	DisplayName          string `json:"displayName"`
	FeatureUpdateVersion string `json:"featureUpdateVersion"`
}

// Collect lists the tenant's feature-update profiles and fans out one export
// job per profile, emitting the three bounded gauges plus one log twin per
// fetched device row. A failure listing profiles, or exporting one profile,
// is logged and joined into the returned error (a 403 is a graceful Info skip
// instead — see the package doc); every other profile still emits whatever it
// successfully fetched.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (err error) {
	defer func() { outcome.RecordError(outcomes, err) }()
	// This collector names its own transport (#141): exportjob never calls LogEvent.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	var errs []error

	profiles, err := c.collectProfiles(ctx, outcomes)
	if err != nil {
		if isForbidden(err) {
			outcome.RecordError(outcomes, err)
			outcomes.Cause(recordoutcome.CausePermissionDenied)
			c.logger.Info("featureupdatedevices: profile list unavailable on this tenant; skipping",
				"collector", collectorName, "error", err)
		} else {
			c.logger.Warn("featureupdatedevices: profile list fetch failed", "collector", collectorName, "error", err)
			errs = append(errs, fmt.Errorf("profile list: %w", err))
		}
	}

	stateCounts := map[[2]string]int64{}
	statusCounts := map[[2]string]int64{}
	alertCounts := map[[2]string]int64{}

	if c.export == nil {
		if len(profiles) > 0 {
			c.logger.Info("featureupdatedevices: no export runner configured; skipping", "collector", collectorName)
		}
	} else {
		for _, p := range profiles {
			if err := c.collectProfileDevices(ctx, e, p, outcomes, stateCounts, statusCounts, alertCounts); err != nil {
				errs = append(errs, err)
			}
		}
	}

	emitStatePoints(e, metricStates, stateCounts, semconv.AttrAggregateState)
	emitStatePoints(e, metricUpdateStatus, statusCounts, semconv.AttrDeviceUpdateStatus)
	emitStatePoints(e, metricAlerts, alertCounts, semconv.AttrLatestAlertMessage)

	return errors.Join(errs...)
}

// collectProfiles pages the tenant's feature-update profiles (bounded by
// admin configuration, not tenant size).
func (c *Collector) collectProfiles(ctx context.Context, outcomes *recordoutcome.Recorder) ([]profileRef, error) {
	raw, err := collectors.GetAllValuesRecorded(ctx, c.g, c.baseURL+"/deviceManagement/windowsFeatureUpdateProfiles", nil, outcomes)
	if err != nil {
		return nil, err
	}

	refs := make([]profileRef, 0, len(raw))
	for _, r := range raw {
		var p featureUpdateProfile
		if err := json.Unmarshal(r, &p); err != nil {
			c.logger.Warn("featureupdatedevices: skipping unparseable windowsFeatureUpdateProfile", "collector", collectorName, "error", err)
			outcome.Errored(outcomes, 1, recordoutcome.CauseDecodeError)
			continue
		}
		if p.ID == "" {
			c.logger.Warn("featureupdatedevices: skipping windowsFeatureUpdateProfile with empty id", "collector", collectorName)
			outcome.Dropped(outcomes, 1, recordoutcome.CauseMappingError)
			continue
		}
		outcome.Filtered(outcomes, 1)
		refs = append(refs, profileRef{id: p.ID, name: orUnknown(p.DisplayName), version: p.FeatureUpdateVersion})
	}
	return refs, nil
}

// collectProfileDevices runs one profile's FeatureUpdateDeviceState export job
// and folds every returned device row into the three gauge count maps plus one
// log twin. A failure exporting this profile is classified and logged (see
// logExportFailure) and returned so the caller can join it into the run-level
// error — EXCEPT a 403, which is a graceful skip that returns nil so it never
// reaches errors.Join (mirroring intune.feature_update_summary).
func (c *Collector) collectProfileDevices(
	ctx context.Context, e telemetry.Emitter, p profileRef, outcomes *recordoutcome.Recorder,
	stateCounts, statusCounts, alertCounts map[[2]string]int64,
) error {
	rows, err := c.export.Export(ctx, exportjob.Request{
		ReportName: reportName,
		Select:     selectColumns,
		Filter:     fmt.Sprintf("(PolicyId eq '%s')", p.id),
		Format:     exportjob.FormatCSV,
	}, e)
	if err != nil {
		if isForbidden(err) {
			outcome.RecordError(outcomes, err)
			outcomes.Cause(recordoutcome.CausePermissionDenied)
			c.logger.Info("featureupdatedevices: export job creation forbidden (missing write scope?); skipping profile",
				"collector", collectorName, "report_name", reportName, "policy_name", p.name, "error", err)
			return nil
		}
		logExportFailure(c.logger, p.name, err)
		outcome.RecordError(outcomes, err)
		return fmt.Errorf("export policy=%s: %w", p.name, err)
	}
	outcome.Emitted(outcomes, uint64(len(rows)))

	for _, row := range rows {
		d := deviceOutcome{
			policyName:            p.name,
			featureUpdateVersion:  p.version,
			deviceID:              row["DeviceId"],
			deviceName:            row["DeviceName"],
			upn:                   row["UPN"],
			aggregateState:        row["AggregateState"],
			aggregateStateLoc:     row["AggregateState_loc"],
			deviceUpdateStatus:    row["CurrentDeviceUpdateStatus"],
			deviceUpdateStatusLoc: row["CurrentDeviceUpdateStatus_loc"],
			latestAlertMessage:    row["LatestAlertMessage"],
			latestAlertMessageLoc: row["LatestAlertMessage_loc"],
		}
		stateCounts[[2]string{d.policyName, d.aggregateState}]++
		statusCounts[[2]string{d.policyName, d.deviceUpdateStatus}]++
		alertCounts[[2]string{d.policyName, d.latestAlertMessage}]++
		e.LogEvent(d.logTwin())
	}
	return nil
}

// deviceOutcome is one FeatureUpdateDeviceState row, decoded into the fields
// this collector maps. PolicyId is deliberately not carried here as a raw
// wire value — policyName/featureUpdateVersion come from the profile listing
// that drove this export, not from the CSV (the report does not echo
// PolicyName or FeatureUpdateVersion).
type deviceOutcome struct {
	policyName            string
	featureUpdateVersion  string
	deviceID              string
	deviceName            string
	upn                   string
	aggregateState        string
	aggregateStateLoc     string
	deviceUpdateStatus    string
	deviceUpdateStatusLoc string
	latestAlertMessage    string
	latestAlertMessageLoc string
}

// isSuccess reports whether this row's aggregate state is the healthy
// terminal value.
func (d deviceOutcome) isSuccess() bool {
	return d.aggregateState == "Success"
}

// hasAlert reports whether this row carries a non-zero alert code. An empty
// or "0" value means no alert.
func (d deviceOutcome) hasAlert() bool {
	return d.latestAlertMessage != "" && d.latestAlertMessage != "0"
}

// severity is Warn when the device is not in the Success aggregate state, or
// when it carries a non-zero alert code — either is worth an operator's
// attention; Info otherwise.
func (d deviceOutcome) severity() telemetry.Severity {
	if !d.isSuccess() || d.hasAlert() {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// displayName picks the most human-readable identifier this row carries,
// falling back through device name, UPN, and device id.
func (d deviceOutcome) displayName() string {
	for _, s := range []string{d.deviceName, d.upn, d.deviceID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// logTwin renders one device row as the OTLP log twin (#114): the per-device
// detail the three bounded gauges cannot carry. Timestamp is left zero — see
// the package doc.
func (d deviceOutcome) logTwin() telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrPolicyName, d.policyName)
	telemetry.SetStr(attrs, semconv.AttrFeatureUpdateVersion, d.featureUpdateVersion)
	telemetry.SetStr(attrs, semconv.AttrDeviceId, d.deviceID)
	telemetry.SetStr(attrs, semconv.AttrDeviceName, d.deviceName)
	telemetry.SetStr(attrs, semconv.AttrUpn, d.upn)
	telemetry.SetStr(attrs, semconv.AttrAggregateState, d.aggregateState)
	telemetry.SetStr(attrs, semconv.AttrAggregateStateLocalized, d.aggregateStateLoc)
	telemetry.SetStr(attrs, semconv.AttrDeviceUpdateStatus, d.deviceUpdateStatus)
	telemetry.SetStr(attrs, semconv.AttrDeviceUpdateStatusLocalized, d.deviceUpdateStatusLoc)
	telemetry.SetStr(attrs, semconv.AttrLatestAlertMessage, d.latestAlertMessage)
	telemetry.SetStr(attrs, semconv.AttrLatestAlertMessageLocalized, d.latestAlertMessageLoc)

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("feature update device %s policy=%s aggregate_state=%s (%s)",
			d.displayName(), d.policyName, d.aggregateState, d.aggregateStateLoc),
		Severity: d.severity(),
		Attrs:    attrs,
	}
}

// emitStatePoints renders one bounded (policy_name, stateAttrKey) count map
// into a GaugeSnapshot. GaugeSnapshot (not Gauge) is used deliberately: a
// (policy, state) combination that no longer appears on a later tick drops out
// of the export instead of ghosting forever under Grafana Cloud's forced
// cumulative temporality.
func emitStatePoints(e telemetry.Emitter, name string, counts map[[2]string]int64, stateAttrKey string) {
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrPolicyName: k[0], stateAttrKey: k[1]},
		})
	}
	e.GaugeSnapshot(name, "{device}", metricDescription(name), points)
}

// metricDescription returns the operator-facing description for one of the
// three metric names emitStatePoints renders.
func metricDescription(name string) string {
	switch name {
	case metricStates:
		return "Per-device Intune Windows feature-update outcome, by policy and aggregate state."
	case metricUpdateStatus:
		return "Per-device Intune Windows feature-update current status code, by policy and device update status code."
	case metricAlerts:
		return "Per-device Intune Windows feature-update latest alert code, by policy and alert message code."
	default:
		return ""
	}
}

// logExportFailure classifies and logs one profile's export failure at the
// same levels intune.feature_update_summary uses for the identical subsystem.
// Forbidden (403) creation is handled by the caller before this is reached —
// this only sees job-failed, SAS-expired, and generic failures.
func logExportFailure(logger *slog.Logger, policyName string, err error) {
	switch {
	case errors.Is(err, exportjob.ErrJobFailed):
		logger.Warn("featureupdatedevices: export job failed", "collector", collectorName, "report_name", reportName, "policy_name", policyName, "error", err)
	case errors.Is(err, exportjob.ErrSASExpired):
		logger.Warn("featureupdatedevices: export SAS url expired before download", "collector", collectorName, "report_name", reportName, "policy_name", policyName, "error", err)
	default:
		logger.Warn("featureupdatedevices: export failed", "collector", collectorName, "report_name", reportName, "policy_name", policyName, "error", err)
	}
}

// isForbidden reports whether err is a Graph 403 — either the profile-list
// endpoint or the export-job-creation call being unavailable (missing scope,
// or the feature unused on this tenant), both a graceful skip rather than a
// failure.
func isForbidden(err error) bool {
	return err != nil && strings.Contains(err.Error(), "status 403")
}

// orUnknown substitutes "unknown" for an empty label value, so a gauge point
// or log attribute never carries an empty policy name.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Export, d.Logger)
	})
}
