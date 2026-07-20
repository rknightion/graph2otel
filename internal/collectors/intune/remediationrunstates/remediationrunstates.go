// Package remediationrunstates is the Intune proactive-remediation per-device
// run-state collector (BETA): for each proactive remediation (deviceHealthScript)
// assigned in the tenant, which devices its detection script passed or FAILED,
// what the detection script actually reported, and whether a remediation ran. A
// failing health detection is a first-class operational + SIEM signal (a device
// is out of policy right now, and the script says exactly why).
//
// Source (beta-only — deviceHealthScripts 404s on v1.0, "Resource not found for
// the segment", live-verified 2026-07-20 as graph2otel-poller):
//
//   - GET /beta/deviceManagement/deviceHealthScripts — the remediations (11 on m7kni).
//   - per remediation: GET .../deviceHealthScripts/{id}/deviceRunStates
//     ?$expand=managedDevice(...) — one row per (remediation, device).
//
// Read-only, least privilege: DeviceManagementConfiguration.Read.All (the
// remediations) + DeviceManagementManagedDevices.Read.All (the managedDevice
// expand). Chosen over the DeviceRunStatesByProactiveRemediation export report
// (#207), which carries the same data but needs a write scope (export-job
// creation) and a per-policy export fan-out — this path needs neither.
//
// State snapshot, not an event stream (#207): each (remediation, device) row
// updates in place, so this is the plain snapshot pattern (twins stamp "now",
// re-emitted each cycle so "which device was failing at 14:00" stays answerable),
// NOT the watermark/dedupe pattern intune.epm_elevation_events needs.
//
// Cardinality (#112/#114): the gauge is keyed only by
// (remediation_name, detection_state, remediation_state) — remediation_name is
// tenant-shaped (bounded by the number of remediations, not device count) and the
// two states are small enums, so the series count is bounded by tenant shape. The
// per-(remediation, device) detail — device, OS, the detection script's output
// message, script errors, timing — rides the log twin and never a metric label.
// Guard test.
package remediationrunstates

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/graphclient"
	"github.com/rknightion/graph2otel/internal/preflight"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName = "intune.remediation_run_states"
	metricName    = "intune.remediation_run_states.devices"
	eventName     = "intune.remediation_run_states"
	// defaultBaseURL is the Graph BETA root — deviceHealthScripts exists only on
	// beta (v1.0 404s), which is why this collector is Experimental.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// listPath lists the tenant's proactive remediations. $select keeps the
	// payload to the three fields the collector labels/attributes with.
	listPath = "/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher"
	// runStatesTmpl is the per-remediation device run-state collection, expanded
	// with just the managedDevice fields the twin carries (name/OS/owner).
	runStatesTmpl = "/deviceManagement/deviceHealthScripts/%s/deviceRunStates" +
		"?$expand=managedDevice($select=deviceName,operatingSystem,osVersion,managedDeviceOwnerType)"
)

// Collector polls the beta deviceHealthScripts run-state endpoints.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

func (c *Collector) Name() string { return collectorName }

func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the read-only least-privilege scopes: reading the
// remediations, and the managedDevice expand for device name/OS.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"}
}

// remediation is one deviceHealthScript (a proactive remediation).
type remediation struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Publisher   string `json:"publisher"`
}

// runState is one device's run state for a remediation. The id is composite
// ("{policyId}:{deviceId}"). detectionState/remediationState bucket the gauge;
// everything else is per-entity twin detail.
type runState struct {
	ID                                  string `json:"id"`
	DetectionState                      string `json:"detectionState"`
	RemediationState                    string `json:"remediationState"`
	PreRemediationDetectionScriptOutput string `json:"preRemediationDetectionScriptOutput"`
	PreRemediationDetectionScriptError  string `json:"preRemediationDetectionScriptError"`
	RemediationScriptError              string `json:"remediationScriptError"`
	LastStateUpdateDateTime             string `json:"lastStateUpdateDateTime"`
	LastSyncDateTime                    string `json:"lastSyncDateTime"`
	ManagedDevice                       struct {
		DeviceName             string `json:"deviceName"`
		OperatingSystem        string `json:"operatingSystem"`
		OSVersion              string `json:"osVersion"`
		ManagedDeviceOwnerType string `json:"managedDeviceOwnerType"`
	} `json:"managedDevice"`
}

// Collect lists the remediations, pages each one's device run states, aggregates
// the bounded (remediation_name, detection_state, remediation_state) gauge, and
// emits one twin per (remediation, device). A per-remediation fetch failure is
// logged and skipped so one bad remediation never drops the others; a 403 (scope
// or feature absent) is a graceful info-level skip.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+listPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("remediationrunstates: deviceHealthScripts forbidden (missing scope?); skipping", "collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("%s: list remediations: %w", collectorName, err)
	}

	counts := map[[3]string]int64{}
	for _, raw := range raws {
		var rem remediation
		if err := json.Unmarshal(raw, &rem); err != nil {
			return fmt.Errorf("%s: decode remediation: %w", collectorName, err)
		}
		if rem.ID == "" {
			continue
		}
		states, ferr := collectors.GetAllValues(ctx, c.g, c.baseURL+fmt.Sprintf(runStatesTmpl, rem.ID), nil)
		if ferr != nil {
			if isForbidden(ferr) {
				c.logger.Info("remediationrunstates: deviceRunStates forbidden; skipping remediation", "collector", collectorName, "remediation", rem.DisplayName, "error", graphclient.FormatODataError(ferr))
				continue
			}
			c.logger.Warn("remediationrunstates: fetching deviceRunStates failed; skipping remediation", "collector", collectorName, "remediation", rem.DisplayName, "error", ferr)
			continue
		}
		for _, sraw := range states {
			var rs runState
			if err := json.Unmarshal(sraw, &rs); err != nil {
				return fmt.Errorf("%s: decode run state: %w", collectorName, err)
			}
			counts[[3]string{rem.DisplayName, rs.DetectionState, rs.RemediationState}]++
			e.LogEvent(runStateTwin(rem, rs))
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrRemediationName:  k[0],
				semconv.AttrDetectionState:   k[1],
				semconv.AttrRemediationState: k[2],
			},
		})
	}
	e.GaugeSnapshot(metricName, "{device}",
		"Intune proactive-remediation device run states, counted by remediation, detection state and remediation state; per-device detail (device, OS, the detection script's output) on the intune.remediation_run_states log twin.",
		points)
	return nil
}

// runStateTwin renders one (remediation, device) run state as a log record. The
// timestamp is left zero ("now"): this is a re-emitted state snapshot, not an
// event (see the package doc); the real assessment time rides last_state_update.
// Severity escalates to WARN when the detection FAILED or either script errored —
// the "this device is unhealthy / the check itself broke" signal.
func runStateTwin(rem remediation, rs runState) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrRemediationId, rem.ID)
	telemetry.SetStr(attrs, semconv.AttrRemediationName, rem.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrPublisher, rem.Publisher)
	telemetry.SetStr(attrs, semconv.AttrDeviceId, deviceIDOf(rs.ID))
	telemetry.SetStr(attrs, semconv.AttrDeviceName, rs.ManagedDevice.DeviceName)
	telemetry.SetStr(attrs, semconv.AttrOs, rs.ManagedDevice.OperatingSystem)
	telemetry.SetStr(attrs, semconv.AttrOsVersion, rs.ManagedDevice.OSVersion)
	telemetry.SetStr(attrs, semconv.AttrOwnership, rs.ManagedDevice.ManagedDeviceOwnerType)
	telemetry.SetStr(attrs, semconv.AttrDetectionState, rs.DetectionState)
	telemetry.SetStr(attrs, semconv.AttrRemediationState, rs.RemediationState)
	telemetry.SetStr(attrs, semconv.AttrDetectionOutput, rs.PreRemediationDetectionScriptOutput)
	telemetry.SetStr(attrs, semconv.AttrDetectionScriptError, rs.PreRemediationDetectionScriptError)
	telemetry.SetStr(attrs, semconv.AttrRemediationScriptError, rs.RemediationScriptError)
	telemetry.SetStr(attrs, semconv.AttrLastStateUpdate, rs.LastStateUpdateDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastSyncDateTime, rs.LastSyncDateTime)

	severity := telemetry.SeverityInfo
	if strings.EqualFold(rs.DetectionState, "fail") ||
		strings.EqualFold(rs.DetectionState, "scriptError") ||
		rs.PreRemediationDetectionScriptError != "" ||
		rs.RemediationScriptError != "" {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("remediation %q on %s: detection=%s remediation=%s", rem.DisplayName, deviceNameOf(rs), rs.DetectionState, rs.RemediationState),
		Severity: severity,
		Attrs:    attrs,
	}
}

// deviceIDOf extracts the deviceId from a deviceRunState composite id
// ("{policyId}:{deviceId}"). Returns "" if the id has no ":" separator.
func deviceIDOf(runStateID string) string {
	if _, dev, ok := strings.Cut(runStateID, ":"); ok {
		return dev
	}
	return ""
}

// deviceNameOf picks the most human identifier for the log body.
func deviceNameOf(rs runState) string {
	if rs.ManagedDevice.DeviceName != "" {
		return rs.ManagedDevice.DeviceName
	}
	if d := deviceIDOf(rs.ID); d != "" {
		return d
	}
	return "unknown"
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing scope
// or the tenant not licensed for remediations) rather than a collection failure.
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

var (
	_ collector.SnapshotCollector  = (*Collector)(nil)
	_ collectors.Experimental      = (*Collector)(nil)
	_ preflight.PermissionRequirer = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
