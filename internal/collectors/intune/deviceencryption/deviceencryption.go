// Package deviceencryption is the Intune per-device disk-encryption posture
// collector (BETA): for every managed device, whether the disk is actually
// encrypted, whether the device is even READY to be encrypted, whether an
// encryption policy is assigned to it, and — for Windows — the specific
// BitLocker blockers standing in the way.
//
// Source (beta-only — v1.0 rejects the segment with
// "400 BadRequest — Resource not found for the segment
// 'managedDeviceEncryptionStates'", live-measured 2026-07-21 as
// graph2otel-poller, which is why this collector is Experimental):
//
//	GET /beta/deviceManagement/managedDeviceEncryptionStates
//
// # Relationship to intune.devices
//
// intune.devices already reports the COARSE managedDevice `isEncrypted` boolean
// (a fleet gauge plus a per-device twin field). This collector is the
// complementary "why is it not encrypted / what is misconfigured" detail, and
// deliberately not a duplicate: readiness state, policy-assignment state, and
// the per-device BitLocker blocker list exist on no other surface.
//
// # Wire shape (live-captured 2026-07-21, all 5 m7kni rows)
//
//   - `deviceType` carries the Intune wire enum VERBATIM — modern Windows hosts
//     report `windowsRT` and Macs report `macMDM`. Those values are emitted
//     unchanged; "correcting" them to a friendlier platform name would invent a
//     value that was never on the wire (#142).
//   - `advancedBitLockerStates` is a COMMA-JOINED flag list
//     ("osVolumeUnprotected,osVolumeTpmRequired,…"); its combinations are
//     unbounded, so it rides the twin as the raw string and never a metric label.
//   - `fileVaultStates` is null on every row of this tenant, so its shape is
//     unknown — decoded defensively (string, JSON array, or absent) so an
//     unexpected shape can never fail a row. See fileVaultStates.
//   - `policyDetails` is an array, empty on every row here. Deliberately NOT
//     mapped: mapping a collection nobody has ever seen populated is mapping
//     against docs, which this project does not do.
//
// # Cardinality (#112/#114)
//
// The gauges carry only bounded wire enums: (encryption_state,
// encryption_readiness_state, device_type) and (encryption_policy_setting_state).
// Device id/name, UPN, OS version, TPM version and the BitLocker blocker list are
// per-entity and ride the intune.device_encryption twin — one record per device
// row, every cycle. Guard test.
package deviceencryption

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
	collectorName = "intune.device_encryption"
	// devicesMetricName counts devices by the bounded encryption posture triple.
	devicesMetricName = "intune.device_encryption.devices"
	// policyStateMetricName counts devices by encryption-policy assignment state
	// — a separate metric name, not another dimension on the gauge above, so a
	// naive sum() over either one is the true device count.
	policyStateMetricName = "intune.device_encryption.policy_state"
	eventName             = "intune.device_encryption"
	// defaultBaseURL is the Graph BETA root — see the package doc.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// listPath is the whole per-device encryption-state collection. No $select
	// (the row is small and every field it carries is mapped) and no $top —
	// GetAllValues already asks for Graph's largest page via the Prefer header,
	// and an unverified $top is how a paged collector earns a 400 (page-size
	// ceilings, docs/graph-api-gotchas.md).
	listPath = "/deviceManagement/managedDeviceEncryptionStates"
	// unknownValue keeps a gauge dimension stable when a row omits one of the
	// bounded enums, rather than emitting an empty label.
	unknownValue = "unknown"
)

// Collector polls the beta managedDeviceEncryptionStates collection.
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

// DefaultInterval matches the other device-posture snapshot collectors
// (intune.devices, intune.remediation_run_states): encryption posture changes on
// a policy/reboot timescale, not a minute one.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental reports true: the endpoint exists only on Graph beta.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the single read-only least-privilege scope. No
// write scope is involved — this is a plain GET.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// encryptionState is one managedDeviceEncryptionState row. The three State
// fields are bounded wire enums and feed the gauges; everything else is
// per-entity twin detail. FileVaultStates is deliberately json.RawMessage — see
// fileVaultStates.
type encryptionState struct {
	ID                           string          `json:"id"`
	DeviceName                   string          `json:"deviceName"`
	UserPrincipalName            string          `json:"userPrincipalName"`
	DeviceType                   string          `json:"deviceType"`
	OSVersion                    string          `json:"osVersion"`
	TPMSpecificationVersion      string          `json:"tpmSpecificationVersion"`
	EncryptionState              string          `json:"encryptionState"`
	EncryptionReadinessState     string          `json:"encryptionReadinessState"`
	EncryptionPolicySettingState string          `json:"encryptionPolicySettingState"`
	AdvancedBitLockerStates      json.RawMessage `json:"advancedBitLockerStates"`
	FileVaultStates              json.RawMessage `json:"fileVaultStates"`
}

// Collect pages the encryption-state collection, aggregates the two bounded
// gauges, and emits one twin per device row. A 403 (missing scope, or the
// surface absent on this tenant) is a graceful info-level skip rather than a
// collection failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+listPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("deviceencryption: managedDeviceEncryptionStates forbidden (missing scope?); skipping",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("%s: list encryption states: %w", collectorName, err)
	}

	deviceCounts := map[[3]string]int64{}
	policyCounts := map[string]int64{}
	for _, raw := range raws {
		var st encryptionState
		if err := json.Unmarshal(raw, &st); err != nil {
			return fmt.Errorf("%s: decode encryption state: %w", collectorName, err)
		}
		deviceCounts[[3]string{
			orUnknown(st.EncryptionState),
			orUnknown(st.EncryptionReadinessState),
			orUnknown(st.DeviceType),
		}]++
		policyCounts[orUnknown(st.EncryptionPolicySettingState)]++
		e.LogEvent(twin(st))
	}

	devicePoints := make([]telemetry.GaugePoint, 0, len(deviceCounts))
	for k, v := range deviceCounts {
		devicePoints = append(devicePoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrEncryptionState:          k[0],
				semconv.AttrEncryptionReadinessState: k[1],
				semconv.AttrDeviceType:               k[2],
			},
		})
	}
	e.GaugeSnapshot(devicesMetricName, "{device}",
		"Intune managed devices by disk-encryption state, encryption readiness state and device type (wire enums verbatim); per-device detail — device, user, OS/TPM version and the BitLocker blockers — on the intune.device_encryption log twin.",
		devicePoints)

	policyPoints := make([]telemetry.GaugePoint, 0, len(policyCounts))
	for k, v := range policyCounts {
		policyPoints = append(policyPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrEncryptionPolicySettingState: k},
		})
	}
	e.GaugeSnapshot(policyStateMetricName, "{device}",
		"Intune managed devices by disk-encryption POLICY setting state (notAssigned/compliant/error/…) — whether an encryption policy even reached the device, which the encryption-state gauge cannot say.",
		policyPoints)

	return nil
}

// twin renders one device's encryption posture as a log record. The timestamp is
// left zero ("now"): this is a re-emitted state snapshot, not an event stream —
// the same device re-emits each cycle so "which devices were unencrypted at
// 14:00" stays answerable.
//
// Severity is WARN whenever the disk is not encrypted — the actionable case, and
// the only one an operator has to chase. Everything else (including "encrypted
// but notReady", the normal steady state for FileVault Macs) is INFO.
func twin(st encryptionState) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, st.ID)
	telemetry.SetStr(attrs, semconv.AttrDeviceName, st.DeviceName)
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, st.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrDeviceType, st.DeviceType)
	telemetry.SetStr(attrs, semconv.AttrOsVersion, st.OSVersion)
	telemetry.SetStr(attrs, semconv.AttrTpmVersion, st.TPMSpecificationVersion)
	telemetry.SetStr(attrs, semconv.AttrEncryptionState, st.EncryptionState)
	telemetry.SetStr(attrs, semconv.AttrEncryptionReadinessState, st.EncryptionReadinessState)
	telemetry.SetStr(attrs, semconv.AttrEncryptionPolicySettingState, st.EncryptionPolicySettingState)
	telemetry.SetStr(attrs, semconv.AttrAdvancedBitlockerStates, flagList(st.AdvancedBitLockerStates))
	telemetry.SetStr(attrs, semconv.AttrFileVaultStates, flagList(st.FileVaultStates))

	severity := telemetry.SeverityInfo
	if !strings.EqualFold(st.EncryptionState, "encrypted") {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventName,
		Body: fmt.Sprintf("device encryption %s: encryption_state=%s readiness=%s policy=%s",
			deviceLabel(st), st.EncryptionState, st.EncryptionReadinessState, st.EncryptionPolicySettingState),
		Severity: severity,
		Attrs:    attrs,
	}
}

// flagList renders one of the two encryption flag-list fields.
// advancedBitLockerStates is live-verified as a comma-joined STRING
// ("osVolumeUnprotected,tpmNotReady", 2026-07-21); fileVaultStates is null on
// every row of that tenant, so its populated shape is unverified — and Graph
// beta returns flag collections both ways. Both fields decode through here: a
// string passes through verbatim, a JSON array is comma-joined to match, and ANY
// other shape yields "" (attribute omitted) rather than failing the row's
// decode, which would drop the whole collection on such a tenant. The tolerance
// is deliberately symmetric — a field whose shape is only known from one tenant
// is not a field whose shape is known.
func flagList(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return strings.Join(list, ",")
	}
	return ""
}

// deviceLabel picks the most human identifier for the log body.
func deviceLabel(st encryptionState) string {
	if st.DeviceName != "" {
		return st.DeviceName
	}
	if st.ID != "" {
		return st.ID
	}
	return unknownValue
}

// orUnknown keeps a bounded gauge dimension from ever carrying an empty label.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing scope
// or the surface absent on this tenant) rather than a collection failure.
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
