// Package blobcategories is the diagnostic-settings blob census (#238): a
// self-observability collector that diffs the tenant's microsoft.aadiam
// diagnostic-settings categories against the Azure Storage containers
// graph2otel's blob collectors actually read, and reports the gaps.
//
// # Why it exists
//
// A diagnostic-settings category can be enabled, writing, and BILLED while
// nothing reads it — six such containers were found by hand in the #251 sweep
// (SignInLogs, several NetworkAccess/RiskyAgents categories). docs/blob-ingest.md
// warns that an empty container is not evidence of a fault, but nothing detected
// the opposite and more dangerous direction: a blob collector polling a container
// that will never be written reports clean success forever. This census closes
// both, and it finds the next such gap automatically as categories or collectors
// are added.
//
// # What it can read, and the boundary
//
// The census reads GET providers/microsoft.aadiam/diagnosticSettings on the ARM
// control plane. Contrary to #134's premise, the poller reads that as ITSELF —
// authorized by its Entra roles, not by Azure RBAC (live-measured 2026-07-23: the
// tenant-level microsoft.aadiam provider returns 200, while microsoft.intune and
// the storage account resource return 403). So this census is the Entra half; the
// Intune half needs an identity with Azure RBAC and is out of scope (recorded on
// #238).
//
// # Capability semantics
//
// "mapped" means graph2otel SHIPS a blob collector whose container matches the
// category's container (`insights-logs-<lowercased-category>`); it does not
// consider per-tenant config gating. A category with a collector this tenant
// happens to disable still counts as mapped. The primary signal — an enabled
// category with NO collector at all — is unaffected, and per-tenant enablement is
// already visible in the collector's own success metrics.
package blobcategories

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "graph2otel.blob_categories"
	// metricCategories counts diagnostic-settings categories by census state.
	metricCategories = "graph2otel.blob.categories"
	// eventCategory is the per-category log twin.
	eventCategory = "graph2otel.blob_category"
	// aadiamURL is the tenant-level diagnostic-settings object. The api-version is
	// the one the endpoint accepts (2017-04-01); diagnosticSettingsCategories 400s,
	// so the setting's own logs[] array is the only enumerable list (#238).
	aadiamURL = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01"
	// containerPrefix is the Azure Monitor container-name convention every
	// insights-logs container follows: this prefix plus the lowercased category.
	containerPrefix = "insights-logs-"
	// interval: diagnostic settings change on the timescale of an admin editing
	// them, not seconds. Hourly is ample and one ARM GET is cheap.
	interval = time.Hour
)

// Census states. A category is one of these, decided by (enabled, mapped).
const (
	stateConsumed          = "consumed"            // enabled AND a blob collector reads it
	stateEnabledUnread     = "enabled_unread"      // enabled but no collector — billed, deleted unread (Warn)
	stateMappedButDisabled = "mapped_but_disabled" // a collector polls it but it is disabled — clean success forever over an empty container (Error)
	stateDisabled          = "disabled"            // disabled and no collector — the benign case
)

// Collector reads the aadiam diagnostic-settings object and classifies each
// category against the registered blob-collector container set.
type Collector struct {
	arm        collectors.ARMReader
	containers map[string]bool
	logger     *slog.Logger
}

// New builds the census. containerNames is the set of Azure Storage container
// names every registered blob collector reads (collectors.BlobContainers).
// A nil arm — the tenant has no blob ingest configured — turns Collect into a
// no-op, since there is nothing to census.
func New(arm collectors.ARMReader, containerNames []string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	set := make(map[string]bool, len(containerNames))
	for _, c := range containerNames {
		set[c] = true
	}
	return &Collector{arm: arm, containers: set, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// RequiredPermissions is empty: ARM access here is authorized by the poller's
// Entra roles, not by a Graph scope, so it cannot be expressed in the
// Graph-scope vocabulary the declaration surface models — the same position as
// defender.quarantine.
func (c *Collector) RequiredPermissions() []string { return nil }

// diagnosticSettingsResponse is the minimal shape of the aadiam response.
type diagnosticSettingsResponse struct {
	Value []diagnosticSetting `json:"value"`
}

type diagnosticSetting struct {
	Name       string `json:"name"`
	Properties struct {
		StorageAccountID string        `json:"storageAccountId"`
		Logs             []logCategory `json:"logs"`
	} `json:"properties"`
}

type logCategory struct {
	Category string `json:"category"`
	Enabled  bool   `json:"enabled"`
}

// Collect reads the aadiam diagnostic settings and emits the census gauge plus
// one twin per category. A nil ARM reader (no blob ingest) is a no-op.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	if c.arm == nil {
		return nil
	}
	body, err := c.arm.RawGet(ctx, aadiamURL)
	if err != nil {
		return fmt.Errorf("read aadiam diagnostic settings: %w", err)
	}
	var resp diagnosticSettingsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode aadiam diagnostic settings: %w", err)
	}

	// Union the enabled/disabled state of each category across every setting that
	// sinks to a storage account. A category is "enabled" for the census if any
	// storage-sinking setting enables it — that is what puts blobs in a container.
	// Settings with no storageAccountId (Event Hub / Log Analytics only) do not
	// write blobs, so they are skipped: a category enabled only there is not
	// "writing to storage" for this census.
	enabled := map[string]bool{}
	seen := map[string]bool{}
	for _, s := range resp.Value {
		if s.Properties.StorageAccountID == "" {
			continue
		}
		for _, l := range s.Properties.Logs {
			if l.Category == "" {
				continue
			}
			seen[l.Category] = true
			if l.Enabled {
				enabled[l.Category] = true
			}
		}
	}
	if len(seen) == 0 {
		// No storage-sinking diagnostic setting — nothing to census. Emit nothing
		// rather than a misleading all-zero.
		return nil
	}

	counts := map[string]int64{}
	for category := range seen {
		container := containerPrefix + strings.ToLower(category)
		mapped := c.containers[container]
		isEnabled := enabled[category]
		state := classify(isEnabled, mapped)
		counts[state]++
		e.LogEvent(categoryTwin(category, container, state, isEnabled, mapped))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for st, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrState: st},
		})
	}
	e.GaugeSnapshot(metricCategories, "{category}",
		"Azure diagnostic-settings categories on the aadiam provider, by census state: consumed / enabled_unread (billed but read by no collector) / mapped_but_disabled (a collector polls a container that is never written) / disabled.",
		points)
	return nil
}

// classify maps (enabled, mapped) to a census state.
func classify(enabled, mapped bool) string {
	switch {
	case enabled && mapped:
		return stateConsumed
	case enabled && !mapped:
		return stateEnabledUnread
	case !enabled && mapped:
		return stateMappedButDisabled
	default:
		return stateDisabled
	}
}

// categoryTwin renders one category as a log record. enabled_unread is Warn
// (billed and deleted unread); mapped_but_disabled is Error (a collector polling
// a container that will never be written — clean success forever over nothing);
// everything else is Info.
func categoryTwin(category, container, state string, enabled, mapped bool) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrDiagnosticCategory, category)
	telemetry.SetStr(attrs, semconv.AttrContainer, container)
	telemetry.SetStr(attrs, semconv.AttrState, state)
	telemetry.SetBool(attrs, semconv.AttrIsEnabled, enabled)
	telemetry.SetBool(attrs, semconv.AttrIsMapped, mapped)

	sev := telemetry.SeverityInfo
	switch state {
	case stateEnabledUnread:
		sev = telemetry.SeverityWarn
	case stateMappedButDisabled:
		sev = telemetry.SeverityError
	}
	return telemetry.Event{
		Name:     eventCategory,
		Body:     fmt.Sprintf("diagnostic category %s (%s): %s", category, container, state),
		Severity: sev,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.ARM, d.BlobContainerNames, d.Logger)
	})
}

var _ collector.SnapshotCollector = (*Collector)(nil)
