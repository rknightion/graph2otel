// Package enrollmentevents is the Intune enrollment-troubleshooting log
// source: a single WindowCollector over GET /deviceManagement/
// troubleshootingEvents, emitting one OTLP log record per failed device
// enrollment through the generic logpipeline engine (#13).
//
// This is the Graph-reachable slice of the Intune OperationalLogs
// diagnostic category (the rest of that category has no Graph endpoint at
// all) and is the primary continuous source for "why are devices failing to
// enroll". It is complementary to, not a replacement for, the M5 #40
// EnrollmentFailures export report: that report is an optional beta
// backfill/deep-dive surface with different columns and freshness, while
// this collector is the continuous live event stream. The two are kept
// distinguishable by EventName alone ("intune.enrollment_event" here vs. the
// export report's own event name) since they never share a dedupe id space.
//
// Constraint (verified against the endpoint docs, not live): this endpoint
// does not support a server-side $filter on eventDateTime, so
// EndpointConfig.NoServerFilter is true — the engine drains the whole
// collection per tick and bounds the [from, to] window client-side instead
// of relying on a $filter predicate. $orderby is likewise not trusted
// (OrderByReliable is false), so the engine sorts the drained window
// client-side by eventDateTime before emitting.
//
// Cardinality note (INVERTED from the metric collectors): these are LOGS, so
// per-entity detail — deviceId, userId, correlationId — belongs here as
// structured log attributes. That same data must NEVER become a metric
// label; this package emits no metrics, only logs.
//
// See GitHub issue #15.
package enrollmentevents

import (
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// path is the Graph v1.0 path this collector polls.
	path = "/deviceManagement/troubleshootingEvents"
	// collectorName is the stable collector key.
	collectorName = "intune.enrollment_events"
	// eventName is the OTLP LogRecord EventName every enrollment
	// troubleshooting record carries.
	eventName = "intune.enrollment_event"
)

// Schedule tuning: enrollment failures are bursty on onboarding/OS-upgrade
// waves rather than scaling with fleet size, so the overlap window is wider
// than the M3 log collectors' default to tolerate a burst landing late.
const (
	interval        = 20 * time.Minute
	lag             = 15 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
	// overlap is deliberately wider than logpipeline.DefaultOverlap (2h) so a
	// burst of enrollment failures that lands late (e.g. behind a slow
	// diagnostic pipeline during an OS-upgrade wave) is still re-queried and
	// deduped rather than missed.
	overlap = 6 * time.Hour
)

// collectorImpl is the enrollment-events WindowCollector: the generic
// LogCollector plus the license + permission declarations the composition
// root reads.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredCapability declares that this collector needs an active Intune
// license: the composition root skips it entirely rather than poll an
// endpoint that 4xxs without one. Implements license.CapabilityRequirer.
func (c *collectorImpl) RequiredCapability() license.Capability { return license.CapIntune }

// RequiredPermissions declares the least-privilege Graph application scope.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// newCollector builds the enrollment-events WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            path,
		TimeField:       "eventDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby not to be trusted; sort client-side
		// troubleshootingEvents does not support a server-side $filter on
		// eventDateTime: the engine drains the whole collection per tick and
		// bounds [from, to] client-side instead.
		NoServerFilter: true,
		Overlap:        overlap,
		Map:            mapEnrollmentEvent,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, lag, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapEnrollmentEvent turns one raw enrollmentTroubleshootingEvent record
// into its dedupe id (the immutable record id) and the OTLP log Event. Every
// record on this endpoint represents a failed enrollment, so severity is
// always Warn. It sets only the attributes actually present, so a record
// missing an optional field (e.g. osVersion) simply omits that attribute
// rather than emitting an empty one.
func mapEnrollmentEvent(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	failureCategory := str(rec, "failureCategory")
	enrollmentType := str(rec, "enrollmentType")
	operatingSystem := str(rec, "operatingSystem")

	attrs := telemetry.Attrs{}
	setStr(attrs, "failure_category", failureCategory)
	setStr(attrs, "enrollment_type", enrollmentType)
	setStr(attrs, "operating_system", operatingSystem)
	setStr(attrs, "os_version", str(rec, "osVersion"))
	setStr(attrs, "failure_reason", str(rec, "failureReason"))
	setStr(attrs, "device_id", str(rec, "deviceId"))
	setStr(attrs, "user_id", str(rec, "userId"))
	setStr(attrs, "correlation_id", str(rec, "correlationId"))

	return id, telemetry.Event{
		Name:     eventName,
		Body:     fmt.Sprintf("enrollment failure: %s (%s, %s)", failureCategory, enrollmentType, operatingSystem),
		Severity: telemetry.SeverityWarn,
		Attrs:    attrs,
	}
}

// --- small defensive accessors for untyped Graph JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// setStr adds key=val only when val is non-empty, so absent fields don't
// emit empty attributes.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
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

// Compile-time checks that the enrollment-events collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector  = (*collectorImpl)(nil)
	_ license.CapabilityRequirer = (*collectorImpl)(nil)
)
