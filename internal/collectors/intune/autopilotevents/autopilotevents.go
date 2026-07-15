// Package autopilotevents is the Intune Windows Autopilot deployment-events
// log source: a WindowCollector over GET /deviceManagement/autopilotEvents
// (the deviceManagementAutopilotEvent resource), emitting one OTLP log
// record per enrollment / Enrollment Status Page (ESP) attempt through the
// generic logpipeline engine (#13).
//
// BETA-ONLY, no v1.0 fallback: the whole resource lives only under
// https://graph.microsoft.com/beta, so EndpointConfig.BaseURLOverride is set
// and this collector implements collectors.Experimental (opt-in, matching
// the beta sign-in streams in internal/collectors/entra/signins) — an
// operator must explicitly enable it. Because this is beta, treat its shape
// and availability as unstable: a schema change or endpoint removal on
// Microsoft's side is a real, expected risk here, not a hypothetical one.
//
// No documented server-side $filter exists for this endpoint, so
// EndpointConfig.NoServerFilter is set: the engine drains the endpoint's
// whole (retention-bounded) collection every poll and bounds the window
// CLIENT-SIDE on eventDateTime, rather than building a $filter predicate.
// $orderby is undocumented too, so OrderByReliable is false — the engine
// sorts the drained window client-side by eventDateTime.
//
// Multiple events can exist per device (retries / successOnRetry): Graph
// assigns each attempt its own record id, so the engine's id-based dedupe
// (SeenIDs) treats a retry as a distinct event rather than collapsing it
// into an earlier attempt — an earlier failure record is never erased by a
// later success. This collector's Map does not merge or reorder records; it
// trusts the id it is given.
//
// Cardinality note (LOGS, inverted from the metric collectors): per-entity
// detail — deviceId, deviceSerialNumber, the record's own id — belongs here
// as structured log attributes. That same data must NEVER become a metric
// label; this package emits no metrics, only logs.
//
// Phase durations (deploymentDuration, deviceSetupDuration,
// accountSetupDuration) arrive as ISO-8601 duration strings and can be
// negative under client clock skew between phase timestamps; a negative
// duration is CLAMPED to zero before being emitted as an attribute (a phase
// cannot take less than no time) — see parseISO8601DurationSeconds. The
// three phase statuses (deploymentState, deviceSetupStatus,
// accountSetupStatus) are kept as three DISTINCT attributes rather than
// collapsed into one enum, since a device can e.g. succeed device setup but
// fail account setup.
//
// See GitHub issue #16.
package autopilotevents

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// autopilotEventsPath is the Graph beta path this collector polls.
	autopilotEventsPath = "/deviceManagement/autopilotEvents"
	// betaBaseURL is the Graph beta service root — this resource has no
	// v1.0 form.
	betaBaseURL = "https://graph.microsoft.com/beta"
	// collectorName is the stable collector key.
	collectorName = "intune.autopilot_events"
	// eventName is the OTLP LogRecord EventName every autopilot event
	// record carries.
	eventName = "intune.autopilot_event"
)

// Schedule tuning. Autopilot events are bursty on device-refresh waves
// (a fleet re-enrolling en masse) but are not latency-sensitive telemetry,
// so this collector polls on a relatively relaxed cadence.
const (
	interval        = 20 * time.Minute
	initialLookback = time.Hour
	maxWindow       = 24 * time.Hour
)

// collectorImpl is the autopilot-events WindowCollector: the generic
// LogCollector plus the Experimental opt-in gate the composition root
// checks before scheduling a beta-endpoint collector.
type collectorImpl struct {
	*logpipeline.LogCollector
}

// RequiredPermissions declares the Graph application permission scope this
// collector needs.
func (c *collectorImpl) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.Read.All"}
}

// Experimental marks this collector as beta/opt-in: the autopilotEvents
// resource exists only on the Graph beta endpoint, with no v1.0 fallback.
func (c *collectorImpl) Experimental() bool { return true }

// newCollector builds the autopilot-events WindowCollector.
func newCollector(d collectors.WindowDeps) *collectorImpl {
	cfg := logpipeline.EndpointConfig{
		Path:            autopilotEventsPath,
		BaseURLOverride: betaBaseURL,
		TimeField:       "eventDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: false, // $orderby is undocumented here; sort client-side
		NoServerFilter:  true,  // no documented $filter; bound the window client-side
		Map:             mapAutopilotEvent,
	}
	lc := logpipeline.NewLogCollector(collectorName, interval, 0, d.TenantID, cfg, d.Fetcher, d.Store)
	return &collectorImpl{LogCollector: lc}
}

// mapAutopilotEvent turns one raw deviceManagementAutopilotEvent record into
// its dedupe id (the immutable event id — each retry attempt gets its own)
// and the OTLP log Event. It sets only the attributes actually present, so a
// record missing an optional field (e.g. enrollmentFailureDetails on a
// success) simply omits that attribute rather than emitting an empty one.
func mapAutopilotEvent(rec map[string]any) (string, telemetry.Event) {
	id := str(rec, "id")
	deviceID := str(rec, "deviceId")
	serial := str(rec, "deviceSerialNumber")
	deploymentState := str(rec, "deploymentState")
	deviceSetupStatus := str(rec, "deviceSetupStatus")
	accountSetupStatus := str(rec, "accountSetupStatus")
	failureDetails := str(rec, "enrollmentFailureDetails")

	attrs := telemetry.Attrs{}
	setStr(attrs, "id", id)
	setStr(attrs, "device_id", deviceID)
	setStr(attrs, "device_serial_number", serial)
	setStr(attrs, "enrollment_type", str(rec, "enrollmentType"))
	setStr(attrs, "deployment_state", deploymentState)
	setStr(attrs, "device_setup_status", deviceSetupStatus)
	setStr(attrs, "account_setup_status", accountSetupStatus)
	setStr(attrs, "enrollment_failure_details", failureDetails)

	setDurationSeconds(attrs, "deployment_duration_seconds", str(rec, "deploymentDuration"))
	setDurationSeconds(attrs, "device_setup_duration_seconds", str(rec, "deviceSetupDuration"))
	setDurationSeconds(attrs, "account_setup_duration_seconds", str(rec, "accountSetupDuration"))

	return id, telemetry.Event{
		Name:     eventName,
		Body:     autopilotEventBody(deviceID, serial, deploymentState, deviceSetupStatus, accountSetupStatus),
		Severity: severityFor(deploymentState, deviceSetupStatus, accountSetupStatus, failureDetails),
		Attrs:    attrs,
	}
}

// autopilotEventBody builds a short human-readable summary line for an
// autopilot event record.
func autopilotEventBody(deviceID, serial, deploymentState, deviceSetupStatus, accountSetupStatus string) string {
	who := deviceID
	if who == "" {
		who = serial
	}
	if who == "" {
		who = "unknown device"
	}
	return "autopilot event for " + who + ": deployment=" + orUnknown(deploymentState) +
		" device_setup=" + orUnknown(deviceSetupStatus) + " account_setup=" + orUnknown(accountSetupStatus)
}

// orUnknown returns s, or "unknown" when s is empty, so the body never reads
// with a blank field.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// severityFor reports Error when the record carries explicit enrollment
// failure details or any of the three phase statuses reads as a failure,
// otherwise Info. This endpoint's beta enum values are not exhaustively
// documented, so failure detection is a case-insensitive "fail" substring
// match rather than an exact-value switch.
func severityFor(deploymentState, deviceSetupStatus, accountSetupStatus, failureDetails string) telemetry.Severity {
	if failureDetails != "" {
		return telemetry.SeverityError
	}
	if isFailure(deploymentState) || isFailure(deviceSetupStatus) || isFailure(accountSetupStatus) {
		return telemetry.SeverityError
	}
	return telemetry.SeverityInfo
}

// isFailure reports whether a phase status string indicates failure.
func isFailure(status string) bool {
	return strings.Contains(strings.ToLower(status), "fail")
}

// isoDurationPattern matches an ISO-8601 duration string as returned by
// Graph for the autopilot phase-duration fields (deploymentDuration,
// deviceSetupDuration, accountSetupDuration), e.g. "PT4M32S" or "PT1H2M3.5S".
// Graph does not document years/months/days appearing in these fields (they
// are short elapsed-time spans within one enrollment attempt), but the
// pattern tolerates the full ISO-8601 duration grammar, including a leading
// "-" for a negative duration, for robustness.
var isoDurationPattern = regexp.MustCompile(`^(-)?P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$`)

// parseISO8601DurationSeconds parses an ISO-8601 duration string into total
// seconds. A negative result (client clock skew between the phase's start
// and end timestamps) is CLAMPED to zero rather than returned negative — a
// phase cannot take less than no time. Returns ok=false for an empty or
// unparseable string, or one with no duration component at all (e.g. bare
// "P"), so the caller can omit the attribute rather than emit a bogus zero.
func parseISO8601DurationSeconds(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	m := isoDurationPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	years, months, days, hours, minutes, seconds := m[2], m[3], m[4], m[5], m[6], m[7]
	if years == "" && months == "" && days == "" && hours == "" && minutes == "" && seconds == "" {
		return 0, false
	}
	total := parseFloat(years)*365*24*3600 +
		parseFloat(months)*30*24*3600 +
		parseFloat(days)*24*3600 +
		parseFloat(hours)*3600 +
		parseFloat(minutes)*60 +
		parseFloat(seconds)
	if m[1] == "-" {
		total = -total
	}
	if total < 0 {
		total = 0
	}
	return total, true
}

// parseFloat parses s as a float64, returning 0 for an empty or
// unparseable string (regex capture groups are validated by
// isoDurationPattern before this is called, so a parse failure here cannot
// happen in practice).
func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// setDurationSeconds sets attrs[key] to the parsed duration in seconds when
// val is a valid ISO-8601 duration, and omits the attribute otherwise.
func setDurationSeconds(attrs telemetry.Attrs, key, val string) {
	if seconds, ok := parseISO8601DurationSeconds(val); ok {
		attrs[key] = seconds
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

// Compile-time checks that the autopilot-events collector satisfies every
// interface the composition root type-asserts on.
var (
	_ collector.WindowCollector = (*collectorImpl)(nil)
	_ collectors.Experimental   = (*collectorImpl)(nil)
)
