// Package certinventoryreport is the Intune fleet-wide device certificate
// inventory collector (BETA, opt-in): bounded aggregate gauges over
// days-until-expiry and collapsed certificate status, sourced from the
// Intune reports export-job subsystem (internal/exportjob, #17) rather than
// any entity-form Graph resource.
//
// There is no flat, fleet-wide Graph collection for device certificates.
// The per-device beta resource (managedDeviceCertificateState, see
// internal/collectors/intune/certificates) only reaches certificates one
// certificate-profile deviceConfiguration at a time and has no reliable
// join back to managedDevice — it does not scale to a full inventory sweep
// on a large fleet. The "AllDeviceCertificates" export report is Microsoft's
// own fleet-wide answer to this gap, so this collector runs it through the
// export-job POST -> poll -> download -> parse flow (see internal/exportjob)
// instead.
//
// Honest gap: there is no stable public Graph resource for Cloud PKI or
// certificate-authority/NDES connector HEALTH (as opposed to per-cert
// status) — that lives outside Graph entirely. This collector does not
// attempt to reconstruct it.
//
// Select-column history: an earlier version of this collector guessed
// column names by mirroring the per-device beta managedDeviceCertificateState
// resource's field names (certificateIssuanceState,
// certificateProfileDisplayName, ...). A live-tenant smoke test returned
// HTTP 400 — the report NAME is correct but those columns do not exist on
// this report. certInventorySelect below is Microsoft's documented
// available-reports column list for AllDeviceCertificates instead: no
// certificateProfileDisplayName equivalent exists on this report, so there
// is no per-profile dimension here — see the IssuerName note below.
//
// Cardinality: Thumbprint, SerialNumber, DeviceId/DeviceName, UserId/UPN,
// SubjectName, ValidFrom/ValidTo (raw), and the raw CertificateStatus value
// are per-entity/unbounded and NEVER become a metric label — they are
// logged (see certLogEvent) as structured attributes on the per-certificate
// intune.device_certificate log event. Metrics are keyed only by the
// bounded IssuerName (capped defensively by valueCapper, same backstop
// pattern as the sibling certificates package's cert-profile-name cap) plus
// a fixed expiry/status bucket.
//
// CertificateStatus collapse caveat: the report's actual CertificateStatus
// values have STILL not been observed (#142). certificateStatusBuckets below
// reuses the same ~20-value vocabulary as the per-device beta resource's
// certificateIssuanceState field, since both describe the same underlying
// Intune certificate-profile issuance status — a reasonable starting
// assumption, not a confirmed mapping. Any value outside that assumed
// vocabulary (including a genuinely different real enum) safely falls into
// "other" via certificateStatusBucketFor rather than growing the "state"
// dimension or panicking, and is announced (see Collect).
//
// What #142 measured live (2026-07-17, probed as graph2otel-poller), so the
// next reader does not re-run it:
//   - AllDeviceCertificates returns a header row and ZERO data rows on m7kni,
//     which holds no device certificates. The value set remains unobserved;
//     confirming it needs a tenant that actually has certificates.
//   - The column gets NO CertificateStatus_loc sibling at ANY localizationType
//     — including an explicit LocalizedValuesAsAdditionalColumn. The sibling
//     export reports' Platform and DeviceState columns DO get one under the
//     same probe. So the decode that fixed those two (read the localized
//     sibling Microsoft already sends) is unavailable here, whatever the
//     values turn out to be.
//
// What that does NOT establish, and what must not be asserted without
// evidence: whether this column returns numeric codes (as Platform and
// ProductStatus do) or the camelCase names assumed below. "No _loc sibling" is
// equally consistent with "numeric enum, unlocalizable" and "already a plain
// string, nothing to localize", so it settles nothing on its own. #142
// deliberately left this collector's mapping untouched for that reason. If the
// unmapped-value warning in Collect ever fires, THAT log is the evidence —
// read it, then fix this map against it.
package certinventoryreport

import (
	"context"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.cert_inventory"

// Metric and log names this collector emits.
const (
	daysUntilExpiryMetricName = "intune.cert_inventory.days_until_expiry"
	stateMetricName           = "intune.cert_inventory.state"
	// logEventName is the OTLP LogRecord EventName every per-certificate log
	// record carries.
	logEventName = "intune.device_certificate"
)

// reportName is the Intune reports-export catalog name for the fleet-wide
// device certificate inventory (v1.0 export mechanism — see the package
// doc for why there is no entity-form alternative). Live-verified: the
// export job is accepted with this name.
const reportName = "AllDeviceCertificates"

// certInventorySelect pins the export job's columns explicitly to
// Microsoft's documented AllDeviceCertificates available-reports column
// list — Microsoft warns the default export column set can change without
// notice, so every export caller must send its own Select. See the package
// doc's Select-column history for why this replaced an earlier guessed list
// that a live smoke test rejected with HTTP 400.
var certInventorySelect = []string{
	"CertificateStatus",
	"DeviceId",
	"DeviceName",
	"IssuerName",
	"PolicyId",
	"SerialNumber",
	"SubjectName",
	"Thumbprint",
	"UPN",
	"UserId",
	"ValidFrom",
	"ValidTo",
	"EnhancedKeyUsage",
	"KeyUsage",
}

// certificateStatusBuckets collapses CertificateStatus values down to a
// bounded set of four named buckets, per #41's spec. See the package doc's
// CertificateStatus collapse caveat: this assumes the same vocabulary as the
// per-device beta resource's certificateIssuanceState field, NOT an
// independently live-verified enum for this report's column. Anything
// absent from this map falls into "other" via certificateStatusBucketFor,
// so the "state" dimension can never grow regardless of whether that
// assumption holds. Mapping rationale:
//   - healthy: the cert is live and usable (issued, enrollmentSucceeded,
//     enrollmentNotNeeded, renewVerified, installed).
//   - pending: issuance is in flight, awaiting a later terminal state
//     (challengeIssued, challengeValidationSucceeded, issuePending,
//     responsePending, renewalRequested, requested).
//   - failed: any named failure/error step in the issuance or install
//     pipeline.
//   - revoked: certificate has been revoked.
var certificateStatusBuckets = map[string]string{
	"challengeIssued":              "pending",
	"challengeIssueFailed":         "failed",
	"requestCreationFailed":        "failed",
	"requestSubmitFailed":          "failed",
	"challengeValidationSucceeded": "pending",
	"challengeValidationFailed":    "failed",
	"issueFailed":                  "failed",
	"issuePending":                 "pending",
	"issued":                       "healthy",
	"responseProcessingFailed":     "failed",
	"responsePending":              "pending",
	"enrollmentSucceeded":          "healthy",
	"enrollmentNotNeeded":          "healthy",
	"revoked":                      "revoked",
	"renewVerified":                "healthy",
	"installFailed":                "failed",
	"installed":                    "healthy",
	"deleteFailed":                 "failed",
	"renewalRequested":             "pending",
	"requested":                    "pending",
}

// otherStateBucket is what certificateStatusBucketFor returns for any raw
// value not present in certificateStatusBuckets (the documented "unknown"
// value, the collection-removal states, a genuinely different real enum
// value, or a future addition).
const otherStateBucket = "other"

func certificateStatusBucketFor(raw string) string {
	if b, ok := certificateStatusBuckets[raw]; ok {
		return b
	}
	return otherStateBucket
}

// Bounded expiry-window buckets for the days_until_expiry dimension. Fixed
// regardless of tenant/cert-count.
const (
	expiryExpired  = "expired"
	expiryUnder7d  = "under_7d"
	expiryUnder30d = "under_30d"
	expiryUnder90d = "under_90d"
	expiryOK       = "ok"
	expiryUnknown  = "unknown"
)

// expiryBucketFor buckets a certificate's ValidTo relative to now. A nil
// ValidTo (an unparseable or absent column) buckets to "unknown" rather
// than being guessed at or dropped.
func expiryBucketFor(now time.Time, validTo *time.Time) string {
	if validTo == nil || validTo.IsZero() {
		return expiryUnknown
	}
	d := validTo.Sub(now)
	switch {
	case d <= 0:
		return expiryExpired
	case d < 7*24*time.Hour:
		return expiryUnder7d
	case d < 30*24*time.Hour:
		return expiryUnder30d
	case d < 90*24*time.Hour:
		return expiryUnder90d
	default:
		return expiryOK
	}
}

// parseRowTime parses an export row's RFC3339 timestamp column, returning
// nil for an empty or unparseable value rather than erroring the whole
// collect — a malformed timestamp on one row must not fail the aggregate.
func parseRowTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// maxIssuerNames caps the issuer dimension. IssuerName (the issuing CA) is
// admin/environment-bounded in practice, but the cap is a defensive
// backstop against a pathological tenant, mirroring the sibling
// certificates package's cert-profile-name cap.
const maxIssuerNames = 50

// valueCapper assigns a bounded set of distinct label values across one
// Collect call: the first maxIssuerNames distinct values seen pass through
// as-is; anything beyond that collapses into "other" so the dimension can
// never grow unboundedly.
type valueCapper struct {
	seen map[string]string
}

func newValueCapper() *valueCapper {
	return &valueCapper{seen: map[string]string{}}
}

func (p *valueCapper) bucket(name string) string {
	if name == "" {
		name = "unknown"
	}
	if v, ok := p.seen[name]; ok {
		return v
	}
	if len(p.seen) >= maxIssuerNames {
		p.seen[name] = "other"
		return "other"
	}
	p.seen[name] = name
	return name
}

// bucketKey is the aggregation key for the days_until_expiry metric: capped
// issuer name x expiry-window bucket.
type bucketKey struct {
	issuer string
	bucket string
}

// Collector runs the AllDeviceCertificates export report and emits the
// bounded gauges described in the package doc, plus one per-certificate log
// event.
type Collector struct {
	export exportjob.Runner
	logger *slog.Logger
	// now returns the current time; overridable in tests so expiry bucketing
	// is deterministic and assertable.
	now func() time.Time
}

// New builds the cert-inventory-report collector. A nil logger falls back
// to the slog default. export may be nil (e.g. a tenant whose composition
// root did not wire an exportjob.Runner) — Collect skips gracefully in that
// case rather than panicking.
func New(export exportjob.Runner, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{export: export, logger: logger, now: time.Now}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. An export job is
// the most expensive kind of poll this codebase runs (its own tight 48/min
// per-app throttle bucket, shared with every other export-based report
// collector), and fleet-wide certificate status/expiry composition drifts
// slowly, so this defaults to a long cadence.
func (c *Collector) DefaultInterval() time.Duration { return 6 * time.Hour }

// Experimental marks this collector as beta/opt-in: it depends on the
// export-job subsystem, which needs a WRITE-level Graph scope just to
// create the export job (see RequiredPermissions), and its CertificateStatus
// collapse map is an unverified assumption (see the package doc).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// DeviceManagementManagedDevices.ReadWrite.All is a WRITE scope, needed only
// to CREATE the export job (POST .../deviceManagement/reports/exportJobs);
// reading the completed job's result back needs no elevated scope. See
// internal/exportjob's package doc and the project CLAUDE.md gotcha
// "Reports export API needs a write-level scope just to create the export
// job" — documented here rather than silently requesting more than that one
// exception requires.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementManagedDevices.ReadWrite.All"}
}

// Collect runs the AllDeviceCertificates export report and rolls its rows
// into the bounded days-until-expiry and collapsed-status gauges, plus one
// intune.device_certificate log event per row. A nil export runner or any
// error from the export itself (permission denied, job failed, SAS
// expired, ...) is logged and treated as a graceful skip for this cycle —
// never a returned error — since the underlying report is opt-in and
// best-effort.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamped here because no engine can: internal/exportjob never calls
	// LogEvent, so report_export has no engine seam (#141). See
	// appinstallreport.Collect for the full reasoning.
	e = telemetry.WithTransport(e, telemetry.TransportReportExport)

	if c.export == nil {
		c.logger.Warn("cert_inventory: export runner not configured; skipping", "collector", collectorName)
		return nil
	}

	req := exportjob.Request{
		ReportName: reportName,
		Select:     certInventorySelect,
		Format:     exportjob.FormatCSV,
	}
	rows, err := c.export.Export(ctx, req, e)
	if err != nil {
		c.logger.Warn("cert_inventory: export failed; skipping this cycle", "collector", collectorName, "error", err)
		return nil
	}

	now := c.now()
	issuers := newValueCapper()
	days := map[bucketKey]int64{}
	states := map[string]int64{}

	for _, row := range rows {
		issuer := issuers.bucket(row["IssuerName"])

		expiryBucket := expiryBucketFor(now, parseRowTime(row["ValidTo"]))
		days[bucketKey{issuer: issuer, bucket: expiryBucket}]++

		stateBucket := certificateStatusBucketFor(row["CertificateStatus"])
		// Announce a value the vocabulary does not cover, naming the raw
		// string. This collector's CertificateStatus mapping is still an
		// ASSUMPTION (see the package doc): m7kni has zero device
		// certificates, so no real value has ever been observed, and #142
		// established that - unlike Platform and DeviceState on the sibling
		// export reports - this column gets no _loc sibling to decode against
		// at any localizationType.
		//
		// So rather than guess, make the gap self-closing: the first tenant
		// with certificates that runs this collector logs the real values, and
		// the assumption is confirmed or corrected from that alone. Without
		// this, a wrong vocabulary is invisible - every row lands in "other",
		// which is a designed-in bucket that looks like a steady state. That
		// is exactly how #142's Defender bug survived in production, and here
		// it would additionally mean failed/revoked certificates never
		// escalate to WARN (see certLogEvent), which is an alerting hole
		// rather than a cosmetic one.
		if stateBucket == otherStateBucket && row["CertificateStatus"] != "" {
			c.logger.Warn("cert_inventory: unmapped CertificateStatus; bucketing as other - please report this value (#142)",
				"collector", collectorName,
				"certificate_status", row["CertificateStatus"],
				"issuer_name", row["IssuerName"])
		}
		states[stateBucket]++

		e.LogEvent(certLogEvent(row, stateBucket))
	}

	dayPoints := make([]telemetry.GaugePoint, 0, len(days))
	for k, v := range days {
		dayPoints = append(dayPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{semconv.AttrIssuer: k.issuer, semconv.AttrBucket: k.bucket},
		})
	}
	e.GaugeSnapshot(daysUntilExpiryMetricName, "{certificate}", "Intune fleet device certificates (AllDeviceCertificates export report) by time-until-expiry window and issuing CA.", dayPoints)

	statePoints := make([]telemetry.GaugePoint, 0, len(states))
	for state, v := range states {
		statePoints = append(statePoints, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{semconv.AttrState: state}})
	}
	e.GaugeSnapshot(stateMetricName, "{certificate}", "Intune fleet device certificates (AllDeviceCertificates export report) by collapsed certificate status.", statePoints)

	return nil
}

// certLogEvent builds the per-certificate intune.device_certificate log
// event for one export row. Every per-entity export column - thumbprint,
// serial number, device/user identity, subject name, the raw uncollapsed
// CertificateStatus, and the validity window - lives here as structured
// attributes instead of a metric label; see the package doc's cardinality
// note. Severity escalates to WARN for a failed or revoked certificate.
func certLogEvent(row exportjob.Row, stateBucket string) telemetry.Event {
	attrs := telemetry.Attrs{semconv.AttrStateBucket: stateBucket}
	telemetry.SetStr(attrs, semconv.AttrDeviceId, row["DeviceId"])
	telemetry.SetStr(attrs, semconv.AttrDeviceName, row["DeviceName"])
	telemetry.SetStr(attrs, semconv.AttrUserId, row["UserId"])
	telemetry.SetStr(attrs, semconv.AttrUpn, row["UPN"])
	telemetry.SetStr(attrs, semconv.AttrSubjectName, row["SubjectName"])
	telemetry.SetStr(attrs, semconv.AttrIssuerName, row["IssuerName"])
	telemetry.SetStr(attrs, semconv.AttrPolicyId, row["PolicyId"])
	telemetry.SetStr(attrs, semconv.AttrSerialNumber, row["SerialNumber"])
	telemetry.SetStr(attrs, semconv.AttrThumbprint, row["Thumbprint"])
	telemetry.SetStr(attrs, semconv.AttrValidFrom, row["ValidFrom"])
	telemetry.SetStr(attrs, semconv.AttrValidTo, row["ValidTo"])
	telemetry.SetStr(attrs, semconv.AttrCertificateStatus, row["CertificateStatus"])
	telemetry.SetStr(attrs, semconv.AttrEnhancedKeyUsage, row["EnhancedKeyUsage"])
	telemetry.SetStr(attrs, semconv.AttrKeyUsage, row["KeyUsage"])

	severity := telemetry.SeverityInfo
	if stateBucket == "failed" || stateBucket == "revoked" {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     logEventName,
		Body:     "Intune device certificate " + stateBucket,
		Severity: severity,
		Attrs:    attrs,
	}
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Export, d.Logger)
	})
}
