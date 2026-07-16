// Package certificates is the Intune certificate-state collector (BETA):
// bounded aggregate gauges over device-issued and user-imported certificate
// state, so an operator can see "how many certs are about to expire" and
// "how many certs are stuck in a failed/pending issuance state" without a
// per-certificate series, PLUS a log twin of the same fetch — one OTEL log
// record per certificate (intune.device_certificate) carrying the per-cert
// identity the gauges never carry: device/user display name, thumbprint,
// serial number, issuer, and issuance/expiry timestamps. A failed cert or a
// stuck VPN/Wi-Fi/S-MIME certificate is an outage waiting to happen, and the
// thumbprint is what a cert-misuse investigation keys on — dropping that
// detail (as this collector previously did, #114) meant graph2otel could say
// "how many" but never "WHICH certificate". Both certificate sources
// (managedDeviceCertificateState and userPfxCertificate) emit the SAME
// EventName with a "source" attribute distinguishing them, since they are
// the same signal from an operator's point of view. Private key material
// (userPFXCertificate's encryptedPfxBlob/encryptedPfxPassword) is never
// decoded or emitted — see userPfxCertificate's type doc.
//
// Two beta-only Graph resources feed the same two metrics:
//
//   - managedDeviceCertificateState — one row per (device, certificate
//     profile). There is NO flat `/deviceManagement/managedDeviceCertificateStates`
//     collection: Graph only exposes it as a navigation property nested under
//     the OWNING certificate-profile deviceConfiguration, cast to that
//     profile's concrete `@odata.type`
//     (`/deviceManagement/deviceConfigurations/{id}/microsoft.graph.<castType>/managedDeviceCertificateStates`,
//     see https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-manageddevicecertificatestate-list?view=graph-rest-beta).
//     So this collector first pages the (admin-config-bounded) deviceConfigurations
//     collection, filters to the certificate-profile types it recognizes (see
//     certProfileTypes), then fetches the states sub-collection per matched
//     profile. It also has NO reliable link back to managedDevice.id — only a
//     free-text deviceDisplayName — so state is aggregated as its own signal,
//     never joined to a specific managedDevice.
//   - userPFXCertificate — a flat `/deviceManagement/userPfxCertificates`
//     collection of admin-imported PFX certs for S/MIME, VPN, and Wi-Fi. It
//     carries no issuance-state field, so every row contributes to a fixed
//     "imported" state bucket (see pfxImportedState).
//
// Honest gap: there is no Graph resource for certificate-authority/NDES
// connector health here (that lives in the general connector-health
// collector, internal/collectors/intune/connectors) and this collector does
// not attempt to reconstruct it. It also does not reach the four
// certificate-profile types nested two levels deep under
// windowsWifiEnterpriseEAPConfiguration/identityCertificateForClientAuthentication
// (windows10PkcsCertificateProfile, windows81SCEPCertificateProfile,
// windows10ImportedPFXCertificateProfile, windowsPhone81ImportedPFXCertificateProfile)
// — reaching those needs a second cast hop this collector doesn't implement,
// so certs issued from those specific Windows Wi-Fi EAP profiles are silently
// absent from the aggregate rather than counted. Both gaps are deliberate
// scope cuts, not oversights.
package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

// collectorName is the stable key used for config (enable/interval),
// self-observability, and the admin status page.
const collectorName = "intune.certificates"

// Metric names this collector emits. Each is its own metric name so summing
// either always yields a true bounded count.
const (
	daysUntilExpiryMetricName = "intune.certificate.days_until_expiry"
	stateCountMetricName      = "intune.certificate.state.count"
)

// eventDeviceCertificate is the log-twin EventName shared by BOTH certificate
// sources this collector aggregates (managedDeviceCertificateState and
// userPfxCertificate) — one record per certificate per cycle, carrying the
// identity/thumbprint detail the two gauges above cannot. A "source"
// attribute ("managed_device" / "user_pfx") distinguishes which Graph
// resource produced a given record. See the package doc.
const eventDeviceCertificate = "intune.device_certificate"

// betaBaseURL is the Graph beta root. Both source resources
// (managedDeviceCertificateState, userPFXCertificate) are beta-only — see the
// package doc — so this collector is Experimental (opt-in, off by default).
const betaBaseURL = "https://graph.microsoft.com/beta"

// certProfileTypes maps every certificate-profile deviceConfiguration
// @odata.type this collector knows how to reach managedDeviceCertificateStates
// from, to the URL cast segment used to reach that sub-collection. Sourced
// from the HTTP request list in
// https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-manageddevicecertificatestate-list?view=graph-rest-beta.
// Deliberately excludes the four types nested under
// windowsWifiEnterpriseEAPConfiguration/identityCertificateForClientAuthentication
// (see the package doc's honest-gap note) — a deviceConfiguration of that
// wrapper type simply won't match this map and is skipped, same as any other
// non-certificate profile.
var certProfileTypes = map[string]string{
	"#microsoft.graph.iosPkcsCertificateProfile":                       "iosPkcsCertificateProfile",
	"#microsoft.graph.iosScepCertificateProfile":                       "iosScepCertificateProfile",
	"#microsoft.graph.macOSPkcsCertificateProfile":                     "macOSPkcsCertificateProfile",
	"#microsoft.graph.macOSScepCertificateProfile":                     "macOSScepCertificateProfile",
	"#microsoft.graph.androidPkcsCertificateProfile":                   "androidPkcsCertificateProfile",
	"#microsoft.graph.androidScepCertificateProfile":                   "androidScepCertificateProfile",
	"#microsoft.graph.iosImportedPFXCertificateProfile":                "iosImportedPFXCertificateProfile",
	"#microsoft.graph.macOSImportedPFXCertificateProfile":              "macOSImportedPFXCertificateProfile",
	"#microsoft.graph.androidImportedPFXCertificateProfile":            "androidImportedPFXCertificateProfile",
	"#microsoft.graph.androidForWorkPkcsCertificateProfile":            "androidForWorkPkcsCertificateProfile",
	"#microsoft.graph.androidForWorkScepCertificateProfile":            "androidForWorkScepCertificateProfile",
	"#microsoft.graph.windowsPhone81SCEPCertificateProfile":            "windowsPhone81SCEPCertificateProfile",
	"#microsoft.graph.aospDeviceOwnerPkcsCertificateProfile":           "aospDeviceOwnerPkcsCertificateProfile",
	"#microsoft.graph.aospDeviceOwnerScepCertificateProfile":           "aospDeviceOwnerScepCertificateProfile",
	"#microsoft.graph.androidDeviceOwnerPkcsCertificateProfile":        "androidDeviceOwnerPkcsCertificateProfile",
	"#microsoft.graph.androidDeviceOwnerScepCertificateProfile":        "androidDeviceOwnerScepCertificateProfile",
	"#microsoft.graph.androidWorkProfilePkcsCertificateProfile":        "androidWorkProfilePkcsCertificateProfile",
	"#microsoft.graph.androidWorkProfileScepCertificateProfile":        "androidWorkProfileScepCertificateProfile",
	"#microsoft.graph.androidForWorkImportedPFXCertificateProfile":     "androidForWorkImportedPFXCertificateProfile",
	"#microsoft.graph.androidDeviceOwnerImportedPFXCertificateProfile": "androidDeviceOwnerImportedPFXCertificateProfile",
}

// issuanceStateBuckets collapses every documented managedDeviceCertificateState
// certificateIssuanceState value
// (https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-certificateissuancestates?view=graph-rest-beta)
// down to a bounded set of six buckets, so the "state" dimension can never
// grow even if Microsoft adds new enum members. Mapping rationale:
//   - issued: the cert is live and usable (issued, enrollmentSucceeded,
//     enrollmentNotNeeded, renewVerified, installed).
//   - pending: issuance is in flight, awaiting a later terminal state
//     (challengeIssued, challengeValidationSucceeded, issuePending,
//     responsePending, renewalRequested, requested).
//   - failed: any named failure/error step in the issuance or install pipeline.
//   - revoked: certificate has been revoked.
//   - deleted: certificate/state record has been removed (deleted,
//     removedFromCollection).
//   - unknown: the documented "unknown" value, or any value this collector
//     doesn't recognize (a future beta enum addition never grows the bucket
//     set - see issuanceBucketFor).
var issuanceStateBuckets = map[string]string{
	"unknown":                      "unknown",
	"challengeIssued":              "pending",
	"challengeIssueFailed":         "failed",
	"requestCreationFailed":        "failed",
	"requestSubmitFailed":          "failed",
	"challengeValidationSucceeded": "pending",
	"challengeValidationFailed":    "failed",
	"issueFailed":                  "failed",
	"issuePending":                 "pending",
	"issued":                       "issued",
	"responseProcessingFailed":     "failed",
	"responsePending":              "pending",
	"enrollmentSucceeded":          "issued",
	"enrollmentNotNeeded":          "issued",
	"revoked":                      "revoked",
	"removedFromCollection":        "deleted",
	"renewVerified":                "issued",
	"installFailed":                "failed",
	"installed":                    "issued",
	"deleteFailed":                 "failed",
	"deleted":                      "deleted",
	"renewalRequested":             "pending",
	"requested":                    "pending",
}

// pfxImportedState is the fixed state bucket every userPfxCertificates row
// contributes: that resource carries no issuance-state field, so this is the
// honest "present as an imported PFX certificate" signal rather than a guess
// at one of the managedDeviceCertificateState buckets above.
const pfxImportedState = "imported"

func issuanceBucketFor(raw string) string {
	if b, ok := issuanceStateBuckets[raw]; ok {
		return b
	}
	return "unknown"
}

// Bounded expiry-window buckets for the days_until_expiry dimension. Fixed
// regardless of tenant/cert-count.
const (
	expiryExpired = "expired"
	expiry0To7    = "0d_7d"
	expiry7To30   = "7d_30d"
	expiry30To90  = "30d_90d"
	expiryOver90  = "over_90d"
	expiryUnknown = "unknown"
)

// expiryBucketFor buckets a certificate's expiration relative to now. A nil
// expiration buckets to "unknown" rather than being guessed at or dropped.
func expiryBucketFor(now time.Time, exp *time.Time) string {
	if exp == nil || exp.IsZero() {
		return expiryUnknown
	}
	d := exp.Sub(now)
	switch {
	case d <= 0:
		return expiryExpired
	case d < 7*24*time.Hour:
		return expiry0To7
	case d < 30*24*time.Hour:
		return expiry7To30
	case d < 90*24*time.Hour:
		return expiry30To90
	default:
		return expiryOver90
	}
}

// maxCertProfileNames caps the cert_profile_name dimension. Profile names are
// admin-configured (bounded by the count of certificate profiles a tenant
// configures, not by device/user count), but the cap is a defensive backstop
// against a pathological tenant, per the tracking issue.
const maxCertProfileNames = 50

// profileNameCapper assigns a bounded set of distinct cert_profile_name label
// values across one Collect call: the first maxCertProfileNames distinct
// names seen pass through as-is; anything beyond that collapses into "other"
// so this dimension can never grow unboundedly.
type profileNameCapper struct {
	seen map[string]string
}

func newProfileNameCapper() *profileNameCapper {
	return &profileNameCapper{seen: map[string]string{}}
}

func (p *profileNameCapper) bucket(name string) string {
	if name == "" {
		name = "unknown"
	}
	if v, ok := p.seen[name]; ok {
		return v
	}
	if len(p.seen) >= maxCertProfileNames {
		p.seen[name] = "other"
		return "other"
	}
	p.seen[name] = name
	return name
}

// deviceConfigListItem is the subset of a deviceConfigurations list element
// this collector reads: just enough to identify certificate-profile entries
// and reach their managedDeviceCertificateStates sub-collection.
type deviceConfigListItem struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	ODataType   string `json:"@odata.type"`
}

// certificateState is the subset of the managedDeviceCertificateState
// resource this collector reads (verified live against the beta docs,
// 2026-07-16:
// https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-manageddevicecertificatestate?view=graph-rest-beta).
// CertificateIssuanceState/CertificateProfileDisplayName/
// CertificateExpirationDateTime bucket the two metrics; every other field
// here feeds ONLY the intune.device_certificate log twin, never a metric
// label (id, device/user display name, thumbprint, serial number, issuer,
// key length, subject name/SAN format, revoke status, issuance/last-change
// timestamps, error code) - see the package doc. Deliberately still excludes
// certificateKeyUsage, certificateValidityPeriod(Units), certificateKeyStorageProvider,
// devicePlatform's less useful siblings, and certificateEnhancedKeyUsage/
// certificateSubjectNameFormatString/certificateSubjectAlternativeNameFormatString
// - lower-value fields for an investigation twin than the ones decoded below.
type certificateState struct {
	ID                                          string     `json:"id"`
	DevicePlatform                              string     `json:"devicePlatform"`
	CertificateIssuanceState                    string     `json:"certificateIssuanceState"`
	CertificateProfileDisplayName               string     `json:"certificateProfileDisplayName"`
	CertificateExpirationDateTime               *time.Time `json:"certificateExpirationDateTime"`
	CertificateIssuanceDateTime                 *time.Time `json:"certificateIssuanceDateTime"`
	CertificateLastIssuanceStateChangedDateTime *time.Time `json:"certificateLastIssuanceStateChangedDateTime"`
	DeviceDisplayName                           string     `json:"deviceDisplayName"`
	UserDisplayName                             string     `json:"userDisplayName"`
	CertificateThumbprint                       string     `json:"certificateThumbprint"`
	CertificateSerialNumber                     string     `json:"certificateSerialNumber"`
	CertificateIssuer                           string     `json:"certificateIssuer"`
	CertificateRevokeStatus                     string     `json:"certificateRevokeStatus"`
	CertificateSubjectNameFormat                string     `json:"certificateSubjectNameFormat"`
	CertificateSubjectAlternativeNameFormat     string     `json:"certificateSubjectAlternativeNameFormat"`
	CertificateKeyLength                        int        `json:"certificateKeyLength"`
	CertificateErrorCode                        int        `json:"certificateErrorCode"`
}

// userPfxCertificate is the subset of the userPFXCertificate resource this
// collector reads (verified live against the beta docs, 2026-07-16:
// https://learn.microsoft.com/en-us/graph/api/resources/intune-raimportcerts-userpfxcertificate?view=graph-rest-beta).
// IntendedPurpose/ExpirationDateTime bucket the metrics; ID/UserPrincipalName/
// Thumbprint/StartDateTime/ProviderName/KeyName feed ONLY the
// intune.device_certificate log twin (source=user_pfx), never a metric
// label. encryptedPfxBlob and encryptedPfxPassword — the two fields this
// resource documents as carrying the certificate's private key material — are
// DELIBERATELY not decoded here and therefore can never reach either output;
// see the package doc.
type userPfxCertificate struct {
	ID                 string     `json:"id"`
	UserPrincipalName  string     `json:"userPrincipalName"`
	Thumbprint         string     `json:"thumbprint"`
	IntendedPurpose    string     `json:"intendedPurpose"`
	StartDateTime      *time.Time `json:"startDateTime"`
	ExpirationDateTime *time.Time `json:"expirationDateTime"`
	ProviderName       string     `json:"providerName"`
	KeyName            string     `json:"keyName"`
}

// bucketKey is the shared aggregation key for the days_until_expiry metric:
// expiry window x collapsed issuance state x capped cert-profile name.
type bucketKey struct {
	expiryBucket string
	state        string
	profileName  string
}

// Collector polls Intune's beta certificate-state resources.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now returns the current time; overridable in tests so expiry bucketing
	// is deterministic and assertable.
	now func() time.Time
}

// New builds the certificates collector. A nil logger falls back to the slog
// default.
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: betaBaseURL, logger: logger, now: time.Now}
}

// Name implements collector.SnapshotCollector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.SnapshotCollector. Certificate
// issuance/expiry composition drifts slowly; a longer cadence is fine.
func (c *Collector) DefaultInterval() time.Duration { return 30 * time.Minute }

// Experimental marks this as a beta, opt-in collector: both source resources
// are beta-only (see the package doc).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the least-privilege Graph application scope.
// Both list operations this collector uses document
// DeviceManagementConfiguration.Read.All as their least-privileged permission.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementConfiguration.Read.All"}
}

// Collect fetches managedDeviceCertificateStates (via the deviceConfigurations
// cast-per-profile path, see the package doc) and userPfxCertificates, and
// emits the two bounded gauges described in the package doc. The two sources
// are independently resilient: a failure in one is logged and joined into the
// returned error, but the other's contribution to the shared metrics still
// emits.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	var errs []error
	now := c.now()

	days := map[bucketKey]int64{}
	states := map[string]int64{}
	capper := newProfileNameCapper()

	if err := c.collectManagedDeviceCertificateStates(ctx, e, now, days, states, capper); err != nil {
		c.logger.Warn("certificates: managedDeviceCertificateStates failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("managed device certificate states: %w", err))
	}

	if err := c.collectUserPfxCertificates(ctx, e, now, days, states, capper); err != nil {
		c.logger.Warn("certificates: userPfxCertificates failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("user pfx certificates: %w", err))
	}

	dayPoints := make([]telemetry.GaugePoint, 0, len(days))
	for k, v := range days {
		dayPoints = append(dayPoints, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{"expiry_bucket": k.expiryBucket, "state": k.state, "cert_profile_name": k.profileName},
		})
	}
	e.GaugeSnapshot(daysUntilExpiryMetricName, "{certificate}", "Intune certificates by time-until-expiry window, issuance state, and certificate profile.", dayPoints)

	statePoints := make([]telemetry.GaugePoint, 0, len(states))
	for state, v := range states {
		statePoints = append(statePoints, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{"state": state}})
	}
	e.GaugeSnapshot(stateCountMetricName, "{certificate}", "Intune certificates by collapsed issuance state.", statePoints)

	return errors.Join(errs...)
}

// collectManagedDeviceCertificateStates pages deviceConfigurations, filters to
// the certificate-profile types certProfileTypes recognizes, and fetches each
// matched profile's managedDeviceCertificateStates sub-collection - see the
// package doc for why this two-hop shape is required. A 403/404 (beta
// endpoint unavailable/unlicensed on this tenant, or a cast Graph doesn't
// support) is skipped-and-logged for the affected call, not treated as a
// failure.
func (c *Collector) collectManagedDeviceCertificateStates(ctx context.Context, e telemetry.Emitter, now time.Time, days map[bucketKey]int64, states map[string]int64, capper *profileNameCapper) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/deviceConfigurations", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("certificates: deviceConfigurations unavailable on this tenant; skipping", "collector", collectorName, "error", err)
			return nil
		}
		return fmt.Errorf("list device configurations: %w", err)
	}

	var errs []error
	for _, r := range raw {
		var dc deviceConfigListItem
		if err := json.Unmarshal(r, &dc); err != nil {
			c.logger.Warn("certificates: skipping malformed deviceConfiguration element", "collector", collectorName, "error", err)
			continue
		}
		segment, ok := certProfileTypes[dc.ODataType]
		if !ok {
			continue // not a certificate profile this collector reaches - see the package doc
		}

		url := c.baseURL + "/deviceManagement/deviceConfigurations/" + dc.ID + "/microsoft.graph." + segment + "/managedDeviceCertificateStates"
		statesRaw, err := collectors.GetAllValues(ctx, c.g, url, nil)
		if err != nil {
			if isUnavailable(err) {
				c.logger.Info("certificates: managedDeviceCertificateStates unavailable for profile; skipping", "collector", collectorName, "profile_type", segment, "error", err)
				continue
			}
			c.logger.Warn("certificates: managedDeviceCertificateStates fetch failed for profile", "collector", collectorName, "profile_type", segment, "error", err)
			errs = append(errs, fmt.Errorf("profile %s (%s): %w", dc.ID, segment, err))
			continue
		}

		for _, sr := range statesRaw {
			var st certificateState
			if err := json.Unmarshal(sr, &st); err != nil {
				c.logger.Warn("certificates: skipping malformed certificate state element", "collector", collectorName, "error", err)
				continue
			}
			profileName := st.CertificateProfileDisplayName
			if profileName == "" {
				profileName = dc.DisplayName
			}
			bucketName := capper.bucket(profileName)
			stateBucket := issuanceBucketFor(st.CertificateIssuanceState)
			expiryBucket := expiryBucketFor(now, st.CertificateExpirationDateTime)

			days[bucketKey{expiryBucket: expiryBucket, state: stateBucket, profileName: bucketName}]++
			states[stateBucket]++
			e.LogEvent(managedDeviceCertLogTwin(st, stateBucket, expiryBucket))
		}
	}
	return errors.Join(errs...)
}

// collectUserPfxCertificates pages the flat userPfxCertificates collection and
// folds each row into the shared aggregates under the fixed pfxImportedState
// bucket - see the package doc for why this resource can't populate the
// managedDeviceCertificateState issuance-state buckets. A 403/404 is
// skipped-and-logged, not treated as a failure.
func (c *Collector) collectUserPfxCertificates(ctx context.Context, e telemetry.Emitter, now time.Time, days map[bucketKey]int64, states map[string]int64, capper *profileNameCapper) error {
	raw, err := collectors.GetAllValues(ctx, c.g, c.baseURL+"/deviceManagement/userPfxCertificates", nil)
	if err != nil {
		if isUnavailable(err) {
			c.logger.Info("certificates: userPfxCertificates unavailable on this tenant; skipping", "collector", collectorName, "error", err)
			return nil
		}
		return fmt.Errorf("list user pfx certificates: %w", err)
	}

	for _, r := range raw {
		var pfx userPfxCertificate
		if err := json.Unmarshal(r, &pfx); err != nil {
			c.logger.Warn("certificates: skipping malformed userPfxCertificate element", "collector", collectorName, "error", err)
			continue
		}
		purpose := pfx.IntendedPurpose
		if purpose == "" {
			purpose = "unknown"
		}
		profileName := capper.bucket("pfx:" + purpose)
		expiryBucket := expiryBucketFor(now, pfx.ExpirationDateTime)

		days[bucketKey{expiryBucket: expiryBucket, state: pfxImportedState, profileName: profileName}]++
		states[pfxImportedState]++
		e.LogEvent(userPfxCertLogTwin(pfx, expiryBucket))
	}
	return nil
}

// managedDeviceCertLogTwin renders one managedDeviceCertificateState as an
// OTLP log record. stateBucket/expiryBucket are the already-collapsed metric
// buckets, passed in so the twin and the gauges never disagree, and so
// severity can key off the same "failed" / "expired" classification the
// metrics use.
//
// Severity escalates to Warn for a failed issuance or an expired
// certificate — either is the concrete "something is broken right now"
// signal an operator acts on (a stuck/failed cert is an outage waiting to
// happen for whatever VPN/Wi-Fi/email flow depends on it); every other state
// (issued, pending, revoked, deleted, unknown) stays Info.
func managedDeviceCertLogTwin(st certificateState, stateBucket, expiryBucket string) telemetry.Event {
	attrs := telemetry.Attrs{"source": "managed_device"}
	setStr(attrs, "id", st.ID)
	setStr(attrs, "device_platform", st.DevicePlatform)
	setStr(attrs, "device_display_name", st.DeviceDisplayName)
	setStr(attrs, "user_display_name", st.UserDisplayName)
	setStr(attrs, "certificate_profile_name", st.CertificateProfileDisplayName)
	setStr(attrs, "thumbprint", st.CertificateThumbprint)
	setStr(attrs, "serial_number", st.CertificateSerialNumber)
	setStr(attrs, "issuer", st.CertificateIssuer)
	setStr(attrs, "issuance_state", st.CertificateIssuanceState)
	setStr(attrs, "revoke_status", st.CertificateRevokeStatus)
	setStr(attrs, "subject_name_format", st.CertificateSubjectNameFormat)
	setStr(attrs, "subject_alternative_name_format", st.CertificateSubjectAlternativeNameFormat)
	if st.CertificateKeyLength != 0 {
		attrs["key_length"] = strconv.Itoa(st.CertificateKeyLength)
	}
	if st.CertificateErrorCode != 0 {
		attrs["error_code"] = strconv.Itoa(st.CertificateErrorCode)
	}
	setStr(attrs, "expiration_date_time", formatTimePtr(st.CertificateExpirationDateTime))
	setStr(attrs, "issuance_date_time", formatTimePtr(st.CertificateIssuanceDateTime))
	setStr(attrs, "last_issuance_state_changed_date_time", formatTimePtr(st.CertificateLastIssuanceStateChangedDateTime))

	sev := telemetry.SeverityInfo
	if stateBucket == "failed" || expiryBucket == expiryExpired {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventDeviceCertificate,
		Body:     fmt.Sprintf("managed device certificate %s: issuance_state=%s", managedCertDisplayOf(st), st.CertificateIssuanceState),
		Severity: sev,
		Attrs:    attrs,
	}
}

// managedCertDisplayOf picks the most human-readable identifier a
// managedDeviceCertificateState carries, falling back through thumbprint and
// device name to id (there is no reliable link back to managedDevice.id -
// see the package doc).
func managedCertDisplayOf(st certificateState) string {
	for _, s := range []string{st.CertificateThumbprint, st.DeviceDisplayName, st.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// userPfxCertLogTwin renders one userPfxCertificate as an OTLP log record.
// encryptedPfxBlob/encryptedPfxPassword are never decoded (see
// userPfxCertificate's type doc) so they can never appear here regardless of
// what this function does.
//
// Severity escalates to Warn for an expired certificate - the same "something
// is broken right now" signal as the managed-device twin above. This
// resource has no issuance-state field (see pfxImportedState), so expiry is
// the only Warn trigger.
func userPfxCertLogTwin(pfx userPfxCertificate, expiryBucket string) telemetry.Event {
	attrs := telemetry.Attrs{"source": "user_pfx"}
	setStr(attrs, "id", pfx.ID)
	setStr(attrs, "user_principal_name", pfx.UserPrincipalName)
	setStr(attrs, "thumbprint", pfx.Thumbprint)
	setStr(attrs, "intended_purpose", pfx.IntendedPurpose)
	setStr(attrs, "provider_name", pfx.ProviderName)
	setStr(attrs, "key_name", pfx.KeyName)
	setStr(attrs, "start_date_time", formatTimePtr(pfx.StartDateTime))
	setStr(attrs, "expiration_date_time", formatTimePtr(pfx.ExpirationDateTime))

	sev := telemetry.SeverityInfo
	if expiryBucket == expiryExpired {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventDeviceCertificate,
		Body:     fmt.Sprintf("user pfx certificate %s: intended_purpose=%s", userPfxDisplayOf(pfx), pfx.IntendedPurpose),
		Severity: sev,
		Attrs:    attrs,
	}
}

// userPfxDisplayOf picks the most human-readable identifier a
// userPfxCertificate carries, falling back through thumbprint and UPN to id.
func userPfxDisplayOf(pfx userPfxCertificate) string {
	for _, s := range []string{pfx.Thumbprint, pfx.UserPrincipalName, pfx.ID} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// formatTimePtr renders a nullable Graph timestamp as RFC3339, or "" when nil
// or zero - setStr then omits the attribute entirely rather than emitting an
// empty value.
func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// setStr adds key=val to attrs only when val is non-empty, so an absent
// string field emits no attribute rather than an empty one - matches the
// entra/risk and purview/labels reference collectors.
func setStr(attrs telemetry.Attrs, key, val string) {
	if val != "" {
		attrs[key] = val
	}
}

// isUnavailable reports whether err is a 4xx from a beta endpoint being
// unavailable/unlicensed on the tenant (403 forbidden, 404 not found) - an
// expected "no data here" condition, not a failure. Mirrors
// entra/recommendations' isUnavailable.
func isUnavailable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "status 403") || strings.Contains(s, "status 404")
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}
