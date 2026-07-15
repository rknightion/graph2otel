// Package certificates is the Intune certificate-state collector (BETA):
// bounded aggregate gauges over device-issued and user-imported certificate
// state, so an operator can see "how many certs are about to expire" and
// "how many certs are stuck in a failed/pending issuance state" without a
// per-certificate series.
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
// resource this collector aggregates on. Intentionally narrow - no id,
// deviceDisplayName, userDisplayName, thumbprint, or serial number is ever
// read, since those are unbounded per-entity identifiers that must never
// become metric labels.
type certificateState struct {
	CertificateIssuanceState      string     `json:"certificateIssuanceState"`
	CertificateProfileDisplayName string     `json:"certificateProfileDisplayName"`
	CertificateExpirationDateTime *time.Time `json:"certificateExpirationDateTime"`
}

// userPfxCertificate is the subset of the userPFXCertificate resource this
// collector aggregates on. No id, thumbprint, or userPrincipalName is ever
// read - see the type doc above.
type userPfxCertificate struct {
	IntendedPurpose    string     `json:"intendedPurpose"`
	ExpirationDateTime *time.Time `json:"expirationDateTime"`
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

	if err := c.collectManagedDeviceCertificateStates(ctx, now, days, states, capper); err != nil {
		c.logger.Warn("certificates: managedDeviceCertificateStates failed", "collector", collectorName, "error", err)
		errs = append(errs, fmt.Errorf("managed device certificate states: %w", err))
	}

	if err := c.collectUserPfxCertificates(ctx, now, days, states, capper); err != nil {
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
func (c *Collector) collectManagedDeviceCertificateStates(ctx context.Context, now time.Time, days map[bucketKey]int64, states map[string]int64, capper *profileNameCapper) error {
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
		}
	}
	return errors.Join(errs...)
}

// collectUserPfxCertificates pages the flat userPfxCertificates collection and
// folds each row into the shared aggregates under the fixed pfxImportedState
// bucket - see the package doc for why this resource can't populate the
// managedDeviceCertificateState issuance-state buckets. A 403/404 is
// skipped-and-logged, not treated as a failure.
func (c *Collector) collectUserPfxCertificates(ctx context.Context, now time.Time, days map[bucketKey]int64, states map[string]int64, capper *profileNameCapper) error {
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
	}
	return nil
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
