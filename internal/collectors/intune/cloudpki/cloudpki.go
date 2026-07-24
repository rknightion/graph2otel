// Package cloudpki is the Intune Cloud PKI collector (BETA): the tenant's
// private certification authorities, when they expire, and every leaf
// certificate they have issued to a device.
//
// # Why this exists
//
// Cloud PKI issues the certificates devices use to authenticate — Wi-Fi, VPN,
// 802.1X. When an issuing CA expires, every device that depends on it loses
// authentication AT ONCE; there is no gradual degradation to notice first.
// entra.credential_expiry watches application and service-principal credentials
// and cannot see this at all: it is a different PKI entirely (#258).
//
// # Sources (beta-only — v1.0 rejects the segment, so this is Experimental)
//
//	GET /beta/deviceManagement/cloudCertificationAuthority                       (2 rows on m7kni)
//	GET /beta/deviceManagement/cloudCertificationAuthority/{id}/cloudCertificationAuthorityLeafCertificate
//
// The leaf route is RESOLVED, live-measured 2026-07-24 as graph2otel-poller: it
// answers 200 with 69 rows for m7kni's issuing CA (8 active / 43 expired / 18
// revoked). The 404 recorded on #258 was against the TOP-LEVEL
// `/beta/deviceManagement/cloudCertificationAuthorityLeafCertificate`, which the
// beta EDM declares but which does not serve; the per-CA navigation is the
// working route and the one used here. The fan-out is one request per CA.
//
// # Expiry comes out of the certificate, not out of a field
//
// Each CA carries its own certificate inline as a
// `data:application/x-x509-ca-cert;base64,…` URI, so the authoritative validity
// window — the one devices actually validate against — is available with no
// second fetch and no credential. It is parsed with crypto/x509 and that is what
// drives the gauge and the twin.
//
// The wire ALSO carries `validityStartDateTime`/`validityEndDateTime`, and they
// agree with the certificate on every live row. They are not used as the source,
// but they are not ignored either: a disagreement is emitted as
// `declared_valid_to` (see semconv.AttrDeclaredValidTo) and escalates severity,
// because Graph and the certificate it handed over disagreeing about when
// fleet-wide authentication stops is worth waking up for. When the certificate
// cannot be parsed at all, the declared value is used instead and
// `expiry_source` says so — a degraded reading must never be indistinguishable
// from a measured one. When neither is available, NO gauge point is emitted; a
// fabricated expiry is worse than a missing one.
//
// LEAF certificates carry no certificate blob, so their validity window comes
// from the wire fields, which are the only source that exists for them.
//
// # Wire facts handled rather than assumed (live-measured 2026-07-24, n=1)
//
//   - `keyUsages` and `extendedKeyUsages` on a LEAF are typed
//     `Collection(Edm.String)` and arrive as a ONE-element collection whose
//     single element is a JSON-ENCODED ARRAY
//     (`["[\"KeyEncipherment\",\"DigitalSignature\"]"]`). They are unwrapped.
//   - `extendedKeyUsages` on a CA is the same NAME with a different SHAPE: a
//     collection of `{name, objectIdentifier}` objects. The human `name` is
//     emitted. Both shapes are decoded defensively so neither can fail a row.
//   - `ocspResponderUri` and `certificationAuthorityIssuerId` come back as EMPTY
//     STRINGS rather than null, `scepServerUrl` and `issuerCommonName` are null
//     on a root CA, and the issuing CA's `scepServerUrl` contains an unexpanded
//     `{{CloudPKIFQDN}}` template token — emitted verbatim rather than
//     "corrected" (#142).
//
// # Deliberately NOT mapped
//
//   - `certificateDownloadUrl` and `certificateSigningRequest`: the blob is
//     public, not secret, but it is kilobytes of base64 no query can use, and
//     everything useful in it is decoded into fields.
//   - `activeVersion`: it re-states the CA's own thumbprint, serial, subject and
//     validity window. Its one unique field, `usage.issuedStagedLeafCertificateCount`,
//     counts STAGED leaves and reads 0 on a tenant with 69 issued ones, so it
//     does not answer the question it looks like it answers — the leaf collection
//     does.
//   - `certificationAuthorityVersionNumber` on a leaf: it is 0 on all 69 live
//     rows while the issuing CA's own `versionNumber` is 1, so 0 is
//     indistinguishable from "not populated". Emitting it would publish a
//     version that does not exist.
//
// # Cardinality (#112/#114)
//
// The gauges are keyed by CA `display_name` plus bounded wire enums.
// display_name is a legitimate dimension here and the reasoning is worth stating
// because it is the exception rather than the rule: a Cloud PKI CA is
// admin-created infrastructure — one root plus a handful of issuers — so the
// series count is bounded by the tenant's PKI topology and does not grow with
// user or device count. The CA's `id` is NOT used, because #112's deny list
// (correctly) bans `id` from metric labels; it rides the twin as the join key.
// Everything per-entity — certificate identity, subjects, device and user
// identity on each leaf — rides one of the two log twins.
//
// # Volume
//
// One twin per CA plus one per LEAF certificate, every cycle. The leaf
// population is bounded by tenant size and by retained history: 69 records for a
// five-device tenant (live-measured 2026-07-24), the majority of them expired or
// revoked certificates the API keeps. That is why the interval is 12h.
package cloudpki

import (
	"context"
	"crypto/x509"
	"encoding/base64"
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
	collectorName = "intune.cloud_pki"
	// authoritiesMetricName counts CAs by type and status — the "does the PKI
	// still look the way it was built" gauge.
	authoritiesMetricName = "intune.cloud_pki.authorities"
	// daysUntilExpiryMetricName is one point per CA, negative once expired.
	daysUntilExpiryMetricName = "intune.cloud_pki.days_until_expiry"
	// leafCertificatesMetricName counts issued leaf certificates by issuing CA
	// and status.
	leafCertificatesMetricName = "intune.cloud_pki.leaf_certificates"

	eventAuthority       = "intune.cloud_pki_authority"
	eventLeafCertificate = "intune.cloud_pki_leaf_certificate"

	// defaultBaseURL is the Graph BETA root — see the package doc.
	defaultBaseURL = "https://graph.microsoft.com/beta"
	// authoritiesPath is the CA collection; leafCertificatesSegment is appended
	// to a single CA to walk the leaves it issued. No $top — GetAllValues already
	// asks for Graph's largest page via the Prefer header, and an unverified $top
	// is how a paged collector earns a 400 (docs/graph-api-gotchas.md).
	authoritiesPath         = "/deviceManagement/cloudCertificationAuthority"
	leafCertificatesSegment = "/cloudCertificationAuthorityLeafCertificate"

	// dataURIPrefix is the exact wrapper Graph puts around the DER-encoded CA
	// certificate.
	dataURIPrefix = "data:application/x-x509-ca-cert;base64,"

	// expirySourceCertificate / expirySourceDeclared are the two values of the
	// expiry_source attribute — see semconv.AttrExpirySource.
	expirySourceCertificate = "certificate"
	expirySourceDeclared    = "declared"

	// unknownValue keeps a bounded gauge dimension stable when a row omits one
	// of the wire enums.
	unknownValue = "unknown"
	// statusActive is the CA status and the leaf status meaning "in service".
	statusActive = "active"
)

// Expiry bucket boundaries, deliberately IDENTICAL to
// entra.credential_expiry's, so the two expiry signals agree about what
// "expiring soon" means and an operator can use one alerting threshold for both.
const (
	windowLt7d  = 7 * 24 * time.Hour
	windowLt30d = 30 * 24 * time.Hour
	windowLt90d = 90 * 24 * time.Hour

	bucketExpired = "expired"
	bucketLt7d    = "lt_7d"
	bucketLt30d   = "lt_30d"
	bucketLt90d   = "lt_90d"
	bucketGt90d   = "gt_90d"
)

// Collector polls the beta Cloud PKI certification authorities and their leaves.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
	// now returns the instant expiry is computed relative to. Tests override it
	// only indirectly, by minting certificates relative to the same clock.
	now func() time.Time
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger, now: time.Now}
}

func (c *Collector) Name() string { return collectorName }

// DefaultInterval is 12h. A CA expiry is months away when it starts to matter,
// so detection latency is not the constraint; the leaf twin volume is — one
// record per issued certificate including retained expired and revoked ones.
func (c *Collector) DefaultInterval() time.Duration { return 12 * time.Hour }

// Experimental reports true: the endpoint exists only on Graph beta.
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares the single read-only least-privilege scope. No
// write scope is involved — this is a plain GET.
func (c *Collector) RequiredPermissions() []string {
	return []string{"DeviceManagementCloudCA.Read.All"}
}

// authority is one cloudCertificationAuthority row. certificateDownloadUrl is
// read (it is the expiry source) but never emitted.
type authority struct {
	ID                              string          `json:"id"`
	DisplayName                     string          `json:"displayName"`
	Description                     string          `json:"description"`
	Type                            string          `json:"cloudCertificationAuthorityType"`
	Status                          string          `json:"certificationAuthorityStatus"`
	CertificateDownloadURL          string          `json:"certificateDownloadUrl"`
	CertificateRevocationListURL    string          `json:"certificateRevocationListUrl"`
	ScepServerURL                   string          `json:"scepServerUrl"`
	CertificationAuthorityIssuerID  string          `json:"certificationAuthorityIssuerId"`
	CertificationAuthorityIssuerURI string          `json:"certificationAuthorityIssuerUri"`
	OcspResponderURI                string          `json:"ocspResponderUri"`
	IssuerCommonName                string          `json:"issuerCommonName"`
	CommonName                      string          `json:"commonName"`
	RootCertificateCommonName       string          `json:"rootCertificateCommonName"`
	SubjectName                     string          `json:"subjectName"`
	Thumbprint                      string          `json:"thumbprint"`
	SerialNumber                    string          `json:"serialNumber"`
	CertificateKeySize              string          `json:"certificateKeySize"`
	HashingAlgorithm                string          `json:"cloudCertificationAuthorityHashingAlgorithm"`
	KeyPlatform                     string          `json:"keyPlatform"`
	GeographicRegion                string          `json:"geographicRegion"`
	OrganizationName                string          `json:"organizationName"`
	OrganizationUnit                string          `json:"organizationUnit"`
	LocalityName                    string          `json:"localityName"`
	StateName                       string          `json:"stateName"`
	CountryName                     string          `json:"countryName"`
	ValidityPeriodInYears           int             `json:"validityPeriodInYears"`
	VersionNumber                   int             `json:"versionNumber"`
	ValidityStartDateTime           string          `json:"validityStartDateTime"`
	ValidityEndDateTime             string          `json:"validityEndDateTime"`
	RoleScopeTagIDs                 []string        `json:"roleScopeTagIds"`
	CreatedDateTime                 string          `json:"createdDateTime"`
	LastModifiedDateTime            string          `json:"lastModifiedDateTime"`
	ExtendedKeyUsages               json.RawMessage `json:"extendedKeyUsages"`
}

// leafCertificate is one cloudCertificationAuthorityLeafCertificate row.
type leafCertificate struct {
	ID                              string          `json:"id"`
	SubjectName                     string          `json:"subjectName"`
	IssuerID                        string          `json:"issuerId"`
	IssuerName                      string          `json:"issuerName"`
	CertificateStatus               string          `json:"certificateStatus"`
	ValidityStartDateTime           string          `json:"validityStartDateTime"`
	ValidityEndDateTime             string          `json:"validityEndDateTime"`
	RevocationDateTime              string          `json:"revocationDateTime"`
	CrlDistributionPointURL         string          `json:"crlDistributionPointUrl"`
	CertificationAuthorityIssuerURI string          `json:"certificationAuthorityIssuerUri"`
	OcspResponderURI                string          `json:"ocspResponderUri"`
	Thumbprint                      string          `json:"thumbprint"`
	SerialNumber                    string          `json:"serialNumber"`
	DeviceID                        string          `json:"deviceId"`
	DeviceName                      string          `json:"deviceName"`
	DevicePlatform                  string          `json:"devicePlatform"`
	UserID                          string          `json:"userId"`
	UserPrincipalName               string          `json:"userPrincipalName"`
	KeyUsages                       json.RawMessage `json:"keyUsages"`
	ExtendedKeyUsages               json.RawMessage `json:"extendedKeyUsages"`
}

// validity is a CA's resolved validity window and where it came from.
type validity struct {
	from string
	to   string
	// end is the parsed expiry instant; zero when no expiry could be established.
	end time.Time
	// source is expirySourceCertificate or expirySourceDeclared; empty when
	// there is no expiry at all.
	source string
	// declaredMismatch holds the wire's validityEndDateTime when it disagrees
	// with the certificate. Empty otherwise, including when it IS the source.
	declaredMismatch string
}

// Collect fetches the CA collection, each CA's issued leaves, and emits the
// three bounded gauges plus a twin per CA and per leaf. A 403 on the CA
// collection (missing scope, or Cloud PKI not licensed on this tenant) is a
// graceful info-level skip rather than a collection failure.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	now := c.now()

	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+authoritiesPath, nil)
	if err != nil {
		if isForbidden(err) {
			c.logger.Info("cloudpki: cloudCertificationAuthority forbidden (missing scope or unlicensed); skipping",
				"collector", collectorName, "error", graphclient.FormatODataError(err))
			return nil
		}
		return fmt.Errorf("%s: list certification authorities: %w", collectorName, err)
	}

	caCounts := map[[2]string]int64{}
	expiryPoints := make([]telemetry.GaugePoint, 0, len(raws))
	leafCounts := map[[2]string]int64{}

	for _, raw := range raws {
		var ca authority
		if err := json.Unmarshal(raw, &ca); err != nil {
			return fmt.Errorf("%s: decode certification authority: %w", collectorName, err)
		}

		v := resolveValidity(&ca)
		caCounts[[2]string{orUnknown(ca.Type), orUnknown(ca.Status)}]++
		if !v.end.IsZero() {
			expiryPoints = append(expiryPoints, telemetry.GaugePoint{
				Value: v.end.Sub(now).Hours() / 24,
				Attrs: telemetry.Attrs{
					semconv.AttrDisplayName:                caLabel(&ca),
					semconv.AttrCertificationAuthorityType: orUnknown(ca.Type),
				},
			})
		} else {
			c.logger.Warn("cloudpki: certification authority has no parseable expiry; omitting its gauge point",
				"collector", collectorName, "certification_authority_id", ca.ID, "display_name", ca.DisplayName)
		}
		e.LogEvent(authorityTwin(&ca, v, now))

		leaves, lerr := c.listLeaves(ctx, ca.ID)
		if lerr != nil {
			// A failed leaf fetch must never become a reported zero, and must
			// never take the CA expiry signal down with it.
			c.logger.Warn("cloudpki: leaf certificate fetch failed; that authority's leaves are omitted this cycle",
				"collector", collectorName, "certification_authority_id", ca.ID, "error", lerr)
			continue
		}
		for i := range leaves {
			leaf := &leaves[i]
			leafCounts[[2]string{caLabel(&ca), orUnknown(leaf.CertificateStatus)}]++
			e.LogEvent(leafTwin(leaf, now))
		}
	}

	caPoints := make([]telemetry.GaugePoint, 0, len(caCounts))
	for k, n := range caCounts {
		caPoints = append(caPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrCertificationAuthorityType:   k[0],
				semconv.AttrCertificationAuthorityStatus: k[1],
			},
		})
	}
	e.GaugeSnapshot(authoritiesMetricName, "{authority}",
		"Intune Cloud PKI certification authorities by type (root/issuing) and status. Per-CA detail — decoded subject and issuer, key platform, CRL and SCEP endpoints — on the intune.cloud_pki_authority log twin.",
		caPoints)

	e.GaugeSnapshot(daysUntilExpiryMetricName, "d",
		"Days until each Intune Cloud PKI certification authority expires, read from the CA's own certificate rather than from a Graph field; negative once expired. When an issuing CA expires every device authenticating with its certificates loses Wi-Fi/VPN/802.1X at once. A CA whose expiry cannot be established emits NO point rather than a fabricated one.",
		expiryPoints)

	leafPoints := make([]telemetry.GaugePoint, 0, len(leafCounts))
	for k, n := range leafCounts {
		leafPoints = append(leafPoints, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{
				semconv.AttrDisplayName:       k[0],
				semconv.AttrCertificateStatus: k[1],
			},
		})
	}
	e.GaugeSnapshot(leafCertificatesMetricName, "{certificate}",
		"Leaf certificates issued by each Intune Cloud PKI certification authority, by status (active/expired/revoked). Which device and user each certificate belongs to is on the intune.cloud_pki_leaf_certificate log twin.",
		leafPoints)

	return nil
}

// listLeaves walks one CA's issued-leaf navigation.
func (c *Collector) listLeaves(ctx context.Context, caID string) ([]leafCertificate, error) {
	url := c.baseURL + authoritiesPath + "/" + caID + leafCertificatesSegment
	raws, err := collectors.GetAllValues(ctx, c.g, url, nil)
	if err != nil {
		return nil, err
	}
	out := make([]leafCertificate, 0, len(raws))
	for _, raw := range raws {
		var leaf leafCertificate
		if err := json.Unmarshal(raw, &leaf); err != nil {
			return nil, fmt.Errorf("decode leaf certificate: %w", err)
		}
		out = append(out, leaf)
	}
	return out, nil
}

// resolveValidity establishes a CA's validity window, preferring the inline
// certificate over the wire's declared dates. See the package doc.
func resolveValidity(ca *authority) validity {
	if cert, ok := parseInlineCertificate(ca.CertificateDownloadURL); ok {
		v := validity{
			from:   cert.NotBefore.UTC().Format(time.RFC3339),
			to:     cert.NotAfter.UTC().Format(time.RFC3339),
			end:    cert.NotAfter,
			source: expirySourceCertificate,
		}
		if declared, derr := parseGraphTime(ca.ValidityEndDateTime); derr == nil && !declared.Equal(cert.NotAfter) {
			v.declaredMismatch = ca.ValidityEndDateTime
		}
		return v
	}
	if declared, err := parseGraphTime(ca.ValidityEndDateTime); err == nil {
		return validity{
			from:   ca.ValidityStartDateTime,
			to:     ca.ValidityEndDateTime,
			end:    declared,
			source: expirySourceDeclared,
		}
	}
	return validity{}
}

// parseInlineCertificate decodes the data: URI Graph inlines the CA certificate
// in and parses the DER. Anything unexpected — a missing URI, a different
// prefix, bad base64, a non-certificate payload — returns ok=false so the caller
// degrades to the declared dates rather than failing the row.
func parseInlineCertificate(uri string) (*x509.Certificate, bool) {
	b64, ok := strings.CutPrefix(uri, dataURIPrefix)
	if !ok || b64 == "" {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	return cert, true
}

// parseGraphTime accepts either RFC3339 or RFC3339Nano, the two forms Graph is
// observed to return for DateTimeOffset fields.
func parseGraphTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}
	if t2, nerr := time.Parse(time.RFC3339Nano, s); nerr == nil {
		return t2, nil
	}
	return time.Time{}, err
}

// authorityTwin renders one CA as a log record. The timestamp is left zero
// ("now"): this is a re-emitted state snapshot, not an event stream.
//
// Severity is WARN when any of three things is true, and INFO otherwise:
//
//   - the CA is expired or expires within 7 days — the same two buckets
//     entra.credential_expiry treats as actionable, deliberately matched;
//   - the CA's status is anything other than active;
//   - the expiry could not be established at all, or the certificate and the
//     wire disagree about it. In both of those cases graph2otel cannot say when
//     fleet-wide authentication stops, which is the one thing this collector
//     exists to answer.
func authorityTwin(ca *authority, v validity, now time.Time) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityId, ca.ID)
	telemetry.SetStr(attrs, semconv.AttrDisplayName, ca.DisplayName)
	telemetry.SetStr(attrs, semconv.AttrDescription, ca.Description)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityType, ca.Type)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityStatus, ca.Status)
	telemetry.SetStr(attrs, semconv.AttrCertificateRevocationListUrl, ca.CertificateRevocationListURL)
	telemetry.SetStr(attrs, semconv.AttrScepServerUrl, ca.ScepServerURL)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityIssuerId, ca.CertificationAuthorityIssuerID)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityIssuerUri, ca.CertificationAuthorityIssuerURI)
	telemetry.SetStr(attrs, semconv.AttrOcspResponderUri, ca.OcspResponderURI)
	telemetry.SetStr(attrs, semconv.AttrCommonName, ca.CommonName)
	telemetry.SetStr(attrs, semconv.AttrRootCertificateCommonName, ca.RootCertificateCommonName)
	telemetry.SetStr(attrs, semconv.AttrOrganizationName, ca.OrganizationName)
	telemetry.SetStr(attrs, semconv.AttrOrganizationUnit, ca.OrganizationUnit)
	telemetry.SetStr(attrs, semconv.AttrLocalityName, ca.LocalityName)
	telemetry.SetStr(attrs, semconv.AttrStateName, ca.StateName)
	telemetry.SetStr(attrs, semconv.AttrCountryName, ca.CountryName)
	telemetry.SetStr(attrs, semconv.AttrThumbprint, ca.Thumbprint)
	telemetry.SetStr(attrs, semconv.AttrSerialNumber, ca.SerialNumber)
	telemetry.SetStr(attrs, semconv.AttrCertificateKeySize, ca.CertificateKeySize)
	telemetry.SetStr(attrs, semconv.AttrHashingAlgorithm, ca.HashingAlgorithm)
	telemetry.SetStr(attrs, semconv.AttrKeyPlatform, ca.KeyPlatform)
	telemetry.SetStr(attrs, semconv.AttrGeographicRegion, ca.GeographicRegion)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, ca.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, ca.LastModifiedDateTime)
	telemetry.SetStrs(attrs, semconv.AttrRoleScopeTagIds, ca.RoleScopeTagIDs)
	telemetry.SetStrs(attrs, semconv.AttrExtendedKeyUsages, caExtendedKeyUsages(ca.ExtendedKeyUsages))
	if ca.ValidityPeriodInYears > 0 {
		attrs[semconv.AttrValidityPeriodYears] = ca.ValidityPeriodInYears
	}
	if ca.VersionNumber > 0 {
		attrs[semconv.AttrVersionNumber] = ca.VersionNumber
	}

	// The decoded subject and issuer are the authoritative pair; the wire's own
	// subjectName/issuerCommonName stand in only when the certificate could not
	// be parsed.
	subject, issuer := ca.SubjectName, ca.IssuerCommonName
	if cert, ok := parseInlineCertificate(ca.CertificateDownloadURL); ok {
		subject, issuer = cert.Subject.String(), cert.Issuer.String()
	}
	telemetry.SetStr(attrs, semconv.AttrSubjectName, subject)
	telemetry.SetStr(attrs, semconv.AttrIssuerName, issuer)

	bucket := ""
	if !v.end.IsZero() {
		bucket = expiryBucketFor(now, v.end)
		telemetry.SetStr(attrs, semconv.AttrValidFrom, v.from)
		telemetry.SetStr(attrs, semconv.AttrValidTo, v.to)
		telemetry.SetStr(attrs, semconv.AttrExpiryBucket, bucket)
		telemetry.SetStr(attrs, semconv.AttrExpirySource, v.source)
		telemetry.SetStr(attrs, semconv.AttrDeclaredValidTo, v.declaredMismatch)
	}

	severity := telemetry.SeverityInfo
	switch {
	case v.end.IsZero(), v.declaredMismatch != "":
		severity = telemetry.SeverityWarn
	case bucket == bucketExpired, bucket == bucketLt7d:
		severity = telemetry.SeverityWarn
	case ca.Status != "" && ca.Status != statusActive:
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventAuthority,
		Body: fmt.Sprintf("cloud pki authority %s: type=%s status=%s expiry_bucket=%s valid_to=%s",
			caLabel(ca), orUnknown(ca.Type), orUnknown(ca.Status), orUnknown(bucket), orUnknown(v.to)),
		Severity: severity,
		Attrs:    attrs,
	}
}

// leafTwin renders one issued leaf certificate as a log record — the per-device
// half of the signal (#114). Its validity window comes from the wire fields:
// unlike a CA, a leaf record carries no certificate blob to parse.
//
// Severity is WARN only for an ACTIVE certificate that is expired or expires
// within 7 days — the device is about to lose (or has lost) authentication.
// Expired and revoked certificates are routine churn on any tenant with cert
// rotation (61 of m7kni's 69), and warning on them would make the severity
// dimension useless for filtering.
func leafTwin(leaf *leafCertificate, now time.Time) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrLeafCertificateId, leaf.ID)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityId, leaf.IssuerID)
	telemetry.SetStr(attrs, semconv.AttrIssuerName, leaf.IssuerName)
	telemetry.SetStr(attrs, semconv.AttrSubjectName, leaf.SubjectName)
	telemetry.SetStr(attrs, semconv.AttrCertificateStatus, leaf.CertificateStatus)
	telemetry.SetStr(attrs, semconv.AttrValidFrom, leaf.ValidityStartDateTime)
	telemetry.SetStr(attrs, semconv.AttrValidTo, leaf.ValidityEndDateTime)
	telemetry.SetStr(attrs, semconv.AttrRevocationDateTime, leaf.RevocationDateTime)
	telemetry.SetStr(attrs, semconv.AttrCrlDistributionPointUrl, leaf.CrlDistributionPointURL)
	telemetry.SetStr(attrs, semconv.AttrCertificationAuthorityIssuerUri, leaf.CertificationAuthorityIssuerURI)
	telemetry.SetStr(attrs, semconv.AttrOcspResponderUri, leaf.OcspResponderURI)
	telemetry.SetStr(attrs, semconv.AttrThumbprint, leaf.Thumbprint)
	telemetry.SetStr(attrs, semconv.AttrSerialNumber, leaf.SerialNumber)
	telemetry.SetStr(attrs, semconv.AttrDeviceId, leaf.DeviceID)
	telemetry.SetStr(attrs, semconv.AttrDeviceName, leaf.DeviceName)
	telemetry.SetStr(attrs, semconv.AttrDevicePlatform, leaf.DevicePlatform)
	telemetry.SetStr(attrs, semconv.AttrUserId, leaf.UserID)
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, leaf.UserPrincipalName)
	telemetry.SetStrs(attrs, semconv.AttrKeyUsages, leafUsageList(leaf.KeyUsages))
	telemetry.SetStrs(attrs, semconv.AttrExtendedKeyUsages, leafUsageList(leaf.ExtendedKeyUsages))

	bucket := ""
	if end, err := parseGraphTime(leaf.ValidityEndDateTime); err == nil {
		bucket = expiryBucketFor(now, end)
		telemetry.SetStr(attrs, semconv.AttrExpiryBucket, bucket)
	}

	severity := telemetry.SeverityInfo
	if leaf.CertificateStatus == statusActive && (bucket == bucketExpired || bucket == bucketLt7d) {
		severity = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name: eventLeafCertificate,
		Body: fmt.Sprintf("cloud pki leaf certificate %s: status=%s device=%s valid_to=%s",
			orUnknown(leaf.SubjectName), orUnknown(leaf.CertificateStatus), orUnknown(leaf.DeviceName), orUnknown(leaf.ValidityEndDateTime)),
		Severity: severity,
		Attrs:    attrs,
	}
}

// leafUsageList unwraps a leaf's keyUsages/extendedKeyUsages. The live shape is
// a one-element collection whose single element is a JSON-encoded array; an
// element that is not JSON passes through verbatim, so a tenant returning the
// plain shape the EDM promises works too. Any other shape yields nil (attribute
// omitted) rather than failing the row.
func leafUsageList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var elems []string
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil
	}
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		var inner []string
		if err := json.Unmarshal([]byte(e), &inner); err == nil {
			out = append(out, inner...)
			continue
		}
		out = append(out, e)
	}
	return out
}

// caExtendedKeyUsages flattens a CA's extendedKeyUsages — a collection of
// {name, objectIdentifier} objects, NOT the leaf's doubly-encoded strings — to
// the human names. A plain string collection is also accepted, so the two wire
// shapes cannot fail each other's row.
func caExtendedKeyUsages(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var objs []struct {
		Name             string `json:"name"`
		ObjectIdentifier string `json:"objectIdentifier"`
	}
	if err := json.Unmarshal(raw, &objs); err == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.Name != "" {
				out = append(out, o.Name)
				continue
			}
			if o.ObjectIdentifier != "" {
				out = append(out, o.ObjectIdentifier)
			}
		}
		return out
	}
	var strs []string
	if err := json.Unmarshal(raw, &strs); err == nil {
		return strs
	}
	return nil
}

// expiryBucketFor maps an expiry instant to one of the fixed buckets, relative
// to now. The boundaries match entra.credential_expiry's exactly — see the const
// block.
func expiryBucketFor(now, end time.Time) string {
	switch d := end.Sub(now); {
	case d <= 0:
		return bucketExpired
	case d <= windowLt7d:
		return bucketLt7d
	case d <= windowLt30d:
		return bucketLt30d
	case d <= windowLt90d:
		return bucketLt90d
	default:
		return bucketGt90d
	}
}

// caLabel is the CA's gauge dimension and log label: the admin-assigned display
// name, falling back to the id when a CA somehow has none.
func caLabel(ca *authority) string {
	if ca.DisplayName != "" {
		return ca.DisplayName
	}
	return orUnknown(ca.ID)
}

// orUnknown keeps a bounded gauge dimension (and a log body) from ever carrying
// an empty value.
func orUnknown(v string) string {
	if v == "" {
		return unknownValue
	}
	return v
}

// isForbidden reports whether err is a Graph 403 — a graceful skip (missing
// scope, or Cloud PKI unlicensed on this tenant) rather than a failure.
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
