package cloudpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	seen   []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.seen = append(f.seen, url)
	if err := f.errs[url]; err != nil {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	rootCAID   = "a29d1328-90ea-4400-a53f-195f870b1444"
	issuerCAID = "f8fe84ba-f536-4e83-baba-4f035037a8f2"
)

func authoritiesURL() string { return defaultBaseURL + authoritiesPath }
func leavesURL(caID string) string {
	return defaultBaseURL + authoritiesPath + "/" + caID + leafCertificatesSegment
}

// liveRootCertificateURI is the root CA's certificateDownloadUrl copied VERBATIM
// off the beta wire (probed as graph2otel-poller on m7kni 2026-07-24). Decoding
// it yields CN=m7kni.io,O=m7kni,OU=home,L=Fair Oak,ST=Hampshire,C=GB valid
// 2025-10-07 → 2050-10-07 — a quarter century out, which is exactly why the
// alerting path needs a second fixture (see nearTermCertificateURI).
const liveRootCertificateURI = "data:application/x-x509-ca-cert;base64,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"

// nearTermCertificate mints a real DER certificate expiring `in` from now and
// returns it wrapped in the same data: URI shape the wire uses.
//
// This exists because m7kni's real CAs expire in 2050 and 2035, so live data can
// never exercise the alerting path — the "a green tick is not evidence of data"
// case. It is a genuine certificate parsed by the same crypto/x509 path as the
// live one, not a hand-written stand-in for the parse result, and its expiry is
// relative to the clock so it cannot rot into a passing-by-accident fixture.
func nearTermCertificate(t *testing.T, in time.Duration) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "expiring.m7kni.io",
			Organization: []string{"m7kni"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(in),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return dataURIPrefix + base64.StdEncoding.EncodeToString(der)
}

// liveRootRow is the root CA row, verbatim off the beta wire apart from the
// certificate blob, which is spliced in so the fixture stays readable. Note
// scepServerUrl and issuerCommonName are null on a root, ocspResponderUri and
// certificationAuthorityIssuerId are EMPTY STRINGS rather than null, and the
// extendedKeyUsages collection is a list of {name, objectIdentifier} OBJECTS.
func liveRootRow() string {
	return `{"id":"` + rootCAID + `","displayName":"root-m7kni","description":null,"scepServerUrl":null,` +
		`"certificateRevocationListUrl":"http://primary-cdn.pki.azure.net/westeurope/crls/ef5e7be8c27046cf8f9a99d0a90a0e64/` + rootCAID + `_v1/current.crl",` +
		`"certificateDownloadUrl":"` + liveRootCertificateURI + `",` +
		`"certificationAuthorityIssuerUri":"","ocspResponderUri":"","certificationAuthorityStatus":"active","eTag":null,` +
		`"lastModifiedDateTime":"2026-04-27T19:41:21Z","roleScopeTagIds":["0"],"createdDateTime":"2025-10-07T10:00:33.6864512Z",` +
		`"certificationAuthorityIssuerId":"","issuerCommonName":null,"cloudCertificationAuthorityType":"rootCertificationAuthority",` +
		`"validityPeriodInYears":25,"validityStartDateTime":"2025-10-07T10:00:29Z","validityEndDateTime":"2050-10-07T10:00:29Z",` +
		`"organizationName":"m7kni","organizationUnit":"home","countryName":"GB","stateName":"Hampshire","localityName":"Fair Oak",` +
		`"certificateKeySize":"rsa4096","cloudCertificationAuthorityHashingAlgorithm":"sha512",` +
		`"thumbprint":"D09052E6EE6A3369618B2E122DC7F30B4AE8C7F1","serialNumber":"00E41047B8BEB59525309D364FED8F1C68",` +
		`"subjectName":"C=GB,ST=Hampshire,L=Fair Oak,O=m7kni,OU=home,CN=m7kni.io","commonName":"m7kni.io",` +
		`"certificateSigningRequest":null,"versionNumber":1,"rootCertificateCommonName":null,` +
		`"keyPlatform":"hardwareSecurityModule","geographicRegion":"Europe",` +
		`"extendedKeyUsages":[{"name":"Server auth","objectIdentifier":"1.3.6.1.5.5.7.3.1"},{"name":"Client auth","objectIdentifier":"1.3.6.1.5.5.7.3.2"}],` +
		`"activeVersion":{"id":"` + rootCAID + `_1","versionNumber":1,"usage":{"issuedStagedLeafCertificateCount":0}}}`
}

// expiringIssuerRow is the issuing CA, live in every respect except that its
// certificate is the near-term one. m7kni's real issuer expires in 2035.
func expiringIssuerRow(certURI string) string {
	return `{"id":"` + issuerCAID + `","displayName":"issuer-m7kni","description":null,` +
		`"scepServerUrl":"https://{{CloudPKIFQDN}}/TrafficGateway/PassThroughRoutingService/CloudPki/CloudPkiService/Scep/e933bb26",` +
		`"certificateRevocationListUrl":"http://primary-cdn.pki.azure.net/westeurope/crls/ef5e/` + issuerCAID + `_v1/current.crl",` +
		`"certificateDownloadUrl":"` + certURI + `",` +
		`"certificationAuthorityIssuerUri":"http://primary-cdn.pki.azure.net/westeurope/cacerts/ef5e/` + rootCAID + `_v1/cert.cer",` +
		`"ocspResponderUri":"","certificationAuthorityStatus":"active","lastModifiedDateTime":"2026-04-27T19:41:21Z",` +
		`"roleScopeTagIds":["0"],"createdDateTime":"2025-10-07T10:04:50.4723236Z",` +
		`"certificationAuthorityIssuerId":"` + rootCAID + `","issuerCommonName":"m7kni.io",` +
		`"cloudCertificationAuthorityType":"issuingCertificationAuthority","validityPeriodInYears":10,` +
		`"validityStartDateTime":"2025-10-07T10:04:44Z","validityEndDateTime":"2035-10-07T10:04:44Z",` +
		`"organizationName":"m7kni","organizationUnit":"home","countryName":"GB","stateName":"Hampshire","localityName":"Fair Oak",` +
		`"certificateKeySize":"rsa4096","cloudCertificationAuthorityHashingAlgorithm":"sha512",` +
		`"thumbprint":"1CEFBC1738FDFBF1DB588B30E173D8990B06F296","serialNumber":"293DDAD21CB4E2A94F67377327C69FE9",` +
		`"subjectName":"C=GB,ST=Hampshire,L=Fair Oak,O=m7kni,OU=home,CN=m7kni.io","commonName":"m7kni.io",` +
		`"versionNumber":1,"rootCertificateCommonName":"m7kni.io","keyPlatform":"hardwareSecurityModule",` +
		`"geographicRegion":"Europe","extendedKeyUsages":[{"name":"Client auth","objectIdentifier":"1.3.6.1.5.5.7.3.2"}]}`
}

// liveLeafRows are three of the 69 leaf certificates the issuing CA has issued
// (live-measured 2026-07-24: 8 active / 43 expired / 18 revoked). Note keyUsages
// and extendedKeyUsages are ONE-element collections whose single element is a
// JSON-encoded array — the doubly-encoded wire trap — and that devicePlatform is
// null and certificationAuthorityVersionNumber is 0 on every row.
const liveLeafRows = `
 {"id":"ab8f4122-1ec0-4ec7-8bd8-ef96418d4ec7","subjectName":"CN=TampooniPad","issuerId":"f8fe84ba-f536-4e83-baba-4f035037a8f2","issuerName":"CN=m7kni.io, O=m7kni, OU=home, L=Fair Oak, S=Hampshire, C=GB","certificateStatus":"active","validityStartDateTime":"2026-07-20T13:52:25Z","validityEndDateTime":"2027-07-20T14:02:25Z","crlDistributionPointUrl":"http://primary-cdn.pki.azure.net/westeurope/crls/ef5e/f8fe84ba_v1/current.crl","certificationAuthorityIssuerUri":"https://ef5e.westeurope.pki.azure.net/certificateAuthorities/f8fe84ba_v1","ocspResponderUri":"","thumbprint":"9D6D324DF4AC8FB3C7FC40787981F72484D92B94","serialNumber":"00D0C5972F7D6EDBAF1DE7F9CA395E7AE5","revocationDateTime":null,"deviceName":"TampooniPad","userPrincipalName":"rob@m7kni.io","deviceId":"2af9ec65-db9b-455c-8b3a-7a2691958b88","userId":"bbcfc3c5-0b93-4135-9ef9-18477a9fb504","devicePlatform":null,"keyUsages":["[\"KeyEncipherment\",\"DigitalSignature\"]"],"extendedKeyUsages":["[\"1.3.6.1.5.5.7.3.2\"]"],"certificationAuthorityVersionNumber":0},
 {"id":"ca55e765-2e71-4c4b-a44d-37e4a2dc2317","subjectName":"CN=bcfff2e0-4b53-49cf-8b82-4e2e8f79d6f3","issuerId":"f8fe84ba-f536-4e83-baba-4f035037a8f2","issuerName":"CN=m7kni.io, O=m7kni, OU=home, L=Fair Oak, S=Hampshire, C=GB","certificateStatus":"revoked","validityStartDateTime":"2025-10-07T10:21:57Z","validityEndDateTime":"2025-11-07T10:31:57Z","crlDistributionPointUrl":"http://primary-cdn.pki.azure.net/westeurope/crls/ef5e/f8fe84ba_v1/current.crl","certificationAuthorityIssuerUri":"https://ef5e.westeurope.pki.azure.net/certificateAuthorities/f8fe84ba_v1","ocspResponderUri":"","thumbprint":"E48748A4FBDA039FA36CA41C3490466FAC61A008","serialNumber":"00AA26EFD505628252115A9A4FDF30592B","revocationDateTime":"2025-10-07T10:41:03Z","deviceName":"Tampooni","userPrincipalName":"rob@m7kni.io","deviceId":"3c1ff69c-ab91-46c7-ae0f-ef53988e92c0","userId":"bbcfc3c5-0b93-4135-9ef9-18477a9fb504","devicePlatform":null,"keyUsages":["[\"KeyEncipherment\",\"DigitalSignature\"]"],"extendedKeyUsages":["[\"1.3.6.1.5.5.7.3.2\",\"1.3.6.1.5.5.7.3.4\"]"],"certificationAuthorityVersionNumber":0},
 {"id":"396e1ccc-7c1d-4d34-afe2-b847563b822e","subjectName":"CN=c5328a21-6e37-448f-8fcb-5f717dfdf980","issuerId":"f8fe84ba-f536-4e83-baba-4f035037a8f2","issuerName":"CN=m7kni.io, O=m7kni, OU=home, L=Fair Oak, S=Hampshire, C=GB","certificateStatus":"expired","validityStartDateTime":"2025-10-07T10:25:55Z","validityEndDateTime":"2025-10-21T10:35:55Z","crlDistributionPointUrl":"http://primary-cdn.pki.azure.net/westeurope/crls/ef5e/f8fe84ba_v1/current.crl","certificationAuthorityIssuerUri":"https://ef5e.westeurope.pki.azure.net/certificateAuthorities/f8fe84ba_v1","ocspResponderUri":"","thumbprint":"AAAA748A4FBDA039FA36CA41C3490466FAC61A00","serialNumber":"00BB26EFD505628252115A9A4FDF30592B","revocationDateTime":null,"deviceName":"Tampooni","userPrincipalName":"rob@m7kni.io","deviceId":"3c1ff69c-ab91-46c7-ae0f-ef53988e92c0","userId":"bbcfc3c5-0b93-4135-9ef9-18477a9fb504","devicePlatform":null,"keyUsages":["[\"KeyEncipherment\",\"DigitalSignature\"]"],"extendedKeyUsages":["[\"1.3.6.1.5.5.7.3.2\"]"],"certificationAuthorityVersionNumber":0}`

func liveGraph(t *testing.T, issuerExpiresIn time.Duration) *fakeGraph {
	t.Helper()
	return &fakeGraph{bodies: map[string]string{
		authoritiesURL():      `{"value":[` + liveRootRow() + `,` + expiringIssuerRow(nearTermCertificate(t, issuerExpiresIn)) + `]}`,
		leavesURL(rootCAID):   `{"value":[]}`,
		leavesURL(issuerCAID): `{"value":[` + liveLeafRows + `]}`,
	}}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func twinFor(t *testing.T, rec *telemetrytest.Recorder, event, key, want string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.EventName == event && l.Attrs[key] == want {
			return l
		}
	}
	t.Fatalf("no %s twin with %s=%q", event, key, want)
	return telemetrytest.LogRecord{}
}

func pointFor(t *testing.T, rec *telemetrytest.Recorder, metric, key, want string) telemetrytest.MetricPoint {
	t.Helper()
	for _, p := range rec.MetricPoints(metric) {
		if p.Attrs[key] == want {
			return p
		}
	}
	t.Fatalf("no %s point with %s=%q (%+v)", metric, key, want, rec.MetricPoints(metric))
	return telemetrytest.MetricPoint{}
}

// The live root's certificate says 2050, and the days-until-expiry gauge is
// derived from the CERTIFICATE, not from the wire's validityEndDateTime.
func TestExpiryIsParsedOutOfTheInlineCertificate(t *testing.T) {
	rec := collect(t, liveGraph(t, 3*24*time.Hour))

	p := pointFor(t, rec, daysUntilExpiryMetricName, semconv.AttrDisplayName, "root-m7kni")
	// 2050-10-07 is well over 8000 days out and, for as long as this project
	// exists, never fewer than 7000.
	if p.Value < 7000 {
		t.Errorf("root days_until_expiry = %v, want the certificate's 2050 NotAfter", p.Value)
	}
	if p.Unit != "d" {
		t.Errorf("unit = %q, want d", p.Unit)
	}
	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, rootCAID)
	if got := tw.Attrs[semconv.AttrValidTo]; got != "2050-10-07T10:00:29Z" {
		t.Errorf("valid_to = %q, want the certificate's NotAfter", got)
	}
	if got := tw.Attrs[semconv.AttrValidFrom]; got != "2025-10-07T10:00:29Z" {
		t.Errorf("valid_from = %q, want the certificate's NotBefore", got)
	}
	if got := tw.Attrs[semconv.AttrExpirySource]; got != expirySourceCertificate {
		t.Errorf("expiry_source = %q, want %q", got, expirySourceCertificate)
	}
	if got := tw.Attrs[semconv.AttrSubjectName]; got != "CN=m7kni.io,OU=home,O=m7kni,L=Fair Oak,ST=Hampshire,C=GB" {
		t.Errorf("subject_name = %q, want the DECODED subject", got)
	}
	if got := tw.Attrs[semconv.AttrIssuerName]; got != "CN=m7kni.io,OU=home,O=m7kni,L=Fair Oak,ST=Hampshire,C=GB" {
		t.Errorf("issuer_name = %q, want the DECODED issuer (self-signed root)", got)
	}
	if tw.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO for a CA expiring in 2050", tw.SeverityText)
	}
	// The blob itself is never emitted.
	for k, v := range tw.Attrs {
		if len(v) > 512 {
			t.Errorf("attribute %q is %d bytes — the certificate blob must never be emitted", k, len(v))
		}
	}
}

// m7kni's CAs expire in 2050 and 2035, so without this fixture the alerting path
// would never run: the collector would sit green forever and a broken severity
// ladder would be invisible (the green-tick rule).
func TestNearTermExpiryWarnsAndBuckets(t *testing.T) {
	rec := collect(t, liveGraph(t, 3*24*time.Hour))

	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, issuerCAID)
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN — the issuing CA expires in 3 days", tw.SeverityText)
	}
	if got := tw.Attrs[semconv.AttrExpiryBucket]; got != bucketLt7d {
		t.Errorf("expiry_bucket = %q, want %q", got, bucketLt7d)
	}
	// The wire says 2035; the certificate says 3 days. The certificate wins, and
	// the disagreement is surfaced rather than silently discarded.
	if got := tw.Attrs[semconv.AttrDeclaredValidTo]; got != "2035-10-07T10:04:44Z" {
		t.Errorf("declared_valid_to = %q, want the disagreeing wire value", got)
	}
	p := pointFor(t, rec, daysUntilExpiryMetricName, semconv.AttrDisplayName, "issuer-m7kni")
	if p.Value < 2 || p.Value > 4 {
		t.Errorf("issuer days_until_expiry = %v, want ~3", p.Value)
	}
}

func TestExpiredCertificateWarnsWithNegativeDays(t *testing.T) {
	rec := collect(t, liveGraph(t, -48*time.Hour))

	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, issuerCAID)
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN", tw.SeverityText)
	}
	if got := tw.Attrs[semconv.AttrExpiryBucket]; got != bucketExpired {
		t.Errorf("expiry_bucket = %q, want %q", got, bucketExpired)
	}
	p := pointFor(t, rec, daysUntilExpiryMetricName, semconv.AttrDisplayName, "issuer-m7kni")
	if p.Value >= 0 {
		t.Errorf("days_until_expiry = %v, want negative once expired", p.Value)
	}
}

// A certificate that cannot be parsed degrades to the wire's own
// validityEndDateTime, and says so — a degraded reading must never be
// indistinguishable from a measured one.
func TestUnparseableCertificateFallsBackAndLabelsTheSource(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		authoritiesURL():    `{"value":[` + expiringIssuerRow("data:application/x-x509-ca-cert;base64,bm90LWEtY2VydA==") + `]}`,
		leavesURL(rootCAID): `{"value":[]}`,
	}}
	g.bodies[leavesURL(issuerCAID)] = `{"value":[]}`
	rec := collect(t, g)

	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, issuerCAID)
	if got := tw.Attrs[semconv.AttrExpirySource]; got != expirySourceDeclared {
		t.Errorf("expiry_source = %q, want %q", got, expirySourceDeclared)
	}
	if got := tw.Attrs[semconv.AttrValidTo]; got != "2035-10-07T10:04:44Z" {
		t.Errorf("valid_to = %q, want the wire's declared value", got)
	}
	if _, ok := tw.Attrs[semconv.AttrDeclaredValidTo]; ok {
		t.Error("declared_valid_to must be absent when it IS the source, not a disagreeing second opinion")
	}
	// The parsed subject is unavailable, so the wire's own subjectName is used.
	if got := tw.Attrs[semconv.AttrSubjectName]; got != "C=GB,ST=Hampshire,L=Fair Oak,O=m7kni,OU=home,CN=m7kni.io" {
		t.Errorf("subject_name = %q, want the wire fallback", got)
	}
}

// With no certificate and no declared date there is no honest expiry to report:
// the gauge point is omitted rather than fabricated, and the twin still emits
// (the entity is never dropped, #114) carrying a WARN because the fleet's
// authentication horizon is unknown.
func TestUnknownExpiryEmitsNoPointButStillTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		authoritiesURL(): `{"value":[{"id":"` + issuerCAID + `","displayName":"issuer-m7kni","cloudCertificationAuthorityType":"issuingCertificationAuthority","certificationAuthorityStatus":"active"}]}`,
	}}
	g.bodies[leavesURL(issuerCAID)] = `{"value":[]}`
	rec := collect(t, g)

	if n := len(rec.MetricPoints(daysUntilExpiryMetricName)); n != 0 {
		t.Errorf("got %d expiry points, want none — an unknown expiry must not be fabricated", n)
	}
	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, issuerCAID)
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN when the expiry cannot be established", tw.SeverityText)
	}
	for _, k := range []string{semconv.AttrValidTo, semconv.AttrExpiryBucket, semconv.AttrExpirySource} {
		if _, ok := tw.Attrs[k]; ok {
			t.Errorf("attribute %q present with no expiry to report: %q", k, tw.Attrs[k])
		}
	}
	if n := len(rec.MetricPoints(authoritiesMetricName)); n != 1 {
		t.Errorf("got %d authority-count points, want 1 — the CA still exists", n)
	}
}

func TestAuthorityGaugeIsBoundedByTypeAndStatus(t *testing.T) {
	rec := collect(t, liveGraph(t, 90*24*time.Hour))

	points := rec.MetricPoints(authoritiesMetricName)
	want := map[[2]string]float64{
		{"rootCertificationAuthority", "active"}:    1,
		{"issuingCertificationAuthority", "active"}: 1,
	}
	if len(points) != len(want) {
		t.Fatalf("got %d authority series, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		key := [2]string{p.Attrs[semconv.AttrCertificationAuthorityType], p.Attrs[semconv.AttrCertificationAuthorityStatus]}
		if p.Value != want[key] {
			t.Errorf("series %v = %v, want %v", key, p.Value, want[key])
		}
		if len(p.Attrs) != 2 {
			t.Errorf("authority series carries extra labels %+v", p.Attrs)
		}
	}
}

func TestLeafCertificateGaugeCountsByStatus(t *testing.T) {
	rec := collect(t, liveGraph(t, 90*24*time.Hour))

	want := map[string]float64{"active": 1, "revoked": 1, "expired": 1}
	points := rec.MetricPoints(leafCertificatesMetricName)
	if len(points) != 3 {
		t.Fatalf("got %d leaf series, want 3: %+v", len(points), points)
	}
	for _, p := range points {
		if p.Attrs[semconv.AttrDisplayName] != "issuer-m7kni" {
			t.Errorf("leaf series display_name = %q, want the ISSUING CA", p.Attrs[semconv.AttrDisplayName])
		}
		if got := want[p.Attrs[semconv.AttrCertificateStatus]]; p.Value != got {
			t.Errorf("leaf series %+v = %v, want %v", p.Attrs, p.Value, got)
		}
	}
}

// keyUsages/extendedKeyUsages arrive as a ONE-element collection whose single
// element is a JSON-encoded array. Emitting that raw would put a quoted JSON
// blob in a list attribute.
func TestLeafTwinUnwrapsDoublyEncodedUsageLists(t *testing.T) {
	rec := collect(t, liveGraph(t, 90*24*time.Hour))

	tw := twinFor(t, rec, eventLeafCertificate, semconv.AttrLeafCertificateId, "ca55e765-2e71-4c4b-a44d-37e4a2dc2317")
	if got := tw.Attrs[semconv.AttrKeyUsages]; got != "KeyEncipherment,DigitalSignature" {
		t.Errorf("key_usages = %q, want the unwrapped list", got)
	}
	if got := tw.Attrs[semconv.AttrExtendedKeyUsages]; got != "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4" {
		t.Errorf("extended_key_usages = %q, want the unwrapped list", got)
	}
	if got := tw.Attrs[semconv.AttrRevocationDateTime]; got != "2025-10-07T10:41:03Z" {
		t.Errorf("revocation_date_time = %q", got)
	}
	if got := tw.Attrs[semconv.AttrDeviceName]; got != "Tampooni" {
		t.Errorf("device_name = %q", got)
	}
	if got := tw.Attrs[semconv.AttrUserPrincipalName]; got != "rob@m7kni.io" {
		t.Errorf("user_principal_name = %q", got)
	}
	if _, ok := tw.Attrs[semconv.AttrDevicePlatform]; ok {
		t.Errorf("device_platform present for a null wire value: %q", tw.Attrs[semconv.AttrDevicePlatform])
	}
	if tw.SeverityText != "INFO" {
		t.Errorf("revoked leaf severity = %q, want INFO — revocation is routine churn", tw.SeverityText)
	}
}

// The CA's extendedKeyUsages is a collection of OBJECTS, not the leaf's
// doubly-encoded strings — one attribute name, two wire shapes.
func TestAuthorityTwinFlattensObjectShapedExtendedKeyUsages(t *testing.T) {
	rec := collect(t, liveGraph(t, 90*24*time.Hour))

	tw := twinFor(t, rec, eventAuthority, semconv.AttrCertificationAuthorityId, rootCAID)
	if got := tw.Attrs[semconv.AttrExtendedKeyUsages]; got != "Server auth,Client auth" {
		t.Errorf("extended_key_usages = %q, want the object names", got)
	}
	if got := tw.Attrs[semconv.AttrKeyPlatform]; got != "hardwareSecurityModule" {
		t.Errorf("key_platform = %q", got)
	}
	if got := tw.Attrs[semconv.AttrValidityPeriodYears]; got != "25" {
		t.Errorf("validity_period_years = %q", got)
	}
	if got := tw.Attrs[semconv.AttrCertificateRevocationListUrl]; got == "" {
		t.Error("certificate_revocation_list_url missing")
	}
	// Empty-string wire values are omitted, not stamped blank.
	for _, k := range []string{semconv.AttrOcspResponderUri, semconv.AttrCertificationAuthorityIssuerId, semconv.AttrScepServerUrl, semconv.AttrDescription, semconv.AttrRootCertificateCommonName} {
		if _, ok := tw.Attrs[k]; ok {
			t.Errorf("attribute %q present for an empty/null wire value on the ROOT: %q", k, tw.Attrs[k])
		}
	}
}

// An active leaf certificate about to lapse is the per-device half of the
// signal: that device loses Wi-Fi/VPN authentication when it does.
func TestActiveLeafExpiringSoonWarns(t *testing.T) {
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	g := &fakeGraph{bodies: map[string]string{
		authoritiesURL():    `{"value":[` + liveRootRow() + `]}`,
		leavesURL(rootCAID): `{"value":[{"id":"leaf1","subjectName":"CN=lapsing","certificateStatus":"active","validityEndDateTime":"` + soon + `","deviceName":"wintest","issuerId":"` + rootCAID + `"}]}`,
	}}
	rec := collect(t, g)

	tw := twinFor(t, rec, eventLeafCertificate, semconv.AttrLeafCertificateId, "leaf1")
	if tw.SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN — an ACTIVE certificate expiring in 2 days", tw.SeverityText)
	}
	if got := tw.Attrs[semconv.AttrExpiryBucket]; got != bucketLt7d {
		t.Errorf("expiry_bucket = %q, want %q", got, bucketLt7d)
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard.
// display_name IS a legitimate gauge dimension here — it is admin-assigned and
// bounded by the tenant's CA count (2 on m7kni), not by user or device count —
// while every certificate and device identifier rides the twins.
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph(t, 90*24*time.Hour))

	banned := map[string]bool{
		semconv.AttrCertificationAuthorityId: true,
		semconv.AttrLeafCertificateId:        true,
		semconv.AttrThumbprint:               true,
		semconv.AttrSerialNumber:             true,
		semconv.AttrSubjectName:              true,
		semconv.AttrDeviceId:                 true,
		semconv.AttrDeviceName:               true,
		semconv.AttrUserPrincipalName:        true,
		semconv.AttrUserId:                   true,
		semconv.AttrValidTo:                  true,
	}
	allowed := map[string]bool{
		semconv.AttrDisplayName:                  true,
		semconv.AttrCertificationAuthorityType:   true,
		semconv.AttrCertificationAuthorityStatus: true,
		semconv.AttrCertificateStatus:            true,
	}
	for _, name := range []string{authoritiesMetricName, daysUntilExpiryMetricName, leafCertificatesMetricName} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if banned[k] {
					t.Errorf("%s carries per-entity metric label %q — it belongs on a twin (#112/#114)", name, k)
				}
				if !allowed[k] {
					t.Errorf("%s carries unexpected metric label %q", name, k)
				}
			}
		}
	}
}

// The leaf fan-out is one request per CA, bounded by the CA count.
func TestLeafFanOutIsOnePerAuthority(t *testing.T) {
	g := liveGraph(t, 90*24*time.Hour)
	collect(t, g)

	want := map[string]bool{leavesURL(rootCAID): true, leavesURL(issuerCAID): true}
	for _, u := range g.seen {
		delete(want, u)
	}
	if len(want) != 0 {
		t.Errorf("missing leaf requests: %v (saw %v)", want, g.seen)
	}
	if len(g.seen) != 3 {
		t.Errorf("issued %d requests, want 1 list + 2 leaf fetches: %v", len(g.seen), g.seen)
	}
}

// A leaf fetch that fails must not take the CA gauges down with it — the CA
// expiry signal is the more important half and does not depend on it.
func TestLeafFetchFailureDoesNotDropAuthorities(t *testing.T) {
	g := liveGraph(t, 90*24*time.Hour)
	g.errs = map[string]error{leavesURL(issuerCAID): errors.New("boom")}
	rec := collect(t, g)

	if n := len(rec.MetricPoints(authoritiesMetricName)); n != 2 {
		t.Errorf("got %d authority series, want 2 despite the leaf failure", n)
	}
	if n := len(rec.MetricPoints(leafCertificatesMetricName)); n != 0 {
		t.Errorf("got %d leaf series, want none — a failed fetch must not report a false zero", n)
	}
}

func TestForbiddenSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{authoritiesURL(): errors.New("graphclient: GET ...: status 403: forbidden")}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on 403")
	}
}

func TestListErrorIsSurfaced(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{authoritiesURL(): errors.New("boom")}}
	if err := New(g, nil).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Error("a non-403 list error must be surfaced")
	}
}

func TestEmptyTenantEmitsNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{authoritiesURL(): `{"value":[]}`}}
	rec := collect(t, g)
	if len(rec.LogRecords()) != 0 {
		t.Error("no CAs => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "intune.cloud_pki" {
		t.Errorf("Name() = %q, want intune.cloud_pki", c.Name())
	}
	// v1.0 has no cloudCertificationAuthority segment (400, live-measured
	// 2026-07-24) — beta base URL, so Experimental (#183).
	if defaultBaseURL != "https://graph.microsoft.com/beta" {
		t.Errorf("defaultBaseURL = %q, want the beta root", defaultBaseURL)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementCloudCA.Read.All" {
		t.Errorf("RequiredPermissions = %v, want the single read-only Cloud CA scope", perms)
	}
	if c.DefaultInterval() != 12*time.Hour {
		t.Errorf("DefaultInterval = %v, want 12h", c.DefaultInterval())
	}
}

// The bucket boundaries deliberately match entra.credential_expiry's, so the two
// expiry signals agree about what "expiring soon" means.
func TestExpiryBucketBoundariesMatchCredentialExpiry(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   time.Duration
		want string
	}{
		{-time.Hour, bucketExpired},
		{0, bucketExpired},
		{6 * 24 * time.Hour, bucketLt7d},
		{7 * 24 * time.Hour, bucketLt7d},
		{8 * 24 * time.Hour, "lt_30d"},
		{30 * 24 * time.Hour, "lt_30d"},
		{31 * 24 * time.Hour, "lt_90d"},
		{90 * 24 * time.Hour, "lt_90d"},
		{91 * 24 * time.Hour, "gt_90d"},
	}
	for _, tc := range tests {
		if got := expiryBucketFor(now, now.Add(tc.in)); got != tc.want {
			t.Errorf("expiryBucketFor(+%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
