package semconv

// Attribute keys introduced by intune.cloud_pki (#258) — Intune Cloud PKI, the
// private CA hierarchy whose certificates devices use for Wi-Fi, VPN and 802.1X
// authentication. When an issuing CA expires, every device depending on it loses
// authentication at once, with no gradual degradation to notice first.
//
// # What is reused rather than re-coined
//
// The certificate-shaped half of both records already has a key here, so a Cloud
// PKI certificate answers the same filters as an Intune SCEP/PKCS certificate:
//
//	subjectName          -> AttrSubjectName       ("subject_name")
//	issuerName           -> AttrIssuerName        ("issuer_name")
//	thumbprint           -> AttrThumbprint        ("thumbprint")
//	serialNumber         -> AttrSerialNumber      ("serial_number")
//	certificateStatus    -> AttrCertificateStatus ("certificate_status")
//	NotBefore / NotAfter -> AttrValidFrom / AttrValidTo
//	expiry window        -> AttrExpiryBucket      ("expiry_bucket")
//	devicePlatform       -> AttrDevicePlatform    ("device_platform")
//
// AttrValidFrom/AttrValidTo carry the values PARSED OUT OF THE CERTIFICATE, not
// the wire's `validityStartDateTime`/`validityEndDateTime` — see AttrExpirySource
// and AttrDeclaredValidTo below.
//
// The certificate blob itself (`certificateDownloadUrl`, a
// `data:application/x-x509-ca-cert;base64,…` URI) and `certificateSigningRequest`
// are never emitted: the blob is public, not secret, but it is kilobytes of
// base64 that no log query can use, and its only useful content — the validity
// window, subject and issuer — is decoded into the fields above.
const (
	// AttrCertificationAuthorityId is the CA's own id. It is the join key from a
	// leaf-certificate record back to its issuing CA, and it is LOG-ONLY: `id`
	// is on the #112 per-entity deny list for metric labels, so the bounded CA
	// gauges are keyed by display name instead.
	AttrCertificationAuthorityId = "certification_authority_id"
	// AttrCertificationAuthorityType is the wire's `cloudCertificationAuthorityType`
	// — `rootCertificationAuthority` or `issuingCertificationAuthority`. A
	// bounded enum, and a gauge dimension: an expiring ISSUING CA stops new
	// issuance, an expiring ROOT invalidates the whole chain.
	AttrCertificationAuthorityType = "certification_authority_type"
	// AttrCertificationAuthorityStatus is the wire's `certificationAuthorityStatus`
	// (`active`, …) — a bounded enum and a gauge dimension.
	AttrCertificationAuthorityStatus = "certification_authority_status"
	// AttrCertificationAuthorityIssuerId is the parent CA's id on an issuing CA;
	// empty string on a root, where the attribute is omitted.
	AttrCertificationAuthorityIssuerId = "certification_authority_issuer_id"
	// AttrCertificationAuthorityIssuerUri is the AIA URI the parent CA
	// certificate is fetched from. Empty on a root.
	AttrCertificationAuthorityIssuerUri = "certification_authority_issuer_uri"
	// AttrCertificateRevocationListUrl is the CA's published CRL endpoint.
	AttrCertificateRevocationListUrl = "certificate_revocation_list_url"
	// AttrCrlDistributionPointUrl is the leaf certificate's CDP — the CRL a
	// relying party checks that leaf against.
	AttrCrlDistributionPointUrl = "crl_distribution_point_url"
	// AttrOcspResponderUri is the OCSP responder URI. Empty string on every live
	// row, so the attribute is omitted in practice.
	AttrOcspResponderUri = "ocsp_responder_uri"
	// AttrScepServerUrl is the issuing CA's SCEP enrollment endpoint — the thing
	// devices actually talk to. Null on a root CA (roots do not issue to
	// devices), which is what distinguishes the two in practice. The live value
	// contains an unexpanded `{{CloudPKIFQDN}}` template token and is emitted
	// verbatim rather than "corrected" (#142).
	AttrScepServerUrl = "scep_server_url"
	// AttrCertificateKeySize is the wire's `certificateKeySize` enum (`rsa4096`).
	AttrCertificateKeySize = "certificate_key_size"
	// AttrHashingAlgorithm is the wire's `cloudCertificationAuthorityHashingAlgorithm`
	// (`sha512`).
	AttrHashingAlgorithm = "hashing_algorithm"
	// AttrKeyPlatform is where the CA's private key lives — `hardwareSecurityModule`
	// on the live tenant. A software-backed key is a materially weaker CA.
	AttrKeyPlatform = "key_platform"
	// AttrGeographicRegion is the region the CA is hosted in (`Europe`).
	AttrGeographicRegion = "geographic_region"
	// AttrCommonName is the CA subject's CN component, as the wire reports it.
	AttrCommonName = "common_name"
	// AttrRootCertificateCommonName is the CN of the root at the top of this
	// CA's chain. Null on a root itself.
	AttrRootCertificateCommonName = "root_certificate_common_name"
	// AttrOrganizationName is the CA subject's O component.
	AttrOrganizationName = "organization_name"
	// AttrOrganizationUnit is the CA subject's OU component.
	AttrOrganizationUnit = "organization_unit"
	// AttrLocalityName is the CA subject's L component.
	AttrLocalityName = "locality_name"
	// AttrStateName is the CA subject's ST component.
	AttrStateName = "state_name"
	// AttrCountryName is the CA subject's C component.
	AttrCountryName = "country_name"
	// AttrValidityPeriodYears is the wire's `validityPeriodInYears` — the CA's
	// configured lifetime (25 for the live root, 10 for its issuer).
	AttrValidityPeriodYears = "validity_period_years"
	// AttrVersionNumber is the CA's current version number. A CA is re-versioned
	// when it is renewed, so a version bump is a renewal event.
	AttrVersionNumber = "version_number"

	// AttrExpirySource records WHERE the emitted validity window came from:
	// `certificate` when it was parsed out of the inline DER (the normal path,
	// and the authoritative one — it is the certificate devices actually
	// validate), or `declared` when the certificate could not be parsed and the
	// wire's own `validityEndDateTime` was used instead. Without this key a
	// degraded reading is indistinguishable from a measured one.
	AttrExpirySource = "expiry_source"
	// AttrDeclaredValidTo is the wire's `validityEndDateTime`, and it is emitted
	// ONLY when it disagrees with the certificate's own NotAfter. They agree on
	// every live row, so the attribute's PRESENCE is the anomaly: Graph and the
	// certificate it handed over do not say the same thing about when fleet-wide
	// authentication stops working.
	AttrDeclaredValidTo = "declared_valid_to"

	// AttrLeafCertificateId is a leaf certificate's own id.
	AttrLeafCertificateId = "leaf_certificate_id"
	// AttrRevocationDateTime is when a leaf certificate was revoked. Null on
	// active and expired certificates, where the attribute is omitted — so its
	// presence distinguishes a revoked certificate from a lapsed one.
	AttrRevocationDateTime = "revocation_date_time"
	// AttrKeyUsages is the leaf certificate's X.509 key-usage list
	// (`KeyEncipherment`, `DigitalSignature`).
	//
	// Wire trap: Graph types this as `Collection(Edm.String)` and returns a
	// ONE-element collection whose single element is a JSON-encoded array
	// (`["[\"KeyEncipherment\",\"DigitalSignature\"]"]`). The mapper unwraps
	// that; emitting it raw would put a quoted JSON blob in a list attribute.
	AttrKeyUsages = "key_usages"
	// AttrExtendedKeyUsages is the extended key usage list. On a LEAF it is the
	// same doubly-encoded shape as AttrKeyUsages and carries raw OIDs
	// (`1.3.6.1.5.5.7.3.2`). On a CA the same-named wire field is a collection of
	// `{name, objectIdentifier}` OBJECTS instead, and the human `name` is what is
	// emitted — two different wire shapes behind one attribute name, both
	// normalized to a list of strings here.
	AttrExtendedKeyUsages = "extended_key_usages"
)
