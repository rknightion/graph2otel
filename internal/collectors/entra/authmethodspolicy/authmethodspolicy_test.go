package authmethodspolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph returns a canned body (or error) for a single URL, mirroring the
// directorycounts test style but for a single-object endpoint rather than a
// $count segment.
type fakeGraph struct {
	body string
	err  error
}

func (f *fakeGraph) RawGet(_ context.Context, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.body), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// livePolicy is a VERBATIM GET /policies/authenticationMethodsPolicy response
// (v1.0 tenant-wide singleton; no pagination or delta query) captured from the
// m7kni tenant, read as graph2otel-poller on 2026-07-17
// `[live-measured 2026-07-17, #165]`. It replaces a docs-derived fixture that
// invented a HardwareOath configuration the live tenant never returns and a
// synthetic "external" custom-GUID method this tenant does not have.
//
// authenticationMethodConfigurations is trimmed to representative WHOLE elements
// (kept entries are byte-verbatim, incl. their @odata.type and nested config)
// preserving the variety the collector must handle: enabled built-ins (Fido2,
// MicrosoftAuthenticator, Sms), a disabled legacy method (Voice), a disabled
// non-legacy built-in (X509Certificate), and two built-in types the collector's
// catalog does not track (VerifiableCredentials, QRCodePin) that must be skipped
// rather than emitted. The collector keys on each entry's `id` and reads
// `state`; the @odata.type discriminator is retained for fidelity though this
// collector does not read it.
const livePolicy = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
  "authenticationMethodConfigurations": [
    {
      "@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration",
      "defaultPasskeyProfile": "00000000-0000-0000-0000-000000000001",
      "excludeTargets": [],
      "id": "Fido2",
      "includeTargets": [
        {
          "allowedPasskeyProfiles": [
            "00000000-0000-0000-0000-000000000001",
            "e47a833c-5dfa-45f1-9471-bb0cf0eb425b"
          ],
          "id": "all_users",
          "isRegistrationRequired": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')/microsoft.graph.fido2AuthenticationMethodConfiguration/includeTargets",
      "isAttestationEnforced": true,
      "isSelfServiceRegistrationAllowed": true,
      "keyRestrictions": {
        "aaGuids": [
          "90a3ccdf-635c-4729-a248-9b709135078f",
          "de1e552d-db1d-4423-a619-566b625cdc84",
          "2fc0579f-8113-47ea-b116-bb5a8db9202a",
          "a25342c0-3cdc-4414-8e46-f4807fca511c",
          "d7781e5d-e353-46aa-afe2-3ca49f13332a",
          "662ef48a-95e2-4aaa-a6c1-5b9c40375824",
          "cb69481e-8ff7-4039-93ec-0a2729a154a8",
          "ee882879-721c-4913-9775-3dfcce97072a",
          "662ef48a-95e2-4aaa-a6c1-5b9c40375824"
        ],
        "enforcementType": "allow",
        "isEnforced": true
      },
      "passkeyProfiles": [
        {
          "attestationEnforcement": "registrationOnly",
          "id": "00000000-0000-0000-0000-000000000001",
          "keyRestrictions": {
            "aaGuids": [
              "90a3ccdf-635c-4729-a248-9b709135078f",
              "de1e552d-db1d-4423-a619-566b625cdc84",
              "2fc0579f-8113-47ea-b116-bb5a8db9202a",
              "a25342c0-3cdc-4414-8e46-f4807fca511c",
              "d7781e5d-e353-46aa-afe2-3ca49f13332a",
              "662ef48a-95e2-4aaa-a6c1-5b9c40375824",
              "cb69481e-8ff7-4039-93ec-0a2729a154a8",
              "ee882879-721c-4913-9775-3dfcce97072a",
              "662ef48a-95e2-4aaa-a6c1-5b9c40375824"
            ],
            "enforcementType": "allow",
            "isEnforced": true
          },
          "name": "Default passkey profile",
          "passkeyTypes": "deviceBound,synced"
        },
        {
          "attestationEnforcement": "disabled",
          "id": "e47a833c-5dfa-45f1-9471-bb0cf0eb425b",
          "keyRestrictions": {
            "aaGuids": [
              "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
              "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
              "adce0002-35bc-c60a-648b-0b25f1f05503",
              "08987058-cadc-4b81-b6e1-30de50dcbe96",
              "9ddd1817-af5a-4672-a2b9-3e3dd95000a9",
              "6028b017-b1d4-4c02-b4b3-afcdafc96bb2"
            ],
            "enforcementType": "allow",
            "isEnforced": false
          },
          "name": "synced",
          "passkeyTypes": "synced"
        }
      ],
      "state": "enabled"
    },
    {
      "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
      "excludeTargets": [],
      "featureSettings": {
        "displayAppInformationRequiredState": {
          "excludeTarget": {
            "id": "00000000-0000-0000-0000-000000000000",
            "targetType": "group"
          },
          "includeTarget": {
            "id": "all_users",
            "targetType": "group"
          },
          "state": "enabled"
        },
        "displayLocationInformationRequiredState": {
          "excludeTarget": {
            "id": "00000000-0000-0000-0000-000000000000",
            "targetType": "group"
          },
          "includeTarget": {
            "id": "all_users",
            "targetType": "group"
          },
          "state": "enabled"
        }
      },
      "id": "MicrosoftAuthenticator",
      "includeTargets": [
        {
          "authenticationMode": "any",
          "id": "all_users",
          "isRegistrationRequired": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')/microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration/includeTargets",
      "isSoftwareOathEnabled": true,
      "state": "enabled"
    },
    {
      "@odata.type": "#microsoft.graph.smsAuthenticationMethodConfiguration",
      "excludeTargets": [
        {
          "id": "c118ea33-87b7-4c8a-9bb3-e72b80bb75dd",
          "targetType": "group"
        }
      ],
      "id": "Sms",
      "includeTargets": [
        {
          "id": "all_users",
          "isRegistrationRequired": false,
          "isUsableForSignIn": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Sms')/microsoft.graph.smsAuthenticationMethodConfiguration/includeTargets",
      "state": "enabled"
    },
    {
      "@odata.type": "#microsoft.graph.voiceAuthenticationMethodConfiguration",
      "excludeTargets": [],
      "id": "Voice",
      "includeTargets": [
        {
          "id": "all_users",
          "isRegistrationRequired": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Voice')/microsoft.graph.voiceAuthenticationMethodConfiguration/includeTargets",
      "isOfficePhoneAllowed": false,
      "state": "disabled"
    },
    {
      "@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration",
      "authenticationModeConfiguration": {
        "rules": [],
        "x509CertificateAuthenticationDefaultMode": "x509CertificateSingleFactor",
        "x509CertificateDefaultRequiredAffinityLevel": "low"
      },
      "certificateAuthorityScopes": [],
      "certificateUserBindings": [
        {
          "priority": 1,
          "trustAffinityLevel": "low",
          "userProperty": "userPrincipalName",
          "x509CertificateField": "PrincipalName"
        },
        {
          "priority": 2,
          "trustAffinityLevel": "low",
          "userProperty": "userPrincipalName",
          "x509CertificateField": "RFC822Name"
        },
        {
          "priority": 3,
          "trustAffinityLevel": "high",
          "userProperty": "certificateUserIds",
          "x509CertificateField": "SubjectKeyIdentifier"
        }
      ],
      "crlValidationConfiguration": {
        "exemptedCertificateAuthoritiesSubjectKeyIdentifiers": [],
        "state": "disabled"
      },
      "excludeTargets": [],
      "id": "X509Certificate",
      "includeTargets": [
        {
          "id": "all_users",
          "isRegistrationRequired": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('X509Certificate')/microsoft.graph.x509CertificateAuthenticationMethodConfiguration/includeTargets",
      "issuerHintsConfiguration": {
        "state": "disabled"
      },
      "state": "disabled"
    },
    {
      "@odata.type": "#microsoft.graph.verifiableCredentialsAuthenticationMethodConfiguration",
      "excludeTargets": [],
      "id": "VerifiableCredentials",
      "includeTargets": [],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('VerifiableCredentials')/microsoft.graph.verifiableCredentialsAuthenticationMethodConfiguration/includeTargets",
      "state": "disabled"
    },
    {
      "@odata.type": "#microsoft.graph.qrCodePinAuthenticationMethodConfiguration",
      "excludeTargets": [],
      "id": "QRCodePin",
      "includeTargets": [
        {
          "id": "all_users",
          "isRegistrationRequired": false,
          "targetType": "group"
        }
      ],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('QRCodePin')/microsoft.graph.qrCodePinAuthenticationMethodConfiguration/includeTargets",
      "pinLength": 8,
      "standardQRCodeLifetimeInDays": 365,
      "state": "disabled"
    }
  ],
  "authenticationMethodConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
  "description": "The tenant-wide policy that controls which authentication methods are allowed in the tenant, authentication method registration requirements, and self-service password reset settings",
  "displayName": "Authentication Methods Policy",
  "id": "authenticationMethodsPolicy",
  "lastModifiedDateTime": "2025-11-21T20:01:36.9599169Z",
  "policyMigrationState": null,
  "policyVersion": "1.5",
  "registrationEnforcement": {
    "authenticationMethodsRegistrationCampaign": {
      "excludeTargets": [],
      "includeTargets": [
        {
          "id": "all_users",
          "targetType": "group",
          "targetedAuthenticationMethod": "microsoftAuthenticator"
        }
      ],
      "snoozeDurationInDays": 1,
      "state": "default"
    }
  }
}`

// TestCollectEmitsOneGaugePerKnownMethod drives the VERBATIM live policy through
// the real collector into a recorder and pins the per-method enabled gauge.
//
// The expectations track the wire, not the docs: HardwareOath, SoftwareOath,
// TemporaryAccessPass and Email are not in the trimmed capture, so the collector
// correctly skips them (absent from the response, not fabricated as 0), leaving
// exactly the five catalog methods the capture carries.
func TestCollectEmitsOneGaugePerKnownMethod(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(methodEnabledMetric)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["method"]] = p.Value
	}
	want := map[string]float64{
		"fido2":                  1,
		"microsoftAuthenticator": 1,
		"sms":                    1,
		"voice":                  0,
		"x509Certificate":        0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for method, v := range want {
		if got[method] != v {
			t.Errorf("series method=%s value = %v, want %v", method, got[method], v)
		}
	}
}

// TestCollectExcludesUncatalogedMethodTypes pins the cardinality guard against
// the live wire: the tenant returns method configurations whose id is not in the
// collector's fixed catalog (VerifiableCredentials, QRCodePin here — this tenant
// has no custom "external" GUID method, so those built-in-but-uncataloged types
// exercise the same skip path). None may become a metric series; the metric's
// cardinality must stay bounded by the catalog, never grow with what Microsoft
// or a tenant adds to the policy.
func TestCollectExcludesUncatalogedMethodTypes(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(methodEnabledMetric)
	for _, p := range pts {
		switch p.Attrs["method"] {
		case "VerifiableCredentials", "QRCodePin":
			t.Fatalf("uncataloged method configuration leaked into metric attrs: %v", p.Attrs)
		}
	}
	const catalogMethodsInCapture = 5
	if len(pts) != catalogMethodsInCapture {
		t.Fatalf("got %d series, want exactly %d catalog method types present on the wire", len(pts), catalogMethodsInCapture)
	}
}

// TestCollectEmitsLegacyEnabledCount pins the convenience count the issue calls
// out: enabled legacy methods (SMS, voice) as a single bounded gauge. In the
// capture Sms is enabled and Voice is disabled, so the count is 1.
func TestCollectEmitsLegacyEnabledCount(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(legacyEnabledMetric)
	if len(pts) != 1 {
		t.Fatalf("got %d series for %s, want exactly 1", len(pts), legacyEnabledMetric)
	}
	if pts[0].Value != 1 {
		t.Errorf("legacy enabled count = %v, want 1 (sms enabled, voice disabled)", pts[0].Value)
	}
}

// TestCollectEmitsPolicyLogTwin pins the singleton entra.auth_methods_policy
// log twin's typed fields against the VERBATIM live capture (#317, Option A):
// the policy's own identity/metadata plus the registration campaign's
// bounded target-id array, never raw configuration JSON.
func TestCollectEmitsPolicyLogTwin(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventPolicy {
			r := r
			found = &r
			break
		}
	}
	if found == nil {
		t.Fatalf("no %s log record emitted", eventPolicy)
	}

	want := map[string]string{
		"id":                        "authenticationMethodsPolicy",
		"display_name":              "Authentication Methods Policy",
		"last_modified_date_time":   "2025-11-21T20:01:36.9599169Z",
		"policy_version":            "1.5",
		"state":                     "default",
		"snooze_duration_in_days":   "1",
		"include_target_ids":        "all_users",
		"include_target_count":      "1",
		"include_targets_truncated": "false",
	}
	for k, v := range want {
		if got := found.Attrs[k]; got != v {
			t.Errorf("policy twin attr %s = %q, want %q", k, got, v)
		}
	}
	// policyMigrationState is wire-null: absent, never a fabricated empty string.
	if _, ok := found.Attrs["policy_migration_state"]; ok {
		t.Errorf("policy_migration_state present = %q, want absent (wire value is null)", found.Attrs["policy_migration_state"])
	}
	// The campaign has no excludeTargets on the wire: absent, not an empty array attr.
	if _, ok := found.Attrs["exclude_target_ids"]; ok {
		t.Errorf("exclude_target_ids present, want absent for an empty excludeTargets array")
	}
}

// TestCollectEmitsOneConfigurationTwinPerReturnedEntry pins the 1:1
// cardinality the #317 decision requires: exactly one
// entra.auth_method_configuration record per entry in
// authenticationMethodConfigurations, matching the seven the live capture
// returns (including the two the metric-side catalog skips).
func TestCollectEmitsOneConfigurationTwinPerReturnedEntry(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var ids []string
	for _, r := range rec.LogRecords() {
		if r.EventName == eventConfig {
			ids = append(ids, r.Attrs["id"])
		}
	}
	want := []string{"Fido2", "MicrosoftAuthenticator", "Sms", "Voice", "X509Certificate", "VerifiableCredentials", "QRCodePin"}
	if len(ids) != len(want) {
		t.Fatalf("got %d configuration twins %v, want %d %v", len(ids), ids, len(want), want)
	}
	for _, w := range want {
		found := false
		for _, id := range ids {
			if id == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing configuration twin for id=%s", w)
		}
	}
}

// TestCollectFido2TwinCarriesSubtypeFields pins the Fido2-specific typed
// fields observed live 2026-07-28 (#317): self-service/attestation flags,
// the default passkey profile id, key restriction enforcement, and the
// bounded aaGuids/passkeyProfiles id arrays — identifiers only, never the
// nested per-profile attestation config.
func TestCollectFido2TwinCarriesSubtypeFields(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var fido2 *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventConfig && r.Attrs["id"] == "Fido2" {
			r := r
			fido2 = &r
			break
		}
	}
	if fido2 == nil {
		t.Fatal("no Fido2 configuration twin emitted")
	}

	want := map[string]string{
		"state":                                "enabled",
		"odata_type":                           "#microsoft.graph.fido2AuthenticationMethodConfiguration",
		"method":                               "fido2",
		"is_self_service_registration_allowed": "true",
		"is_attestation_enforced":              "true",
		"default_passkey_profile_id":           "00000000-0000-0000-0000-000000000001",
		"key_restriction_enforced":             "true",
		"key_restriction_enforcement_type":     "allow",
		"key_restriction_aaguids_truncated":    "false",
		"passkey_profile_ids_truncated":        "false",
		"include_target_ids":                   "all_users",
		"include_target_count":                 "1",
	}
	for k, v := range want {
		if got := fido2.Attrs[k]; got != v {
			t.Errorf("fido2 twin attr %s = %q, want %q", k, got, v)
		}
	}
	if got := fido2.Attrs["key_restriction_aaguids"]; got == "" {
		t.Error("key_restriction_aaguids missing")
	}
	if got := fido2.Attrs["passkey_profile_ids"]; got != "00000000-0000-0000-0000-000000000001,e47a833c-5dfa-45f1-9471-bb0cf0eb425b" {
		t.Errorf("passkey_profile_ids = %q", got)
	}
	// excludeTargets is an empty array on the wire for Fido2: absent, not a
	// zero count masquerading as "measured empty".
	if _, ok := fido2.Attrs["exclude_target_ids"]; ok {
		t.Errorf("exclude_target_ids present, want absent for an empty excludeTargets array")
	}
}

// TestCollectSmsTwinHasNoFido2Fields pins that the union-struct decoding
// approach never leaks another subtype's fields onto an unrelated
// configuration: Sms carries no isSelfServiceRegistrationAllowed on the
// wire, so its twin must not claim one.
func TestCollectSmsTwinHasNoFido2Fields(t *testing.T) {
	g := &fakeGraph{body: livePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var sms *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventConfig && r.Attrs["id"] == "Sms" {
			r := r
			sms = &r
			break
		}
	}
	if sms == nil {
		t.Fatal("no Sms configuration twin emitted")
	}
	for _, k := range []string{"is_self_service_registration_allowed", "is_attestation_enforced", "default_passkey_profile_id", "key_restriction_aaguids", "passkey_profile_ids", "is_office_phone_allowed", "pin_length"} {
		if _, ok := sms.Attrs[k]; ok {
			t.Errorf("sms twin unexpectedly carries %s=%q", k, sms.Attrs[k])
		}
	}
	if got, want := sms.Attrs["method"], "sms"; got != want {
		t.Errorf("method = %q, want %q", got, want)
	}
	if got, want := sms.Attrs["exclude_target_ids"], "c118ea33-87b7-4c8a-9bb3-e72b80bb75dd"; got != want {
		t.Errorf("exclude_target_ids = %q, want %q", got, want)
	}
}

// unknownSubtypePolicy is a SYNTHETIC (hand-built, not a live capture)
// single-configuration policy body used only to exercise the unknown-subtype
// fallback path deterministically. It stands in for any configuration type
// this collector has not observed evidence for (Temporary Access Pass,
// hardware/software OATH, email, custom/external...) — the point of the test
// is the CODE PATH, not an assertion about what any particular real subtype's
// wire shape is. Deliberately includes includeTargets and subtype-shaped
// extra fields to prove they are dropped, not merely absent from the input.
const unknownSubtypePolicy = `{
  "id": "authenticationMethodsPolicy",
  "authenticationMethodConfigurations": [
    {
      "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
      "id": "TemporaryAccessPass",
      "state": "disabled",
      "includeTargets": [{"id": "all_users", "targetType": "group"}],
      "isUsableOnce": true
    }
  ]
}`

// TestCollectUnknownSubtypeEmitsOnlyGenericFields pins the load-bearing half
// of the #317 decision: a configuration whose @odata.type is not in the
// known-observed set gets id/state/odata_type and NOTHING else — not even
// the include/exclude target arrays every KNOWN configuration carries —
// because an unreviewed field on an unseen subtype could be sensitive.
func TestCollectUnknownSubtypeEmitsOnlyGenericFields(t *testing.T) {
	g := &fakeGraph{body: unknownSubtypePolicy}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var tap *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventConfig {
			r := r
			tap = &r
			break
		}
	}
	if tap == nil {
		t.Fatal("no configuration twin emitted")
	}
	want := map[string]string{
		"id":         "TemporaryAccessPass",
		"state":      "disabled",
		"odata_type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
	}
	if len(tap.Attrs) != len(want) {
		t.Fatalf("got %d attrs %v, want exactly %v", len(tap.Attrs), tap.Attrs, want)
	}
	for k, v := range want {
		if got := tap.Attrs[k]; got != v {
			t.Errorf("attr %s = %q, want %q", k, got, v)
		}
	}
}

func TestCollectSurfacesFetchError(t *testing.T) {
	g := &fakeGraph{err: errors.New("throttled")}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("expected Collect to surface the fetch error")
	}
	if pts := rec.MetricPoints(methodEnabledMetric); len(pts) != 0 {
		t.Errorf("got %d series after a fetch error, want 0", len(pts))
	}
}

func TestCollectSurfacesDecodeError(t *testing.T) {
	g := &fakeGraph{body: "not json"}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter(), nil); err == nil {
		t.Fatal("expected Collect to surface the decode error")
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.auth_methods_policy" {
		t.Errorf("Name = %q", c.Name())
	}
	// Policy.Read.AuthenticationMethod is the least-privileged application
	// permission per current Microsoft Graph docs (verified 2026-07-15) —
	// Policy.Read.All is listed there as a higher-privileged alternative, not
	// the least-privilege scope the M2 guide asks for.
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Policy.Read.AuthenticationMethod" {
		t.Errorf("RequiredPermissions = %v, want [Policy.Read.AuthenticationMethod]", perms)
	}
}

func TestDefaultInterval(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want positive", c.DefaultInterval())
	}
}
