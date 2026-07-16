package appprotection

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned raw bodies (or errors), mirroring the
// manageddevices reference collector's test fake.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	if body, ok := f.bodies[url]; ok {
		return []byte(body), nil
	}
	return nil, errors.New("unmapped url: " + url)
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

func newTestCollector(g collectors.GraphClient) *Collector {
	return New(g, nil)
}

func page(items ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"value": items})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func assignable(isAssigned bool) map[string]any {
	return map[string]any{"isAssigned": isAssigned}
}

func registration(platformODataType string, flaggedReasons ...string) map[string]any {
	m := map[string]any{"flaggedReasons": flaggedReasons}
	if platformODataType != "" {
		m["appIdentifier"] = map[string]any{"@odata.type": platformODataType}
	}
	return m
}

// registrationWithIdentity is registration() plus the log-twin-only identity
// fields (userId, deviceTag) - #114.
func registrationWithIdentity(platformODataType, userID, deviceTag string, flaggedReasons ...string) map[string]any {
	m := registration(platformODataType, flaggedReasons...)
	m["userId"] = userID
	m["deviceTag"] = deviceTag
	return m
}

// registrationWithApp is registration() plus the concrete per-app identifier
// (packageId for Android, bundleId for iOS) nested inside appIdentifier -
// #112 follow-up on #114.
func registrationWithApp(platformODataType, appIDKey, appIDValue string, flaggedReasons ...string) map[string]any {
	m := registration(platformODataType, flaggedReasons...)
	ai := m["appIdentifier"].(map[string]any)
	ai[appIDKey] = appIDValue
	return m
}

func fullFixtureBodies() map[string]string {
	return map[string]string{
		iosPoliciesURL():     page(assignable(true), assignable(true), assignable(false)),
		androidPoliciesURL(): page(assignable(true), assignable(false)),
		targetedConfigsURL(): page(assignable(false)),
		registrationsURL(): page(
			registration("#microsoft.graph.androidMobileAppIdentifier", "none"),
			registration("#microsoft.graph.androidMobileAppIdentifier", "rootedDevice"),
			registration("#microsoft.graph.iosMobileAppIdentifier", "rootedDevice"),
			registration("#microsoft.graph.iosMobileAppIdentifier"),
			registration("#microsoft.graph.someOtherIdentifier", "somethingUnexpected"),
		),
		wipPoliciesURL():    page(assignable(true)),
		mdmWipPoliciesURL(): page(assignable(true), assignable(false)),
	}
}

func iosPoliciesURL() string {
	return base + "/deviceAppManagement/iosManagedAppProtections?$select=isAssigned"
}
func androidPoliciesURL() string {
	return base + "/deviceAppManagement/androidManagedAppProtections?$select=isAssigned"
}
func targetedConfigsURL() string {
	return base + "/deviceAppManagement/targetedManagedAppConfigurations?$select=isAssigned"
}
func registrationsURL() string {
	return base + "/deviceAppManagement/managedAppRegistrations?$select=flaggedReasons,appIdentifier,userId,deviceTag&$top=999"
}
func wipPoliciesURL() string {
	return base + "/deviceAppManagement/windowsInformationProtectionPolicies?$select=isAssigned"
}
func mdmWipPoliciesURL() string {
	return base + "/deviceAppManagement/mdmWindowsInformationProtectionPolicies?$select=isAssigned"
}

func TestCollectEmitsPolicyCountByPlatformAndAssigned(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(policyCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["platform"]+"/"+p.Attrs["assigned"]] = p.Value
	}
	want := map[string]float64{
		"ios/true": 2, "ios/false": 1,
		"android/true": 1, "android/false": 1,
		"cross_platform/false": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d policy series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCollectEmitsFlaggedRegistrationsByReasonAndPlatform(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(flaggedRegistrationsMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["flagged_reason"]+"/"+p.Attrs["platform"]] = p.Value
	}
	want := map[string]float64{
		"none/android":          1,
		"rooted_device/android": 1,
		"rooted_device/ios":     1,
		"none/ios":              1, // absent flaggedReasons buckets to "none"
		"other/other":           1, // unrecognized reason -> bounded "other" bucket
	}
	if len(got) != len(want) {
		t.Fatalf("got %d flagged_registrations series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// Never a per-entity label: userId/appIdentifier/deviceTag must not appear.
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "flagged_reason" && k != "platform" {
				t.Errorf("unexpected attribute key %q on flagged_registrations series (must stay bounded to flagged_reason/platform)", k)
			}
		}
	}
}

func TestCollectEmitsWIPPolicyCountByAssigned(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(wipPolicyCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["assigned"]] = p.Value
	}
	want := map[string]float64{"true": 2, "false": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d wip series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("assigned=%s = %v, want %v", k, got[k], v)
		}
	}
}

// TestWIPEmptyBodyBucketsAsZeroKnownPolicies pins the live-verified gotcha:
// windowsInformationProtectionPolicies / mdmWindowsInformationProtectionPolicies
// returned a genuinely empty response body on a real tenant. An empty body
// must decode as "zero WIP policies" (no points, no error), not as a JSON
// decode failure - and the rest of the collector's metrics are unaffected.
func TestWIPEmptyBodyBucketsAsZeroKnownPolicies(t *testing.T) {
	bodies := fullFixtureBodies()
	bodies[wipPoliciesURL()] = ""
	bodies[mdmWipPoliciesURL()] = ""
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil", err)
	}

	if pts := rec.MetricPoints(wipPolicyCountMetricName); len(pts) != 0 {
		t.Errorf("wip policy count points = %+v, want none (empty body = zero known policies)", pts)
	}
	if len(rec.MetricPoints(policyCountMetricName)) == 0 {
		t.Error("policy count metric should still emit")
	}
	if len(rec.MetricPoints(flaggedRegistrationsMetricName)) == 0 {
		t.Error("flagged_registrations metric should still emit")
	}
}

// TestWIPDecodeErrorDropsSeriesButNotCollector pins that a WIP endpoint
// returning a non-empty, unparseable body (or any other fetch error) is
// best-effort: it is logged and the intune.wip.policy.count series is
// dropped for the cycle, but Collect still returns nil and every other
// metric still emits - a deprecated, quirky endpoint must never fail this
// collector's self-obs status.
func TestWIPDecodeErrorDropsSeriesButNotCollector(t *testing.T) {
	bodies := fullFixtureBodies()
	bodies[wipPoliciesURL()] = "{ this is not valid json"
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (a WIP decode failure must never fail the collector)", err)
	}

	if pts := rec.MetricPoints(wipPolicyCountMetricName); len(pts) != 0 {
		t.Errorf("wip policy count points = %+v, want none after a decode failure", pts)
	}
	if len(rec.MetricPoints(policyCountMetricName)) == 0 {
		t.Error("policy count metric should still emit despite the WIP failure")
	}
	if len(rec.MetricPoints(flaggedRegistrationsMetricName)) == 0 {
		t.Error("flagged_registrations metric should still emit despite the WIP failure")
	}
}

// TestWIPFetchErrorDropsSeriesButNotCollector covers the transport/HTTP-error
// flavor of WIP unavailability (e.g. a 400/404 from a tenant where the
// deprecated feature is fully removed), not just a bad body.
func TestWIPFetchErrorDropsSeriesButNotCollector(t *testing.T) {
	bodies := fullFixtureBodies()
	delete(bodies, wipPoliciesURL())
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{wipPoliciesURL(): errors.New("400 Bad Request")},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (a WIP fetch failure must never fail the collector)", err)
	}

	if pts := rec.MetricPoints(wipPolicyCountMetricName); len(pts) != 0 {
		t.Errorf("wip policy count points = %+v, want none after a fetch failure", pts)
	}
	if len(rec.MetricPoints(policyCountMetricName)) == 0 {
		t.Error("policy count metric should still emit despite the WIP failure")
	}
}

// TestCollectIsResilientToPartialFailure pins that a failure fetching one
// policy source is logged and joined into the returned error, but every
// other metric still emits (matches manageddevices' resilience contract).
func TestCollectIsResilientToPartialFailure(t *testing.T) {
	bodies := fullFixtureBodies()
	delete(bodies, androidPoliciesURL())
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{androidPoliciesURL(): errors.New("boom")},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("Collect: want non-nil error from the failed android fetch, got nil")
	}

	// The other platforms' policy counts still emit.
	pts := rec.MetricPoints(policyCountMetricName)
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Attrs["platform"]+"/"+p.Attrs["assigned"]] = p.Value
	}
	if got["ios/true"] != 2 || got["ios/false"] != 1 {
		t.Errorf("ios counts = %v, want ios/true=2 ios/false=1", got)
	}
	if _, ok := got["android/true"]; ok {
		t.Errorf("android should have no series after fetch failure, got %v", got)
	}

	// The unrelated wip metric still emits despite the app-protection failure.
	wipPts := rec.MetricPoints(wipPolicyCountMetricName)
	if len(wipPts) == 0 {
		t.Error("wip policy count metric should still emit after an unrelated fetch failure")
	}
}

// TestCollectTwinsOnlyFlaggedRegistrations pins the scoping decision for
// #114's intune.appprotection lane: managedAppRegistrations is a
// per-user-per-app collection that can run into the tens/hundreds of
// thousands on a large estate (see the package doc) - the same unbounded
// volume shape that got entra.consent's per-grant twin scoped down to
// high-privilege grants only, rather than twinning every row like
// manageddevices/mfaregistration (which are bounded by device/user count, not
// a user x app cross product). So only registrations carrying an actual
// flagged reason (anything but the bounded "none" bucket) get an
// intune.app_registration log twin - the fixture's two "none"/absent-reason
// registrations must NOT be twinned, while the rooted-device pair and the
// unrecognized-reason ("other") registration must be.
func TestCollectTwinsOnlyFlaggedRegistrations(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 3 {
		t.Fatalf("got %d log records, want 3 (flagged registrations only - 'none' registrations must not be twinned): %+v", len(logs), logs)
	}
	for _, l := range logs {
		if l.EventName != eventAppRegistration {
			t.Errorf("EventName = %q, want %q", l.EventName, eventAppRegistration)
		}
		if l.Attrs["flagged_reasons"] == "" || l.Attrs["flagged_reasons"] == "none" {
			t.Errorf("twinned log has flagged_reasons=%q, want a non-none reason", l.Attrs["flagged_reasons"])
		}
	}
}

// TestFlaggedRegistrationLogTwinCarriesIdentityAndSeverity asserts the
// per-registration log record carries the userId/deviceTag identity the
// managedAppRegistrations $select deliberately withheld from every metric,
// and that a rooted-device flagged reason escalates severity to Warn.
func TestFlaggedRegistrationLogTwinCarriesIdentityAndSeverity(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		iosPoliciesURL():     page(),
		androidPoliciesURL(): page(),
		targetedConfigsURL(): page(),
		registrationsURL(): page(
			registrationWithIdentity("#microsoft.graph.androidMobileAppIdentifier", "user-123", "tag-abc", "rootedDevice"),
		),
		wipPoliciesURL():    page(),
		mdmWipPoliciesURL(): page(),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
	}
	l := logs[0]
	if l.Attrs["user_id"] != "user-123" {
		t.Errorf("user_id = %q, want user-123", l.Attrs["user_id"])
	}
	if l.Attrs["device_tag"] != "tag-abc" {
		t.Errorf("device_tag = %q, want tag-abc", l.Attrs["device_tag"])
	}
	if l.Attrs["platform"] != "android" {
		t.Errorf("platform = %q, want android", l.Attrs["platform"])
	}
	if l.SeverityText != telemetry.SeverityWarn.String() {
		t.Errorf("severity = %s, want %s for a rooted-device flagged registration", l.SeverityText, telemetry.SeverityWarn)
	}
}

// TestFlaggedRegistrationLogTwinCarriesAppIdentifier asserts the concrete
// per-app identifier (packageId on Android, bundleId on iOS) rides onto the
// log twin as a single app_identifier attribute - whichever one the
// platform's appIdentifier subtype actually carries - while the METRIC's
// platform bucket (still @odata.type-derived) is unaffected. This closes the
// #112-style gap where appIdentifier decoded only @odata.type and dropped
// packageId/bundleId, even though the concrete app is a material part of the
// "who is running what on a rooted device" signal.
func TestFlaggedRegistrationLogTwinCarriesAppIdentifier(t *testing.T) {
	cases := []struct {
		name       string
		odataType  string
		appIDKey   string
		appIDValue string
		platform   string
	}{
		{"android", "#microsoft.graph.androidMobileAppIdentifier", "packageId", "com.contoso.app", "android"},
		{"ios", "#microsoft.graph.iosMobileAppIdentifier", "bundleId", "com.contoso.iosapp", "ios"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{
				iosPoliciesURL():     page(),
				androidPoliciesURL(): page(),
				targetedConfigsURL(): page(),
				registrationsURL(): page(
					registrationWithApp(tc.odataType, tc.appIDKey, tc.appIDValue, "rootedDevice"),
				),
				wipPoliciesURL():    page(),
				mdmWipPoliciesURL(): page(),
			}}
			rec := telemetrytest.New()

			if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}

			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
			}
			if got := logs[0].Attrs["app_identifier"]; got != tc.appIDValue {
				t.Errorf("app_identifier = %q, want %q", got, tc.appIDValue)
			}
			if got := logs[0].Attrs["platform"]; got != tc.platform {
				t.Errorf("platform = %q, want %q", got, tc.platform)
			}

			// The metric's platform bucket must stay @odata.type-derived and
			// must never carry the concrete app identifier.
			pts := rec.MetricPoints(flaggedRegistrationsMetricName)
			for _, p := range pts {
				if p.Attrs["platform"] != tc.platform {
					t.Errorf("metric platform = %q, want %q", p.Attrs["platform"], tc.platform)
				}
				for k := range p.Attrs {
					if k == "app_identifier" || k == "packageId" || k == "bundleId" {
						t.Errorf("metric point has concrete app identifier attribute %q - cardinality violation", k)
					}
				}
			}
		})
	}
}

// TestUnrecognizedFlaggedReasonStaysInfo asserts an unrecognized flagged
// reason (bucketed "other") is still twinned (never silently dropped) but
// does not escalate severity - only a known rooted/jailbroken signal does.
func TestUnrecognizedFlaggedReasonStaysInfo(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		iosPoliciesURL():     page(),
		androidPoliciesURL(): page(),
		targetedConfigsURL(): page(),
		registrationsURL(): page(
			registration("#microsoft.graph.androidMobileAppIdentifier", "somethingUnexpected"),
		),
		wipPoliciesURL():    page(),
		mdmWipPoliciesURL(): page(),
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
	}
	if logs[0].SeverityText != telemetry.SeverityInfo.String() {
		t.Errorf("severity = %s, want %s for an unrecognized (non-rooted-device) flagged reason", logs[0].SeverityText, telemetry.SeverityInfo)
	}
}

// TestNoPerRegistrationAttributesOnMetrics pins that the identity fields the
// log twin carries (userId/deviceTag/id/the concrete app identifier) never
// leak onto a metric point - the metrics stay bounded by
// platform/assigned/flagged_reason only.
func TestNoPerRegistrationAttributesOnMetrics(t *testing.T) {
	g := &fakeGraph{bodies: fullFixtureBodies()}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, metric := range []string{policyCountMetricName, flaggedRegistrationsMetricName, wipPolicyCountMetricName} {
		for _, p := range rec.MetricPoints(metric) {
			for k := range p.Attrs {
				switch k {
				case "userId", "user_id", "deviceTag", "device_tag", "id", "packageId", "bundleId", "app_identifier":
					t.Errorf("metric %s has a per-registration attribute %q - cardinality violation", metric, k)
				}
			}
		}
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.app_protection" {
		t.Errorf("Name() = %q, want intune.app_protection", c.Name())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementApps.Read.All" {
		t.Errorf("RequiredPermissions() = %v, want [DeviceManagementApps.Read.All]", perms)
	}
}
