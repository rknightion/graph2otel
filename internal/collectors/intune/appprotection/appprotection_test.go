package appprotection

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
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
	return base + "/deviceAppManagement/managedAppRegistrations?$select=flaggedReasons,appIdentifier&$top=999"
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
