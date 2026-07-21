package deviceencryption

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors), satisfying
// collectors.GraphClient so Collector runs through collectors.GetAllValues with
// no live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body for %q", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func listURL() string { return defaultBaseURL + listPath }

// liveBody is the tenant's FULL managedDeviceEncryptionStates collection, copied
// verbatim off the beta wire (probed as graph2otel-poller on m7kni 2026-07-21):
// two encrypted Windows hosts / two "notReady" but encrypted Macs / one
// unencrypted Windows host with the full BitLocker blocker list. Mapper written
// against this, never against docs (#142).
const liveBody = `{"value":[
 {"id":"0d705f2d-4dd3-496f-bacb-0ae04afa7f8a","userPrincipalName":"rob@m7kni.io","deviceType":"windowsRT","osVersion":"10.0.26200.8037","tpmSpecificationVersion":"2.0","deviceName":"DESKTOP-2F6PPF2","encryptionReadinessState":"ready","encryptionState":"encrypted","encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":"osVolumeEncryptionMethodMismatch","fileVaultStates":null,"policyDetails":[]},
 {"id":"7bed7008-3922-465a-8af2-a435b6119bef","userPrincipalName":"rob@m7kni.io","deviceType":"windowsRT","osVersion":"10.0.26200.6584","tpmSpecificationVersion":"2.0","deviceName":"DESKTOP-MHTMHH4","encryptionReadinessState":"ready","encryptionState":"notEncrypted","encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":"osVolumeUnprotected,tpmNotReady","fileVaultStates":null,"policyDetails":[]},
 {"id":"33dcca32-d6ea-478b-88d9-e2a891f9d83a","userPrincipalName":"rob@m7kni.io","deviceType":"macMDM","osVersion":"27.0 (26A5378n)","tpmSpecificationVersion":null,"deviceName":"mbp14","encryptionReadinessState":"notReady","encryptionState":"encrypted","encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":null,"fileVaultStates":null,"policyDetails":[]},
 {"id":"57d346d7-ddf1-489b-b70d-a30dce1e2458","userPrincipalName":"rob@m7kni.io","deviceType":"macMDM","osVersion":"27.0 (26A5388g)","tpmSpecificationVersion":null,"deviceName":"MBP16","encryptionReadinessState":"notReady","encryptionState":"encrypted","encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":null,"fileVaultStates":null,"policyDetails":[]},
 {"id":"4ada2149-e9cb-4c34-827a-8df692a9065c","userPrincipalName":"rob@m7kni.io","deviceType":"windowsRT","osVersion":"10.0.26200.8875","tpmSpecificationVersion":"2.0","deviceName":"wintest","encryptionReadinessState":"ready","encryptionState":"notEncrypted","encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":"osVolumeUnprotected,osVolumeTpmRequired,osVolumeTpmOnlyRequired,osVolumeEncryptionMethodMismatch,tpmNotReady","fileVaultStates":null,"policyDetails":[]}
]}`

func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{listURL(): liveBody}}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

// twinFor finds the emitted twin for a device name.
func twinFor(t *testing.T, rec *telemetrytest.Recorder, deviceName string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrDeviceName] == deviceName {
			return l
		}
	}
	t.Fatalf("no twin for device %q", deviceName)
	return telemetrytest.LogRecord{}
}

func TestCollectEmitsBoundedDeviceGauge(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(devicesMetricName)
	if len(points) != 3 {
		t.Fatalf("got %d gauge series, want 3: %+v", len(points), points)
	}
	want := map[[3]string]float64{
		{"encrypted", "ready", "windowsRT"}:    1,
		{"notEncrypted", "ready", "windowsRT"}: 2,
		{"encrypted", "notReady", "macMDM"}:    2,
	}
	for _, p := range points {
		if p.Kind != "gauge" {
			t.Errorf("metric kind = %q, want gauge", p.Kind)
		}
		key := [3]string{
			p.Attrs[semconv.AttrEncryptionState],
			p.Attrs[semconv.AttrEncryptionReadinessState],
			p.Attrs[semconv.AttrDeviceType],
		}
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected series %+v", p.Attrs)
			continue
		}
		if p.Value != w {
			t.Errorf("series %v value = %v, want %v", key, p.Value, w)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing series: %v", want)
	}
}

func TestCollectEmitsPolicyStateGauge(t *testing.T) {
	rec := collect(t, liveGraph())

	points := rec.MetricPoints(policyStateMetricName)
	if len(points) != 1 {
		t.Fatalf("got %d policy-state series, want 1: %+v", len(points), points)
	}
	p := points[0]
	if p.Attrs[semconv.AttrEncryptionPolicySettingState] != "notAssigned" || p.Value != 5 {
		t.Errorf("policy-state series = %+v value %v, want notAssigned=5", p.Attrs, p.Value)
	}
	if len(p.Attrs) != 1 {
		t.Errorf("policy-state series carries extra attributes %+v, want only %s", p.Attrs, semconv.AttrEncryptionPolicySettingState)
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard: the
// per-device identity and the unbounded BitLocker blocker list ride the twin,
// never a metric label. signalcapture.Main covers a fixed banned list; this
// pins THIS collector's own per-entity fields (tpm/os_version/bitlocker states
// are not on that list).
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph())

	banned := map[string]bool{
		semconv.AttrDeviceId:                true,
		semconv.AttrDeviceName:              true,
		semconv.AttrUserPrincipalName:       true,
		semconv.AttrOsVersion:               true,
		semconv.AttrTpmSpecificationVersion: true,
		semconv.AttrAdvancedBitlockerStates: true,
		semconv.AttrFileVaultStates:         true,
	}
	allowed := map[string]bool{
		semconv.AttrEncryptionState:              true,
		semconv.AttrEncryptionReadinessState:     true,
		semconv.AttrDeviceType:                   true,
		semconv.AttrEncryptionPolicySettingState: true,
	}
	for _, name := range []string{devicesMetricName, policyStateMetricName} {
		for _, p := range rec.MetricPoints(name) {
			for k := range p.Attrs {
				if banned[k] {
					t.Errorf("%s carries per-entity metric label %q — it belongs on the %s twin (#112/#114)", name, k, eventName)
				}
				if !allowed[k] {
					t.Errorf("%s carries unexpected metric label %q", name, k)
				}
			}
		}
	}
}

func TestUnencryptedDeviceTwinIsWarnAndCarriesBlockers(t *testing.T) {
	rec := collect(t, liveGraph())

	if n := len(rec.LogRecords()); n != 5 {
		t.Fatalf("got %d twins, want 5 (one per device row)", n)
	}
	tw := twinFor(t, rec, "wintest")
	if tw.EventName != eventName {
		t.Errorf("EventName = %q, want %q", tw.EventName, eventName)
	}
	if !tw.Timestamp.IsZero() {
		t.Errorf("twin timestamp = %v, want zero (state snapshot, not an event)", tw.Timestamp)
	}
	if tw.SeverityText != "WARN" {
		t.Errorf("unencrypted device severity = %q, want WARN", tw.SeverityText)
	}
	wantAttrs := map[string]string{
		semconv.AttrDeviceId:                     "4ada2149-e9cb-4c34-827a-8df692a9065c",
		semconv.AttrDeviceName:                   "wintest",
		semconv.AttrUserPrincipalName:            "rob@m7kni.io",
		semconv.AttrOsVersion:                    "10.0.26200.8875",
		semconv.AttrDeviceType:                   "windowsRT",
		semconv.AttrTpmSpecificationVersion:      "2.0",
		semconv.AttrEncryptionState:              "notEncrypted",
		semconv.AttrEncryptionReadinessState:     "ready",
		semconv.AttrEncryptionPolicySettingState: "notAssigned",
		semconv.AttrAdvancedBitlockerStates:      "osVolumeUnprotected,osVolumeTpmRequired,osVolumeTpmOnlyRequired,osVolumeEncryptionMethodMismatch,tpmNotReady",
	}
	for k, want := range wantAttrs {
		if got := tw.Attrs[k]; got != want {
			t.Errorf("twin attr %s = %q, want %q", k, got, want)
		}
	}
}

func TestEncryptedDeviceTwinIsInfoAndOmitsAbsentFields(t *testing.T) {
	rec := collect(t, liveGraph())

	tw := twinFor(t, rec, "mbp14")
	if tw.SeverityText != "INFO" {
		t.Errorf("encrypted device severity = %q, want INFO", tw.SeverityText)
	}
	if tw.Attrs[semconv.AttrDeviceType] != "macMDM" {
		t.Errorf("device_type = %q, want the verbatim wire enum macMDM (#142)", tw.Attrs[semconv.AttrDeviceType])
	}
	// Nulls on the wire must be omitted, never emitted as "".
	for _, k := range []string{semconv.AttrTpmSpecificationVersion, semconv.AttrAdvancedBitlockerStates, semconv.AttrFileVaultStates} {
		if _, ok := tw.Attrs[k]; ok {
			t.Errorf("attribute %q present for a null wire value: %q", k, tw.Attrs[k])
		}
	}
}

// fileVaultStates is null on every m7kni row, so its shape is unknown: Graph
// beta returns flag collections either comma-joined (advancedBitLockerStates) or
// as a JSON array. Both must decode, and neither may fail the whole row.
func TestFileVaultStatesDecodesDefensively(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"success"`, "success"},
		{"array", `["driveEncryptedByUser","success"]`, "driveEncryptedByUser,success"},
		{"empty array", `[]`, ""},
		{"unexpected shape", `{"state":"success"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{listURL(): `{"value":[
				{"id":"33dcca32-d6ea-478b-88d9-e2a891f9d83a","deviceName":"mbp14","deviceType":"macMDM",
				 "encryptionState":"encrypted","encryptionReadinessState":"notReady",
				 "encryptionPolicySettingState":"notAssigned","fileVaultStates":` + tc.raw + `}]}`}}
			rec := collect(t, g)
			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d twins, want 1 — an unexpected fileVaultStates shape must not drop the row", len(logs))
			}
			got, ok := logs[0].Attrs[semconv.AttrFileVaultStates]
			if tc.want == "" {
				if ok {
					t.Errorf("file_vault_states = %q, want the attribute omitted", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("file_vault_states = %q, want %q", got, tc.want)
			}
		})
	}
}

// advancedBitLockerStates is live-verified as a comma-joined string, but that is
// n=1 — one tenant, one day. It is the same KIND of flag list as
// fileVaultStates, so it gets the same tolerance: an array-shaped value on some
// other tenant must not fail the row's decode and take the whole collection down
// with it.
func TestAdvancedBitLockerStatesDecodesDefensively(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"live comma-joined string", `"osVolumeUnprotected,tpmNotReady"`, "osVolumeUnprotected,tpmNotReady"},
		{"array", `["osVolumeUnprotected","tpmNotReady"]`, "osVolumeUnprotected,tpmNotReady"},
		{"unexpected shape", `{"state":"osVolumeUnprotected"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{listURL(): `{"value":[
				{"id":"7bed7008-3922-465a-8af2-a435b6119bef","deviceName":"DESKTOP-MHTMHH4","deviceType":"windowsRT",
				 "encryptionState":"notEncrypted","encryptionReadinessState":"ready",
				 "encryptionPolicySettingState":"notAssigned","advancedBitLockerStates":` + tc.raw + `}]}`}}
			rec := collect(t, g)
			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d twins, want 1 — an unexpected advancedBitLockerStates shape must not drop the row", len(logs))
			}
			got, ok := logs[0].Attrs[semconv.AttrAdvancedBitlockerStates]
			if tc.want == "" {
				if ok {
					t.Errorf("advanced_bitlocker_states = %q, want the attribute omitted", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("advanced_bitlocker_states = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCollectFollowsNextLink(t *testing.T) {
	page2 := defaultBaseURL + listPath + "?$skiptoken=abc"
	g := &fakeGraph{bodies: map[string]string{
		listURL(): `{"@odata.nextLink":"` + page2 + `","value":[
			{"id":"dev1","deviceName":"one","deviceType":"windowsRT","encryptionState":"encrypted",
			 "encryptionReadinessState":"ready","encryptionPolicySettingState":"notAssigned"}]}`,
		page2: `{"value":[
			{"id":"dev2","deviceName":"two","deviceType":"windowsRT","encryptionState":"encrypted",
			 "encryptionReadinessState":"ready","encryptionPolicySettingState":"notAssigned"}]}`,
	}}
	rec := collect(t, g)
	if n := len(rec.LogRecords()); n != 2 {
		t.Fatalf("got %d twins, want 2 (both pages consumed)", n)
	}
	points := rec.MetricPoints(devicesMetricName)
	if len(points) != 1 || points[0].Value != 2 {
		t.Fatalf("gauge = %+v, want a single series of 2", points)
	}
}

func TestForbiddenSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL(): errors.New("graphclient: GET ...: status 403: forbidden")}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.MetricPoints(devicesMetricName)) != 0 || len(rec.LogRecords()) != 0 {
		t.Error("expected no emissions on 403")
	}
}

func TestListErrorIsSurfaced(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL(): errors.New("boom")}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("a non-403 list error must be surfaced")
	}
}

func TestEmptyCollectionEmitsNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{listURL(): `{"value":[]}`}}
	rec := collect(t, g)
	if len(rec.LogRecords()) != 0 {
		t.Error("no rows => no twins")
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "intune.device_encryption" {
		t.Errorf("Name() = %q, want intune.device_encryption", c.Name())
	}
	// v1.0 has no managedDeviceEncryptionStates segment (400 BadRequest,
	// live-measured 2026-07-21) — beta base URL, so Experimental.
	if defaultBaseURL != "https://graph.microsoft.com/beta" {
		t.Errorf("defaultBaseURL = %q, want the beta root", defaultBaseURL)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v, want the single read-only device scope", perms)
	}
	if c.DefaultInterval() != time.Hour {
		t.Errorf("DefaultInterval = %v, want 1h", c.DefaultInterval())
	}
}
