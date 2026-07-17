package defenderreport

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeRunner is a canned exportjob.Runner: it returns a fixed set of rows or
// a fixed error, ignoring the request (tests assert the request separately
// where that matters). Mirrors the fake-Runner pattern the other M5 export
// consumers (e.g. appinstallreport) use to avoid any live Graph/export-job
// dependency in unit tests.
type fakeRunner struct {
	rows     []exportjob.Row
	err      error
	lastReq  exportjob.Request
	callSeen bool
}

func (f *fakeRunner) Export(_ context.Context, req exportjob.Request, _ telemetry.Emitter) ([]exportjob.Row, error) {
	f.lastReq = req
	f.callSeen = true
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

var _ exportjob.Runner = (*fakeRunner)(nil)

// liveDeviceStateLoc is the DeviceState -> DeviceState_loc pairing observed on
// the live DefenderAgents export (probed as graph2otel-poller 2026-07-17,
// #142). It has exactly ONE entry because the live tenant's three devices are
// all healthy, so only code 0 has ever been seen on the wire.
//
// That is deliberate: adding a second entry here would mean inventing a
// code/name pair from Microsoft's documentation, and this file's whole reason
// for existing (#142) is that a fixture asserting a value the API has never
// sent is worse than no fixture. The collector decodes DeviceState from the
// _loc sibling precisely so it needs no such table.
var liveDeviceStateLoc = map[string]string{
	"0": "Clean",
}

// row builds a DefenderAgents export row exactly as the live export returns
// it (#142, live 2026-07-17):
//   - deviceStateCode is a NUMERIC CODE, with a DeviceState_loc sibling
//     Microsoft returns whether or not it was selected;
//   - productStatus is a raw BITMASK integer, with NO _loc sibling at any
//     localizationType;
//   - the flag columns are "True"/"False" (capitalised - see boolStr).
//
// The predecessor of this helper took enum NAMES ("clean", "noStatus",
// "avSignaturesOutOfDate") for both columns. The export has never sent those.
func row(deviceID, deviceName, upn, deviceStateCode, productStatus string, rtpEnabled, networkInspectionEnabled, signatureOverdue, tamperEnabled, malwareEnabled bool) exportjob.Row {
	return exportjob.Row{
		colDeviceID:                  deviceID,
		colDeviceName:                deviceName,
		colUPN:                       upn,
		colDeviceState:               deviceStateCode,
		colDeviceStateLoc:            liveDeviceStateLoc[deviceStateCode],
		colProductStatus:             productStatus,
		colRealTimeProtectionEnabled: boolStr(rtpEnabled),
		colNetworkInspectionSystemOn: boolStr(networkInspectionEnabled),
		colSignatureUpdateOverdue:    boolStr(signatureOverdue),
		colTamperProtectionEnabled:   boolStr(tamperEnabled),
		colMalwareProtectionEnabled:  boolStr(malwareEnabled),
	}
}

// boolStr renders the export API's literal flag encoding. LIVE-MEASURED
// 2026-07-17 (#142): the wire sends "True"/"False", capitalised - not the
// "true"/"false" this helper produced before. strconv.ParseBool accepts both
// spellings, so the collector was never wrong here; the fixture was.
func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func TestSelectColumnsMatchLiveVerifiedSet(t *testing.T) {
	want := map[string]bool{
		colDeviceID:                  true,
		colDeviceName:                true,
		colDeviceState:               true,
		colMalwareProtectionEnabled:  true,
		colNetworkInspectionSystemOn: true,
		colProductStatus:             true,
		colRealTimeProtectionEnabled: true,
		colSignatureUpdateOverdue:    true,
		colTamperProtectionEnabled:   true,
		colUPN:                       true,
	}
	if len(selectColumns) != len(want) {
		t.Fatalf("selectColumns = %v, want %d columns", selectColumns, len(want))
	}
	for _, c := range selectColumns {
		if !want[c] {
			t.Errorf("unexpected column %q in selectColumns", c)
		}
	}
}

func TestCollectEmitsBoundedSignalGaugesAndUnhealthyLogsOnly(t *testing.T) {
	runner := &fakeRunner{rows: []exportjob.Row{
		// Fully healthy: no signal should trip, no log emitted.
		row("dev-1", "LAPTOP-1", "alice@contoso.com", "0", "524288", true, true, false, true, true),
		// RTP off + signature overdue.
		row("dev-2", "LAPTOP-2", "bob@contoso.com", "0", "32", false, true, true, true, true),
		// Tamper protection off.
		row("dev-3", "LAPTOP-3", "carol@contoso.com", "0", "524288", true, true, false, false, true),
		// Malware protection off.
		row("dev-4", "LAPTOP-4", "dave@contoso.com", "0", "2", true, true, false, true, false),
		// Network inspection off.
		row("dev-5", "LAPTOP-5", "erin@contoso.com", "0", "524288", true, false, false, true, true),
	}}
	c := New(runner, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if !runner.callSeen {
		t.Fatal("expected Export to be called")
	}
	if runner.lastReq.ReportName != reportName {
		t.Errorf("ReportName = %q, want %q", runner.lastReq.ReportName, reportName)
	}
	if len(runner.lastReq.Select) == 0 {
		t.Error("Select must be non-empty")
	}

	points := rec.MetricPoints(signalCountMetricName)
	want := map[string]float64{
		signalRealTimeProtectionOff:  1, // dev-2
		signalSignatureUpdateOverdue: 1, // dev-2
		signalTamperProtectionOff:    1, // dev-3
		signalMalwareProtectionOff:   1, // dev-4
		signalNetworkInspectionOff:   1, // dev-5
	}
	if len(points) != len(want) {
		t.Fatalf("got %d gauge points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		wv, ok := want[p.Attrs["signal"]]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("signal %q: value = %v, want %v", p.Attrs["signal"], p.Value, wv)
		}
	}

	logs := rec.LogRecords()
	if len(logs) != 4 {
		t.Fatalf("got %d log records, want 4 (healthy dev-1 must not log)", len(logs))
	}
	seenDevices := map[string]bool{}
	for _, l := range logs {
		if l.EventName != "intune.defender_agent" {
			t.Errorf("log EventName = %q, want intune.defender_agent", l.EventName)
		}
		if l.Attrs["device_id"] == "" {
			t.Error("expected device_id attr on every log record")
		}
		if l.Attrs["device_id"] == "dev-1" {
			t.Error("healthy device dev-1 must not produce a log record")
		}
		if l.Attrs["product_status"] == "" {
			t.Error("expected product_status attr on every log record")
		}
		seenDevices[l.Attrs["device_id"]] = true
	}
	for _, want := range []string{"dev-2", "dev-3", "dev-4", "dev-5"} {
		if !seenDevices[want] {
			t.Errorf("expected a log record for unhealthy device %s", want)
		}
	}

	// product_status is a top-line breakdown over ALL rows, not just the
	// unhealthy ones the signal gauge and logs cover.
	psPoints := rec.MetricPoints(productStatusMetricName)
	psWant := map[string]float64{
		"no_status_flags_set":                        3, // dev-1, dev-3, dev-5 (2^19)
		"av_signatures_out_of_date":                  1, // dev-2 (2^5)
		"service_started_without_malware_protection": 1, // dev-4 (2^1)
	}
	if len(psPoints) != len(psWant) {
		t.Fatalf("got %d product_status points, want %d: %+v", len(psPoints), len(psWant), psPoints)
	}
	for _, p := range psPoints {
		wv, ok := psWant[p.Attrs["status"]]
		if !ok {
			t.Errorf("unexpected product_status point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("status %q: value = %v, want %v", p.Attrs["status"], p.Value, wv)
		}
	}
}

func TestCollectSkipsAndLogsOnExportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"job failed", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrJobFailed)},
		{"sas expired", fmt.Errorf("exportjob: %s: %w", reportName, exportjob.ErrSASExpired)},
		{"forbidden", errors.New("exportjob: DefenderAgents: create: graphclient: POST https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs: status 403: forbidden")},
		{"other", errors.New("exportjob: DefenderAgents: create: boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{err: tc.err}
			c := New(runner, nil)
			rec := telemetrytest.New()

			if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect returned error, want nil (skip-and-log): %v", err)
			}
			if points := rec.MetricPoints(signalCountMetricName); len(points) != 0 {
				t.Errorf("expected no gauge points on export failure, got %+v", points)
			}
			if logs := rec.LogRecords(); len(logs) != 0 {
				t.Errorf("expected no log records on export failure, got %+v", logs)
			}
		})
	}
}

func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	c := New(nil, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error, want nil: %v", err)
	}
	if points := rec.MetricPoints(signalCountMetricName); len(points) != 0 {
		t.Errorf("expected no gauge points, got %+v", points)
	}
}

// TestProductStatusesForDecodesLiveBitmask is the #142 regression guard for
// the Defender half.
//
// ProductStatus is a BITMASK of windowsDefenderProductStatus flags, and the
// wire sends the integer — never a name. Probed as graph2otel-poller against
// DefenderAgents on 2026-07-17: the column returned '524288' and '524416', and
// gets NO ProductStatus_loc sibling even when localizationType is explicitly
// set to LocalizedValuesAsAdditionalColumn (unlike DeviceState, which does get
// one). So there is no server-side decode to lean on here at all.
//
// The predecessor of this test asserted productStatusBucketFor("noStatus") and
// ("AVSignaturesOutOfDate") — enum NAMES. The old lookup was name-keyed, so
// those passed, while every live row fell to "other". The fixture agreed with
// the code and both disagreed with the wire.
func TestProductStatusesForDecodesLiveBitmask(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		// Both values below were observed live on m7kni 2026-07-17.
		{
			name: "live 524288 is the single noStatusFlagsSet bit (2^19)",
			raw:  "524288",
			want: []string{"no_status_flags_set"},
		},
		{
			// The whole reason a scalar lookup cannot work: this is TWO flags.
			name: "live 524416 is two flags: 2^19 | 2^7",
			raw:  "524416",
			want: []string{"no_status_flags_set", "no_quick_scan_happened_for_specified_period"},
		},
		{
			// noStatus (0) has no bits set, so a naive bit-walk emits nothing
			// at all for it and the device silently vanishes from the metric.
			// It is also NOT the same thing as noStatusFlagsSet (524288).
			name: "0 is noStatus, a distinct value from noStatusFlagsSet",
			raw:  "0",
			want: []string{"no_status"},
		},
		{
			name: "an unmapped bit is named, never silently dropped",
			raw:  "536870912", // 2^29, undocumented
			want: []string{"unknown_bit_29"},
		},
		{
			name: "a known flag alongside an unmapped bit keeps both",
			raw:  "536870916", // 2^29 | 2^2
			want: []string{"pending_full_scan_due_to_threat_action", "unknown_bit_29"},
		},
		{name: "empty column", raw: "", want: []string{productStatusUnknown}},
		{name: "unparseable", raw: "not-an-int", want: []string{productStatusUnknown}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := productStatusesFor(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("productStatusesFor(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g] = true
			}
			for _, w := range tc.want {
				if !gotSet[w] {
					t.Errorf("productStatusesFor(%q) = %v, want it to contain %q", tc.raw, got, w)
				}
			}
		})
	}
}

// TestProductStatusNeverBucketsWholeFleetToOther is the direct regression test
// for the shipped symptom: intune_defender_agents_product_status{status="other"}
// was 100% of the fleet, every cycle, and looked healthy because "other" is a
// designed-in bucket rather than an error.
func TestProductStatusNeverBucketsWholeFleetToOther(t *testing.T) {
	// The exact three rows the live tenant returns, device-for-device
	// (probed 2026-07-17; the export was re-run selecting only
	// DeviceName+ProductStatus to pin which device carries which value,
	// rather than assuming an order).
	runner := &fakeRunner{rows: []exportjob.Row{
		row("dev-1", "HAMRIG", "rob@m7kni.io", "0", "524288", true, true, false, true, true),
		row("dev-2", "LAPHAM", "rob@m7kni.io", "0", "524288", true, true, false, true, true),
		row("dev-3", "DESKTOP-CB3D9AB", "rob@m7kni.io", "0", "524416", true, true, false, true, true),
	}}
	c := New(runner, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	points := rec.MetricPoints(productStatusMetricName)
	if len(points) == 0 {
		t.Fatal("no product_status points emitted")
	}
	// One point per SET FLAG, mirroring this collector's sibling
	// count{signal} gauge: flags are independent, so this is a set of counts,
	// not a partition. 524416 contributes to both of its flags.
	want := map[string]float64{
		"no_status_flags_set":                         3, // all three rows carry 2^19
		"no_quick_scan_happened_for_specified_period": 1, // only DESKTOP-CB3D9AB's 524416
	}
	if len(points) != len(want) {
		t.Fatalf("got %d product_status points, want %d: %+v", len(points), len(want), points)
	}
	for _, p := range points {
		if p.Attrs["status"] == "other" {
			t.Errorf("live wire values bucketed to \"other\" - the #142 bug is back: %+v", p)
		}
		wv, ok := want[p.Attrs["status"]]
		if !ok {
			t.Errorf("unexpected product_status point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("status %q: value = %v, want %v", p.Attrs["status"], p.Value, wv)
		}
	}
}

func TestExperimentalAndPermissions(t *testing.T) {
	c := New(nil, nil)
	if !c.Experimental() {
		t.Error("expected Experimental() = true")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.ReadWrite.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.ReadWrite.All]", perms)
	}
	if c.Name() != collectorName {
		t.Errorf("Name() = %q, want %q", c.Name(), collectorName)
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval() = %v, want 6h", c.DefaultInterval())
	}
}
