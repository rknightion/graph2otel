package hardwareinventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is the GET+POST double this collector needs: GET for the id-listing
// page walk, POST for /$batch. Every batch request body is retained so the tests
// can assert the chunking (20 sub-requests per call) rather than trusting it.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error

	// batchBodies are the raw POST bodies sent to /$batch, in order.
	batchBodies [][]byte
	// batchReply, when set, produces the response for the Nth batch call.
	batchReply func(n int, req batchRequest) ([]byte, error)
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

func (f *fakeGraph) RawPost(_ context.Context, url string, body []byte, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	n := len(f.batchBodies)
	f.batchBodies = append(f.batchBodies, body)
	var req batchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("fakeGraph: undecodable batch body: %w", err)
	}
	if f.batchReply == nil {
		return nil, fmt.Errorf("fakeGraph: no batch reply configured for %q", url)
	}
	return f.batchReply(n, req)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

func listURL() string { return defaultBaseURL + listPath }
func batchURL() string {
	return defaultBaseURL + batchPath
}

// liveList is the id-listing page for the ten m7kni devices, in the order the
// probe returned them. Only id + deviceName are selected: everything else on the
// twin comes from the per-device $batch sub-response.
const liveList = `{"value":[
 {"id":"0d705f2d-4dd3-496f-bacb-0ae04afa7f8a","deviceName":"DESKTOP-2F6PPF2"},
 {"id":"e4639a7f-4d77-d901-1e78-57646ca78cb8","deviceName":"oli"},
 {"id":"4ada2149-e9cb-4c34-827a-8df692a9065c","deviceName":"wintest"},
 {"id":"7bed7008-3922-465a-8af2-a435b6119bef","deviceName":"DESKTOP-MHTMHH4"},
 {"id":"2af9ec65-db9b-455c-8b3a-7a2691958b88","deviceName":"TampooniPad"},
 {"id":"ef50a512-0b94-4d2f-8bd2-cb91c4c86417","deviceName":"tablet-office"},
 {"id":"ed93eebf-969a-4595-956f-fae11a31af99","deviceName":"tablet-lounge"},
 {"id":"3c1ff69c-ab91-46c7-ae0f-ef53988e92c0","deviceName":"Tampooni"},
 {"id":"33dcca32-d6ea-478b-88d9-e2a891f9d83a","deviceName":"mbp14"},
 {"id":"57d346d7-ddf1-489b-b70d-a30dce1e2458","deviceName":"MBP16"}
]}`

// liveBatchResponse is the verbatim $batch payload for those ten devices —
// every hardwareInformation body byte-for-byte off the beta wire (probed as
// graph2otel-poller on m7kni, 2026-07-21), wrapped in the documented $batch
// response envelope. Mappers are written against this and never against
// Microsoft's docs (#142).
func liveBatchResponse(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "batch-response.json"))
	if err != nil {
		t.Fatalf("read live batch fixture: %v", err)
	}
	return raw
}

func liveGraph(t *testing.T) *fakeGraph {
	t.Helper()
	body := liveBatchResponse(t)
	return &fakeGraph{
		bodies:     map[string]string{listURL(): liveList},
		batchReply: func(int, batchRequest) ([]byte, error) { return body, nil },
	}
}

func collect(t *testing.T, g *fakeGraph) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func twinFor(t *testing.T, rec *telemetrytest.Recorder, deviceName string) telemetrytest.LogRecord {
	t.Helper()
	for _, l := range rec.LogRecords() {
		if l.Attrs[semconv.AttrDeviceName] == deviceName {
			return l
		}
	}
	t.Fatalf("no %s twin for device %q", eventName, deviceName)
	return telemetrytest.LogRecord{}
}

// seriesByKey indexes a metric's points by the values of the given attribute
// keys, so a test asserts on the whole series set rather than one point.
func seriesByKey(t *testing.T, rec *telemetrytest.Recorder, metric string, keys ...string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		if p.Kind != "gauge" {
			t.Errorf("%s kind = %q, want gauge", metric, p.Kind)
		}
		if len(p.Attrs) != len(keys) {
			t.Errorf("%s series %+v carries %d attributes, want exactly %v", metric, p.Attrs, len(p.Attrs), keys)
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, p.Attrs[k])
		}
		out[strings.Join(parts, "|")] = p.Value
	}
	return out
}

func TestDevicesGaugeCountsByOsAndManufacturer(t *testing.T) {
	rec := collect(t, liveGraph(t))

	got := seriesByKey(t, rec, devicesMetricName, semconv.AttrOperatingSystem, semconv.AttrManufacturer)
	want := map[string]float64{
		"windows|Parallels International GmbH.": 1,
		"windows|Microsoft Corporation":         1,
		"windows|QEMU":                          1,
		"ios|Apple":                             4,
		"macos|Apple":                           2,
		// oli, the Defender-managed Linux host, reports a null manufacturer.
		"linux|unknown": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d device series, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("devices[%s] = %v, want %v", k, got[k], w)
		}
	}
}

func TestTpmGaugeCountsBySpecificationVersion(t *testing.T) {
	rec := collect(t, liveGraph(t))

	got := seriesByKey(t, rec, tpmMetricName, semconv.AttrTpmSpecificationVersion)
	// The wire value is a comma-joined TRIPLE, not a plain version number, and is
	// emitted verbatim (#142). Seven devices (Linux/iOS/macOS) report none.
	want := map[string]float64{
		"2.0, 0, 1.16": 1,
		"2.0, 0, 1.38": 1,
		"2.0, 0, 1.64": 1,
		"unknown":      7,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tpm series, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("tpm_devices[%s] = %v, want %v", k, got[k], w)
		}
	}
}

func TestDeviceGuardGaugeCountsByVbsAndCredentialGuardState(t *testing.T) {
	rec := collect(t, liveGraph(t))

	got := seriesByKey(t, rec, deviceGuardMetricName, semconv.AttrVbsState, semconv.AttrCredentialGuardState)
	// The non-Windows devices report Windows-only Device Guard values verbatim —
	// see the package doc; they are NOT filtered by OS and NOT "corrected".
	want := map[string]float64{
		"notConfigured|virtualizationBasedSecurityNotRunning": 2,
		"notConfigured|notLicensed":                           1,
		"running|running":                                     7,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d device-guard series, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("device_guard_devices[%s] = %v, want %v", k, got[k], w)
		}
	}
}

func TestStorageGaugeSumsBytesByOsAndState(t *testing.T) {
	rec := collect(t, liveGraph(t))

	got := seriesByKey(t, rec, storageMetricName, semconv.AttrOperatingSystem, semconv.AttrStorageState)
	want := map[string]float64{
		"windows|total": 515984326656,
		"windows|free":  441223593984,
		"ios|total":     1924145348608,
		"ios|free":      1154645222179,
		"macos|total":   2998960914432,
		"macos|free":    2435246456832,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d storage series, want %d: %+v", len(got), len(want), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("storage_bytes[%s] = %v, want %v", k, got[k], w)
		}
	}
	// oli reports totalStorageSpace=0 on a running Linux host: not a measurement,
	// "not reported". It must contribute NO series rather than claim zero bytes.
	for k := range got {
		if strings.HasPrefix(k, "linux|") {
			t.Errorf("storage_bytes has a linux series %q — a device reporting totalStorageSpace=0 must be excluded, not summed as zero", k)
		}
	}
	for _, p := range rec.MetricPoints(storageMetricName) {
		if p.Unit != "By" {
			t.Errorf("storage_bytes unit = %q, want By", p.Unit)
		}
	}
}

// TestPerEntityFieldsNeverBecomeMetricLabels is the #112/#114 guard: storage
// bytes, serial numbers, wired IPs, TPM instance versions and the device
// identity ride the twin, never a metric label. signalcapture.Main covers a
// fixed banned list; this pins THIS collector's per-entity fields, most of which
// are not on that list.
func TestPerEntityFieldsNeverBecomeMetricLabels(t *testing.T) {
	rec := collect(t, liveGraph(t))

	allowed := map[string]bool{
		semconv.AttrOperatingSystem:         true,
		semconv.AttrManufacturer:            true,
		semconv.AttrTpmSpecificationVersion: true,
		semconv.AttrVbsState:                true,
		semconv.AttrCredentialGuardState:    true,
		semconv.AttrStorageState:            true,
	}
	banned := map[string]bool{
		semconv.AttrDeviceId:                    true,
		semconv.AttrDeviceName:                  true,
		semconv.AttrSerialNumber:                true,
		semconv.AttrTotalStorageBytes:           true,
		semconv.AttrFreeStorageBytes:            true,
		semconv.AttrWiredIpv4Addresses:          true,
		semconv.AttrTpmVersion:                  true,
		semconv.AttrTpmManufacturer:             true,
		semconv.AttrProductName:                 true,
		semconv.AttrSystemManagementBiosVersion: true,
		semconv.AttrImei:                        true,
		semconv.AttrPhoneNumber:                 true,
	}
	for _, name := range []string{devicesMetricName, tpmMetricName, deviceGuardMetricName, storageMetricName} {
		points := rec.MetricPoints(name)
		if len(points) == 0 {
			t.Errorf("%s emitted no points — the guard would pass vacuously", name)
		}
		for _, p := range points {
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

func TestWindowsTwinCarriesTheNewHardwareFields(t *testing.T) {
	rec := collect(t, liveGraph(t))

	if n := len(rec.LogRecords()); n != 10 {
		t.Fatalf("got %d twins, want 10 (one per device)", n)
	}
	tw := twinFor(t, rec, "DESKTOP-MHTMHH4")
	if tw.EventName != eventName {
		t.Errorf("EventName = %q, want %q", tw.EventName, eventName)
	}
	if !tw.Timestamp.IsZero() {
		t.Errorf("twin timestamp = %v, want zero (state snapshot, not an event)", tw.Timestamp)
	}
	if tw.SeverityText != "INFO" {
		t.Errorf("severity = %q, want INFO", tw.SeverityText)
	}
	want := map[string]string{
		semconv.AttrDeviceId:                            "7bed7008-3922-465a-8af2-a435b6119bef",
		semconv.AttrDeviceName:                          "DESKTOP-MHTMHH4",
		semconv.AttrOperatingSystem:                     "Windows",
		semconv.AttrManufacturer:                        "QEMU",
		semconv.AttrTotalStorageBytes:                   "106362306560",
		semconv.AttrFreeStorageBytes:                    "87930781696",
		semconv.AttrTpmSpecificationVersion:             "2.0, 0, 1.64",
		semconv.AttrTpmManufacturer:                     "IBM",
		semconv.AttrTpmVersion:                          "8217.4131.22.13878",
		semconv.AttrSystemManagementBiosVersion:         "4.2025.05-2",
		semconv.AttrOperatingSystemEdition:              "Enterprise",
		semconv.AttrOperatingSystemProductType:          "72",
		semconv.AttrOperatingSystemLanguage:             "en-GB",
		semconv.AttrDeviceLicensingStatus:               "unknown",
		semconv.AttrIsSupervised:                        "false",
		semconv.AttrIsSharedDevice:                      "false",
		semconv.AttrWiredIpv4Addresses:                  "10.0.25.136,10.0.50.152,10.0.0.199,10.0.100.231",
		semconv.AttrDeviceGuardHardwareRequirementState: "meetHardwareRequirements",
		semconv.AttrVbsState:                            "notConfigured",
		semconv.AttrCredentialGuardState:                "virtualizationBasedSecurityNotRunning",
	}
	for k, w := range want {
		if got := tw.Attrs[k]; got != w {
			t.Errorf("twin attr %s = %q, want %q", k, got, w)
		}
	}
	// Fields intune.devices already owns are deliberately NOT re-emitted here.
	for _, k := range []string{semconv.AttrSerialNumber, semconv.AttrModel, semconv.AttrWifiMacAddress, semconv.AttrIsEncrypted} {
		if v, ok := tw.Attrs[k]; ok {
			t.Errorf("twin re-emits %q = %q, which intune.devices already carries", k, v)
		}
	}
}

// Battery health and charge cycles read 0 on EVERY device on the wire, including
// two working MacBook Pros. Zero battery health on a working laptop is not a
// measurement, it is "not reported" — so 0 omits the attribute. batteryLevelPercentage
// is NOT given the same treatment: 100.0 there is live and plausible.
func TestBatteryZeroIsAbsentButLevelIsEmitted(t *testing.T) {
	rec := collect(t, liveGraph(t))

	tw := twinFor(t, rec, "mbp14")
	for _, k := range []string{semconv.AttrBatteryHealthPercentage, semconv.AttrBatteryChargeCycles} {
		if v, ok := tw.Attrs[k]; ok {
			t.Errorf("twin attr %s = %q for a wire 0 — 0 means 'not reported' on this field and must omit the attribute", k, v)
		}
	}
	if got := tw.Attrs[semconv.AttrBatteryLevelPercentage]; got != "100" {
		t.Errorf("battery_level_percentage = %q, want 100 (live and plausible — never suppressed)", got)
	}
	// The Linux host reports a NULL battery level: absent, not 0.
	if v, ok := twinFor(t, rec, "oli").Attrs[semconv.AttrBatteryLevelPercentage]; ok {
		t.Errorf("battery_level_percentage = %q for a null wire value, want the attribute omitted", v)
	}
}

// Nulls vary by platform: iOS/macOS/Linux populate a different subset than
// Windows. A null field omits its attribute rather than emitting "".
func TestNullFieldsOmitTheirAttributes(t *testing.T) {
	rec := collect(t, liveGraph(t))

	tw := twinFor(t, rec, "oli")
	for _, k := range []string{
		semconv.AttrManufacturer,
		semconv.AttrTpmSpecificationVersion,
		semconv.AttrTpmManufacturer,
		semconv.AttrTpmVersion,
		semconv.AttrSystemManagementBiosVersion,
		semconv.AttrOperatingSystemEdition,
		semconv.AttrOperatingSystemLanguage,
		semconv.AttrProductName,
		semconv.AttrWiredIpv4Addresses, // [] on the wire
		semconv.AttrTotalStorageBytes,  // 0 = not reported
		semconv.AttrFreeStorageBytes,
	} {
		if v, ok := tw.Attrs[k]; ok {
			t.Errorf("twin attr %s = %q for a null/empty wire value, want it omitted", k, v)
		}
	}
	// Device Guard reports Windows-only values on this Linux host. Emitted
	// verbatim — not filtered by OS, and not to be read as a Linux security posture.
	if got := tw.Attrs[semconv.AttrVbsState]; got != "running" {
		t.Errorf("vbs_state = %q, want the verbatim wire value running", got)
	}
}

// The cellular identity fields exist on no other collector, so they ride this
// twin (#114: "not a metric label" means log twin, never dropped).
func TestCellularTwinFields(t *testing.T) {
	rec := collect(t, liveGraph(t))

	tw := twinFor(t, rec, "Tampooni")
	want := map[string]string{
		semconv.AttrImei:               "354687611308343",
		semconv.AttrEsimIdentifier:     "89049032020008884800227743738943",
		semconv.AttrPhoneNumber:        "+447869113493",
		semconv.AttrSubscriberCarrier:  "EE",
		semconv.AttrCellularTechnology: "GSM",
		semconv.AttrProductName:        "iPhone18,2",
		semconv.AttrIsSupervised:       "true",
	}
	for k, w := range want {
		if got := tw.Attrs[k]; got != w {
			t.Errorf("twin attr %s = %q, want %q", k, got, w)
		}
	}
	// tablet-office reports phoneNumber "" — omitted, never emitted blank.
	if v, ok := twinFor(t, rec, "tablet-office").Attrs[semconv.AttrPhoneNumber]; ok {
		t.Errorf("phone_number = %q for an empty wire value, want it omitted", v)
	}
}

// deviceLicensingStatus is a STRING on the wire, and one live row carries the
// numeric-looking "25" — Graph stringifies an enum member it has no name for. It
// must survive as a string, and a tenant that sends a bare number must not fail
// the row.
func TestDeviceLicensingStatusTolerantScalar(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"live named value", `"unknown"`, "unknown"},
		{"live stringified number", `"25"`, "25"},
		{"bare number", `25`, "25"},
		{"null", `null`, ""},
		{"unexpected shape", `{"code":25}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := oneDeviceGraph(t, `{"id":"dev1","deviceName":"one","operatingSystem":"Windows",
				"hardwareInformation":{"deviceLicensingStatus":`+tc.raw+`}}`)
			rec := collect(t, g)
			logs := rec.LogRecords()
			if len(logs) != 1 {
				t.Fatalf("got %d twins, want 1 — an unexpected deviceLicensingStatus shape must not drop the row", len(logs))
			}
			got, ok := logs[0].Attrs[semconv.AttrDeviceLicensingStatus]
			if tc.want == "" {
				if ok {
					t.Errorf("device_licensing_status = %q, want the attribute omitted", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("device_licensing_status = %q, want %q", got, tc.want)
			}
		})
	}
}

// oneDeviceGraph wires a single-device list plus a $batch reply carrying body as
// that device's sub-response.
func oneDeviceGraph(t *testing.T, body string) *fakeGraph {
	t.Helper()
	return &fakeGraph{
		bodies: map[string]string{listURL(): `{"value":[{"id":"dev1","deviceName":"one"}]}`},
		batchReply: func(_ int, req batchRequest) ([]byte, error) {
			if len(req.Requests) != 1 {
				t.Fatalf("got %d sub-requests, want 1", len(req.Requests))
			}
			return []byte(`{"responses":[{"id":"` + req.Requests[0].ID + `","status":200,"body":` + body + `}]}`), nil
		},
	}
}

// The Graph $batch ceiling is 20 sub-requests. A fleet larger than that must
// split across calls, not send one oversized batch that Graph rejects wholesale.
func TestBatchChunksAtTwenty(t *testing.T) {
	const n = 25
	var list strings.Builder
	list.WriteString(`{"value":[`)
	for i := range n {
		if i > 0 {
			list.WriteString(",")
		}
		fmt.Fprintf(&list, `{"id":"dev%d","deviceName":"d%d"}`, i, i)
	}
	list.WriteString(`]}`)

	g := &fakeGraph{
		bodies: map[string]string{listURL(): list.String()},
		batchReply: func(_ int, req batchRequest) ([]byte, error) {
			if len(req.Requests) > batchChunkSize {
				t.Errorf("batch carried %d sub-requests, want at most %d", len(req.Requests), batchChunkSize)
			}
			var resp strings.Builder
			resp.WriteString(`{"responses":[`)
			for i, sub := range req.Requests {
				if i > 0 {
					resp.WriteString(",")
				}
				if sub.Method != "GET" {
					t.Errorf("sub-request method = %q, want GET", sub.Method)
				}
				if strings.Contains(sub.URL, defaultBaseURL) {
					t.Errorf("sub-request URL %q carries the service root; $batch sub-URLs are service-relative", sub.URL)
				}
				fmt.Fprintf(&resp, `{"id":%q,"status":200,"body":{"id":"x%d","deviceName":"n%d","operatingSystem":"Windows","hardwareInformation":{"manufacturer":"ACME"}}}`, sub.ID, i, i)
			}
			resp.WriteString(`]}`)
			return []byte(resp.String()), nil
		},
	}

	rec := collect(t, g)

	if len(g.batchBodies) != 2 {
		t.Fatalf("sent %d batch requests for %d devices, want 2 (ceil(25/20))", len(g.batchBodies), n)
	}
	var first, second batchRequest
	if err := json.Unmarshal(g.batchBodies[0], &first); err != nil {
		t.Fatalf("decode first batch: %v", err)
	}
	if err := json.Unmarshal(g.batchBodies[1], &second); err != nil {
		t.Fatalf("decode second batch: %v", err)
	}
	if len(first.Requests) != batchChunkSize || len(second.Requests) != n-batchChunkSize {
		t.Errorf("chunk sizes = %d/%d, want %d/%d", len(first.Requests), len(second.Requests), batchChunkSize, n-batchChunkSize)
	}
	if got := len(rec.LogRecords()); got != n {
		t.Errorf("got %d twins, want %d (every chunk consumed)", got, n)
	}
}

// Graph does NOT guarantee $batch responses come back in request order; they are
// correlated by sub-request id.
func TestBatchResponsesAreMatchedByIdNotOrder(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{listURL(): `{"value":[{"id":"a","deviceName":"alpha"},{"id":"b","deviceName":"bravo"}]}`},
		batchReply: func(_ int, req batchRequest) ([]byte, error) {
			// Reply in REVERSE order, and give each body a distinctive manufacturer.
			var resp strings.Builder
			resp.WriteString(`{"responses":[`)
			for i := len(req.Requests) - 1; i >= 0; i-- {
				sub := req.Requests[i]
				if i < len(req.Requests)-1 {
					resp.WriteString(",")
				}
				name := "alpha"
				mfr := "AlphaCorp"
				if strings.Contains(sub.URL, "/b?") || strings.HasSuffix(sub.URL, "/b") {
					name, mfr = "bravo", "BravoCorp"
				}
				fmt.Fprintf(&resp, `{"id":%q,"status":200,"body":{"id":%q,"deviceName":%q,"operatingSystem":"Windows","hardwareInformation":{"manufacturer":%q}}}`,
					sub.ID, name[:1], name, mfr)
			}
			resp.WriteString(`]}`)
			return []byte(resp.String()), nil
		},
	}
	rec := collect(t, g)
	if got := twinFor(t, rec, "bravo").Attrs[semconv.AttrManufacturer]; got != "BravoCorp" {
		t.Errorf("bravo manufacturer = %q, want BravoCorp — sub-responses must be correlated by id", got)
	}
}

// A per-device sub-response failure (the device was deleted between the list and
// the batch, or is scoped away) skips that device with a warning. It must not
// fail the collection or drop the other 19 devices in the chunk.
func TestFailedSubResponseIsSkippedNotFatal(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{listURL(): `{"value":[{"id":"a","deviceName":"alpha"},{"id":"b","deviceName":"bravo"},{"id":"c","deviceName":"charlie"}]}`},
		batchReply: func(_ int, req batchRequest) ([]byte, error) {
			statuses := map[string]int{"a": 200, "b": 404, "c": 403}
			var resp strings.Builder
			resp.WriteString(`{"responses":[`)
			for i, sub := range req.Requests {
				if i > 0 {
					resp.WriteString(",")
				}
				key := sub.URL[strings.LastIndex(sub.URL, "/")+1 : strings.Index(sub.URL, "?")]
				switch statuses[key] {
				case 200:
					fmt.Fprintf(&resp, `{"id":%q,"status":200,"body":{"id":"a","deviceName":"alpha","operatingSystem":"Windows","hardwareInformation":{"manufacturer":"ACME"}}}`, sub.ID)
				default:
					fmt.Fprintf(&resp, `{"id":%q,"status":%d,"body":{"error":{"code":"ResourceNotFound","message":"gone"}}}`, sub.ID, statuses[key])
				}
			}
			resp.WriteString(`]}`)
			return []byte(resp.String()), nil
		},
	}

	rec := collect(t, g)

	if n := len(rec.LogRecords()); n != 1 {
		t.Fatalf("got %d twins, want 1 — the 404 and 403 devices are skipped, the 200 device is kept", n)
	}
	if got := twinFor(t, rec, "alpha").Attrs[semconv.AttrManufacturer]; got != "ACME" {
		t.Errorf("surviving twin manufacturer = %q, want ACME", got)
	}
	points := seriesByKey(t, rec, devicesMetricName, semconv.AttrOperatingSystem, semconv.AttrManufacturer)
	if len(points) != 1 || points["windows|ACME"] != 1 {
		t.Errorf("devices gauge = %+v, want a single windows|ACME series of 1", points)
	}
}

// A device the list returned but the batch never answered for at all (Graph
// dropped the sub-response) is skipped, not silently counted as an empty device.
func TestMissingSubResponseIsSkipped(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{listURL(): `{"value":[{"id":"a","deviceName":"alpha"},{"id":"b","deviceName":"bravo"}]}`},
		batchReply: func(_ int, req batchRequest) ([]byte, error) {
			sub := req.Requests[0]
			return fmt.Appendf(nil, `{"responses":[{"id":%q,"status":200,"body":{"id":"a","deviceName":"alpha","operatingSystem":"Windows","hardwareInformation":{"manufacturer":"ACME"}}}]}`, sub.ID), nil
		},
	}
	rec := collect(t, g)
	if n := len(rec.LogRecords()); n != 1 {
		t.Fatalf("got %d twins, want 1", n)
	}
}

// A whole-batch POST failure is NOT partial-data territory: the gauges are a
// fleet snapshot, and emitting one that silently omits a chunk would read as
// devices disappearing. The collection fails and emits nothing.
func TestBatchPostFailureFailsTheCollection(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{listURL(): liveList},
		errs:   map[string]error{batchURL(): errors.New("boom")},
	}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("a $batch POST failure must be surfaced")
	}
	if len(rec.LogRecords()) != 0 || len(rec.MetricPoints(devicesMetricName)) != 0 {
		t.Error("a failed batch must emit nothing — a partial fleet snapshot reads as devices vanishing")
	}
}

func TestForbiddenListSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{listURL(): errors.New("graphclient: GET ...: status 403: forbidden")}}
	rec := telemetrytest.New()
	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("403 should be a graceful skip, got: %v", err)
	}
	if len(rec.LogRecords()) != 0 || len(rec.MetricPoints(devicesMetricName)) != 0 {
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

func TestEmptyFleetSendsNoBatchAndEmitsNoTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{listURL(): `{"value":[]}`}}
	rec := collect(t, g)
	if len(g.batchBodies) != 0 {
		t.Errorf("sent %d batch requests for an empty fleet, want 0", len(g.batchBodies))
	}
	if len(rec.LogRecords()) != 0 {
		t.Error("no devices => no twins")
	}
}

// A Graph client with no POST capability cannot run this collector at all.
// Failing loudly beats a silent empty snapshot.
func TestMissingPosterIsAnError(t *testing.T) {
	rec := telemetrytest.New()
	err := New(getOnlyGraph{}, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("a GraphClient without RawPost must fail the collection, not emit an empty snapshot")
	}
	if !strings.Contains(err.Error(), "$batch") {
		t.Errorf("error = %v, want it to name the missing $batch capability", err)
	}
}

type getOnlyGraph struct{}

func (getOnlyGraph) RawGet(context.Context, string) ([]byte, error) { return nil, errors.New("no") }
func (getOnlyGraph) RawGetWithHeaders(context.Context, string, map[string]string) ([]byte, error) {
	return nil, errors.New("no")
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != collectorName || collectorName != "intune.hardware_inventory" {
		t.Errorf("Name() = %q, want intune.hardware_inventory", c.Name())
	}
	// hardwareInformation does not exist on the v1.0 managedDevice type at all
	// (live-measured 2026-07-21) — beta base URL, so Experimental.
	if defaultBaseURL != "https://graph.microsoft.com/beta" {
		t.Errorf("defaultBaseURL = %q, want the beta root", defaultBaseURL)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta-only property)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.Read.All" {
		t.Errorf("RequiredPermissions = %v, want the single read-only device scope", perms)
	}
	if c.DefaultInterval() != 24*time.Hour {
		t.Errorf("DefaultInterval = %v, want 24h — Intune refreshes device hardware inventory on a multi-day cycle", c.DefaultInterval())
	}
	if batchChunkSize != 20 {
		t.Errorf("batchChunkSize = %d, want 20 (the Graph $batch ceiling)", batchChunkSize)
	}
}

// The emitter is the only thing that stamps tenant_id and ingest_transport
// (#141/#143); a collector that sets either itself is a second writer.
func TestTwinDoesNotStampEmitterOwnedAttributes(t *testing.T) {
	rec := collect(t, liveGraph(t))
	for _, l := range rec.LogRecords() {
		for _, k := range []string{semconv.AttrTenantID, semconv.AttrIngestTransport} {
			if v, ok := l.Attrs[k]; ok {
				t.Errorf("twin sets emitter-owned attribute %s = %q", k, v)
			}
		}
	}
}
