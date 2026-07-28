package featureupdatedevices

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors) - mirrors
// intune/configprofiles's test fake.
type fakeGraph struct {
	bodies       map[string]string
	errs         map[string]error
	requestedURL []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.requestedURL = append(f.requestedURL, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const profilesURL = betaBaseURL + "/deviceManagement/windowsFeatureUpdateProfiles"

// forbidden403 mimics the graphclient error format that RawGet/RawPost produce
// for an HTTP 403, so isForbidden's substring check is exercised the way it
// would be against the real client.
func forbidden403(what string) error {
	return errors.New("graphclient: " + what + ": status 403: Forbidden")
}

// liveProfilesBody is VERBATIM (id, displayName, featureUpdateVersion) from
// the two windowsFeatureUpdateProfiles captured on m7kni, probed as
// graph2otel-poller 2026-07-28 (#351). Other fields the live response carries
// (description, createdDateTime, rolloutSettings, ...) are omitted: this
// collector never reads them.
const liveProfilesBody = `{
  "@odata.count": 2,
  "value": [
    {
      "id": "29851ca2-ee8c-4508-8eec-b4f21f31ebc0",
      "displayName": "Windows Autopatch - DSS policy - autopatch multiphase - Phase 1",
      "featureUpdateVersion": "Windows 11, version 25H2"
    },
    {
      "id": "8714504a-9bf5-498c-ac03-3aa086a26d9e",
      "displayName": "feature",
      "featureUpdateVersion": "Windows 11, version 25H2"
    }
  ]
}`

const (
	firstPolicyID   = "29851ca2-ee8c-4508-8eec-b4f21f31ebc0"
	firstPolicyName = "Windows Autopatch - DSS policy - autopatch multiphase - Phase 1"
	secondPolicyID  = "8714504a-9bf5-498c-ac03-3aa086a26d9e"
)

// liveDeviceRows is VERBATIM the 9-row FeatureUpdateDeviceState export
// captured for firstPolicyID on m7kni, probed as graph2otel-poller 2026-07-28
// (#351): 6 Success rows and 3 InProgress rows, all with alert code "0".
func liveDeviceRows() []exportjob.Row {
	success := func(deviceID, deviceName, upn string) exportjob.Row {
		return exportjob.Row{
			"PolicyId":                      firstPolicyID,
			"DeviceId":                      deviceID,
			"DeviceName":                    deviceName,
			"UPN":                           upn,
			"AggregateState":                "Success",
			"AggregateState_loc":            "Success",
			"CurrentDeviceUpdateStatus":     "8",
			"CurrentDeviceUpdateStatus_loc": "Installed",
			"LatestAlertMessage":            "0",
			"LatestAlertMessage_loc":        "Not applicable",
		}
	}
	inProgress := func(deviceID, deviceName, upn string) exportjob.Row {
		return exportjob.Row{
			"PolicyId":                      firstPolicyID,
			"DeviceId":                      deviceID,
			"DeviceName":                    deviceName,
			"UPN":                           upn,
			"AggregateState":                "InProgress",
			"AggregateState_loc":            "In progress",
			"CurrentDeviceUpdateStatus":     "2",
			"CurrentDeviceUpdateStatus_loc": "Offering",
			"LatestAlertMessage":            "0",
			"LatestAlertMessage_loc":        "Not applicable",
		}
	}
	return []exportjob.Row{
		success("dc910cbf-ca70-4b6b-a91b-1fffaa3fe54a", "DESKTOP-ROTDNUB", "vmuser@m7kni.io"),
		success("e596236c-d93b-401c-bbd7-3339b5e5487a", "DESKTOP-88S17PG", "vmuser@m7kni.io"),
		success("a4cf1d34-823c-484c-9557-74e2eb1ace06", "winsrv", "rob@m7kni.io"),
		success("13bca6e7-5430-4fb7-9bd2-d91a2d6c8e13", "LAPHAM", "rob@m7kni.io"),
		success("9a799f82-e14b-422e-927f-ecc9ca555b7a", "DESKTOP-N3FH69O", "vmuser@m7kni.io"),
		success("0703fa65-0894-4cce-8492-f4a3bc15b32b", "DESKTOP-HMG7DH5", "vmuser@m7kni.io"),
		inProgress("fd6c44f4-2cf6-4ca2-8713-78acc50bd35b", "DESKTOP-SL2JERV", "rob@m7kni.io"),
		inProgress("ed7fa97c-43e8-47bb-8ce1-b61fdd78969d", "DESKTOP-82I1146", "rob@m7kni.io"),
		inProgress("4ada2149-e9cb-4c34-827a-8df692a9065c", "wintest", "rob@m7kni.io"),
	}
}

// fakeExport is a fakeable exportjob.Runner keyed by the request Filter, so a
// test can give each fanned-out profile its own canned rows or error.
type fakeExport struct {
	rowsByFilter map[string][]exportjob.Row
	errByFilter  map[string]error
	reqs         []exportjob.Request
}

func (f *fakeExport) Export(_ context.Context, req exportjob.Request, _ telemetry.Emitter) ([]exportjob.Row, error) {
	f.reqs = append(f.reqs, req)
	if err, ok := f.errByFilter[req.Filter]; ok {
		return nil, err
	}
	return f.rowsByFilter[req.Filter], nil
}

var _ exportjob.Runner = (*fakeExport)(nil)

func filterFor(policyID string) string {
	return "(PolicyId eq '" + policyID + "')"
}

// twoProfilesGraph returns a fakeGraph that lists both live profiles.
func twoProfilesGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{profilesURL: liveProfilesBody}}
}

// TestCollectMapsLiveNineDeviceRows pins the full fan-out: 2 profiles listed,
// one export per profile, the first returning the live 9-row fixture and the
// second returning zero rows (a real, healthy state - #351 acceptance
// criterion), the three gauges correctly bucketed, and a log twin per row.
func TestCollectMapsLiveNineDeviceRows(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  liveDeviceRows(),
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(exp.reqs) != 2 {
		t.Fatalf("export calls = %d, want 2 (one per profile)", len(exp.reqs))
	}

	logs := rec.LogRecords()
	if len(logs) != 9 {
		t.Fatalf("log records = %d, want 9", len(logs))
	}

	warnCount, infoCount := 0, 0
	for _, l := range logs {
		switch l.SeverityText {
		case "WARN":
			warnCount++
		case "INFO":
			infoCount++
		default:
			t.Errorf("unexpected severity %q on log record: %+v", l.SeverityText, l)
		}
		if l.Attrs[semconv.AttrPolicyName] != firstPolicyName {
			t.Errorf("policy_name = %q, want %q", l.Attrs[semconv.AttrPolicyName], firstPolicyName)
		}
		if l.Attrs[semconv.AttrFeatureUpdateVersion] != "Windows 11, version 25H2" {
			t.Errorf("feature_update_version = %q", l.Attrs[semconv.AttrFeatureUpdateVersion])
		}
	}
	if warnCount != 3 {
		t.Errorf("warn twins = %d, want 3 (the InProgress rows)", warnCount)
	}
	if infoCount != 6 {
		t.Errorf("info twins = %d, want 6 (the Success rows)", infoCount)
	}

	// Spot-check one row's full attribute set, including both halves of every
	// bare/_loc pair.
	var first *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].Attrs[semconv.AttrDeviceId] == "dc910cbf-ca70-4b6b-a91b-1fffaa3fe54a" {
			first = &logs[i]
			break
		}
	}
	if first == nil {
		t.Fatal("no twin found for device dc910cbf-...")
	}
	wantAttrs := map[string]string{
		semconv.AttrPolicyName:                  firstPolicyName,
		semconv.AttrFeatureUpdateVersion:        "Windows 11, version 25H2",
		semconv.AttrDeviceId:                    "dc910cbf-ca70-4b6b-a91b-1fffaa3fe54a",
		semconv.AttrDeviceName:                  "DESKTOP-ROTDNUB",
		semconv.AttrUpn:                         "vmuser@m7kni.io",
		semconv.AttrAggregateState:              "Success",
		semconv.AttrAggregateStateLocalized:     "Success",
		semconv.AttrDeviceUpdateStatus:          "8",
		semconv.AttrDeviceUpdateStatusLocalized: "Installed",
		semconv.AttrLatestAlertMessage:          "0",
		semconv.AttrLatestAlertMessageLocalized: "Not applicable",
	}
	for k, want := range wantAttrs {
		if got := first.Attrs[k]; got != want {
			t.Errorf("twin attr %q = %q, want %q", k, got, want)
		}
	}
	// +1 for ingest_transport: telemetry.WithTransport stamps it on every
	// record at the emitter boundary (#141) - this collector does not author
	// it itself.
	if len(first.Attrs) != len(wantAttrs)+1 {
		t.Errorf("twin has %d attrs, want %d (%d authored + ingest_transport): %+v", len(first.Attrs), len(wantAttrs)+1, len(wantAttrs), first.Attrs)
	}

	statePoints := rec.MetricPoints(metricStates)
	wantStates := map[[2]string]float64{
		{firstPolicyName, "Success"}:    6,
		{firstPolicyName, "InProgress"}: 3,
	}
	assertGaugeCounts(t, statePoints, semconv.AttrAggregateState, wantStates)

	statusPoints := rec.MetricPoints(metricUpdateStatus)
	wantStatus := map[[2]string]float64{
		{firstPolicyName, "8"}: 6,
		{firstPolicyName, "2"}: 3,
	}
	assertGaugeCounts(t, statusPoints, semconv.AttrDeviceUpdateStatus, wantStatus)

	alertPoints := rec.MetricPoints(metricAlerts)
	wantAlerts := map[[2]string]float64{
		{firstPolicyName, "0"}: 9,
	}
	assertGaugeCounts(t, alertPoints, semconv.AttrLatestAlertMessage, wantAlerts)
}

func assertGaugeCounts(t *testing.T, points []telemetrytest.MetricPoint, stateKey string, want map[[2]string]float64) {
	t.Helper()
	if len(points) != len(want) {
		t.Fatalf("got %d points, want %d: %+v", len(points), len(want), points)
	}
	seen := map[[2]string]bool{}
	for _, p := range points {
		k := [2]string{p.Attrs[semconv.AttrPolicyName], p.Attrs[stateKey]}
		wv, ok := want[k]
		if !ok {
			t.Errorf("unexpected point %+v", p)
			continue
		}
		if p.Value != wv {
			t.Errorf("point %+v value = %v, want %v", k, p.Value, wv)
		}
		if p.Unit != "{device}" {
			t.Errorf("point %+v unit = %q, want {device}", k, p.Unit)
		}
		seen[k] = true
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("missing point for %+v", k)
		}
	}
}

// TestMetricValuesAreMachineCodesNeverLocalizedKeysOrValues is the structural
// #351 guard, at BOTH layers a swap can hide in.
//
// A key-only guard (the previous shape of this test, named
// TestNoLocalizedValueReachesAnyMetricAttribute) cannot see a mapper that
// keys the gauge off the WRONG column while still writing it under the RIGHT
// attribute key — e.g. `aggregate_state: row["AggregateState_loc"]` instead
// of `row["AggregateState"]`. The key set is identical either way; only the
// value differs. Proven by a live sabotage round-trip against this exact
// swap (see the package's finishing report) — with only the key check, that
// swap passed clean and only an incidental, hardcoded-value test caught it.
//
// So this test checks both: the three localized keys are absent (a
// regression that would at least be visible), AND the three CODE attributes
// never carry their localized twin's value. The discriminating fixture rows
// are the InProgress ones, deliberately: AggregateState "Success" and
// AggregateState_loc "Success" are byte-identical, so a Success-only fixture
// cannot tell the two columns apart at all — this is exactly why an
// all-Success sample under-specifies the check. "InProgress" vs "In
// progress" (space, lowercase p) actually differs, so it is the only row
// shape that can prove which column fed the gauge.
func TestMetricValuesAreMachineCodesNeverLocalizedKeysOrValues(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  liveDeviceRows(),
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	localizedKeys := []string{
		semconv.AttrAggregateStateLocalized,
		semconv.AttrDeviceUpdateStatusLocalized,
		semconv.AttrLatestAlertMessageLocalized,
	}
	for _, name := range []string{metricStates, metricUpdateStatus, metricAlerts} {
		for _, p := range rec.MetricPoints(name) {
			for _, lk := range localizedKeys {
				if _, ok := p.Attrs[lk]; ok {
					t.Errorf("metric %q point %+v carries localized key %q", name, p, lk)
				}
			}
			for k := range p.Attrs {
				if k == semconv.AttrDeviceId || k == semconv.AttrDeviceName || k == semconv.AttrUpn {
					t.Errorf("metric %q point %+v carries per-entity key %q", name, p, k)
				}
			}
		}
	}

	// Value-level: the live fixture's InProgress rows are the only ones that
	// can discriminate machine value from localized display string.
	wantStateValues := map[string]bool{"Success": true, "InProgress": true}
	for _, p := range rec.MetricPoints(metricStates) {
		v := p.Attrs[semconv.AttrAggregateState]
		if !wantStateValues[v] {
			t.Errorf("metric %q aggregate_state = %q, want one of %v", metricStates, v, wantStateValues)
		}
		if v == "In progress" {
			t.Errorf("metric %q aggregate_state = %q: the LOCALIZED string reached a metric attribute (want the machine code %q)", metricStates, v, "InProgress")
		}
	}

	wantStatusValues := map[string]bool{"8": true, "2": true}
	for _, p := range rec.MetricPoints(metricUpdateStatus) {
		v := p.Attrs[semconv.AttrDeviceUpdateStatus]
		if !wantStatusValues[v] {
			t.Errorf("metric %q device_update_status = %q, want one of %v", metricUpdateStatus, v, wantStatusValues)
		}
		if v == "Offering" || v == "Installed" {
			t.Errorf("metric %q device_update_status = %q: the LOCALIZED string reached a metric attribute (want the machine code)", metricUpdateStatus, v)
		}
	}

	wantAlertValues := map[string]bool{"0": true}
	for _, p := range rec.MetricPoints(metricAlerts) {
		v := p.Attrs[semconv.AttrLatestAlertMessage]
		if !wantAlertValues[v] {
			t.Errorf("metric %q latest_alert_message = %q, want one of %v", metricAlerts, v, wantAlertValues)
		}
		if v == "Not applicable" {
			t.Errorf("metric %q latest_alert_message = %q: the LOCALIZED string reached a metric attribute (want the machine code)", metricAlerts, v)
		}
	}
}

// TestNonZeroAlertCodeWarnsEvenWhenStateIsSuccess pins the OR in the severity
// rule: a healthy AggregateState with a non-zero alert code must still Warn.
func TestNonZeroAlertCodeWarnsEvenWhenStateIsSuccess(t *testing.T) {
	row := exportjob.Row{
		"PolicyId":                      firstPolicyID,
		"DeviceId":                      "dev1",
		"DeviceName":                    "dev1-name",
		"UPN":                           "user@example.com",
		"AggregateState":                "Success",
		"AggregateState_loc":            "Success",
		"CurrentDeviceUpdateStatus":     "8",
		"CurrentDeviceUpdateStatus_loc": "Installed",
		"LatestAlertMessage":            "1",
		"LatestAlertMessage_loc":        "Some alert",
	}
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  {row},
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("log records = %d, want 1", len(logs))
	}
	if logs[0].SeverityText != "WARN" {
		t.Errorf("severity = %q, want WARN (non-zero alert code)", logs[0].SeverityText)
	}
}

// TestNonSuccessStateWarns pins the other half: any AggregateState other than
// Success Warns, even with a zero alert code.
func TestNonSuccessStateWarns(t *testing.T) {
	row := exportjob.Row{
		"PolicyId":                      firstPolicyID,
		"DeviceId":                      "dev1",
		"DeviceName":                    "dev1-name",
		"UPN":                           "user@example.com",
		"AggregateState":                "Failed",
		"AggregateState_loc":            "Failed",
		"CurrentDeviceUpdateStatus":     "1",
		"CurrentDeviceUpdateStatus_loc": "Error",
		"LatestAlertMessage":            "0",
		"LatestAlertMessage_loc":        "Not applicable",
	}
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  {row},
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 || logs[0].SeverityText != "WARN" {
		t.Fatalf("logs = %+v, want one WARN record", logs)
	}
}

// TestFailedProfileDoesNotDiscardHealthyOnes is the acceptance criterion from
// #351: one profile's export failing must not blank the other profile's data,
// and the failed profile contributes NO points (a gap, not a zero, #240).
func TestFailedProfileDoesNotDiscardHealthyOnes(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{
		rowsByFilter: map[string][]exportjob.Row{
			filterFor(firstPolicyID): liveDeviceRows(),
		},
		errByFilter: map[string]error{
			filterFor(secondPolicyID): errors.New("exportjob: FeatureUpdateDeviceState: boom"),
		},
	}
	c := New(g, exp, nil)
	rec := telemetrytest.New()

	err := c.Collect(context.Background(), rec.Emitter(), nil)
	if err == nil {
		t.Fatal("Collect error = nil, want the joined second-profile failure")
	}

	logs := rec.LogRecords()
	if len(logs) != 9 {
		t.Fatalf("log records = %d, want 9 (only the healthy profile's rows)", len(logs))
	}
	states := rec.MetricPoints(metricStates)
	if len(states) != 2 {
		t.Fatalf("state points = %d, want 2 (Success + InProgress, both from the healthy profile only)", len(states))
	}
}

// TestExportForbiddenSkipsProfileGracefully verifies a 403 creating the export
// job is a graceful Info skip: NOT joined into the returned error, and the
// other profile's data is unaffected.
func TestExportForbiddenSkipsProfileGracefully(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{
		rowsByFilter: map[string][]exportjob.Row{
			filterFor(firstPolicyID): liveDeviceRows(),
		},
		errByFilter: map[string]error{
			filterFor(secondPolicyID): forbidden403("POST exportJobs"),
		},
	}
	c := New(g, exp, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v, want nil (403 is a graceful skip)", err)
	}
	if len(rec.LogRecords()) != 9 {
		t.Fatalf("log records = %d, want 9", len(rec.LogRecords()))
	}
}

// TestProfileListForbiddenSkipsEntirely verifies a 403 listing profiles is a
// graceful Info skip with no export attempted at all.
func TestProfileListForbiddenSkipsEntirely(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{profilesURL: forbidden403("GET " + profilesURL)}}
	exp := &fakeExport{}
	c := New(g, exp, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v, want nil (403 is a graceful skip)", err)
	}
	if len(exp.reqs) != 0 {
		t.Errorf("export calls = %d, want 0", len(exp.reqs))
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("log records = %d, want 0", len(rec.LogRecords()))
	}
}

// TestZeroProfilesIsSuccess: an empty profile list is a real, healthy state -
// no export attempted, no error.
func TestZeroProfilesIsSuccess(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{profilesURL: `{"value":[]}`}}
	exp := &fakeExport{}
	c := New(g, exp, nil)
	rec := telemetrytest.New()

	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(exp.reqs) != 0 {
		t.Errorf("export calls = %d, want 0", len(exp.reqs))
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("log records = %d, want 0", len(rec.LogRecords()))
	}
	if len(rec.MetricPoints(metricStates)) != 0 {
		t.Errorf("state points = %d, want 0", len(rec.MetricPoints(metricStates)))
	}
}

// TestCollectSkipsWhenExportRunnerIsNil mirrors
// intune.feature_update_summary's nil-runner degrade.
func TestCollectSkipsWhenExportRunnerIsNil(t *testing.T) {
	g := twoProfilesGraph()
	c := New(g, nil, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(rec.LogRecords()) != 0 {
		t.Errorf("log records = %d, want 0", len(rec.LogRecords()))
	}
}

// TestColumnPinningOnPOSTBody asserts the export request pins the exact 10
// columns and filters on the profile id, for every fanned-out profile.
func TestColumnPinningOnPOSTBody(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  liveDeviceRows(),
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(exp.reqs) != 2 {
		t.Fatalf("export calls = %d, want 2", len(exp.reqs))
	}
	wantSelect := []string{
		"PolicyId", "DeviceId", "DeviceName", "UPN",
		"AggregateState", "AggregateState_loc",
		"CurrentDeviceUpdateStatus", "CurrentDeviceUpdateStatus_loc",
		"LatestAlertMessage", "LatestAlertMessage_loc",
	}
	seenFilters := map[string]bool{}
	for _, req := range exp.reqs {
		if req.ReportName != reportName {
			t.Errorf("ReportName = %q, want %q", req.ReportName, reportName)
		}
		if len(req.Select) != len(wantSelect) {
			t.Fatalf("Select = %v, want %v", req.Select, wantSelect)
		}
		for i, col := range wantSelect {
			if req.Select[i] != col {
				t.Errorf("Select[%d] = %q, want %q", i, req.Select[i], col)
			}
		}
		if req.Format != exportjob.FormatCSV {
			t.Errorf("Format = %q, want csv", req.Format)
		}
		seenFilters[req.Filter] = true
	}
	if !seenFilters[filterFor(firstPolicyID)] || !seenFilters[filterFor(secondPolicyID)] {
		t.Errorf("filters seen = %v, want both profile filters", seenFilters)
	}
}

// TestTimestampsAreZero pins the "poll time, not a fabricated event time"
// decision: every twin's Timestamp must be the zero value.
func TestTimestampsAreZero(t *testing.T) {
	g := twoProfilesGraph()
	exp := &fakeExport{rowsByFilter: map[string][]exportjob.Row{
		filterFor(firstPolicyID):  liveDeviceRows(),
		filterFor(secondPolicyID): {},
	}}
	c := New(g, exp, nil)
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, l := range rec.LogRecords() {
		if !l.Timestamp.IsZero() {
			t.Errorf("twin timestamp = %v, want zero", l.Timestamp)
		}
	}
}

func TestCollectorContract(t *testing.T) {
	c := New(nil, nil, nil)
	if c.Name() != collectorName {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.DefaultInterval().Hours() != 6 {
		t.Errorf("DefaultInterval = %v, want 6h", c.DefaultInterval())
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (windowsFeatureUpdateProfiles is beta)")
	}
	if got := c.IngestTransport(); got != telemetry.TransportReportExport {
		t.Errorf("IngestTransport = %q", got)
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{
		"DeviceManagementConfiguration.Read.All":       true,
		"DeviceManagementManagedDevices.ReadWrite.All": true,
	}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %d entries", perms, len(want))
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}
