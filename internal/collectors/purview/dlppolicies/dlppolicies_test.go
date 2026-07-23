package dlppolicies

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned response bodies (or errors). It
// satisfies collectors.GraphClient without any live Graph call.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	calls  int
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.calls++
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const policyFilesURL = betaBaseURL + policyFilesPath

// livePolicyFiles is the VERBATIM GET /beta/security/dataSecurityAndGovernance/
// policyFiles response from the m7kni tenant, read as graph2otel-poller
// `[live-measured 2026-07-15, #246]`: three file rows (DataCollectionPolicy /
// DlpPolicy / CustomClassifications), the DlpPolicy row carrying base64 of
// UTF-16LE XML (6 policies, 8 rules). Kept in testdata because the content field
// alone is ~200KB of base64.
func livePolicyFiles(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/policyFiles.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// collectLive drives the live fixture end-to-end through a fresh collector into a
// fresh Recorder and returns both.
func collectLive(t *testing.T) (*Collector, *telemetrytest.Recorder) {
	t.Helper()
	g := &fakeGraph{bodies: map[string]string{policyFilesURL: livePolicyFiles(t)}}
	c := New(g, nil, "", nil)
	// Pin "now" just after the newest policy change (4962a25c @ 2026-07-16
	// 22:13:57Z) so the age gauge is deterministic (100s).
	c.now = func() time.Time { return mustTime(t, "2026-07-16 22:15:37Z") }
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return c, rec
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(whenChangedLayout, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

func logsByEvent(rec *telemetrytest.Recorder, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestPoliciesByModeGauge pins purview.dlp.policies{enforcement_mode}: 4
// AuditAndNotify policies and 2 Enforce, counted from the live set.
func TestPoliciesByModeGauge(t *testing.T) {
	_, rec := collectLive(t)
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricPolicies) {
		got[p.Attrs["enforcement_mode"]] = p.Value
	}
	want := map[string]float64{"AuditAndNotify": 4, "Enforce": 2}
	if len(got) != len(want) {
		t.Fatalf("byMode = %v, want %v", got, want)
	}
	for m, v := range want {
		if got[m] != v {
			t.Errorf("byMode[%s] = %v, want %v", m, got[m], v)
		}
	}
}

// TestRulesByWorkloadActionGauge pins purview.dlp.rules{workload, action}: a
// rule contributes to (workload, action) for each of its workloads x distinct
// actions. Spot-checks a few of the 19 live series.
func TestRulesByWorkloadActionGauge(t *testing.T) {
	_, rec := collectLive(t)
	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricRules) {
		got[[2]string{p.Attrs["workload"], p.Attrs["action"]}] = p.Value
	}
	checks := map[[2]string]float64{
		{"Exchange", "NotifyUser"}:                        5,
		{"Exchange", "GenerateIncidentReport"}:            3,
		{"Exchange", "BlockAccess"}:                       1,
		{"Exchange", "GenerateAlert"}:                     2,
		{"EndpointDevices", "EndpointRestrictAccess"}:     3,
		{"EndpointDevices", "NotifyUser"}:                 3,
		{"Teams", "NotifyUser"}:                           5,
		{"OneDriveForBusiness", "GenerateIncidentReport"}: 3,
	}
	for k, v := range checks {
		if got[k] != v {
			t.Errorf("rules[%s/%s] = %v, want %v", k[0], k[1], got[k], v)
		}
	}
}

// TestBindingsGauge pins purview.dlp.policy_bindings{workload, binding_type}:
// all bindings are Tenant-typed; the per-workload counts are the number of
// policies bound to each.
func TestBindingsGauge(t *testing.T) {
	_, rec := collectLive(t)
	got := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricBindings) {
		got[[2]string{p.Attrs["workload"], p.Attrs["binding_type"]}] = p.Value
	}
	want := map[[2]string]float64{
		{"EndpointDevices", "Tenant"}:     5,
		{"Exchange", "Tenant"}:            4,
		{"Teams", "Tenant"}:               4,
		{"OneDriveForBusiness", "Tenant"}: 3,
		{"SharePoint", "Tenant"}:          3,
	}
	if len(got) != len(want) {
		t.Fatalf("bindings = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("bindings[%s/%s] = %v, want %v", k[0], k[1], got[k], v)
		}
	}
}

// TestLastChangedAgeGauge pins the single, unlabeled age gauge: seconds since
// the most recently changed policy (2026-07-16 22:13:57Z), with now pinned 100s
// later.
func TestLastChangedAgeGauge(t *testing.T) {
	_, rec := collectLive(t)
	pts := rec.MetricPoints(metricLastChanged)
	if len(pts) != 1 {
		t.Fatalf("got %d %s series, want exactly 1 (a single max-age gauge, never keyed by policy)", len(pts), metricLastChanged)
	}
	if len(pts[0].Attrs) != 0 {
		t.Errorf("age gauge carries labels %v, want none", pts[0].Attrs)
	}
	if pts[0].Value != 100 {
		t.Errorf("age = %v, want 100", pts[0].Value)
	}
	if pts[0].Unit != "s" {
		t.Errorf("age unit = %q, want s", pts[0].Unit)
	}
}

// TestPolicyTwinsWarnWhenNotEnforcing pins the Warn condition: one
// purview.dlp_policy twin per policy (6), WARN when the policy is not enforcing
// (mode != Enforce), INFO for an Enforce policy.
func TestPolicyTwinsWarnWhenNotEnforcing(t *testing.T) {
	_, rec := collectLive(t)
	logs := logsByEvent(rec, eventPolicy)
	if len(logs) != 6 {
		t.Fatalf("got %d %s twins, want 6 (one per policy)", len(logs), eventPolicy)
	}
	sevByMode := map[string]map[string]int{}
	for _, r := range logs {
		mode := r.Attrs["enforcement_mode"]
		if sevByMode[mode] == nil {
			sevByMode[mode] = map[string]int{}
		}
		sevByMode[mode][r.SeverityText]++
	}
	if sevByMode["AuditAndNotify"]["WARN"] != 4 {
		t.Errorf("AuditAndNotify twins WARN = %d, want 4 (audit-only is the downgraded-enforcement signal)", sevByMode["AuditAndNotify"]["WARN"])
	}
	if sevByMode["Enforce"]["INFO"] != 2 {
		t.Errorf("Enforce twins INFO = %d, want 2", sevByMode["Enforce"]["INFO"])
	}
}

// TestPolicyTwinCarriesDefinition pins the per-policy twin's definition attrs,
// including the comma-joined bound workloads.
func TestPolicyTwinCarriesDefinition(t *testing.T) {
	_, rec := collectLive(t)
	var secrets *telemetrytest.LogRecord
	logs := logsByEvent(rec, eventPolicy)
	for i := range logs {
		if logs[i].Attrs["policy_id"] == "acaec97a-890c-469c-8e74-1841f34f22ee" {
			secrets = &logs[i]
		}
	}
	if secrets == nil {
		t.Fatal("no twin for the Secrets policy")
	}
	if secrets.Attrs["policy_name"] != "Homelab - Secrets and Credentials" {
		t.Errorf("policy_name = %q", secrets.Attrs["policy_name"])
	}
	if secrets.Attrs["when_changed_utc"] == "" || secrets.Attrs["when_rules_changed_utc"] == "" {
		t.Error("when_changed_utc / when_rules_changed_utc empty")
	}
	bw := secrets.Attrs["bound_workloads"]
	for _, w := range []string{"Exchange", "Teams", "OneDriveForBusiness", "SharePoint", "EndpointDevices"} {
		if !strings.Contains(bw, w) {
			t.Errorf("bound_workloads %q missing %q", bw, w)
		}
	}
}

// TestRuleTwinsEmitSensitiveInfoTypes pins the per-rule twin (8 total) and that
// a classification rule carries its sensitive-info-type ids + confidence/count
// band, while an adaptive rule (no containsDataClassification) carries none.
func TestRuleTwinsEmitSensitiveInfoTypes(t *testing.T) {
	_, rec := collectLive(t)
	logs := logsByEvent(rec, eventRule)
	if len(logs) != 8 {
		t.Fatalf("got %d %s twins, want 8 (one per rule)", len(logs), eventRule)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, r := range logs {
		byID[r.Attrs["rule_id"]] = r
	}

	// The Secrets classification rule: 7 sensitive-info-types, confidence band
	// 75..100, count band 1..-1 (unlimited), effective mode inherits Enforce from
	// its Rule object (the wire has no rule mode -> inherits the policy's
	// AuditAndNotify). Actions NotifyUser + GenerateIncidentReport.
	secrets := byID["f800c2c8-91cd-4f08-8a95-261db82713ff"]
	if !strings.Contains(secrets.Attrs["sensitive_info_type_ids"], "c7bc98e8-551a-4c35-a92d-d2c8cda714a7") {
		t.Errorf("secrets rule sensitive_info_type_ids = %q, want it to contain the first live SIT id", secrets.Attrs["sensitive_info_type_ids"])
	}
	if secrets.Attrs["min_confidence"] != "75" || secrets.Attrs["max_confidence"] != "100" {
		t.Errorf("secrets confidence band = %s..%s, want 75..100", secrets.Attrs["min_confidence"], secrets.Attrs["max_confidence"])
	}
	if secrets.Attrs["min_count"] != "1" || secrets.Attrs["max_count"] != "-1" {
		t.Errorf("secrets count band = %s..%s, want 1..-1", secrets.Attrs["min_count"], secrets.Attrs["max_count"])
	}
	if secrets.Attrs["management_rule_id"] != "1b481bd0-d71f-46bf-82eb-d05eb31cfb6f" {
		t.Errorf("management_rule_id = %q", secrets.Attrs["management_rule_id"])
	}
	if !strings.Contains(secrets.Attrs["actions"], "NotifyUser") || !strings.Contains(secrets.Attrs["actions"], "GenerateIncidentReport") {
		t.Errorf("secrets actions = %q, want NotifyUser + GenerateIncidentReport", secrets.Attrs["actions"])
	}
	if secrets.Attrs["policy_id"] != "acaec97a-890c-469c-8e74-1841f34f22ee" {
		t.Errorf("rule policy_id = %q", secrets.Attrs["policy_id"])
	}

	// An adaptive (endpoint) rule matches on file-type / group membership, not a
	// classification, so it has no sensitive-info-type ids. Its own mode is
	// Enforce and it is enabled.
	adaptive := byID["d81d10c9-e849-4afc-8af3-df42aff51811"]
	if adaptive.Attrs["sensitive_info_type_ids"] != "" {
		t.Errorf("adaptive rule sensitive_info_type_ids = %q, want empty", adaptive.Attrs["sensitive_info_type_ids"])
	}
	if adaptive.Attrs["enforcement_mode"] != "Enforce" {
		t.Errorf("adaptive rule enforcement_mode = %q, want Enforce", adaptive.Attrs["enforcement_mode"])
	}
	if adaptive.Attrs["enabled"] != "true" {
		t.Errorf("adaptive rule enabled = %q, want true", adaptive.Attrs["enabled"])
	}
}

// TestNoConditionValuesEmitted is the mandated secrets guard (#246): a policy
// DEFINITION (rule names, sensitive-info-type GUIDs, thresholds) is emitted, but
// a rule CONDITION's value text (notify recipients, custom-group GUIDs,
// file-type GUIDs, free text) must NEVER reach any emitted signal. It drives the
// full live set and asserts every known condition value from the sample is
// absent from every emitted metric attribute and log attribute/body.
func TestNoConditionValuesEmitted(t *testing.T) {
	_, rec := collectLive(t)

	forbidden := []string{
		"rob@m7kni.io", // NotifyUser recipient argument value
		"This looks sensitive. Check before sharing.", // notify body text
		"IncludeExternalUsers",                        // <equal> AccessScope condition value
		"FCB9FA93-6269-4ACF-A756-832E79B36A2A",        // IsMemberOfCustomGroups value
		"29b89383-a6f8-47ad-b594-3b364698b921",        // ContentFileType <is> value
		"pasteSensitiveDomainsGroup",                  // endpoint action argument value name
	}

	var emitted []string
	for _, name := range rec.MetricNames() {
		for _, p := range rec.MetricPoints(name) {
			for _, v := range p.Attrs {
				emitted = append(emitted, v)
			}
		}
	}
	for _, r := range rec.LogRecords() {
		emitted = append(emitted, r.Body)
		for _, v := range r.Attrs {
			emitted = append(emitted, v)
		}
	}
	haystack := strings.Join(emitted, "\x00")

	for _, bad := range forbidden {
		if strings.Contains(haystack, bad) {
			t.Errorf("condition value %q leaked into an emitted signal — only policy DEFINITION may be emitted, never a matched/condition value", bad)
		}
	}

	// Positive control: a sensitive-info-type GUID (policy DEFINITION) SHOULD be
	// present, proving the guard above is asserting over real emissions.
	if !strings.Contains(haystack, "c7bc98e8-551a-4c35-a92d-d2c8cda714a7") {
		t.Error("expected a sensitive-info-type id in emissions (definition is safe to emit); guard may be over an empty capture")
	}
}

// TestParseSkipReusesCacheWhenVersionUnchanged pins the checkpoint parse-skip:
// two Collects with the same version hash decode the ~76KB content exactly once,
// and the second cycle still re-emits the gauges from cache.
func TestParseSkipReusesCacheWhenVersionUnchanged(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{policyFilesURL: livePolicyFiles(t)}}
	c := New(g, nil, "", nil)

	rec1 := telemetrytest.New()
	if err := c.Collect(context.Background(), rec1.Emitter()); err != nil {
		t.Fatalf("Collect #1: %v", err)
	}
	rec2 := telemetrytest.New()
	if err := c.Collect(context.Background(), rec2.Emitter()); err != nil {
		t.Fatalf("Collect #2: %v", err)
	}

	if c.parseCount != 1 {
		t.Errorf("parseCount = %d, want 1 (the second unchanged cycle must skip the decode)", c.parseCount)
	}
	// The second cycle still emits from cache (a snapshot gauge must not vanish).
	if pts := rec2.MetricPoints(metricPolicies); len(pts) == 0 {
		t.Error("second cycle emitted no policies gauge; the parse-skip must re-emit from cache, not go silent")
	}
}

// TestPersistsVersionToStore pins that the version hash is written to the
// checkpoint store (used across restarts to detect a changed policy set).
func TestPersistsVersionToStore(t *testing.T) {
	store := checkpoint.NewStore(t.TempDir())
	g := &fakeGraph{bodies: map[string]string{policyFilesURL: livePolicyFiles(t)}}
	c := New(g, store, "tenant-1", nil)

	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	cp, err := store.Load("tenant-1", endpoint)
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	const wantVersion = "37EB53662A3265F3E4A05468128F4E14289E8A7DAD698DBF3712B0ADE0E27DD44B8C18BD2F9F4227AF559F1061CF9C32"
	if _, ok := cp.SeenIDs[wantVersion]; !ok {
		t.Errorf("stored SeenIDs = %v, want it to contain the DlpPolicy version hash", cp.SeenIDs)
	}
}

// TestForbiddenSkipsGracefully pins that a 403 (surface/scope missing) is a
// graceful info-skip returning no error and emitting nothing.
func TestForbiddenSkipsGracefully(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{policyFilesURL: errors.New("graph: status 403 Forbidden")}}
	rec := telemetrytest.New()
	if err := New(g, nil, "", nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect should swallow 403, got %v", err)
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("emitted %d policy series on a 403, want 0", len(pts))
	}
}

// TestNoDlpRow pins that a response without a DlpPolicy row emits nothing and
// does not error.
func TestNoDlpRow(t *testing.T) {
	const body = `{"value":[{"id":"DataCollectionPolicy","fileType":"dataCollectionPolicy","status":"noContent","content":null}]}`
	g := &fakeGraph{bodies: map[string]string{policyFilesURL: body}}
	rec := telemetrytest.New()
	if err := New(g, nil, "", nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricPolicies); len(pts) != 0 {
		t.Errorf("emitted %d policy series with no DlpPolicy row, want 0", len(pts))
	}
}

func TestNameExperimentalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil, "", nil)
	if c.Name() != "purview.dlp_policies" {
		t.Errorf("Name = %q", c.Name())
	}
	if !c.Experimental() {
		t.Error("Experimental = false, want true (beta endpoint)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "InformationProtectionPolicy.Read.All" {
		t.Errorf("RequiredPermissions = %v", perms)
	}
}
