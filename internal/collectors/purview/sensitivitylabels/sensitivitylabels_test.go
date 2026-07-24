package sensitivitylabels

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeGraph is a canned-response GraphClient: bodies keyed by exact URL, or an
// error keyed by exact URL.
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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	sensitivityURL = "https://graph.microsoft.com/v1.0/security/dataSecurityAndGovernance/sensitivityLabels"
	piiLabelName   = "Confidential Finance-Payroll"
)

// dataInsightsForbidden is the RETENTION data plane's live app-only refusal
// signature, in graphclient's error format (live 2026-07-16, #109/#126). It
// appears in this package's tests for one reason: to prove that the string the
// retention collector treats as "skip" is treated as a FAILURE here. The
// paired assertion lives in the retention package's
// TestForbiddenSkipIsRetentionOnly, which drives both collectors with this same
// signature — see internal/collectors/purview/retentionlabels.
const dataInsightsForbidden = `status 500: {"error":{"code":"UnknownError","message":"{\"ErrorCode\":\"DataInsightsRequestError\",\"Message\":\"DataInsights command(GET) FAILED - Forbidden. TargetServer = X.PROD.OUTLOOK.COM\"}"}}`

func TestSensitivityCollectBucketsByApplicableTo(t *testing.T) {
	// A label applicable to multiple targets contributes to each bucket; an
	// empty applicableTo lands in "none"; an unrecognized target in "unknown".
	body := `{"value":[
	  {"applicableTo":"email,file","name":"` + piiLabelName + `","priority":5,"isEnabled":true},
	  {"applicableTo":"file","name":"Secret","priority":6},
	  {"applicableTo":"teamwork,site","name":"Team"},
	  {"applicableTo":"","name":"NoTarget"},
	  {"applicableTo":"martian","name":"Weird"}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()

	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(sensitivityMetric) {
		got[p.Attrs["applicable_to"]] = p.Value
	}
	want := map[string]float64{
		"email": 1, "file": 2, "teamwork": 1, "site": 1, "none": 1, "unknown": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("applicable_to=%s count = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

// TestSensitivityNoPIIInLabels is the cardinality/PII guard: no metric point
// may carry a label display name (or any attr key beyond the bounded set).
func TestSensitivityNoPIIInLabels(t *testing.T) {
	body := `{"value":[{"applicableTo":"file","name":"` + piiLabelName + `","priority":9,"tooltip":"secret finance"}]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()
	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	allowedKeys := map[string]bool{"applicable_to": true}
	pts := rec.MetricPoints(sensitivityMetric)
	if len(pts) == 0 {
		t.Fatal("expected at least one metric point")
	}
	for _, p := range pts {
		for k, v := range p.Attrs {
			if !allowedKeys[k] {
				t.Errorf("unexpected metric label key %q (value %q) — only bounded dims allowed", k, v)
			}
			if v == piiLabelName {
				t.Errorf("PII label display name leaked into metric label %q=%q", k, v)
			}
		}
	}
}

// TestSensitivityErrorsAlwaysFail pins that the sensitivity collector has NO
// skip path: every error class fails, emitting neither metrics nor logs.
//
// # This is the sensitivity half of #126's asymmetry
//
// The retention collector (a separate package by design — see this package's
// doc) treats a refusal from the Exchange compliance data plane as an expected
// "no data here" and skips. This collector must not, because its endpoint is GA
// and live-verified 200 app-only with SensitivityLabel.Read (2026-07-16): a 403
// here is missing admin consent, an operator-fixable misconfiguration that must
// be loud. Swallowing it is precisely how #109 mistook a missing scope for a
// permanent product gap — the collector reported success over zero data and
// nothing ever contradicted it.
func TestSensitivityErrorsAlwaysFail(t *testing.T) {
	cases := []struct {
		name string
		err  string
	}{
		{
			// #126: the live signature of missing admin consent for
			// SensitivityLabel.Read. THE case this issue exists for.
			name: "forbidden_403",
			err:  `status 403: {"error":{"code":"InsufficientGraphPermissions","message":"Insufficient privileges to complete the operation."}}`,
		},
		{
			// The endpoint is GA and live-verified 200 — a 404 means it moved or
			// was withdrawn, which is real news, not a tenant condition.
			name: "not_found_404",
			err:  "status 404: not found",
		},
		{
			// #102's shape: a non-Graph data plane refusing the principal with the
			// scope in-token. A different diagnosis, still a failure.
			name: "unauthorized_401",
			err:  "status 401: unauthorized",
		},
		{
			// Retention's real, permanent gap — NOT sensitivity's. The retention
			// collector skips this exact string; this one must not.
			name: "data_insights_forbidden",
			err:  dataInsightsForbidden,
		},
		{
			name: "generic_500",
			err:  "status 500: boom",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGraph{errs: map[string]error{
				sensitivityURL: errors.New("graphclient: GET " + sensitivityURL + ": " + tc.err),
			}}
			rec := telemetrytest.New()
			err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter())
			if err == nil {
				t.Fatalf("Collect returned nil: a sensitivity-label fetch failure must never be swallowed (#126); error was %q", tc.err)
			}
			if len(rec.MetricPoints(sensitivityMetric)) != 0 {
				t.Error("expected no metric points on a failed fetch")
			}
			if len(rec.LogRecords()) != 0 {
				t.Error("expected no log twin records on a failed fetch")
			}
		})
	}
}

// TestSensitivityForbiddenErrorNamesTheMissingScope pins that the 403 failure is
// self-diagnosing. #109 spent days concluding "permanent app-only gap" from a
// bare 403; the error must name the grant that fixes it so the next reader does
// not re-run that investigation.
func TestSensitivityForbiddenErrorNamesTheMissingScope(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		sensitivityURL: errors.New("graphclient: GET " + sensitivityURL +
			`: status 403: {"error":{"code":"InsufficientGraphPermissions"}}`),
	}}
	err := NewSensitivity(g, nil).Collect(context.Background(), telemetrytest.New().Emitter())
	if err == nil {
		t.Fatal("expected a 403 to fail the collector")
	}
	if !strings.Contains(err.Error(), "SensitivityLabel.Read") {
		t.Errorf("a 403 error must name the missing scope, got: %v", err)
	}
	if !strings.Contains(err.Error(), "status 403") {
		t.Errorf("a 403 error must preserve the underlying graphclient error, got: %v", err)
	}
}

// TestSensitivityCollectEmitsLogTwin is the log-twin half of #111: every
// catalog row emits one purview.sensitivity_label log carrying the per-row
// detail (id, name, priority, applicable_to, description) the metric
// deliberately never carries.
func TestSensitivityCollectEmitsLogTwin(t *testing.T) {
	body := `{"value":[
	  {"id":"aaa","applicableTo":"email,file","name":"` + piiLabelName + `","priority":5,"description":"Finance payroll data"},
	  {"id":"bbb","applicableTo":"file","name":"Secret","priority":6}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()

	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	var twins []telemetrytest.LogRecord
	for _, l := range logs {
		if l.EventName == sensitivityLabelEventName {
			twins = append(twins, l)
		}
	}
	if len(twins) != 2 {
		t.Fatalf("got %d purview.sensitivity_label logs, want 2 (all: %+v)", len(twins), logs)
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range twins {
		byID[l.Attrs["id"]] = l
	}

	first, ok := byID["aaa"]
	if !ok {
		t.Fatalf("no log record for id=aaa (all: %+v)", twins)
	}
	if first.Attrs["name"] != piiLabelName {
		t.Errorf("name = %q, want %q", first.Attrs["name"], piiLabelName)
	}
	if first.Attrs["priority"] != "5" {
		t.Errorf("priority = %q, want \"5\"", first.Attrs["priority"])
	}
	if first.Attrs["applicable_to"] != "email,file" {
		t.Errorf("applicable_to = %q, want \"email,file\"", first.Attrs["applicable_to"])
	}
	if first.Attrs["description"] != "Finance payroll data" {
		t.Errorf("description = %q, want %q", first.Attrs["description"], "Finance payroll data")
	}

	second, ok := byID["bbb"]
	if !ok {
		t.Fatalf("no log record for id=bbb (all: %+v)", twins)
	}
	if _, present := second.Attrs["description"]; present {
		t.Errorf("absent description should be omitted from attrs, got %q", second.Attrs["description"])
	}
}

func TestSensitivityGatingMetadata(t *testing.T) {
	c := NewSensitivity(&fakeGraph{}, nil)
	if got := c.RequiredCapability(); got != license.CapPurviewInfoProtection {
		t.Errorf("RequiredCapability = %v, want %v", got, license.CapPurviewInfoProtection)
	}
	// SensitivityLabel.Read is the scope that live-verified 200 on this endpoint
	// (#126). InformationProtectionPolicy.Read.All is a DIFFERENT permission for
	// a different endpoint; asserting it here is what kept the wrong scope in
	// docs/collectors.md, where it told operators to grant something that does
	// not unblock the collector.
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "SensitivityLabel.Read" {
		t.Errorf("RequiredPermissions = %v, want [SensitivityLabel.Read]", got)
	}
	if c.Name() != sensitivityName {
		t.Errorf("Name = %q, want %q", c.Name(), sensitivityName)
	}
}

// --- wire-assumption watchdog (#233/#234) --------------------------------
//
// applicable_to is a METRIC LABEL, and an unrecognized target collapses into
// "unknown" — a bucket nobody inspects. A target Microsoft adds to the
// sensitivityLabelTarget flags enum therefore moves the per-target counts with
// nothing saying why.

func findings(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		out[p.Attrs[semconv.AttrKind]+"/"+p.Attrs[semconv.AttrField]] += p.Value
	}
	return out
}

func TestSensitivityMappedTargetsReportNothingUnexpected(t *testing.T) {
	// Every member of sensitivityTargets, plus an EMPTY applicableTo — an absent
	// optional field is the normal case and must never be a finding.
	body := `{"value":[
	  {"applicableTo":"email,file","name":"A"},
	  {"applicableTo":"teamwork,site,schematizedData","name":"B"},
	  {"applicableTo":"","name":"C"}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()
	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := findings(rec); len(got) != 0 {
		t.Errorf("mapped targets produced findings %v, want none", got)
	}
}

func TestSensitivityUnmappedTargetIsReported(t *testing.T) {
	body := `{"value":[
	  {"applicableTo":"file","name":"Secret"},
	  {"applicableTo":"file,martian","name":"Weird"}
	]}`
	g := &fakeGraph{bodies: map[string]string{sensitivityURL: body}}
	rec := telemetrytest.New()
	if err := NewSensitivity(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	key := wirecheck.KindUnmappedValue + "/" + semconv.AttrApplicableTo
	if got := findings(rec)[key]; got != 1 {
		t.Errorf("findings[%s] = %v, want 1; all=%v", key, got, findings(rec))
	}
	// Report-only: both labels still counted, the surprise one under "unknown".
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(sensitivityMetric) {
		got[p.Attrs[semconv.AttrApplicableTo]] = p.Value
	}
	if got["file"] != 2 || got["unknown"] != 1 {
		t.Errorf("counts = %v, want file=2 unknown=1 — an unexpected target must not drop a label", got)
	}
}
