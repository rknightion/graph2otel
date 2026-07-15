package certinventoryreport

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/exportjob"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeRunner is a canned exportjob.Runner: it returns the fixed rows/err
// regardless of the Request passed in, mirroring the M5 lanes' fake-Runner
// test approach (no live export-job/Graph calls).
type fakeRunner struct {
	rows []exportjob.Row
	err  error
}

func (f *fakeRunner) Export(context.Context, exportjob.Request, telemetry.Emitter) ([]exportjob.Row, error) {
	return f.rows, f.err
}

var _ exportjob.Runner = (*fakeRunner)(nil)

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func newTestCollector(r exportjob.Runner) *Collector {
	c := New(r, nil)
	c.now = fixedClock
	return c
}

// row builds one AllDeviceCertificates export row using the report's real,
// live-verified column names, plus fixed non-cardinality-relevant per-cert
// detail so the log-event tests have something to assert on.
func row(issuer, status string, validTo *time.Time) exportjob.Row {
	r := exportjob.Row{
		"IssuerName":        issuer,
		"CertificateStatus": status,
		"DeviceId":          "11111111-1111-1111-1111-111111111111",
		"DeviceName":        "DEVICE-1",
		"UserId":            "22222222-2222-2222-2222-222222222222",
		"UPN":               "user@example.com",
		"SubjectName":       "CN=DEVICE-1",
		"PolicyId":          "policy-1",
		"SerialNumber":      "0123456789ABCDEF",
		"Thumbprint":        "ABCDEF0123456789",
		"ValidFrom":         fixedNow.Add(-365 * 24 * time.Hour).Format(time.RFC3339),
		"EnhancedKeyUsage":  "Client Authentication",
		"KeyUsage":          "Digital Signature, Key Encipherment",
	}
	if validTo != nil {
		r["ValidTo"] = validTo.Format(time.RFC3339)
	}
	return r
}

func daysFromNow(d int) *time.Time {
	t := fixedNow.Add(time.Duration(d) * 24 * time.Hour)
	return &t
}

func TestCollectAggregatesDaysUntilExpiryByIssuer(t *testing.T) {
	rows := []exportjob.Row{
		row("Contoso Issuing CA", "issued", daysFromNow(120)),
		row("Contoso Issuing CA", "issuePending", daysFromNow(5)),
		row("Fabrikam Issuing CA", "revoked", daysFromNow(-1)),
	}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	days := map[string]float64{}
	for _, p := range rec.MetricPoints(daysUntilExpiryMetricName) {
		days[p.Attrs["issuer"]+"/"+p.Attrs["bucket"]] = p.Value
	}
	want := map[string]float64{
		"Contoso Issuing CA/ok":       1,
		"Contoso Issuing CA/under_7d": 1,
		"Fabrikam Issuing CA/expired": 1,
	}
	if len(days) != len(want) {
		t.Fatalf("got %d days_until_expiry series, want %d: %v", len(days), len(want), days)
	}
	for k, v := range want {
		if days[k] != v {
			t.Errorf("days[%s] = %v, want %v (all: %v)", k, days[k], v, days)
		}
	}
}

// TestCollectAggregatesStateAcrossIssuers asserts the state metric is keyed
// only by {state} - no issuer dimension - per #41's rework spec, unlike the
// expiry metric which carries {issuer, bucket}.
func TestCollectAggregatesStateAcrossIssuers(t *testing.T) {
	rows := []exportjob.Row{
		row("Contoso Issuing CA", "issued", nil),
		row("Fabrikam Issuing CA", "issuePending", nil),
		row("Fabrikam Issuing CA", "revoked", nil),
	}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(stateMetricName) {
		got[p.Attrs["state"]] = p.Value
		if _, ok := p.Attrs["issuer"]; ok {
			t.Errorf("state metric point unexpectedly carries an issuer attribute: %+v", p)
		}
	}
	want := map[string]float64{"healthy": 1, "pending": 1, "revoked": 1}
	if len(got) != len(want) {
		t.Fatalf("got %d state series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("states[%s] = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

// TestCollectCollapsesCertificateStatusEnumToBoundedBuckets pins #41's
// required collapse test: every value in the assumed CertificateStatus
// vocabulary (plus one unrecognized future value) must land in exactly one
// of the five bounded buckets {healthy, pending, failed, revoked, other} -
// the dimension can never grow past that regardless of what the real enum
// turns out to contain.
func TestCollectCollapsesCertificateStatusEnumToBoundedBuckets(t *testing.T) {
	raw := []string{
		"unknown", "challengeIssued", "challengeIssueFailed", "requestCreationFailed",
		"requestSubmitFailed", "challengeValidationSucceeded", "challengeValidationFailed",
		"issueFailed", "issuePending", "issued", "responseProcessingFailed", "responsePending",
		"enrollmentSucceeded", "enrollmentNotNeeded", "revoked", "removedFromCollection",
		"renewVerified", "installFailed", "installed", "deleteFailed", "deleted",
		"renewalRequested", "requested", "someBrandNewFutureEnumValue",
	}
	rows := make([]exportjob.Row, 0, len(raw))
	for _, s := range raw {
		rows = append(rows, row("Contoso Issuing CA", s, nil))
	}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]float64{}
	for _, p := range rec.MetricPoints(stateMetricName) {
		got[p.Attrs["state"]] += p.Value
	}
	want := map[string]float64{
		"healthy": 5, // issued, enrollmentSucceeded, enrollmentNotNeeded, renewVerified, installed
		"pending": 6, // challengeIssued, challengeValidationSucceeded, issuePending, responsePending, renewalRequested, requested
		"failed":  8, // challengeIssueFailed, requestCreationFailed, requestSubmitFailed, challengeValidationFailed, issueFailed, responseProcessingFailed, installFailed, deleteFailed
		"revoked": 1,
		"other":   4, // unknown, removedFromCollection, deleted, someBrandNewFutureEnumValue
	}
	if len(got) != len(want) {
		t.Fatalf("got %d state bucket(s), want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("state=%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

// TestCollectEmitsPerCertificateLogEvents asserts per-cert detail
// (thumbprint, serial number, device/user identity, subject, raw status) is
// surfaced as a log record's structured attributes - never as a metric
// label.
func TestCollectEmitsPerCertificateLogEvents(t *testing.T) {
	rows := []exportjob.Row{row("Contoso Issuing CA", "issued", daysFromNow(10))}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(logs), logs)
	}
	lr := logs[0]
	if lr.EventName != logEventName {
		t.Errorf("EventName = %q, want %q", lr.EventName, logEventName)
	}
	if got := lr.Attrs["thumbprint"]; got != "ABCDEF0123456789" {
		t.Errorf("thumbprint = %q", got)
	}
	if got := lr.Attrs["serial_number"]; got != "0123456789ABCDEF" {
		t.Errorf("serial_number = %q", got)
	}
	if got := lr.Attrs["device_name"]; got != "DEVICE-1" {
		t.Errorf("device_name = %q", got)
	}
	if got := lr.Attrs["upn"]; got != "user@example.com" {
		t.Errorf("upn = %q", got)
	}
	if got := lr.Attrs["subject_name"]; got != "CN=DEVICE-1" {
		t.Errorf("subject_name = %q", got)
	}
	if got := lr.Attrs["issuer_name"]; got != "Contoso Issuing CA" {
		t.Errorf("issuer_name = %q", got)
	}
	if got := lr.Attrs["certificate_status"]; got != "issued" {
		t.Errorf("certificate_status = %q, want raw uncollapsed value", got)
	}
	if got := lr.Attrs["state_bucket"]; got != "healthy" {
		t.Errorf("state_bucket = %q, want healthy", got)
	}
}

// TestCollectEscalatesSeverityForFailedOrRevoked asserts a failed/revoked
// certificate's log record carries WARN severity so it stands out from the
// routine healthy/pending stream.
func TestCollectEscalatesSeverityForFailedOrRevoked(t *testing.T) {
	rows := []exportjob.Row{row("Contoso Issuing CA", "revoked", nil)}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("got %d log records, want 1", len(logs))
	}
	if logs[0].Severity < int(telemetry.SeverityWarn) {
		t.Errorf("revoked certificate log severity = %+v, want WARN", logs[0])
	}
}

func TestCollectSkipsGracefullyWhenExportRunnerNil(t *testing.T) {
	rec := telemetrytest.New()
	c := New(nil, nil)
	c.now = fixedClock

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect with nil runner returned error %v, want nil (graceful skip)", err)
	}
	if pts := rec.MetricPoints(stateMetricName); len(pts) != 0 {
		t.Errorf("expected no metrics emitted with a nil runner, got %+v", pts)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("expected no log records emitted with a nil runner, got %+v", logs)
	}
}

func TestCollectSkipsGracefullyOnExportError(t *testing.T) {
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{err: errors.New("boom: permission denied")})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect on export error returned %v, want nil (graceful skip)", err)
	}
	if pts := rec.MetricPoints(stateMetricName); len(pts) != 0 {
		t.Errorf("expected no metrics emitted on export error, got %+v", pts)
	}
}

func TestCollectCapsIssuerCardinality(t *testing.T) {
	rows := make([]exportjob.Row, 0, maxIssuerNames+5)
	for i := 0; i < maxIssuerNames+5; i++ {
		rows = append(rows, row(fmt.Sprintf("issuer-%d", i), "issued", nil))
	}
	rec := telemetrytest.New()
	c := newTestCollector(&fakeRunner{rows: rows})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	issuers := map[string]struct{}{}
	for _, p := range rec.MetricPoints(daysUntilExpiryMetricName) {
		issuers[p.Attrs["issuer"]] = struct{}{}
	}
	if want := maxIssuerNames + 1; len(issuers) != want { // capped names + "other"
		t.Fatalf("got %d distinct issuer values, want %d (cap + other): %v", len(issuers), want, issuers)
	}
	if _, ok := issuers["other"]; !ok {
		t.Error(`expected "other" issuer bucket once the cap is exceeded`)
	}
}

func TestCollectorMetadata(t *testing.T) {
	c := New(&fakeRunner{}, nil)
	if got := c.Name(); got != collectorName {
		t.Errorf("Name = %q, want %q", got, collectorName)
	}
	if got := c.DefaultInterval(); got != 6*time.Hour {
		t.Errorf("DefaultInterval = %v, want 6h", got)
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (beta, opt-in: needs a write scope)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "DeviceManagementManagedDevices.ReadWrite.All" {
		t.Errorf("RequiredPermissions = %v, want [DeviceManagementManagedDevices.ReadWrite.All]", perms)
	}
}
