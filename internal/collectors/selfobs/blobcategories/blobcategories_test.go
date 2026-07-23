package blobcategories

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeARM returns canned bytes (or an error) for RawGet, recording the URL.
type fakeARM struct {
	body []byte
	err  error
	url  string
}

func (f *fakeARM) RawGet(_ context.Context, url string) ([]byte, error) {
	f.url = url
	if f.err != nil {
		return nil, f.err
	}
	return f.body, nil
}

// sample is a trimmed but structurally faithful aadiam diagnosticSettings
// response: two settings, only the first sinks to a storage account. It exercises
// every census state plus the "second setting has no storage sink, so its enables
// do not count" rule (AuditLogs is disabled in the storage setting but enabled in
// the Log-Analytics-only setting — it must stay classified from the storage one).
const sample = `{
  "value": [
    {
      "name": "graph2otel",
      "properties": {
        "storageAccountId": "/subscriptions/x/providers/Microsoft.Storage/storageAccounts/acct",
        "logs": [
          {"category": "MicrosoftGraphActivityLogs", "enabled": true},
          {"category": "SignInLogs", "enabled": true},
          {"category": "AuditLogs", "enabled": false},
          {"category": "ADFSSignInLogs", "enabled": false}
        ]
      }
    },
    {
      "name": "to-log-analytics",
      "properties": {
        "storageAccountId": "",
        "workspaceId": "/subscriptions/x/.../workspace",
        "logs": [
          {"category": "AuditLogs", "enabled": true}
        ]
      }
    }
  ]
}`

func collectSample(t *testing.T, containers []string) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(&fakeARM{body: []byte(sample)}, containers, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func TestCollect_ClassifiesEveryState(t *testing.T) {
	// insights-logs-microsoftgraphactivitylogs is read (consumed).
	// insights-logs-auditlogs is read but the category is disabled in the storage
	// setting (mapped_but_disabled), and its enable in the LA-only setting must be
	// ignored. SignInLogs is enabled with no reader (enabled_unread). ADFS is
	// disabled with no reader (disabled).
	containers := []string{
		"insights-logs-microsoftgraphactivitylogs",
		"insights-logs-auditlogs",
		"insights-logs-advancedhunting-deviceinfo", // a defender container, matches no aadiam category
	}
	rec := collectSample(t, containers)

	want := map[string]float64{
		stateConsumed:          1, // MicrosoftGraphActivityLogs
		stateEnabledUnread:     1, // SignInLogs
		stateMappedButDisabled: 1, // AuditLogs (disabled in storage setting, has a reader)
		stateDisabled:          1, // ADFSSignInLogs
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCategories) {
		got[p.Attrs[semconv.AttrState]] = p.Value
	}
	if len(got) != len(want) {
		t.Fatalf("gauge states = %v, want %v", got, want)
	}
	for st, n := range want {
		if got[st] != n {
			t.Errorf("state %q count = %v, want %v", st, got[st], n)
		}
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	containers := []string{"insights-logs-microsoftgraphactivitylogs", "insights-logs-auditlogs"}
	rec := collectSample(t, containers)

	byCategory := map[string]telemetrytest.LogRecord{}
	for _, l := range rec.LogRecords() {
		if l.EventName == eventCategory {
			byCategory[l.Attrs[semconv.AttrDiagnosticCategory]] = l
		}
	}
	if len(byCategory) != 4 {
		t.Fatalf("want 4 category twins, got %d", len(byCategory))
	}
	// The container attribute is the derived insights-logs-<lowercase> name.
	if c := byCategory["SignInLogs"].Attrs[semconv.AttrContainer]; c != "insights-logs-signinlogs" {
		t.Errorf("SignInLogs container = %q", c)
	}
	// State rides the twin too.
	if s := byCategory["SignInLogs"].Attrs[semconv.AttrState]; s != stateEnabledUnread {
		t.Errorf("SignInLogs state = %q", s)
	}
	if s := byCategory["AuditLogs"].Attrs[semconv.AttrState]; s != stateMappedButDisabled {
		t.Errorf("AuditLogs state = %q", s)
	}
}

// TestCategoryTwin_Severity drives the mapper directly and compares this
// project's telemetry.Severity enum — the telemetrytest doc warns that the
// captured SeverityNumber is a DIFFERENT scale (log.Severity), so asserting
// severity end-to-end is a known trap.
func TestCategoryTwin_Severity(t *testing.T) {
	cases := []struct {
		state string
		want  telemetry.Severity
	}{
		{stateConsumed, telemetry.SeverityInfo},
		{stateDisabled, telemetry.SeverityInfo},
		{stateEnabledUnread, telemetry.SeverityWarn},
		{stateMappedButDisabled, telemetry.SeverityError},
	}
	for _, tc := range cases {
		got := categoryTwin("Cat", "insights-logs-cat", tc.state, true, true).Severity
		if got != tc.want {
			t.Errorf("state %q severity = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestCollect_NilARM_NoOp(t *testing.T) {
	rec := telemetrytest.New()
	c := New(nil, []string{"insights-logs-signinlogs"}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricCategories); len(pts) != 0 {
		t.Errorf("nil ARM should emit nothing, got %d points", len(pts))
	}
}

func TestCollect_NoStorageSink_NoOp(t *testing.T) {
	body := `{"value":[{"name":"la","properties":{"storageAccountId":"","logs":[{"category":"SignInLogs","enabled":true}]}}]}`
	rec := telemetrytest.New()
	c := New(&fakeARM{body: []byte(body)}, []string{"insights-logs-signinlogs"}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if pts := rec.MetricPoints(metricCategories); len(pts) != 0 {
		t.Errorf("no storage-sinking setting should emit nothing, got %d points", len(pts))
	}
}

func TestCollect_ARMError_Propagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(&fakeARM{err: errors.New("403 AuthorizationFailed")}, nil, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when ARM read fails")
	}
}
