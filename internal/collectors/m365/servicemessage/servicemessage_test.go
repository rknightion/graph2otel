package servicemessage

import (
	"context"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeGraph struct{ bodies map[string]string }

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	return []byte(f.bodies[url]), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const messagesURL = defaultBaseURL + messagesPath

// fixture is a /messages response shaped after the live m7kni wire (2026-07-18,
// #182): a stayInformed post, a planForChange major-change post carrying a
// services list + a body, and a preventOrFixIssue post with an
// actionRequiredByDateTime (null on the others — the omit case).
const fixture = `{"value":[
  {
    "id": "MC1009930", "title": "Teams: distinguish invite roles",
    "category": "stayInformed", "severity": "normal",
    "isMajorChange": false, "hasAttachments": false,
    "startDateTime": "2025-02-19T00:45:30Z", "endDateTime": "2026-11-30T07:00:00Z",
    "actionRequiredByDateTime": null, "lastModifiedDateTime": "2026-07-16T16:50:22Z",
    "services": ["Microsoft Teams"],
    "body": {"content": "<p>We are updating Teams invites.</p>", "contentType": "html"}
  },
  {
    "id": "MC2000001", "title": "Retirement of the old admin page",
    "category": "planForChange", "severity": "normal",
    "isMajorChange": true, "hasAttachments": false,
    "startDateTime": "2026-07-01T00:00:00Z", "endDateTime": "2026-12-01T00:00:00Z",
    "actionRequiredByDateTime": null, "lastModifiedDateTime": "2026-07-10T00:00:00Z",
    "services": ["Exchange Online", "SharePoint Online"],
    "body": {"content": "<p>Plan for this change.</p>", "contentType": "html"}
  },
  {
    "id": "MC3000002", "title": "Fix required for a connector",
    "category": "preventOrFixIssue", "severity": "normal",
    "isMajorChange": false, "hasAttachments": true,
    "startDateTime": "2026-07-05T00:00:00Z", "endDateTime": "2026-08-05T00:00:00Z",
    "actionRequiredByDateTime": "2026-07-31T00:00:00Z", "lastModifiedDateTime": "2026-07-12T00:00:00Z",
    "services": ["Exchange Online"],
    "body": {"content": "<p>Action needed.</p>", "contentType": "html"}
  }
]}`

func newFixtureCollector() *Collector {
	return New(&fakeGraph{bodies: map[string]string{messagesURL: fixture}}, nil)
}

func TestCollectCountsByCategoryAndTwinsEveryMessage(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	counts := map[[2]string]float64{}
	for _, p := range rec.MetricPoints(metricMessagesTotal) {
		counts[[2]string{p.Attrs["category"], p.Attrs["severity"]}] = p.Value
	}
	for _, c := range []string{"stayInformed", "planForChange", "preventOrFixIssue"} {
		if counts[[2]string{c, "normal"}] != 1 {
			t.Errorf("messages.total{category=%s,severity=normal} = %v, want 1", c, counts[[2]string{c, "normal"}])
		}
	}

	// Every message produces exactly one twin (no dedup drop, no double-emit).
	if n := len(rec.LogRecords()); n != 3 {
		t.Fatalf("emitted %d twins, want 3 (one per message)", n)
	}
}

func TestMetricsCarryNoPerMessageAttribute(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	allowed := map[string]bool{"category": true, "severity": true, "tenant_id": true}
	for _, p := range rec.MetricPoints(metricMessagesTotal) {
		for k := range p.Attrs {
			if !allowed[k] {
				t.Errorf("metric %s has per-message attribute %q (id/title must never be a metric label): %v", metricMessagesTotal, k, p.Attrs)
			}
		}
	}
}

func TestTwinCarriesDetailAndHandlesNullActionDate(t *testing.T) {
	rec := telemetrytest.New()
	if err := newFixtureCollector().Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]telemetrytest.LogRecord{}
	for _, l := range rec.LogRecords() {
		byID[l.Attrs["id"]] = l
	}

	// The major-change post: severity escalates to WARN, services list carried.
	major := byID["MC2000001"]
	if major.EventName != eventMessage {
		t.Errorf("event name = %q, want %q", major.EventName, eventMessage)
	}
	if major.Attrs["is_major_change"] != "true" {
		t.Errorf("is_major_change = %q, want \"true\"", major.Attrs["is_major_change"])
	}
	if major.Attrs["services"] == "" {
		t.Error("services should be carried on the twin")
	}
	if major.Attrs["message_body"] == "" {
		t.Error("message_body (the announcement text) should be carried")
	}
	// stayInformed post has a null actionRequiredByDateTime — must be omitted.
	info := byID["MC1009930"]
	if _, present := info.Attrs["action_required_by_date_time"]; present {
		t.Errorf("action_required_by_date_time must be omitted when null, got %q", info.Attrs["action_required_by_date_time"])
	}
	// preventOrFixIssue post carries a real actionRequiredByDateTime.
	fix := byID["MC3000002"]
	if fix.Attrs["action_required_by_date_time"] != "2026-07-31T00:00:00Z" {
		t.Errorf("action_required_by_date_time = %q, want the deadline", fix.Attrs["action_required_by_date_time"])
	}
	if fix.Attrs["has_attachments"] != "true" {
		t.Errorf("has_attachments = %q, want \"true\"", fix.Attrs["has_attachments"])
	}
}
