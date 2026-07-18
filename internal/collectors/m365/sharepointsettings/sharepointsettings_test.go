package sharepointsettings

import (
	"context"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph serves one canned body for the settings URL.
type fakeGraph struct{ body string }

func (f *fakeGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	if !strings.HasSuffix(url, "/admin/sharepoint/settings") {
		return nil, nil
	}
	return []byte(f.body), nil
}

func (f *fakeGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return f.RawGet(ctx, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// liveSettings is a real /admin/sharepoint/settings response captured off m7kni
// as graph2otel-poller (2026-07-18, #127): permissive external+guest sharing,
// legacy auth OFF, empty domain lists — the shape a mapper must handle.
const liveSettings = `{
  "sharingCapability": "externalUserAndGuestSharing",
  "sharingDomainRestrictionMode": "none",
  "sharingAllowedDomainList": [],
  "sharingBlockedDomainList": [],
  "isResharingByExternalUsersEnabled": true,
  "isLegacyAuthProtocolsEnabled": false,
  "isUnmanagedSyncAppForTenantRestricted": false,
  "deletedUserPersonalSiteRetentionPeriodInDays": 30,
  "personalSiteDefaultStorageLimitInMB": 1048576,
  "siteCreationDefaultStorageLimitInMB": 26214400,
  "idleSessionSignOut": { "isEnabled": false, "warnAfterInSeconds": 0, "signOutAfterInSeconds": 0 }
}`

func TestCollectEmitsPostureGaugesAndTwin(t *testing.T) {
	rec := telemetrytest.New()
	c := New(&fakeGraph{body: liveSettings}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// The sharing info gauge carries the enum posture as bounded attributes.
	sh := rec.MetricPoints(metricSharing)
	if len(sh) != 1 || sh[0].Value != 1 {
		t.Fatalf("%s = %v, want a single point of 1", metricSharing, sh)
	}
	if got := sh[0].Attrs[semconv.AttrSharingCapability]; got != "externalUserAndGuestSharing" {
		t.Errorf("sharing_capability attr = %q, want externalUserAndGuestSharing", got)
	}

	// Bool posture gauges: legacy auth OFF -> 0.
	if la := rec.MetricPoints(metricLegacyAuth); len(la) != 1 || la[0].Value != 0 {
		t.Errorf("%s = %v, want 0 (legacy auth off)", metricLegacyAuth, la)
	}
	if er := rec.MetricPoints(metricExternalResharing); len(er) != 1 || er[0].Value != 1 {
		t.Errorf("%s = %v, want 1 (external resharing on)", metricExternalResharing, er)
	}

	// Numeric limits pass through.
	if r := rec.MetricPoints(metricRetentionDays); len(r) != 1 || r[0].Value != 30 {
		t.Errorf("%s = %v, want 30", metricRetentionDays, r)
	}
	if p := rec.MetricPoints(metricPersonalStorageMB); len(p) != 1 || p[0].Value != 1048576 {
		t.Errorf("%s = %v, want 1048576", metricPersonalStorageMB, p)
	}

	// Domain-list counts are gauges; the lists themselves are log-only.
	if ad := rec.MetricPoints(metricAllowedDomains); len(ad) != 1 || ad[0].Value != 0 {
		t.Errorf("%s = %v, want 0", metricAllowedDomains, ad)
	}

	// Exactly one log twin, carrying the posture.
	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d log records, want 1", len(logs))
	}
	if logs[0].EventName != eventName {
		t.Errorf("event name = %q, want %q", logs[0].EventName, eventName)
	}
	if got := logs[0].Attrs[semconv.AttrSharingCapability]; got != "externalUserAndGuestSharing" {
		t.Errorf("twin sharing_capability = %q", got)
	}
}

func TestCollectWarnsOnLegacyAuth(t *testing.T) {
	rec := telemetrytest.New()
	body := strings.Replace(liveSettings, `"isLegacyAuthProtocolsEnabled": false`, `"isLegacyAuthProtocolsEnabled": true`, 1)
	c := New(&fakeGraph{body: body}, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if la := rec.MetricPoints(metricLegacyAuth); len(la) != 1 || la[0].Value != 1 {
		t.Errorf("%s = %v, want 1 (legacy auth on)", metricLegacyAuth, la)
	}
}
