package oauthapps

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveSummary is a verbatim summarize result captured from m7kni as
// graph2otel-poller on 2026-07-23: apps/consented_users/max_risk by the four
// bounded categorical dimensions. IsAdminConsented is SByte-encoded.
const liveSummary = `[
  {"PrivilegeLevel":"Low","AppStatus":"Enabled","AppOrigin":"External","IsAdminConsented":0,"apps":239,"consented_users":239,"max_risk":72},
  {"PrivilegeLevel":"High","AppStatus":"Enabled","AppOrigin":"External","IsAdminConsented":0,"apps":234,"consented_users":231,"max_risk":65},
  {"PrivilegeLevel":"High","AppStatus":"Enabled","AppOrigin":"External","IsAdminConsented":1,"apps":258,"consented_users":0,"max_risk":90},
  {"PrivilegeLevel":"Medium","AppStatus":"Enabled","AppOrigin":"Internal","IsAdminConsented":0,"apps":77,"consented_users":0,"max_risk":27},
  {"PrivilegeLevel":"High","AppStatus":"Enabled","AppOrigin":"Internal","IsAdminConsented":0,"apps":109,"consented_users":2,"max_risk":70}
]`

// liveTwin is the verbatim ChatGPT row: a High-privilege, admin-consented,
// externally-owned app with a verified publisher, a {} ConsentedUsersCount, and a
// Permissions list of embedded-JSON strings.
const liveTwin = `{
  "ReportId":"51958331-784d-4d16-91f2-de484fbf9f6f","Timestamp":"2026-07-23T18:03:20.928Z",
  "OAuthAppId":"e0476654-c1d5-430b-ab80-70cbd947616a","ServicePrincipalId":"eded70f5-6542-4cc4-9480-60054167566e",
  "AppName":"ChatGPT","AddedOnTime":"2026-07-17T19:37:10Z","LastModifiedTime":"2026-07-17T19:37:43Z",
  "AppStatus":"Enabled","PrivilegeLevel":"High",
  "Permissions@odata.type":"#Collection(String)","Permissions":[
    "{\"PermissionType\":\"Delegated\",\"PermissionValue\":\"Files.Read.All\",\"InUse\":\"true\",\"PrivilegeLevel\":\"High\"}",
    "{\"PermissionType\":\"Delegated\",\"PermissionValue\":\"Mail.ReadWrite\",\"InUse\":\"true\",\"PrivilegeLevel\":\"High\"}"
  ],
  "IsAdminConsented@odata.type":"#SByte","IsAdminConsented":1,"AppOrigin":"External",
  "AppOwnerTenantId":"a48cca56-e6da-484e-a814-9c849652bcb3","LastUsedTime":"2026-07-20T23:11:51.791Z",
  "RiskScore":56,"AssignedRoles@odata.type":"#Collection(String)","AssignedRoles":[],"ConsentedUsersCount":{},
  "VerifiedPublisher":{"@odata.type":"#microsoft.graph.security.dynamicColumnValue","displayName":"OpenAI, L.L.C.","verifiedPublisherId":"6692127","addedDateTime":"2023-10-05T16:48:39.0000000Z"}
}`

// liveTwinUnverified is a Low-privilege app with no verified publisher ({} on the
// wire) to drive the is_verified=false / Info branch.
const liveTwinUnverified = `{
  "OAuthAppId":"bbb","ServicePrincipalId":"ccc","AppName":"some internal tool","AppStatus":"Enabled",
  "PrivilegeLevel":"Low","AppOrigin":"Internal","RiskScore":18,"ConsentedUsersCount":3,
  "IsAdminConsented@odata.type":"#SByte","IsAdminConsented":0,
  "Permissions@odata.type":"#Collection(String)","Permissions":[],"VerifiedPublisher":{}
}`

type fakeHunt struct {
	summary []map[string]any
	twins   map[string][]map[string]any // by PrivilegeLevel
	err     error
}

func (f *fakeHunt) Query(_ context.Context, _ string, kql string) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	if strings.Contains(kql, "summarize") {
		return f.summary, nil
	}
	for priv, rows := range f.twins {
		if strings.Contains(kql, `== "`+priv+`"`) {
			return rows, nil
		}
	}
	return nil, nil
}

func rows(t *testing.T, docs ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func rowsFromArray(t *testing.T, doc string) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		t.Fatalf("unmarshal array fixture: %v", err)
	}
	return out
}

func TestCollect_Gauges(t *testing.T) {
	f := &fakeHunt{summary: rowsFromArray(t, liveSummary), twins: map[string][]map[string]any{}}
	rec := telemetrytest.New()
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// apps: 5 categorical series on the wire.
	if got := len(rec.MetricPoints(metricApps)); got != 5 {
		t.Errorf("apps: got %d series, want 5", got)
	}
	// max_risk_score collapses to privilege: High = max(90,65,70) = 90.
	for _, p := range rec.MetricPoints(metricMaxRiskScore) {
		if p.Attrs[semconv.AttrPrivilegeLevel] == "High" && p.Value != 90 {
			t.Errorf("High max_risk_score = %v, want 90 (max of maxes)", p.Value)
		}
	}
	// consented_users collapses to privilege: High = 231+0+2 = 233.
	for _, p := range rec.MetricPoints(metricConsentedUsers) {
		if p.Attrs[semconv.AttrPrivilegeLevel] == "High" && p.Value != 233 {
			t.Errorf("High consented_users = %v, want 233 (sum of sums)", p.Value)
		}
	}
	// RiskScore must NOT appear as a metric label anywhere.
	for _, m := range []string{metricApps, metricMaxRiskScore, metricConsentedUsers} {
		for _, p := range rec.MetricPoints(m) {
			if _, bad := p.Attrs[semconv.AttrRiskScore]; bad {
				t.Errorf("%s carries risk_score as a label — it must be twin-only", m)
			}
		}
	}
}

func TestCollect_Twin(t *testing.T) {
	f := &fakeHunt{
		summary: rowsFromArray(t, liveSummary),
		twins:   map[string][]map[string]any{"High": rows(t, liveTwin)},
	}
	rec := telemetrytest.New()
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var twin map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			twin = l.Attrs
		}
	}
	if twin == nil {
		t.Fatal("no oauth_app twin emitted")
	}
	if twin[semconv.AttrAppName] != "ChatGPT" {
		t.Errorf("app_name = %q", twin[semconv.AttrAppName])
	}
	if twin[semconv.AttrRiskScore] != "56" {
		t.Errorf("risk_score = %q, want 56", twin[semconv.AttrRiskScore])
	}
	if twin[semconv.AttrVerifiedPublisherName] != "OpenAI, L.L.C." {
		t.Errorf("verified_publisher_name = %q", twin[semconv.AttrVerifiedPublisherName])
	}
	if twin[semconv.AttrVerifiedPublisherId] != "6692127" {
		t.Errorf("verified_publisher_id = %q", twin[semconv.AttrVerifiedPublisherId])
	}
	if twin[semconv.AttrIsVerifiedPublisher] != "true" {
		t.Errorf("is_verified_publisher = %q, want true", twin[semconv.AttrIsVerifiedPublisher])
	}
	// Permissions parsed from the embedded-JSON list.
	if !strings.Contains(twin[semconv.AttrPermissionValues], "Files.Read.All") ||
		!strings.Contains(twin[semconv.AttrPermissionValues], "Mail.ReadWrite") {
		t.Errorf("permission_values = %q, want the two granted scopes", twin[semconv.AttrPermissionValues])
	}
	if twin[semconv.AttrPermissionsCount] != "2" {
		t.Errorf("permissions_count = %q, want 2", twin[semconv.AttrPermissionsCount])
	}
	// ConsentedUsersCount is {} on the wire -> omitted.
	if _, present := twin[semconv.AttrConsentedUsersCount]; present {
		t.Error("null ({}) consented_users_count should be omitted")
	}
}

func TestAppTwin_Severity(t *testing.T) {
	high := appTwin(rows(t, liveTwin)[0])
	if high.Severity != telemetry.SeverityWarn {
		t.Errorf("High-privilege severity = %v, want Warn", high.Severity)
	}
	low := appTwin(rows(t, liveTwinUnverified)[0])
	if low.Severity != telemetry.SeverityInfo {
		t.Errorf("Low-privilege severity = %v, want Info", low.Severity)
	}
	// The unverified app reports is_verified_publisher=false.
	if got := low.Attrs[semconv.AttrIsVerifiedPublisher]; got != "false" {
		t.Errorf("unverified is_verified_publisher = %v, want false", got)
	}
}

func TestCollect_SummaryFailureIsFatal(t *testing.T) {
	f := &fakeHunt{err: errors.New("403")}
	if err := New(collectors.HuntDeps{Client: f}).Collect(context.Background(), telemetrytest.New().Emitter()); err == nil {
		t.Fatal("summary failure should be fatal")
	}
}
