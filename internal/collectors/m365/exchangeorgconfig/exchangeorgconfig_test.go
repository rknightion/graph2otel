package exchangeorgconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// liveOrgConfig is a VERBATIM Get-OrganizationConfig record captured from the
// m7kni tenant as graph2otel-poller on 2026-07-23 over the Exchange Online admin
// API, narrowed to the keys the mapper reads (the live record carries 336).
//
// Two shapes the mapper must respect, both live:
//   - PublicFoldersEnabled is the STRING "Local", not a boolean — it must never
//     land in the 0/1 posture gauge.
//   - MessageRecallEnabled, FocusedInboxOn and DefaultAuthenticationPolicy are
//     null: tri-state "not configured", NOT false.
const liveOrgConfig = `{
  "Name": "m7knio.onmicrosoft.com",
  "Identity": "m7knio.onmicrosoft.com",
  "Guid": "27c9b323-e32f-428a-bd76-d8d19d791c0e",
  "DisplayName": "m7kni",
  "OAuth2ClientProfileEnabled": true,
  "AuditDisabled": false,
  "IsDehydrated": false,
  "CustomerLockboxEnabled": true,
  "EwsEnabled": false,
  "EwsAllowOutlook": null,
  "EwsAllowMacOutlook": null,
  "EwsApplicationAccessPolicy": null,
  "AutoExpandingArchiveEnabled": false,
  "MailTipsAllTipsEnabled": true,
  "MailTipsExternalRecipientsTipsEnabled": true,
  "ConnectorsEnabled": true,
  "ConnectorsEnabledForOutlook": true,
  "ConnectorsEnabledForTeams": true,
  "ConnectorsEnabledForYammer": true,
  "PublicFoldersEnabled": "Local",
  "PublicComputersDetectionEnabled": false,
  "ActivityBasedAuthenticationTimeoutEnabled": true,
  "ActivityBasedAuthenticationTimeoutInterval": "06:00:00",
  "ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled": true,
  "DefaultAuthenticationPolicy": null,
  "SendFromAliasEnabled": false,
  "AutodiscoverPartialDirSync": false,
  "BookingsEnabled": true,
  "OutlookMobileGCCRestrictionsEnabled": false,
  "FocusedInboxOn": null,
  "LinkPreviewEnabled": true,
  "MessageRemindersEnabled": true,
  "SmtpActionableMessagesEnabled": true,
  "IPListBlocked": [],
  "WorkspaceTenantEnabled": true,
  "MessageRecallEnabled": null,
  "DirectReportsGroupAutoCreationEnabled": false,
  "UnblockUnsafeSenderPromptEnabled": true,
  "MaskClientIpInReceivedHeadersEnabled": true,
  "ElcProcessingDisabled": false,
  "HierarchicalAddressBookRoot": null,
  "IsMixedMode": true
}`

type fakeEXO struct {
	recs []map[string]any
	err  error
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
}

func recordsFrom(t *testing.T, docs ...string) []map[string]any {
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

func collect(t *testing.T, recs []map[string]any) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{recs: recs}})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func settingValues(rec *telemetrytest.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metricSetting) {
		out[p.Attrs[semconv.AttrSetting]] = p.Value
	}
	return out
}

func TestCollect_PostureGauge(t *testing.T) {
	got := settingValues(collect(t, recordsFrom(t, liveOrgConfig)))

	want := map[string]float64{
		"oauth2_client_profile_enabled":              1,
		"audit_disabled":                             0,
		"customer_lockbox_enabled":                   1,
		"ews_enabled":                                0,
		"connectors_enabled":                         1,
		"send_from_alias_enabled":                    0,
		"elc_processing_disabled":                    0,
		"is_mixed_mode":                              1,
		"mail_tips_external_recipients_tips_enabled": 1,
	}
	for setting, w := range want {
		v, ok := got[setting]
		if !ok {
			t.Errorf("setting %s missing from the posture gauge", setting)
			continue
		}
		if v != w {
			t.Errorf("setting %s = %v, want %v", setting, v, w)
		}
	}
}

// TestCollect_NullSettingIsOmittedNotZero: MessageRecallEnabled is null, meaning
// "not configured". A 0 there would assert the tenant turned message recall OFF,
// which it never did.
func TestCollect_NullSettingIsOmittedNotZero(t *testing.T) {
	got := settingValues(collect(t, recordsFrom(t, liveOrgConfig)))
	if v, present := got["message_recall_enabled"]; present {
		t.Errorf("null MessageRecallEnabled emitted as %v — it must be omitted", v)
	}
}

// TestCollect_StringSettingNeverEntersTheGauge: PublicFoldersEnabled is the
// string "Local". Coercing it to a boolean would silently report 0.
func TestCollect_StringSettingNeverEntersTheGauge(t *testing.T) {
	got := settingValues(collect(t, recordsFrom(t, liveOrgConfig)))
	if v, present := got["public_folders_enabled"]; present {
		t.Errorf("string PublicFoldersEnabled emitted as %v — it belongs on the twin", v)
	}
	// ...and it IS on the twin, verbatim.
	for _, l := range collect(t, recordsFrom(t, liveOrgConfig)).LogRecords() {
		if l.EventName == eventName && l.Attrs[semconv.AttrPublicFoldersEnabled] != "Local" {
			t.Errorf("public_folders_enabled = %q, want the verbatim \"Local\"", l.Attrs[semconv.AttrPublicFoldersEnabled])
		}
	}
}

func TestCollect_GaugeIsBounded(t *testing.T) {
	got := settingValues(collect(t, recordsFrom(t, liveOrgConfig)))
	if len(got) > len(booleanSettings) {
		t.Errorf("posture series = %d, cannot exceed the %d candidate settings", len(got), len(booleanSettings))
	}
	if len(got) == 0 {
		t.Fatal("no posture series emitted")
	}
}

func TestCollect_Twin(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveOrgConfig))
	var a map[string]string
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
			n++
		}
	}
	if n != 1 {
		t.Fatalf("twins = %d, want exactly 1", n)
	}
	if a[semconv.AttrDisplayName] != "m7kni" {
		t.Errorf("display_name = %q", a[semconv.AttrDisplayName])
	}
	if a[semconv.AttrName] != "m7knio.onmicrosoft.com" {
		t.Errorf("name = %q", a[semconv.AttrName])
	}
	if a[semconv.AttrActivityBasedAuthTimeoutInterval] != "06:00:00" {
		t.Errorf("activity timeout interval = %q", a[semconv.AttrActivityBasedAuthTimeoutInterval])
	}
	if a[semconv.AttrOauth2ClientProfileEnabled] != "true" {
		t.Errorf("oauth2_client_profile_enabled = %q", a[semconv.AttrOauth2ClientProfileEnabled])
	}
	if a[semconv.AttrAuditDisabled] != "false" {
		t.Errorf("audit_disabled = %q", a[semconv.AttrAuditDisabled])
	}
	// Null string fields are omitted, not stamped empty.
	if _, present := a[semconv.AttrDefaultAuthenticationPolicy]; present {
		t.Error("null DefaultAuthenticationPolicy should be omitted")
	}
}

// TestConfigTwin_Severity: modern authentication off means legacy auth — which
// bypasses conditional access and MFA — so it is Error. Org-wide mailbox
// auditing off is a recording blind spot and is Warn.
func TestConfigTwin_Severity(t *testing.T) {
	healthy := configTwin(recordsFrom(t, liveOrgConfig)[0])
	if healthy.Severity != telemetry.SeverityInfo {
		t.Errorf("healthy severity = %v, want Info", healthy.Severity)
	}

	noModernAuth := recordsFrom(t, liveOrgConfig)[0]
	noModernAuth["OAuth2ClientProfileEnabled"] = false
	if s := configTwin(noModernAuth).Severity; s != telemetry.SeverityError {
		t.Errorf("modern-auth-off severity = %v, want Error", s)
	}

	auditOff := recordsFrom(t, liveOrgConfig)[0]
	auditOff["AuditDisabled"] = true
	if s := configTwin(auditOff).Severity; s != telemetry.SeverityWarn {
		t.Errorf("audit-disabled severity = %v, want Warn", s)
	}
}

func TestCollect_EmptyResult_NoEmit(t *testing.T) {
	rec := collect(t, nil)
	if pts := rec.MetricPoints(metricSetting); len(pts) != 0 {
		t.Errorf("no config object should emit nothing, got %d points", len(pts))
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("no config object should emit no twin, got %d", len(logs))
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
