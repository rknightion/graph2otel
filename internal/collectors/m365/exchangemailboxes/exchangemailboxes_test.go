package exchangemailboxes

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

// The three fixtures below are VERBATIM Get-Mailbox records captured from the
// m7kni tenant as graph2otel-poller on 2026-07-23 over the Exchange Online admin
// API, narrowed to the keys the mapper reads (the live records carry 336 keys
// each). The tenant supplies real variance: the DiscoveryMailbox has auditing
// AND single-item recovery OFF and is hidden and account-disabled, while the two
// user mailboxes have both protections on.
//
// Shapes worth noting, all live:
//   - quotas are FORMATTED STRINGS, not numbers ("99 GB (106,300,440,576 bytes)")
//   - LitigationHoldDuration is the string "Unlimited"
//   - RetainDeletedItemsFor / AuditLogAgeLimit are .NET TimeSpans ("14.00:00:00")
//   - EmailAddresses is a prefixed list (smtp:/SMTP:/SIP:/SPO:)
//   - ExternalDirectoryObjectId is "" (not null) on the discovery mailbox
const liveDiscoveryMailbox = `{
  "UserPrincipalName": "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@m7knio.onmicrosoft.com",
  "DisplayName": "Discovery Search Mailbox",
  "PrimarySmtpAddress": "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@m7knio.onmicrosoft.com",
  "RecipientTypeDetails": "DiscoveryMailbox",
  "ExchangeGuid": "a607efe4-0e5b-4e71-a31e-9c3f704de07d",
  "ExternalDirectoryObjectId": "",
  "LitigationHoldEnabled": false,
  "LitigationHoldDuration": "Unlimited",
  "LitigationHoldDate": null,
  "LitigationHoldOwner": "",
  "InPlaceHolds": [],
  "RetentionHoldEnabled": false,
  "SingleItemRecoveryEnabled": false,
  "RetainDeletedItemsFor": "14.00:00:00",
  "ComplianceTagHoldApplied": false,
  "ForwardingAddress": null,
  "ForwardingSmtpAddress": null,
  "DeliverToMailboxAndForward": false,
  "HiddenFromAddressListsEnabled": true,
  "AuditEnabled": false,
  "AuditLogAgeLimit": "90.00:00:00",
  "ArchiveStatus": "None",
  "ArchiveState": "None",
  "ArchiveGuid": "00000000-0000-0000-0000-000000000000",
  "IsMailboxEnabled": true,
  "AccountDisabled": true,
  "WhenMailboxCreated": "2025-08-08T18:39:16.0000000+00:00",
  "MessageCopyForSentAsEnabled": false,
  "MessageCopyForSendOnBehalfEnabled": false,
  "GrantSendOnBehalfTo": [],
  "ProhibitSendQuota": "50 GB (53,687,091,200 bytes)",
  "ProhibitSendReceiveQuota": "50 GB (53,687,091,200 bytes)",
  "IssueWarningQuota": "50 GB (53,687,091,200 bytes)",
  "MailboxPlan": null,
  "IsDirSynced": false,
  "IsShared": true,
  "IsResource": false,
  "IsInactiveMailbox": false,
  "EmailAddresses": ["SMTP:DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@m7knio.onmicrosoft.com"],
  "Identity": "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}"
}`

const liveUserMailbox = `{
  "UserPrincipalName": "rob@m7kni.io",
  "DisplayName": "Rob Knight",
  "PrimarySmtpAddress": "rob@m7kni.io",
  "RecipientTypeDetails": "UserMailbox",
  "ExchangeGuid": "2f0eef8a-ac24-475e-beae-3da243345ad9",
  "ExternalDirectoryObjectId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
  "LitigationHoldEnabled": false,
  "LitigationHoldDuration": "Unlimited",
  "LitigationHoldDate": null,
  "LitigationHoldOwner": "",
  "InPlaceHolds": [],
  "RetentionHoldEnabled": false,
  "SingleItemRecoveryEnabled": true,
  "RetainDeletedItemsFor": "14.00:00:00",
  "ComplianceTagHoldApplied": false,
  "ForwardingAddress": null,
  "ForwardingSmtpAddress": null,
  "DeliverToMailboxAndForward": false,
  "HiddenFromAddressListsEnabled": false,
  "AuditEnabled": true,
  "AuditLogAgeLimit": "90.00:00:00",
  "ArchiveStatus": "None",
  "ArchiveState": "None",
  "ArchiveGuid": "00000000-0000-0000-0000-000000000000",
  "IsMailboxEnabled": true,
  "AccountDisabled": false,
  "WhenMailboxCreated": "2025-11-11T09:47:38.0000000+00:00",
  "MessageCopyForSentAsEnabled": false,
  "MessageCopyForSendOnBehalfEnabled": false,
  "GrantSendOnBehalfTo": [],
  "ProhibitSendQuota": "99 GB (106,300,440,576 bytes)",
  "ProhibitSendReceiveQuota": "100 GB (107,374,182,400 bytes)",
  "IssueWarningQuota": "98 GB (105,226,698,752 bytes)",
  "MailboxPlan": "ExchangeOnlineEnterprise-b25353e8-da0a-43b2-b980-e977863ed352",
  "IsDirSynced": false,
  "IsShared": false,
  "IsResource": false,
  "IsInactiveMailbox": false,
  "EmailAddresses": [
    "smtp:rob@m7kni.com", "smtp:rob@rob-knight.com", "SIP:rob@m7kni.io",
    "SMTP:rob@m7kni.io",
    "SPO:SPO_71603498-72de-4c30-a6bd-a1e6019c3fc5@SPO_4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
  ],
  "Identity": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504"
}`

const liveUserMailbox2 = `{
  "UserPrincipalName": "vmuser@m7kni.io",
  "DisplayName": "vmuser",
  "PrimarySmtpAddress": "vmuser@m7kni.io",
  "RecipientTypeDetails": "UserMailbox",
  "ExchangeGuid": "1cc1bda9-7fa3-414c-b532-f960af587001",
  "ExternalDirectoryObjectId": "7957928c-3cd2-4bbb-98c8-cfc8466f490a",
  "LitigationHoldEnabled": false, "LitigationHoldDuration": "Unlimited",
  "LitigationHoldDate": null, "LitigationHoldOwner": "", "InPlaceHolds": [],
  "RetentionHoldEnabled": false, "SingleItemRecoveryEnabled": true,
  "RetainDeletedItemsFor": "14.00:00:00", "ComplianceTagHoldApplied": false,
  "ForwardingAddress": null, "ForwardingSmtpAddress": null,
  "DeliverToMailboxAndForward": false, "HiddenFromAddressListsEnabled": false,
  "AuditEnabled": true, "AuditLogAgeLimit": "90.00:00:00",
  "ArchiveStatus": "None", "ArchiveState": "None",
  "ArchiveGuid": "00000000-0000-0000-0000-000000000000",
  "IsMailboxEnabled": true, "AccountDisabled": false,
  "WhenMailboxCreated": "2026-07-21T08:00:17.0000000+00:00",
  "MessageCopyForSentAsEnabled": false, "MessageCopyForSendOnBehalfEnabled": false,
  "GrantSendOnBehalfTo": [],
  "ProhibitSendQuota": "99 GB (106,300,440,576 bytes)",
  "ProhibitSendReceiveQuota": "100 GB (107,374,182,400 bytes)",
  "IssueWarningQuota": "98 GB (105,226,698,752 bytes)",
  "MailboxPlan": "ExchangeOnlineEnterprise-b25353e8-da0a-43b2-b980-e977863ed352",
  "IsDirSynced": false, "IsShared": false, "IsResource": false, "IsInactiveMailbox": false,
  "EmailAddresses": ["SIP:vmuser@m7kni.io", "SMTP:vmuser@m7kni.io"],
  "Identity": "7957928c-3cd2-4bbb-98c8-cfc8466f490a"
}`

// forwardingMailbox exercises the exfiltration path. m7kni has no forwarding
// mailbox, so the field NAMES are live-verified (present as null above) and only
// the populated values here are synthetic — the mapper reads them as plain
// strings, the shape the cmdlet documents and the only shape a single address
// can take.
const forwardingMailbox = `{
  "UserPrincipalName": "victim@m7kni.io", "DisplayName": "victim",
  "PrimarySmtpAddress": "victim@m7kni.io", "RecipientTypeDetails": "UserMailbox",
  "ForwardingSmtpAddress": "smtp:attacker@evil.test",
  "ForwardingAddress": null, "DeliverToMailboxAndForward": true,
  "AuditEnabled": true, "SingleItemRecoveryEnabled": true,
  "LitigationHoldEnabled": false, "RetentionHoldEnabled": false,
  "HiddenFromAddressListsEnabled": false, "ArchiveStatus": "None",
  "Identity": "victim"
}`

type fakeEXO struct {
	recs   []map[string]any
	err    error
	params map[string]any
}

func (f *fakeEXO) Invoke(_ context.Context, _ string, params map[string]any) ([]map[string]any, error) {
	f.params = params
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

func collectWith(t *testing.T, exo *fakeEXO) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func collect(t *testing.T, recs []map[string]any) *telemetrytest.Recorder {
	t.Helper()
	return collectWith(t, &fakeEXO{recs: recs})
}

// liveTenant is m7kni exactly as captured.
func liveTenant(t *testing.T) []map[string]any {
	t.Helper()
	return recordsFrom(t, liveDiscoveryMailbox, liveUserMailbox, liveUserMailbox2)
}

// TestCollect_AsksForEveryMailbox is the no-silent-truncation guard. A truncated
// page's @odata.nextLink cannot be followed (its $skiptoken is bound to backend
// affinity this client cannot reproduce — live-measured 2026-07-23), so the
// cmdlet's own parameter is the ONLY way to defeat the page. Without
// ResultSize=Unlimited a tenant larger than one page silently reports a fraction
// of its mailboxes.
func TestCollect_AsksForEveryMailbox(t *testing.T) {
	exo := &fakeEXO{recs: liveTenant(t)}
	collectWith(t, exo)
	if got := exo.params[paramResultSize]; got != resultSizeUnlimited {
		t.Errorf("%s = %v, want %q", paramResultSize, got, resultSizeUnlimited)
	}
}

func gaugeBy(rec *telemetrytest.Recorder, metric string, keys ...string) map[string]float64 {
	out := map[string]float64{}
	for _, p := range rec.MetricPoints(metric) {
		k := ""
		for i, key := range keys {
			if i > 0 {
				k += "/"
			}
			k += p.Attrs[key]
		}
		out[k] = p.Value
	}
	return out
}

func TestCollect_MailboxCensus(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricMailboxes,
		semconv.AttrRecipientTypeDetails, semconv.AttrForwardingConfigured, semconv.AttrAuditEnabled)

	if got["UserMailbox/false/true"] != 2 {
		t.Errorf("UserMailbox/no-forwarding/audited = %v, want 2", got["UserMailbox/false/true"])
	}
	if got["DiscoveryMailbox/false/false"] != 1 {
		t.Errorf("DiscoveryMailbox/no-forwarding/unaudited = %v, want 1", got["DiscoveryMailbox/false/false"])
	}
	if len(got) != 2 {
		t.Errorf("census series = %d, want 2 observed combos", len(got))
	}
}

// TestCollect_ProtectionGauge is the posture half: how many mailboxes have each
// named protection ON. The tenant genuinely differs per setting, so this is not
// a constant.
func TestCollect_ProtectionGauge(t *testing.T) {
	rec := collect(t, liveTenant(t))
	got := gaugeBy(rec, metricSetting, semconv.AttrSetting)

	want := map[string]float64{
		settingAuditEnabled:       2, // the discovery mailbox is unaudited
		settingSingleItemRecovery: 2,
		settingLitigationHold:     0,
		settingRetentionHold:      0,
		settingHiddenFromAddress:  1,
		settingForwarding:         0,
		settingArchiveEnabled:     0,
		settingComplianceTagHold:  0,
		settingDeliverAndForward:  0,
		settingMessageCopySentAs:  0,
		settingInactiveMailbox:    0,
		settingAccountDisabled:    1,
	}
	for setting, w := range want {
		if got[setting] != w {
			t.Errorf("protection %s = %v, want %v", setting, got[setting], w)
		}
	}
	if len(got) != len(protectionSettings) {
		t.Errorf("protection series = %d, want %d (one per setting, all seeded)", len(got), len(protectionSettings))
	}
}

func TestCollect_TwinPerMailbox(t *testing.T) {
	rec := collect(t, liveTenant(t))
	n := 0
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			n++
		}
	}
	if n != 3 {
		t.Errorf("twins = %d, want 3", n)
	}
}

func TestCollect_TwinAttributes(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveUserMailbox))
	var a map[string]string
	for _, l := range rec.LogRecords() {
		if l.EventName == eventName {
			a = l.Attrs
		}
	}
	if a == nil {
		t.Fatal("no twin")
	}
	if a[semconv.AttrUserPrincipalName] != "rob@m7kni.io" {
		t.Errorf("upn = %q", a[semconv.AttrUserPrincipalName])
	}
	if a[semconv.AttrRecipientTypeDetails] != "UserMailbox" {
		t.Errorf("recipient_type_details = %q", a[semconv.AttrRecipientTypeDetails])
	}
	if a[semconv.AttrAuditEnabled] != "true" {
		t.Errorf("audit_enabled = %q", a[semconv.AttrAuditEnabled])
	}
	// Quotas stay VERBATIM: the wire gives a formatted string, and re-deriving a
	// number from it would be inventing a value the API never sent.
	if a[semconv.AttrProhibitSendQuota] != "99 GB (106,300,440,576 bytes)" {
		t.Errorf("prohibit_send_quota = %q, want the verbatim string", a[semconv.AttrProhibitSendQuota])
	}
	if a[semconv.AttrLitigationHoldDuration] != "Unlimited" {
		t.Errorf("litigation_hold_duration = %q", a[semconv.AttrLitigationHoldDuration])
	}
	if a[semconv.AttrRetainDeletedItemsFor] != "14.00:00:00" {
		t.Errorf("retain_deleted_items_for = %q", a[semconv.AttrRetainDeletedItemsFor])
	}
	if a[semconv.AttrMailboxPlan] == "" {
		t.Error("mailbox_plan should be present")
	}
	// The prefixed address list is joined, not dropped (#114).
	for _, want := range []string{"SMTP:rob@m7kni.io", "smtp:rob@rob-knight.com"} {
		if !contains(a[semconv.AttrEmailAddresses], want) {
			t.Errorf("email_addresses %q missing %q", a[semconv.AttrEmailAddresses], want)
		}
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (hay == needle ||
		len(hay) > 0 && (indexOf(hay, needle) >= 0))
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestCollect_EmptyStringsOmitted: ExternalDirectoryObjectId is "" (not null) on
// the discovery mailbox and must be omitted rather than stamped blank.
func TestCollect_EmptyStringsOmitted(t *testing.T) {
	rec := collect(t, recordsFrom(t, liveDiscoveryMailbox))
	for _, l := range rec.LogRecords() {
		if l.EventName != eventName {
			continue
		}
		if _, present := l.Attrs[semconv.AttrExternalDirectoryObjectId]; present {
			t.Error(`empty ExternalDirectoryObjectId should be omitted`)
		}
		if _, present := l.Attrs[semconv.AttrLitigationHoldOwner]; present {
			t.Error("empty LitigationHoldOwner should be omitted")
		}
	}
}

// TestMailboxTwin_Severity: SMTP forwarding off the tenant is the mailbox-level
// exfiltration path and rates Error. An unaudited mailbox is a blind spot rather
// than an active leak, so it is Warn.
func TestMailboxTwin_Severity(t *testing.T) {
	fwd := mailboxTwin(recordsFrom(t, forwardingMailbox)[0])
	if fwd.Severity != telemetry.SeverityError {
		t.Errorf("forwarding mailbox severity = %v, want Error", fwd.Severity)
	}
	if fwd.Attrs[semconv.AttrForwardingSmtpAddress] != "smtp:attacker@evil.test" {
		t.Errorf("forwarding_smtp_address = %v", fwd.Attrs[semconv.AttrForwardingSmtpAddress])
	}
	unaudited := mailboxTwin(recordsFrom(t, liveDiscoveryMailbox)[0])
	if unaudited.Severity != telemetry.SeverityWarn {
		t.Errorf("unaudited mailbox severity = %v, want Warn", unaudited.Severity)
	}
	ok := mailboxTwin(recordsFrom(t, liveUserMailbox)[0])
	if ok.Severity != telemetry.SeverityInfo {
		t.Errorf("healthy mailbox severity = %v, want Info", ok.Severity)
	}
}

func TestCollect_NoMailboxesStillSeedsProtection(t *testing.T) {
	rec := collect(t, nil)
	if got := len(rec.MetricPoints(metricSetting)); got != len(protectionSettings) {
		t.Errorf("protection series with no mailboxes = %d, want %d seeded", got, len(protectionSettings))
	}
	if got := len(rec.MetricPoints(metricMailboxes)); got != 0 {
		t.Errorf("census series with no mailboxes = %d, want 0 (no recipient types observed)", got)
	}
}

func TestCollect_ErrorPropagates(t *testing.T) {
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: &fakeEXO{err: errors.New("403")}})
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Fatal("want error when the cmdlet fails")
	}
}
