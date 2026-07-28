package mailboxdelegation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// Live wire captures (live-measured 2026-07-28, #355) against the m7kni
// tenant as graph2otel-poller, over the Exchange Online admin API.

const mailboxPermSelfPlain = `{
  "User": "NT AUTHORITY\\SELF",
  "AccessRights": ["FullAccess, ReadPermission"],
  "Deny": false,
  "IsInherited": false,
  "UserSid": "S-1-5-10",
  "PrimarySmtpAddress": ""
}`

const mailboxPermSelfExternal = `{
  "User": "NT AUTHORITY\\SELF",
  "AccessRights": ["FullAccess, ExternalAccount, ReadPermission"],
  "Deny": false,
  "IsInherited": false,
  "UserSid": "S-1-5-10",
  "PrimarySmtpAddress": ""
}`

const mailboxPermDiscoveryMgmt = `{
  "User": "Discovery Management",
  "AccessRights": ["FullAccess"],
  "Deny": false,
  "IsInherited": false,
  "UserSid": "S-1-5-21-1196097974-1292650839-4244031858-1272443",
  "PrimarySmtpAddress": ""
}`

const mailboxPermRob = `{
  "User": "rob@m7kni.io",
  "AccessRights": ["FullAccess"],
  "Deny": false,
  "IsInherited": false,
  "UserSid": "S-1-5-21-1196097974-1292650839-4244031858-1272489",
  "PrimarySmtpAddress": ""
}`

const recipientPermSelf = `{
  "Trustee": "NT AUTHORITY\\SELF",
  "AccessRights": ["SendAs"],
  "AccessControlType": "Allow",
  "TrusteeSidString": "S-1-5-10",
  "TrusteeWithPrimarySmtpAddress": ""
}`

const recipientPermRob = `{
  "Trustee": "rob@m7kni.io",
  "AccessRights": ["SendAs"],
  "AccessControlType": "Allow",
  "TrusteeSidString": "S-1-5-21-1196097974-1292650839-4244031858-1272489",
  "TrusteeWithPrimarySmtpAddress": ""
}`

// fakeEXO is a canned collectors.EXOClient: distinct rows per cmdlet name,
// with no live tenant, no Exchange grants, no HTTP. Also drives Get-Mailbox
// for exofanout.Enumerate.
type fakeEXO struct {
	mailboxRows          []map[string]any
	mailboxPermByAddr    map[string][]map[string]any
	recipientPermByAddr  map[string][]map[string]any
	mailboxPermErrAddr   string
	recipientPermErrAddr string
	err                  error // Get-Mailbox itself failing
}

func (f *fakeEXO) Invoke(_ context.Context, cmdlet string, params map[string]any) ([]map[string]any, error) {
	switch cmdlet {
	case "Get-Mailbox":
		if f.err != nil {
			return nil, f.err
		}
		return f.mailboxRows, nil
	case "Get-MailboxPermission":
		addr, _ := params["Identity"].(string)
		if addr == f.mailboxPermErrAddr && addr != "" {
			return nil, errors.New("boom mailbox permission")
		}
		return f.mailboxPermByAddr[addr], nil
	case "Get-RecipientPermission":
		addr, _ := params["Identity"].(string)
		if addr == f.recipientPermErrAddr && addr != "" {
			return nil, errors.New("boom recipient permission")
		}
		return f.recipientPermByAddr[addr], nil
	default:
		return nil, errors.New("unexpected cmdlet " + cmdlet)
	}
}

func mailboxRow(addr string) map[string]any {
	return map[string]any{
		"PrimarySmtpAddress":   addr,
		"DisplayName":          "dn-" + addr,
		"Identity":             "id-" + addr,
		"RecipientTypeDetails": "UserMailbox",
	}
}

func rowsFrom(t *testing.T, docs ...string) []map[string]any {
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

func collect(t *testing.T, exo *fakeEXO, cap int) *telemetrytest.Recorder {
	t.Helper()
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo, PerMailboxCap: cap})
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rec
}

func gaugePoints(t *testing.T, rec *telemetrytest.Recorder, metric string) []telemetrytest.MetricPoint {
	t.Helper()
	return rec.MetricPoints(metric)
}

func singleGaugeValue(t *testing.T, rec *telemetrytest.Recorder, metric string) float64 {
	t.Helper()
	pts := gaugePoints(t, rec, metric)
	if len(pts) != 1 {
		t.Fatalf("%s: want 1 point, got %d (%+v)", metric, len(pts), pts)
	}
	return pts[0].Value
}

func TestConstructedFromZeroValuedDeps(t *testing.T) {
	// The composition root calls the factory with a zero-valued EXODeps to
	// build the availability candidate and on the transport-init error path,
	// then immediately calls Name() on the result. The factory must never
	// return nil, and Name/DefaultInterval/RequiredPermissions must all be
	// safe against a totally zero-valued collector (no client, no cap).
	c := New(collectors.EXODeps{})
	if c == nil {
		t.Fatal("New(EXODeps{}) returned nil, must always be non-nil")
	}
	if got := c.Name(); got != collectorName {
		t.Errorf("Name() = %q, want %q", got, collectorName)
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval() must be positive")
	}
	if got := c.RequiredPermissions(); got != nil {
		t.Errorf("RequiredPermissions() = %v, want nil", got)
	}
}

func TestPerMailboxCollectorIsSelfDeclared(t *testing.T) {
	c := New(collectors.EXODeps{})
	if !collectors.IsPerMailbox(c) {
		t.Error("collectors.IsPerMailbox(c) = false, want true")
	}
}

func TestCoverageGaugesEmittedEveryCycle(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x"), mailboxRow("b@x"), mailboxRow("c@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, mailboxPermSelfPlain),
			"b@x": rowsFrom(t, mailboxPermSelfPlain),
			"c@x": rowsFrom(t, mailboxPermSelfPlain),
		},
		recipientPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, recipientPermSelf),
			"b@x": rowsFrom(t, recipientPermSelf),
			"c@x": rowsFrom(t, recipientPermSelf),
		},
	}
	rec := collect(t, exo, 2) // cap below the 3 mailboxes -> truncated

	if got := singleGaugeValue(t, rec, metricMailboxesTotal); got != 3 {
		t.Errorf("mailboxes_total = %v, want 3", got)
	}
	if got := singleGaugeValue(t, rec, metricMailboxesCovered); got != 2 {
		t.Errorf("mailboxes_covered = %v, want 2", got)
	}
}

func TestSelfPermissionCountedButNotTwinned(t *testing.T) {
	// Trap 3: NT AUTHORITY\SELF (SID S-1-5-10) is an implicit self-permission
	// on every mailbox, not a delegation. It must be counted in the assignment
	// gauge under trustee_kind=self, but never produce a log twin.
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, mailboxPermSelfPlain),
		},
		recipientPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, recipientPermSelf),
		},
	}
	rec := collect(t, exo, 0)

	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Fatalf("self-only tenant should emit no twins, got %d", len(logs))
	}

	pts := gaugePoints(t, rec, metricAssignments)
	var sawFullAccessSelf, sawSendAsSelf bool
	for _, p := range pts {
		if p.Attrs[semconv.AttrKind] == kindFullAccess && p.Attrs[semconv.AttrTrusteeKind] == trusteeKindSelf {
			sawFullAccessSelf = true
			if p.Value != 1 {
				t.Errorf("full_access/self value = %v, want 1", p.Value)
			}
		}
		if p.Attrs[semconv.AttrKind] == kindSendAs && p.Attrs[semconv.AttrTrusteeKind] == trusteeKindSelf {
			sawSendAsSelf = true
			if p.Value != 1 {
				t.Errorf("send_as/self value = %v, want 1", p.Value)
			}
		}
	}
	if !sawFullAccessSelf {
		t.Error("expected a full_access/self bucket counting the implicit SELF permission")
	}
	if !sawSendAsSelf {
		t.Error("expected a send_as/self bucket counting the implicit SELF permission")
	}
}

func TestSameSelfSidTwiceIsNotDeduped(t *testing.T) {
	// Trap 4: the same SELF SID appears TWICE on one mailbox with different
	// rights (plain FullAccess and FullAccess+ExternalAccount). Both rows must
	// be counted; deduping by SID would silently drop one.
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, mailboxPermSelfPlain, mailboxPermSelfExternal),
		},
		recipientPermByAddr: map[string][]map[string]any{
			"a@x": nil,
		},
	}
	rec := collect(t, exo, 0)

	pts := gaugePoints(t, rec, metricAssignments)
	var total float64
	for _, p := range pts {
		if p.Attrs[semconv.AttrKind] == kindFullAccess && p.Attrs[semconv.AttrTrusteeKind] == trusteeKindSelf {
			total += p.Value
		}
	}
	if total != 2 {
		t.Errorf("full_access/self total = %v, want 2 (both SELF rows counted)", total)
	}
}

func TestAccessRightsCommaJoinedElementIsSplit(t *testing.T) {
	// Trap 1: AccessRights is a collection whose ELEMENTS are comma-joined
	// strings: ["FullAccess, ReadPermission"] is ONE array element carrying
	// TWO rights. The mapper must split within the element, not just iterate
	// the array.
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("a@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"a@x": rowsFrom(t, mailboxPermSelfExternal), // rob's real target below
		},
		recipientPermByAddr: map[string][]map[string]any{"a@x": nil},
	}
	// Also verify the non-self, non-comma-joined single-element case still
	// classifies as full_access.
	exo.mailboxPermByAddr["a@x"] = append(exo.mailboxPermByAddr["a@x"], rowsFrom(t, mailboxPermRob)...)
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want exactly 1 twin (the non-self row), got %d", len(logs))
	}
	if rights := logs[0].Attrs[semconv.AttrRights]; rights == "" {
		t.Fatal("rights attribute missing on twin")
	}
}

func TestPrimarySmtpAddressNeverTrusted(t *testing.T) {
	// Trap 2: PrimarySmtpAddress / TrusteeWithPrimarySmtpAddress are EMPTY even
	// on genuine non-self delegations. The mailbox attribute on the twin must
	// come from the mailbox being polled (exofanout), never from the row.
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, mailboxPermRob),
		},
		recipientPermByAddr: map[string][]map[string]any{"owner@x": nil},
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want 1 twin, got %d", len(logs))
	}
	if got := logs[0].Attrs[semconv.AttrMailbox]; got != "owner@x" {
		t.Errorf("mailbox attr = %q, want %q (from exofanout, not the empty wire field)", got, "owner@x")
	}
	if got := logs[0].Attrs[semconv.AttrTrustee]; got != "rob@m7kni.io" {
		t.Errorf("trustee attr = %q, want rob@m7kni.io", got)
	}
}

func TestNonSelfFullAccessEmitsTwin(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, mailboxPermSelfPlain, mailboxPermDiscoveryMgmt, mailboxPermRob),
		},
		recipientPermByAddr: map[string][]map[string]any{"owner@x": nil},
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 2 {
		t.Fatalf("want 2 twins (Discovery Management + rob), got %d: %+v", len(logs), logs)
	}
	seen := map[string]bool{}
	for _, l := range logs {
		if l.EventName != eventName {
			t.Errorf("event name = %q, want %q", l.EventName, eventName)
		}
		seen[l.Attrs[semconv.AttrTrustee]] = true
		if l.Attrs[semconv.AttrKind] != kindFullAccess {
			t.Errorf("kind attr = %q, want %q", l.Attrs[semconv.AttrKind], kindFullAccess)
		}
		if l.Attrs[semconv.AttrTrusteeKind] != trusteeKindDelegated {
			t.Errorf("trustee_kind attr = %q, want %q", l.Attrs[semconv.AttrTrusteeKind], trusteeKindDelegated)
		}
	}
	if !seen["Discovery Management"] || !seen["rob@m7kni.io"] {
		t.Errorf("expected twins for both non-self trustees, got %+v", seen)
	}
}

func TestNonSelfSendAsEmitsTwinWithAccessControlType(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"owner@x": nil,
		},
		recipientPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, recipientPermSelf, recipientPermRob),
		},
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want 1 twin (rob, not SELF), got %d", len(logs))
	}
	l := logs[0]
	if l.Attrs[semconv.AttrKind] != kindSendAs {
		t.Errorf("kind attr = %q, want %q", l.Attrs[semconv.AttrKind], kindSendAs)
	}
	if l.Attrs[semconv.AttrAccessControlType] != "Allow" {
		t.Errorf("access_control_type = %q, want Allow", l.Attrs[semconv.AttrAccessControlType])
	}
	if l.Attrs[semconv.AttrTrustee] != "rob@m7kni.io" {
		t.Errorf("trustee = %q, want rob@m7kni.io", l.Attrs[semconv.AttrTrustee])
	}
}

func TestDenyAndIsInheritedOmittedWhenAbsent(t *testing.T) {
	// Absent-field rule: an absent optional scalar is OMITTED, never
	// fabricated as false. Get-RecipientPermission rows carry no Deny/
	// IsInherited keys at all live.
	exo := &fakeEXO{
		mailboxRows:       []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{"owner@x": nil},
		recipientPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, recipientPermRob),
		},
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want 1 twin, got %d", len(logs))
	}
	if _, present := logs[0].Attrs[semconv.AttrDeny]; present {
		t.Error("deny attribute must be absent on a send_as twin (no Deny field on the wire)")
	}
}

func TestDenyPresentAndFalseIsRecordedNotOmitted(t *testing.T) {
	// Distinguish "absent" from "present as false": a genuinely-false Deny
	// must still be omitted per this collector's own rule only when absent —
	// when PRESENT as false, that is real information and belongs on the
	// twin. This pins the pointer semantics: present+false != absent.
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, mailboxPermRob),
		},
		recipientPermByAddr: map[string][]map[string]any{"owner@x": nil},
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("want 1 twin, got %d", len(logs))
	}
	got, present := logs[0].Attrs[semconv.AttrDeny]
	if !present {
		t.Fatal("deny attribute should be present (Deny=false was on the wire)")
	}
	if got != "false" {
		t.Errorf("deny attr = %q, want %q", got, "false")
	}
}

func TestIsInheritedTrueIsFilteredNotTwinned(t *testing.T) {
	rows := rowsFrom(t, mailboxPermRob)
	rows[0]["IsInherited"] = true
	exo := &fakeEXO{
		mailboxRows:         []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr:   map[string][]map[string]any{"owner@x": rows},
		recipientPermByAddr: map[string][]map[string]any{"owner@x": nil},
	}
	rec := collect(t, exo, 0)

	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Fatalf("an inherited, non-self permission must not be twinned, got %d", len(logs))
	}
	pts := gaugePoints(t, rec, metricAssignments)
	var found bool
	for _, p := range pts {
		if p.Attrs[semconv.AttrIsInherited] == "true" && p.Attrs[semconv.AttrTrusteeKind] == trusteeKindDelegated {
			found = true
			if p.Value != 1 {
				t.Errorf("value = %v, want 1", p.Value)
			}
		}
	}
	if !found {
		t.Error("expected a bucket with is_inherited=true, trustee_kind=delegated counting the row")
	}
}

func TestIsInheritedAbsentBucketsAsUnknown(t *testing.T) {
	// Get-RecipientPermission carries no IsInherited field live at all.
	exo := &fakeEXO{
		mailboxRows:       []map[string]any{mailboxRow("owner@x")},
		mailboxPermByAddr: map[string][]map[string]any{"owner@x": nil},
		recipientPermByAddr: map[string][]map[string]any{
			"owner@x": rowsFrom(t, recipientPermRob),
		},
	}
	rec := collect(t, exo, 0)

	pts := gaugePoints(t, rec, metricAssignments)
	var found bool
	for _, p := range pts {
		if p.Attrs[semconv.AttrKind] == kindSendAs && p.Attrs[semconv.AttrTrusteeKind] == trusteeKindDelegated {
			found = true
			if p.Attrs[semconv.AttrIsInherited] != "unknown" {
				t.Errorf("is_inherited = %q, want unknown", p.Attrs[semconv.AttrIsInherited])
			}
		}
	}
	if !found {
		t.Error("expected a send_as/delegated bucket")
	}
}

func TestPerMailboxErrorSkipsThatMailboxNotWholeCycle(t *testing.T) {
	exo := &fakeEXO{
		mailboxRows: []map[string]any{mailboxRow("bad@x"), mailboxRow("good@x")},
		mailboxPermByAddr: map[string][]map[string]any{
			"good@x": rowsFrom(t, mailboxPermRob),
		},
		recipientPermByAddr: map[string][]map[string]any{
			"bad@x":  nil,
			"good@x": nil,
		},
		mailboxPermErrAddr: "bad@x",
	}
	rec := collect(t, exo, 0)

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("good@x should still produce its twin despite bad@x erroring, got %d", len(logs))
	}
	if logs[0].Attrs[semconv.AttrMailbox] != "good@x" {
		t.Errorf("mailbox = %q, want good@x", logs[0].Attrs[semconv.AttrMailbox])
	}
}

func TestEnumerateErrorPropagates(t *testing.T) {
	sentinel := errors.New("enumerate boom")
	exo := &fakeEXO{err: sentinel}
	rec := telemetrytest.New()
	c := New(collectors.EXODeps{Client: exo})
	err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped %v", err, sentinel)
	}
}

func TestEmptyTenantEmitsZeroCoverageNoTwins(t *testing.T) {
	exo := &fakeEXO{mailboxRows: nil}
	rec := collect(t, exo, 0)

	if got := singleGaugeValue(t, rec, metricMailboxesTotal); got != 0 {
		t.Errorf("mailboxes_total = %v, want 0", got)
	}
	if got := singleGaugeValue(t, rec, metricMailboxesCovered); got != 0 {
		t.Errorf("mailboxes_covered = %v, want 0", got)
	}
	if logs := rec.LogRecords(); len(logs) != 0 {
		t.Errorf("empty tenant should emit no twins, got %d", len(logs))
	}
}

func TestIngestTransportIsExchangeOnline(t *testing.T) {
	c := New(collectors.EXODeps{})
	if got := c.IngestTransport(); got != "exchange_online" {
		t.Errorf("IngestTransport() = %q, want exchange_online", got)
	}
}
