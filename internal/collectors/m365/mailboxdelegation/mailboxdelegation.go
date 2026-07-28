// Package mailboxdelegation is the Exchange Online mailbox delegation
// collector (#355): standing FullAccess and SendAs mailbox delegation, read
// over the Exchange Online admin API's app-only cmdlet transport, the same
// shape as the sibling exchangeauditbypass / exchangemailboxes collectors
// (#356, #250).
//
// # Why this matters
//
// A mailbox's owner is not the only identity that can read or send as it.
// FullAccess (Get-MailboxPermission) grants open-and-read-everything;
// SendAs (Get-RecipientPermission) grants "send mail that looks like it came
// from this mailbox". Neither is visible on any Graph endpoint on this
// project's path — this collector is the only place standing delegation
// shows up at all. A delegation an admin forgot to revoke, or one an
// attacker added, both look identical here: a row with a non-self trustee.
//
// # Why per-mailbox, and why it is gated (#233, exofanout)
//
// Get-MailboxPermission returns HTTP 400 "Invalid Operation" when called
// without an -Identity — it cannot be called tenant-wide, only per mailbox.
// That makes this collector's cost linear in mailbox count with no batch
// form, live-measured at ~846ms/mailbox (FullAccess) + ~602ms/mailbox
// (SendAs), so 1+2N calls total. It implements collectors.PerMailboxCollector
// so the composition root's exo_per_mailbox.enabled gate covers it without a
// hand-kept name list (#355/#363). Enumeration and the coverage cap are
// internal/exofanout's job, not this package's — see its doc for why a cap is
// a signal, never a silent floor, and why PerMailboxCap is used verbatim.
//
// # Both sides of the cardinality boundary
//
// From each mailbox's two cmdlet calls:
//
//   - a bounded GAUGE m365.mailbox.delegation.assignments{kind, trustee_kind,
//     is_inherited} — kind is full_access|send_as (which cmdlet), trustee_kind
//     is self|delegated (see below), is_inherited is true|false|unknown. None
//     of the three grows with tenant size;
//   - bounded GAUGES m365.mailbox.delegation.mailboxes_covered and
//     .mailboxes_total, emitted every cycle regardless of findings — the
//     whole point of the cap: partial coverage is acceptable, partial
//     coverage that LOOKS complete is not. covered < total is the alert;
//   - one LOG twin per NON-SELF, NON-INHERITED assignment, carrying the
//     mailbox address, trustee, SID, and full right set. THAT is the
//     finding — mailbox and trustee identity are never metric labels (#112).
//
// # NT AUTHORITY\SELF is retained and counted, never elevated
//
// Every mailbox carries an implicit self-permission — User/Trustee
// "NT AUTHORITY\SELF", SID S-1-5-10 — on both FullAccess and SendAs. It is
// not a delegation and must never look like one, but dropping it silently
// would make "0 assignments" ambiguous between "nothing to see" and "the
// mapper ate the healthy baseline". So it is counted in a distinct
// trustee_kind=self gauge bucket every cycle, and never given a log twin.
// "Self" is keyed primarily on the SID (S-1-5-10), with the
// "NT AUTHORITY\" prefix as a fallback — the SID is the stable identifier;
// the display string is localizable.
//
// The same SELF SID can appear TWICE on one mailbox with different
// AccessRights (a plain "FullAccess, ReadPermission" row and a
// "FullAccess, ExternalAccount, ReadPermission" row, both live-measured on
// the same mailbox). This collector never dedupes by SID — each row is
// counted independently — because deduping by SID would silently drop one
// of two genuinely distinct grants.
//
// # AccessRights is a collection of COMMA-JOINED elements
//
// The wire shape is easy to get wrong in one direction only: AccessRights is
// a JSON array, but each ELEMENT can itself carry multiple rights joined by
// ", " — ["FullAccess, ReadPermission"] is ONE array element holding TWO
// rights. Both a single-right element (["FullAccess"]) and a multi-right
// element occur live, so the mapper splits every element on ", " and
// flattens, rather than assuming either shape alone.
//
// # PrimarySmtpAddress is never trusted
//
// PrimarySmtpAddress (FullAccess) and TrusteeWithPrimarySmtpAddress (SendAs)
// are empty even on genuine non-self delegations, live-measured. The
// mailbox address on every twin comes from the exofanout.Mailbox being
// polled, never from the row; trustee identity comes from User/Trustee.
//
// # Unobserved, and deliberately unwatched (#233/#234)
//
// Deny (Get-MailboxPermission) and AccessControlType (Get-RecipientPermission,
// which reads "Allow" on every live row) were NEVER observed to take any
// other value on this tenant: Deny is false on every row, AccessControlType
// is always "Allow". Both fields are decoded and carried on the twin because
// mapping them is safe, but neither backs an internal/wirecheck enum watcher
// and neither must be read as implying the collector has seen a Deny=true or
// AccessControlType=Deny row — one observed value is not a value set, and a
// watchdog built from it would fire on perfectly correct data the moment a
// tenant's first genuine deny-ACE appeared. IsInherited is also unwatched for
// the same reason (always false where present at all).
//
// # Absent-field rule: an absent optional scalar is OMITTED, not fabricated
//
// Deny and IsInherited decode as *bool. Get-RecipientPermission carries
// neither key at all, live-measured — so on a SendAs twin both are omitted
// rather than defaulted to false, which would silently claim a fact this
// collector never observed. IsInherited additionally backs a metric label:
// there it buckets to "unknown" rather than assuming false, so an absent
// value never masquerades as a healthy signal on the gauge either.
//
// A state snapshot, not an event stream: the gauges and twins are stamped at
// poll time.
package mailboxdelegation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exofanout"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.mailbox_delegation"
	// eventName is the OTLP LogRecord EventName each delegation twin carries.
	eventName = "m365.mailbox_delegation"

	// metricAssignments is the bounded assignment-count gauge, labeled
	// kind/trustee_kind/is_inherited (see package doc).
	metricAssignments = "m365.mailbox.delegation.assignments"
	// metricMailboxesCovered / metricMailboxesTotal are exofanout's coverage
	// gauges, emitted every cycle regardless of any finding.
	metricMailboxesCovered = "m365.mailbox.delegation.mailboxes_covered"
	metricMailboxesTotal   = "m365.mailbox.delegation.mailboxes_total"

	unitAssignment = "{assignment}"
	unitMailbox    = "{mailbox}"

	// cmdletMailboxPermission / cmdletRecipientPermission are the two
	// per-mailbox cmdlets this collector runs. Neither has a tenant-wide form
	// (see package doc).
	cmdletMailboxPermission   = "Get-MailboxPermission"
	cmdletRecipientPermission = "Get-RecipientPermission"
	paramIdentity             = "Identity"

	// kindFullAccess / kindSendAs are the two AttrKind values this collector
	// emits, one per cmdlet.
	kindFullAccess = "full_access"
	kindSendAs     = "send_as"

	// trusteeKindSelf / trusteeKindDelegated are the two AttrTrusteeKind
	// values. See the package doc's SELF section.
	trusteeKindSelf      = "self"
	trusteeKindDelegated = "delegated"

	// rightFullAccess / rightSendAs are the AccessRights tokens (after
	// splitting, see package doc) that make a row an assignment of the
	// matching kind. A row lacking the token is not an assignment this
	// collector tracks (e.g. a bare ReadPermission-only row).
	rightFullAccess = "FullAccess"
	rightSendAs     = "SendAs"

	// sidSelf is the well-known SID for the implicit self-permission every
	// mailbox carries. Primary key for "is this row SELF" — see package doc.
	sidSelf = "S-1-5-10"
	// ntAuthorityPrefix is the fallback key when a SID is unavailable: the
	// display string is localizable, so the SID above is preferred.
	ntAuthorityPrefix = `NT AUTHORITY\`

	// interval: standing delegation changes when an admin runs
	// Add-MailboxPermission / Add-RecipientPermission, an infrequent
	// administrative action, and the per-mailbox cost (see package doc) rules
	// out a short cadence regardless.
	interval = 6 * time.Hour
)

// Wire field names, read by exact name so the "<Name>@data.type"/"@odata.type"
// sidecars are ignored.
const (
	fieldMailboxPermUser        = "User"
	fieldMailboxPermUserSid     = "UserSid"
	fieldMailboxPermDeny        = "Deny"
	fieldMailboxPermIsInherited = "IsInherited"

	fieldRecipientPermTrustee           = "Trustee"
	fieldRecipientPermTrusteeSid        = "TrusteeSidString"
	fieldRecipientPermAccessControlType = "AccessControlType"

	// fieldAccessRights is shared by both cmdlets.
	fieldAccessRights = "AccessRights"
)

// Collector reads Exchange Online standing mailbox delegation, per mailbox.
type Collector struct {
	client collectors.EXOClient
	cap    int
}

// New builds the mailbox-delegation collector. It is ALWAYS safe to call with
// a zero-valued collectors.EXODeps: the composition root constructs an
// availability candidate (and retries on the transport-init error path) from
// a zero-valued EXODeps and calls Name() on the result before any real
// Client exists.
func New(d collectors.EXODeps) *Collector {
	return &Collector{client: d.Client, cap: d.PerMailboxCap}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Exchange Online admin
// API rather than Graph (#141).
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the
// Graph-scope vocabulary (Exchange.ManageAsApp + a directory role), the same
// boundary documented on the sibling EXO collectors.
func (c *Collector) RequiredPermissions() []string { return nil }

// PerMailbox implements collectors.PerMailboxCollector: this collector's cost
// is linear in mailbox count, so exo_per_mailbox.enabled gates it.
func (c *Collector) PerMailbox() bool { return true }

// bucketKey identifies one series of metricAssignments.
type bucketKey struct {
	kind        string
	trusteeKind string
	isInherited string
}

// Collect enumerates the tenant's mailboxes (capped by exofanout), runs both
// per-mailbox permission cmdlets, emits the coverage gauges every cycle, the
// bounded assignment gauge, and one twin per non-self, non-inherited
// assignment.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Stamp the transport HERE: with no ingest engine on this path the
	// Scheduler baseline is TransportGraph.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	res, err := exofanout.Enumerate(ctx, c.client, c.cap)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return fmt.Errorf("enumerate mailboxes: %w", err)
	}

	// Coverage gauges are emitted every cycle, regardless of what follows —
	// see the package doc's truncation-is-a-signal note.
	e.GaugeSnapshot(metricMailboxesTotal, unitMailbox,
		"Mailboxes the tenant actually has, per Get-Mailbox. Compare against m365.mailbox.delegation.mailboxes_covered: covered < total means this cycle's assignment gauge and twins are a PARTIAL view, not a complete one.",
		[]telemetry.GaugePoint{{Value: float64(res.Total)}})
	e.GaugeSnapshot(metricMailboxesCovered, unitMailbox,
		"Mailboxes this cycle actually polled for delegation, bounded by exo_per_mailbox's cap. See m365.mailbox.delegation.mailboxes_total.",
		[]telemetry.GaugePoint{{Value: float64(res.Covered)}})

	var fetched, mapped, filtered, emitted, errored uint64
	buckets := map[bucketKey]float64{}

	for _, mb := range res.Mailboxes {
		faRows, err := c.client.Invoke(ctx, cmdletMailboxPermission, map[string]any{paramIdentity: mb.PrimarySmtpAddress})
		if err != nil {
			errored++
			outcomes.Cause(recordoutcome.CauseSourceError)
		} else {
			fetched += uint64(len(faRows))
			for _, r := range faRows {
				m, f, em := c.classifyFullAccess(e, mb, r, buckets)
				mapped += m
				filtered += f
				emitted += em
			}
		}

		raRows, err := c.client.Invoke(ctx, cmdletRecipientPermission, map[string]any{paramIdentity: mb.PrimarySmtpAddress})
		if err != nil {
			errored++
			outcomes.Cause(recordoutcome.CauseSourceError)
		} else {
			fetched += uint64(len(raRows))
			for _, r := range raRows {
				m, f, em := c.classifySendAs(e, mb, r, buckets)
				mapped += m
				filtered += f
				emitted += em
			}
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(buckets))
	keys := make([]bucketKey, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		if keys[i].trusteeKind != keys[j].trusteeKind {
			return keys[i].trusteeKind < keys[j].trusteeKind
		}
		return keys[i].isInherited < keys[j].isInherited
	})
	for _, k := range keys {
		points = append(points, telemetry.GaugePoint{
			Value: buckets[k],
			Attrs: telemetry.Attrs{
				semconv.AttrKind:        k.kind,
				semconv.AttrTrusteeKind: k.trusteeKind,
				semconv.AttrIsInherited: k.isInherited,
			},
		})
	}
	e.GaugeSnapshot(metricAssignments, unitAssignment,
		"Standing FullAccess/SendAs mailbox delegation assignments this poll examined, bucketed by kind (full_access|send_as), trustee_kind (self|delegated) and is_inherited (true|false|unknown). trustee_kind=self is the implicit NT AUTHORITY\\SELF permission present on every mailbox, counted here but never given a log twin — see the package doc. Mailbox and trustee identity are never labels (#112); see the m365.mailbox_delegation log twin for those.",
		points)

	if fetched > 0 || mapped > 0 || filtered > 0 || errored > 0 {
		outcomes.Add(recordoutcome.OutcomeFetched, fetched)
		outcomes.Add(recordoutcome.OutcomeMapped, mapped)
		outcomes.Add(recordoutcome.OutcomeEmitted, emitted)
		outcomes.Add(recordoutcome.OutcomeFiltered, filtered)
		outcomes.Add(recordoutcome.OutcomeErrored, errored)
	}

	return nil
}

// classifyFullAccess processes one Get-MailboxPermission row for mailbox mb,
// updating buckets and emitting a twin when the row is a non-self,
// non-inherited FullAccess assignment. Returns (mapped, filtered, emitted)
// deltas for outcome accounting.
func (c *Collector) classifyFullAccess(e telemetry.Emitter, mb exofanout.Mailbox, r map[string]any, buckets map[bucketKey]float64) (mapped, filtered, emitted uint64) {
	rights := parseRights(r, fieldAccessRights)
	if !containsRight(rights, rightFullAccess) {
		return 0, 1, 0
	}

	trustee := str(r, fieldMailboxPermUser)
	sid := str(r, fieldMailboxPermUserSid)
	self := isSelfTrustee(sid, trustee)
	inheritedPtr := boolPtr(r, fieldMailboxPermIsInherited)
	denyPtr := boolPtr(r, fieldMailboxPermDeny)

	key := bucketKey{kind: kindFullAccess, trusteeKind: trusteeKindFor(self), isInherited: isInheritedLabel(inheritedPtr)}
	buckets[key]++

	if self || (inheritedPtr != nil && *inheritedPtr) {
		return 0, 1, 0
	}

	e.LogEvent(delegationTwin(kindFullAccess, mb.PrimarySmtpAddress, trustee, sid, rights, denyPtr, ""))
	return 1, 0, 1
}

// classifySendAs processes one Get-RecipientPermission row for mailbox mb,
// mirroring classifyFullAccess for the SendAs shape (AccessControlType
// instead of Deny; no IsInherited field observed on this cmdlet at all).
func (c *Collector) classifySendAs(e telemetry.Emitter, mb exofanout.Mailbox, r map[string]any, buckets map[bucketKey]float64) (mapped, filtered, emitted uint64) {
	rights := parseRights(r, fieldAccessRights)
	if !containsRight(rights, rightSendAs) {
		return 0, 1, 0
	}

	trustee := str(r, fieldRecipientPermTrustee)
	sid := str(r, fieldRecipientPermTrusteeSid)
	self := isSelfTrustee(sid, trustee)
	// Get-RecipientPermission carries no IsInherited field, live-measured —
	// nil here is what buckets to "unknown" rather than a fabricated false.
	inheritedPtr := boolPtr(r, fieldMailboxPermIsInherited)

	key := bucketKey{kind: kindSendAs, trusteeKind: trusteeKindFor(self), isInherited: isInheritedLabel(inheritedPtr)}
	buckets[key]++

	if self || (inheritedPtr != nil && *inheritedPtr) {
		return 0, 1, 0
	}

	accessControlType := str(r, fieldRecipientPermAccessControlType)
	e.LogEvent(delegationTwin(kindSendAs, mb.PrimarySmtpAddress, trustee, sid, rights, nil, accessControlType))
	return 1, 0, 1
}

// delegationTwin renders one non-self, non-inherited assignment as a log
// record — the finding this collector exists to surface (see package doc).
func delegationTwin(kind, mailboxAddr, trustee, sid string, rights []string, deny *bool, accessControlType string) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrKind, kind)
	telemetry.SetStr(attrs, semconv.AttrTrusteeKind, trusteeKindDelegated)
	telemetry.SetStr(attrs, semconv.AttrMailbox, mailboxAddr)
	telemetry.SetStr(attrs, semconv.AttrTrustee, trustee)
	telemetry.SetStr(attrs, semconv.AttrTrusteeSid, sid)
	telemetry.SetStrs(attrs, semconv.AttrRights, rights)
	if deny != nil {
		telemetry.SetBool(attrs, semconv.AttrDeny, *deny)
	}
	telemetry.SetStr(attrs, semconv.AttrAccessControlType, accessControlType)

	body := fmt.Sprintf("mailbox delegation: %q granted %s on %q (rights=%s)", trustee, kind, mailboxAddr, strings.Join(rights, ","))
	return telemetry.Event{Name: eventName, Body: body, Severity: telemetry.SeverityInfo, Attrs: attrs}
}

// parseRights reads the AccessRights column and flattens it: the wire is a
// JSON array whose ELEMENTS may themselves be ", "-joined multi-right
// strings (#355 trap 1), so every element is split before being returned.
func parseRights(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		for _, part := range strings.Split(s, ", ") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// containsRight reports whether rights contains target, exactly.
func containsRight(rights []string, target string) bool {
	for _, r := range rights {
		if r == target {
			return true
		}
	}
	return false
}

// isSelfTrustee reports whether a row is the implicit NT AUTHORITY\SELF
// permission, keyed primarily on the SID (stable) with the display-string
// prefix as a fallback (localizable) — see package doc.
func isSelfTrustee(sid, trustee string) bool {
	if sid == sidSelf {
		return true
	}
	return strings.HasPrefix(trustee, ntAuthorityPrefix)
}

// trusteeKindFor maps the self/non-self classification to its bounded
// AttrTrusteeKind value.
func trusteeKindFor(self bool) string {
	if self {
		return trusteeKindSelf
	}
	return trusteeKindDelegated
}

// isInheritedLabel buckets an optional IsInherited reading into its bounded
// AttrIsInherited value: "unknown" when the field was absent from the wire,
// never a fabricated "false" (absent-field rule, see package doc).
func isInheritedLabel(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "true"
	}
	return "false"
}

// boolPtr reads a boolean column, returning nil when the key is absent or
// not a JSON bool — the distinction the absent-field rule depends on.
func boolPtr(m map[string]any, key string) *bool {
	v, present := m[key]
	if !present {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

// str reads a string column, "" when absent or non-string. Reading by exact
// name ignores the "<Name>@data.type"/"@odata.type" sidecars.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var (
	_ collector.SnapshotCollector    = (*Collector)(nil)
	_ collectors.PerMailboxCollector = (*Collector)(nil)
)
