// Package allowblocklist is the Tenant Allow/Block List collector (#250): the
// tenant-managed entries that let mail bypass — or be killed by — Microsoft
// Defender for Office 365, read over the Exchange Online admin API's app-only
// cmdlet transport (internal/exoclient).
//
// # Why this matters
//
// An allow-list entry is a standing hole past mail security, and creating one is
// a documented attacker persistence technique: get a sender, URL, file hash or
// IP onto the allow list and every later message from it sails through spam,
// phish and malware filtering untouched. There is no Graph API for any of it and
// no other transport — this cmdlet pair is the only way to see the list at all.
//
// # The three expiry shapes, and why the severity turns on them
//
// Live-measured 2026-07-23, all three are real and they are NOT interchangeable:
//
//   - ExpirationDate set                     -> bounded, ends on a known date
//   - ExpirationDate null, RemoveAfter set   -> bounded, auto-removes N days
//     after last use
//   - ExpirationDate null, RemoveAfter null  -> NOTHING EVER REMOVES IT
//
// The third is a permanent bypass, so an Allow in that shape is the collector's
// Error condition. Spoof entries carry no expiry mechanism at all, so a spoof
// Allow is permanent by construction and takes the same Error.
//
// # Both sides of the cardinality boundary
//
// From the same five cmdlet calls:
//
//   - bounded GAUGEs — entries{list_type, action, list_subtype} (4x2x2 at most),
//     non_expiring_allow{list_type}, expiring_soon{list_type, action} and
//     spoof_entries{spoof_type, action}. Every key is a value set fixed by the
//     API; none grows with tenant size;
//   - one LOG twin per entry carrying the value, notes, who set it and when —
//     the per-entity detail the gauges collapse (#112/#114). "How many standing
//     allows" is a gauge; "WHICH domain is allowed" is only ever the twin.
//
// The zero baselines are seeded deliberately: an empty list still publishes its
// series, so the first allow entry ever added reads as a change from 0 rather
// than a series springing into existence, which alerts cannot see.
//
// A state snapshot, not an event stream: the twins are stamped at poll time.
package allowblocklist

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "defender.allow_block_list"
	// eventName is the OTLP LogRecord EventName every twin carries — one name
	// for list entries and spoof entries alike, with list_type telling them
	// apart, so a single LogQL selector sees the whole list.
	eventName = "defender.allow_block_list"

	// metricEntries counts list entries by the bounded categorical tuple.
	metricEntries = "defender.allow_block_list.entries"
	// metricNonExpiringAllow counts allow entries that nothing will ever remove.
	metricNonExpiringAllow = "defender.allow_block_list.non_expiring_allow"
	// metricExpiringSoon counts entries whose ExpirationDate falls inside
	// expiringSoonWindow — the entra.credential_expiry pattern.
	metricExpiringSoon = "defender.allow_block_list.expiring_soon"
	// metricSpoofEntries counts spoof-intelligence overrides.
	metricSpoofEntries = "defender.allow_block_list.spoof_entries"

	// unitEntry is the annotation unit for a countable list entry.
	unitEntry = "{entry}"

	// itemsCmdlet is run once per list type; spoofCmdlet takes no list type.
	itemsCmdlet = "Get-TenantAllowBlockListItems"
	spoofCmdlet = "Get-TenantAllowBlockListSpoofItems"
	// paramListType is itemsCmdlet's required list selector.
	paramListType = "ListType"

	// interval: the list changes when an admin edits it. Hourly is ample and
	// the five cmdlet calls are cheap.
	interval = time.Hour
	// expiringSoonWindow is how far ahead "expiring soon" looks.
	expiringSoonWindow = 7 * 24 * time.Hour
)

// The four list types the items cmdlet accepts, in the order they are polled.
const (
	listTypeSender = "Sender"
	listTypeURL    = "Url"
	listTypeFile   = "FileHash"
	listTypeIP     = "IP"
)

// listTypes is the fixed polling order and the seeded key space.
var listTypes = []string{listTypeSender, listTypeURL, listTypeFile, listTypeIP}

// The two actions an entry can carry.
const (
	actionAllow = "Allow"
	actionBlock = "Block"
)

var actions = []string{actionAllow, actionBlock}

// subtypeTenant is the ListSubType every manually-created entry carries
// (live-measured); AdvancedDelivery is the other value the API emits, and it
// gets its own series only when observed. The seeded zeros use Tenant because
// that is the list an operator manages.
const subtypeTenant = "Tenant"

// spoofTypes is the bounded spoof-classification set.
var spoofTypes = []string{"External", "Internal"}

// Expiry buckets. The first four mirror entra.credential_expiry; the last two
// name the two ways an entry can have no expiry DATE at all, which is the
// distinction the whole collector turns on.
const (
	bucketExpired            = "expired"
	bucketLt7d               = "lt_7d"
	bucketLt30d              = "lt_30d"
	bucketGt30d              = "gt_30d"
	bucketRemoveAfterLastUse = "remove_after_last_use"
	bucketNever              = "never"
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars and
// the malformed duplicate "LastUsedDate(DateTime])" key are ignored.
const (
	fieldAction                = "Action"
	fieldValue                 = "Value"
	fieldNotes                 = "Notes"
	fieldListSubType           = "ListSubType"
	fieldExpirationDate        = "ExpirationDate"
	fieldRemoveAfter           = "RemoveAfter"
	fieldSysManaged            = "SysManaged"
	fieldModifiedBy            = "ModifiedBy"
	fieldSubmissionID          = "SubmissionID"
	fieldLastUsedDate          = "LastUsedDate"
	fieldCreatedDateTime       = "CreatedDateTime"
	fieldLastModifiedDateTime  = "LastModifiedDateTime"
	fieldEntryValueHash        = "EntryValueHash"
	fieldObjectState           = "ObjectState"
	fieldError                 = "Error"
	fieldIdentity              = "Identity"
	fieldSpoofedUser           = "SpoofedUser"
	fieldSendingInfrastructure = "SendingInfrastructure"
	fieldSpoofType             = "SpoofType"
)

// entryKey is the bounded tuple the entries gauge is counted by.
type entryKey struct {
	listType string
	action   string
	subtype  string
}

// Collector reads the tenant allow/block lists.
type Collector struct {
	c collectors.EXOClient
	// now is injected so expiry bucketing is deterministic under test.
	now func() time.Time
}

// New builds the allow/block-list collector.
func New(d collectors.EXODeps) *Collector {
	return &Collector{c: d.Client, now: time.Now}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record as coming from the Exchange Online admin
// API rather than Graph (#141). There is no ingest engine on this path, so the
// collector is the only thing that can say so.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the Graph-scope
// vocabulary (Exchange.ManageAsApp + Security Reader), as for every EXO
// collector. Both cmdlets are authorized at Security Reader — no Global Reader
// needed (live-measured 2026-07-23).
func (c *Collector) RequiredPermissions() []string { return nil }

// Collect runs the five cmdlets and emits the four gauges plus a twin per entry.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE: with no ingest engine on this path the Scheduler
	// baseline is TransportGraph, so without this every record would claim to be
	// a Graph poll.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	now := c.now()

	// Seed the bounded key spaces at zero, then count over them.
	counts := map[entryKey]float64{}
	nonExpiring := map[string]float64{}
	expiringSoon := map[[2]string]float64{}
	for _, lt := range listTypes {
		nonExpiring[lt] = 0
		for _, a := range actions {
			counts[entryKey{lt, a, subtypeTenant}] = 0
			expiringSoon[[2]string{lt, a}] = 0
		}
	}
	spoofCounts := map[[2]string]float64{}
	for _, st := range spoofTypes {
		for _, a := range actions {
			spoofCounts[[2]string{st, a}] = 0
		}
	}

	var errs []error
	for _, lt := range listTypes {
		recs, err := c.c.Invoke(ctx, itemsCmdlet, map[string]any{paramListType: lt})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s -%s %s: %w", itemsCmdlet, paramListType, lt, err))
			continue
		}
		for _, r := range recs {
			action := str(r, fieldAction)
			subtype := str(r, fieldListSubType)
			if subtype == "" {
				// Never invent a subtype the wire did not carry; fold it into
				// the tenant-managed bucket only when the API actually said so.
				subtype = subtypeTenant
			}
			counts[entryKey{lt, action, subtype}]++

			exp, hasExp := timeField(r, fieldExpirationDate)
			_, hasRemoveAfter := numField(r, fieldRemoveAfter)
			if action == actionAllow && !hasExp && !hasRemoveAfter {
				nonExpiring[lt]++
			}
			if hasExp && exp.After(now) && exp.Sub(now) <= expiringSoonWindow {
				expiringSoon[[2]string{lt, action}]++
			}

			e.LogEvent(entryTwin(r, lt, now))
		}
	}

	spoofRecs, err := c.c.Invoke(ctx, spoofCmdlet, nil)
	if err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", spoofCmdlet, err))
	}
	for _, r := range spoofRecs {
		spoofCounts[[2]string{str(r, fieldSpoofType), str(r, fieldAction)}]++
		e.LogEvent(spoofTwin(r))
	}

	emitEntries(e, counts)
	emitNonExpiring(e, nonExpiring)
	emitExpiringSoon(e, expiringSoon)
	emitSpoof(e, spoofCounts)

	return errors.Join(errs...)
}

// emitEntries publishes the entry census in a deterministic order: the seeded
// tuples first, then any additional subtype the wire produced.
func emitEntries(e telemetry.Emitter, counts map[entryKey]float64) {
	pts := make([]telemetry.GaugePoint, 0, len(counts))
	seen := map[entryKey]bool{}
	add := func(k entryKey) {
		if seen[k] {
			return
		}
		seen[k] = true
		pts = append(pts, telemetry.GaugePoint{Value: counts[k], Attrs: telemetry.Attrs{
			semconv.AttrListType:    k.listType,
			semconv.AttrAction:      k.action,
			semconv.AttrListSubtype: k.subtype,
		}})
	}
	for _, lt := range listTypes {
		for _, a := range actions {
			add(entryKey{lt, a, subtypeTenant})
		}
	}
	for k := range counts {
		add(k)
	}
	e.GaugeSnapshot(metricEntries, unitEntry,
		"Tenant Allow/Block List entries by list type, action and list subtype. Which VALUE is listed is on the defender.allow_block_list log twin, never here.",
		pts)
}

// emitNonExpiring publishes the headline signal: allow entries that nothing will
// ever remove.
func emitNonExpiring(e telemetry.Emitter, nonExpiring map[string]float64) {
	pts := make([]telemetry.GaugePoint, 0, len(listTypes))
	for _, lt := range listTypes {
		pts = append(pts, telemetry.GaugePoint{Value: nonExpiring[lt], Attrs: telemetry.Attrs{
			semconv.AttrListType: lt,
		}})
	}
	e.GaugeSnapshot(metricNonExpiringAllow, unitEntry,
		"Allow entries with neither an expiration date nor a remove-after-last-use window — a permanent bypass of mail security. Each one also emits an Error-severity defender.allow_block_list log record naming it.",
		pts)
}

// emitExpiringSoon publishes the entries whose expiry falls inside the window.
func emitExpiringSoon(e telemetry.Emitter, expiringSoon map[[2]string]float64) {
	pts := make([]telemetry.GaugePoint, 0, len(expiringSoon))
	for _, lt := range listTypes {
		for _, a := range actions {
			pts = append(pts, telemetry.GaugePoint{Value: expiringSoon[[2]string{lt, a}], Attrs: telemetry.Attrs{
				semconv.AttrListType: lt,
				semconv.AttrAction:   a,
			}})
		}
	}
	e.GaugeSnapshot(metricExpiringSoon, unitEntry,
		fmt.Sprintf("Tenant Allow/Block List entries whose expiration date falls within %d days. An expiring BLOCK silently restores delivery from a sender that was blocked for a reason.", int(expiringSoonWindow.Hours()/24)),
		pts)
}

// emitSpoof publishes the spoof-intelligence override census.
func emitSpoof(e telemetry.Emitter, spoofCounts map[[2]string]float64) {
	pts := make([]telemetry.GaugePoint, 0, len(spoofCounts))
	for _, st := range spoofTypes {
		for _, a := range actions {
			pts = append(pts, telemetry.GaugePoint{Value: spoofCounts[[2]string{st, a}], Attrs: telemetry.Attrs{
				semconv.AttrSpoofType: st,
				semconv.AttrAction:    a,
			}})
		}
	}
	e.GaugeSnapshot(metricSpoofEntries, unitEntry,
		"Spoof-intelligence overrides by spoof type and action. A spoof allow has no expiry mechanism at all, so it is permanent by construction.",
		pts)
}

// entryTwin renders one list entry as a log record. Error when an Allow entry
// has neither an expiration date nor a remove-after window — nothing will ever
// remove it, so it is a permanent hole past mail security.
func entryTwin(r map[string]any, listType string, now time.Time) telemetry.Event {
	action := str(r, fieldAction)
	exp, hasExp := timeField(r, fieldExpirationDate)
	_, hasRemoveAfter := numField(r, fieldRemoveAfter)

	bucket := bucketNever
	switch {
	case hasExp:
		bucket = expiryBucketFor(now, exp)
	case hasRemoveAfter:
		bucket = bucketRemoveAfterLastUse
	}

	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrListType, listType)
	telemetry.SetStr(attrs, semconv.AttrAction, action)
	telemetry.SetStr(attrs, semconv.AttrListSubtype, str(r, fieldListSubType))
	telemetry.SetStr(attrs, semconv.AttrEntryValue, str(r, fieldValue))
	telemetry.SetStr(attrs, semconv.AttrNotes, str(r, fieldNotes))
	telemetry.SetStr(attrs, semconv.AttrExpiryBucket, bucket)
	telemetry.SetStr(attrs, semconv.AttrExpirationDateTime, str(r, fieldExpirationDate))
	telemetry.SetNum(attrs, semconv.AttrRemoveAfterDays, r, fieldRemoveAfter)
	telemetry.SetBool(attrs, semconv.AttrSysManaged, boolVal(r, fieldSysManaged))
	telemetry.SetStr(attrs, semconv.AttrModifiedBy, str(r, fieldModifiedBy))
	telemetry.SetStr(attrs, semconv.AttrSubmissionId, str(r, fieldSubmissionID))
	telemetry.SetStr(attrs, semconv.AttrLastUsedDate, str(r, fieldLastUsedDate))
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, str(r, fieldCreatedDateTime))
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, str(r, fieldLastModifiedDateTime))
	telemetry.SetStr(attrs, semconv.AttrEntryValueHash, str(r, fieldEntryValueHash))
	telemetry.SetStr(attrs, semconv.AttrObjectState, str(r, fieldObjectState))
	telemetry.SetStr(attrs, semconv.AttrEntryError, str(r, fieldError))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldIdentity))

	sev := telemetry.SeverityInfo
	standing := action == actionAllow && !hasExp && !hasRemoveAfter
	if standing {
		sev = telemetry.SeverityError
	}

	body := fmt.Sprintf("%s %s entry %q: expiry=%s", listType, strings.ToLower(action), str(r, fieldValue), bucket)
	if standing {
		body = fmt.Sprintf("%s allow entry %q never expires — a permanent bypass of mail security", listType, str(r, fieldValue))
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// spoofTwin renders one spoof-intelligence override. These records carry no
// expiry field at all, so an allow is permanent by construction and takes the
// same Error as a standing allow on the other lists.
func spoofTwin(r map[string]any) telemetry.Event {
	action := str(r, fieldAction)
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrListType, "Spoof")
	telemetry.SetStr(attrs, semconv.AttrAction, action)
	telemetry.SetStr(attrs, semconv.AttrSpoofType, str(r, fieldSpoofType))
	telemetry.SetStr(attrs, semconv.AttrSpoofedUser, str(r, fieldSpoofedUser))
	telemetry.SetStr(attrs, semconv.AttrSendingInfrastructure, str(r, fieldSendingInfrastructure))
	telemetry.SetStr(attrs, semconv.AttrId, str(r, fieldIdentity))

	sev := telemetry.SeverityInfo
	body := fmt.Sprintf("spoof %s: %s via %s", strings.ToLower(action), str(r, fieldSpoofedUser), str(r, fieldSendingInfrastructure))
	if action == actionAllow {
		sev = telemetry.SeverityError
		body = fmt.Sprintf("spoof allow for %s via %s never expires — spoof overrides have no expiry mechanism", str(r, fieldSpoofedUser), str(r, fieldSendingInfrastructure))
	}
	return telemetry.Event{Name: eventName, Body: body, Severity: sev, Attrs: attrs}
}

// expiryBucketFor maps an expiration date to one of the fixed date buckets.
func expiryBucketFor(now, exp time.Time) string {
	d := exp.Sub(now)
	switch {
	case d <= 0:
		return bucketExpired
	case d < 7*24*time.Hour:
		return bucketLt7d
	case d < 30*24*time.Hour:
		return bucketLt30d
	default:
		return bucketGt30d
	}
}

// str reads a string column, "" when absent or non-string. Reading by exact name
// ignores both the "<Name>@data.type" sidecars and the malformed duplicate
// "LastUsedDate(DateTime])" key the items cmdlet emits (live-measured).
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolVal reads a boolean column. Booleans on THIS transport are real JSON
// bools, unlike the advanced-hunting API's SByte 0/1 encoding (#249).
func boolVal(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// numField reads a numeric column, reporting whether it was present as a number.
// A null RemoveAfter is absent, not zero — the difference between "removes after
// 0 days" and "never removes".
func numField(m map[string]any, key string) (float64, bool) {
	f, ok := m[key].(float64)
	return f, ok
}

// timeField parses a datetime column, reporting whether it was present and
// parseable. A null ExpirationDate is absent, which is the standing-hole case.
func timeField(m map[string]any, key string) (time.Time, bool) {
	s := str(m, key)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
