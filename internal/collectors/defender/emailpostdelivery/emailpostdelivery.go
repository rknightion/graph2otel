// Package emailpostdelivery is the Defender advanced-hunting
// EmailPostDeliveryEvents blob collector (#233): one OTLP log per action
// Defender for Office 365 takes on a message AFTER it was delivered — ZAP,
// manual and automated remediation, and redelivery — read from the shared
// Azure Storage account.
//
// This is the missing half of defender.email's delivery story: EmailEvents
// records where a message landed at delivery time, and only this table records
// it MOVING afterwards, into or out of quarantine. The two join on
// network_message_id.
//
// EmailPostDeliveryEvents is a per-MESSAGE table like EmailEvents, not one of
// the Device* tables: there is no DeviceId/MachineGroup and no
// InitiatingProcess block, so do NOT call defender.StampDeviceCommon or
// defender.StampInitiatingProcess here. Every column on it is a string — there
// are no numeric or boolean columns — and its ReportId is a composite STRING
// (network message id + sequence), not the numeric per-device sequence the
// Device* event tables carry, so it is mapped as a StrField.
//
// # What this collector watches, and what it deliberately does not (#234)
//
// This package shipped against exactly ONE live record (2026-07-23, #233), so
// nearly everything it "knows" about the table's values is an n=1 measurement.
// wirecheck watches the two assumptions that would otherwise fail SILENTLY, and
// pointedly does not watch the enums:
//
//   - WATCHED, MissingField(network_message_id). The whole point of this table
//     is joining a post-delivery action back to the message, and every other
//     quarantine-relevant signal graph2otel emits (defender.email,
//     defender.email_url, defender.quarantine, m365.unified_audit) keys on the
//     same id. A record without it still emits — it simply cannot be joined,
//     which is invisible unless reported. Same reasoning, and the same finding
//     kind, as defender.quarantine's unparseable Identity.
//
//   - WATCHED, Invariant(string_columns). "Every column is a string" is a
//     single-measurement claim and it is load-bearing: all thirteen columns are
//     mapped as defender.StrField, and StrField reads a non-string as "" and
//     then OMITS the attribute. If Microsoft ships ReportId as a NUMBER — which
//     is exactly what the Device* tables already do — report_id silently
//     vanishes from every record and nothing else changes. The check is exact
//     rather than probabilistic: it fires only when a mapped column is present,
//     non-null, and not a string, so it cannot fire on correct data.
//
//   - NOT WATCHED: ActionType, ActionTrigger, ActionResult, Action,
//     DeliveryLocation, EmailDirection, ThreatTypes, DetectionMethods. #234
//     names the first three specifically, and the honest answer is that their
//     value sets are established by nothing in this repository. The single live
//     record carries one value of each (Redelivery / SpecialAction / Success /
//     Reprocessed / Inbox) and nulls for the last three, and no map here keys on
//     their members. severity() tests ActionResult against "Success", but that
//     is a two-way partition, not a set — declaring {"Success"} would fire on
//     every legitimate "Failed". One observed value is not a value set, and a
//     watchdog that fires on correct data is worse than none.
//     WHAT WOULD CLOSE IT: a KQL `summarize by ActionType` (and the same for the
//     other two) over a tenant with real post-delivery activity — ZAP and manual
//     remediation, not just the one Redelivery this fixture caught — or an
//     advanced-hunting error body that enumerates the members, which is how
//     defender.quarantine's eleven QuarantineTypes were obtained. Note the gap
//     costs a log reader's attention and not a wrong number: this collector
//     emits no domain metric, so none of these fields is a metric label
//     anywhere. (The package's one metric is self-observability —
//     graph2otel.api.unexpected — which is the narrow exception to the
//     "log-only" property internal/collectors/defender's doc describes for the
//     advanced-hunting tables. No advanced-hunting COLUMN becomes a metric
//     label; the counter's labels are all strings from graph2otel's own source.)
//
//   - NOT WATCHED: ReportId's composite shape. The doc above says it is "network
//     message id + sequence", and on the one live record it is exactly
//     NetworkMessageId + "-" + a 19-digit sequence. That is n=1, the collector
//     parses nothing out of it, and no emitted value depends on the separator —
//     unlike defender.quarantine's Identity, where the same shape IS the join key
//     and a parse failure loses it. Watching it would risk firing on a correct
//     record whose sequence is formatted differently, in exchange for no
//     protection at all.
package emailpostdelivery

import (
	"context"
	"fmt"
	"sync"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/defender"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	// name is the stable collector key and config-enable key.
	name = "defender.email_post_delivery"
	// table is the advanced-hunting table, lowercased into its container.
	table = "emailpostdeliveryevents"
	// eventName is the OTLP LogRecord EventName every record carries.
	eventName = "defender.email_post_delivery"
)

// ruleStringColumns names the invariant that every column on this table arrives
// as a JSON string. It is measured once, on one record, and it decides how all
// thirteen columns are mapped — see the package doc. A break is silent: the
// column's attribute simply stops appearing.
const ruleStringColumns = "string_columns"

// postDeliveryStrFields is the table's complete column set — message identity,
// the remediation action with its trigger and result, the recipient and the
// resulting delivery location, and the threat verdicts that justified it. All
// of them are strings on the wire; the table carries no numeric or boolean
// columns. Timestamp is consumed by defender.EventTime, not stamped.
var postDeliveryStrFields = []defender.StrField{
	{Attr: semconv.AttrNetworkMessageId, Src: "NetworkMessageId"},
	{Attr: semconv.AttrInternetMessageId, Src: "InternetMessageId"},
	{Attr: semconv.AttrAction, Src: "Action"},
	{Attr: semconv.AttrActionType, Src: "ActionType"},
	{Attr: semconv.AttrActionTrigger, Src: "ActionTrigger"},
	{Attr: semconv.AttrActionResult, Src: "ActionResult"},
	{Attr: semconv.AttrRecipientEmailAddress, Src: "RecipientEmailAddress"},
	{Attr: semconv.AttrDeliveryLocation, Src: "DeliveryLocation"},
	{Attr: semconv.AttrThreatTypes, Src: "ThreatTypes"},
	{Attr: semconv.AttrDetectionMethods, Src: "DetectionMethods"},
	{Attr: semconv.AttrReportId, Src: "ReportId"},
	{Attr: semconv.AttrSenderFromAddress, Src: "SenderFromAddress"},
	{Attr: semconv.AttrEmailDirection, Src: "EmailDirection"},
}

// severity maps ActionResult to a log severity: a remediation that did not
// succeed is the interesting case, so anything other than Success (or an
// absent result) warns.
func severity(actionResult string) telemetry.Severity {
	if actionResult == "Success" || actionResult == "" {
		return telemetry.SeverityInfo
	}
	return telemetry.SeverityWarn
}

// mapRecord turns one raw EmailPostDeliveryEvents record into its OTLP log
// Event: unwrap properties, bind the timestamp to properties.Timestamp, and
// stamp the string columns.
func mapRecord(rec map[string]any) (telemetry.Event, bool) {
	props := defender.Props(rec)
	if props == nil {
		return telemetry.Event{}, false
	}
	ts, ok := defender.EventTime(props)
	if !ok {
		return telemetry.Event{}, false
	}

	attrs := telemetry.Attrs{}
	defender.StampStrings(attrs, props, postDeliveryStrFields)

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("%s (%s) for %s: %s", defender.Str(props, "Action"), defender.Str(props, "ActionType"), defender.Str(props, "RecipientEmailAddress"), defender.Str(props, "ActionResult")),
		Severity:  severity(defender.Str(props, "ActionResult")),
		Timestamp: ts,
		Attrs:     attrs,
	}, true
}

// watcher carries the wire-assumption reporter across blobpipeline's mapper
// boundary (#234).
//
// blobpipeline.ContainerConfig.Map is func(rec) (Event, bool) — it is handed no
// emitter, because the ~30 Defender tables that share it emit nothing but their
// log twin. wirecheck needs one: the WARN log alone is not alertable, and the
// counter is the whole point. Rather than widen a signature every Defender table
// depends on, this collector BINDS the emitter of the poll that is running for
// the duration of its own Collect, and the mapper reads it back.
//
// Poll runs synchronously inside Collect, so the mapper always sees the emitter
// of the poll it is part of. The mutex is not for that: it is because nothing in
// the collector interface promises Collect is never entered twice at once, and a
// data race on a plain field would be a real one under -race.
type watcher struct {
	r *wirecheck.Reporter

	mu sync.Mutex
	e  telemetry.Emitter
}

// bind sets the emitter findings are counted onto; bind(nil) clears it. A nil
// emitter still logs the WARN, it just cannot count — see wirecheck.report.
func (w *watcher) bind(e telemetry.Emitter) {
	w.mu.Lock()
	w.e = e
	w.mu.Unlock()
}

func (w *watcher) emitter() telemetry.Emitter {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.e
}

// mapRecord is the pipeline's Map hook: the pure mapper, plus the wire checks on
// any record that mapped. A dropped record (no properties, no parseable
// Timestamp) is deliberately NOT checked — blobpipeline drops it before it can
// be emitted, so reporting a missing join key on it would report an absence
// nobody was going to see anyway.
func (w *watcher) mapRecord(rec map[string]any) (telemetry.Event, bool) {
	ev, ok := mapRecord(rec)
	if !ok {
		return ev, false
	}
	w.check(defender.Props(rec))
	return ev, true
}

// check reports anything on this record that contradicts what the collector was
// built against. It never rejects a record: see the package doc for why each
// check exists, and for the fields deliberately left unwatched.
func (w *watcher) check(props map[string]any) {
	e := w.emitter()

	// The join key. Every other quarantine-relevant signal graph2otel emits keys
	// on this id, so a record without it describes an action against a message
	// nothing can name.
	if defender.Str(props, "NetworkMessageId") == "" {
		w.r.MissingField(e, semconv.AttrNetworkMessageId)
	}

	// "Every column is a string" decides how all thirteen are mapped. A column
	// that arrives as a number or a bool is read as "" by defender.StrField and
	// then omitted, so the attribute vanishes with nothing else changing. A JSON
	// null is NOT a break — three columns are null on the live record — so only a
	// present, non-null, non-string value is reported.
	for _, f := range postDeliveryStrFields {
		v, present := props[f.Src]
		if !present || v == nil {
			continue
		}
		if _, isStr := v.(string); isStr {
			continue
		}
		w.r.Invariant(e, ruleStringColumns,
			fmt.Sprintf("column %s arrived as %T, not a string — %s is now silently omitted from every record", f.Src, v, f.Attr))
	}
}

// blobCollector wraps the generic BlobCollector so collectordoc recovers THIS
// package by reflection (a bare *blobpipeline.BlobCollector resolves to the
// blobpipeline package).
type blobCollector struct {
	*blobpipeline.BlobCollector
	watch *watcher
}

// Collect binds the tick's emitter for the duration of the poll, so findings
// raised inside the mapper reach the counter, then delegates to the generic
// collector. See the watcher type for why the emitter has to travel this way.
func (c blobCollector) Collect(ctx context.Context, e telemetry.Emitter) error {
	c.watch.bind(e)
	defer c.watch.bind(nil)
	return c.BlobCollector.Collect(ctx, e)
}

func newBlobCollector(d collectors.BlobDeps) collector.SnapshotCollector {
	w := &watcher{r: wirecheck.New(name, d.Logger)}
	return blobCollector{BlobCollector: defender.New(name, table, w.mapRecord, d), watch: w}
}

func init() { collectors.RegisterBlob(newBlobCollector) }

var _ collector.SnapshotCollector = blobCollector{}
