// Package messagetrace is the per-message mail-flow collector (#254), read over
// Exchange Online's Get-MessageTraceV2 cmdlet (internal/exoclient).
//
// # Why it is worth having
//
// It is the ONLY per-message mail-flow record that does not depend on Defender
// for Office 365 streaming export being enabled and billed. On a tenant without
// that export it is the sole answer to "did this message arrive, and what
// happened to it" — the most common mail question an operator is ever asked. It
// joins to defender.email* and to defender.quarantine on the RFC 5322
// Message-ID, which all three emit as the same attribute key
// (semconv.AttrInternetMessageId).
//
// # It ships OFF, and why that is HighVolume and not Experimental
//
// One record per message PER RECIPIENT is a firehose: the volume scales with
// mail traffic, not with tenant size, so enabling graph2otel must never switch
// it on by accident. It therefore declares collectors.HighVolume, which gates it
// behind an explicit config enable.
//
// It deliberately does NOT declare Experimental, even though the gate mechanism
// is identical. #183 reserved that for genuine Graph BETA surfaces, and
// Get-MessageTraceV2 is neither beta nor Graph — claiming otherwise would tell
// an operator that a GA endpoint is schema-unstable while hiding the one fact
// they actually need to plan capacity against.
//
// Measured volume: 28 records per 24h on m7kni, which has 3 mailboxes — about 9
// records per mailbox per day (live-measured 2026-07-23). m7kni is a tiny
// tenant; real per-mailbox rates run far higher, so extrapolate per mailbox
// rather than per tenant.
//
// # Pagination is a keyset walk, and the cursor comes from the DATA
//
// Every fact in this section is live-measured 2026-07-23/24 on m7kni as
// graph2otel-poller. None of it is derived from documentation, and several
// points contradict the shape every other collector on this transport uses.
//
//   - A truncated Get-MessageTraceV2 response carries NO "@odata.nextLink", so
//     exoclient's InvokeResult.Truncated is FALSE on it. The only truncation
//     signal is a non-empty Warnings. A collector reading Truncated here reports
//     one page of a firehose and looks perfectly healthy doing it.
//   - The warning text names the continuation in prose:
//     `...Get-MessageTraceV2 -StartDate "..." -EndDate "..."
//     -StartingRecipientAddress "rob@m7kni.io" -ResultSize 2`.
//     This collector does NOT parse it. The -EndDate and
//     -StartingRecipientAddress it names are exactly the Received and
//     RecipientAddress of the LAST RECORD OF THE PAGE, so the cursor is derived
//     from the data instead — same value, and it cannot rot when Microsoft
//     rewords the prose. The warning is used only as the boolean "there is
//     more".
//   - Records come back ordered by Received DESCENDING, so the walk goes
//     backwards through time. The next page is the same StartDate, EndDate = the
//     last record's Received, StartingRecipientAddress = its RecipientAddress.
//     BOTH halves are load-bearing: several records routinely share one Received
//     (one message fanning out to several recipients), and a Received-only
//     cursor re-requests the identical page forever.
//   - The walk is proven lossless by control experiment: over one fixed window
//     an unpaged read returned 37 distinct MessageTraceIds, and the derived
//     keyset walk at ResultSize 5 took 9 pages and returned the same 37 — zero
//     missed, zero extra.
//   - DUPLICATES ARE INHERENT, not a paging artifact: that same single unpaged
//     read returned 44 ROWS for those 37 distinct ids. Dedupe on MessageTraceId
//     is mandatory even when the walk is one page long.
//
// ResultSize is deliberately NOT sent. The page size the service picks was large
// enough to return the whole measured window unpaged, the warning is the
// measured truncation signal so a known page length buys no second termination
// test, and a documented maximum is exactly the kind of fact that has been wrong
// on every load-bearing detail of this project's path.
//
// # Both sides of the cardinality boundary
//
// Per-message detail — MessageTraceId, Message-ID, sender, recipient, subject,
// FromIP/ToIP, size — is LOG ONLY (#112). A metric keyed by recipient is one
// series per mailbox per status and grows with the tenant; keyed by message it
// is one sample per series, forever. The metrics are two monotonic counters
// labeled by Status alone, whose value set is a small closed enum: message count
// and total bytes, so "spam share" and "average message size" are both one
// division and neither costs a series per mailbox.
//
// Counters, not a gauge of "messages in this window": the poll window varies —
// a catch-up tick after an outage is up to maxWindow long — so a window-count
// gauge spikes by the window ratio and is indistinguishable from a real mail
// surge. increase() over a monotonic counter has no such artifact, and because
// the counter only advances for records that survived the dedupe, it is exactly
// "messages ingested". This is the same call mdca.discovery_parse made against
// its own issue's suggestion, for the same reason.
package messagetrace

import (
	"context"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/exoclient"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	// collectorName is the stable key for config, self-observability and the
	// admin status page.
	collectorName = "m365.message_trace"
	// eventName is the OTLP LogRecord EventName every message twin carries.
	eventName = "m365.message_trace"
	// checkpointKey namespaces this collector's watermark + dedupe set. The '#'
	// segment keeps it distinct from anything else on the cmdlet transport.
	checkpointKey = "Get-MessageTraceV2#m365.message_trace"
	// cmdletMessageTrace is the single Exchange Online cmdlet this collector
	// runs. V1 (Get-MessageTrace) 400s on this transport — use V2 (#233).
	cmdletMessageTrace = "Get-MessageTraceV2"
)

// The cmdlet's parameter names. StartDate/EndDate bound the window;
// StartingRecipientAddress is the second half of the keyset cursor and is sent
// only once a page has been read.
const (
	paramStartDate         = "StartDate"
	paramEndDate           = "EndDate"
	paramStartingRecipient = "StartingRecipientAddress"
)

// Wire field names, read by exact name so the "<Name>@data.type" sidecars that
// travel beside Received and Size are ignored.
const (
	fieldMessageTraceId   = "MessageTraceId"
	fieldMessageId        = "MessageId"
	fieldReceived         = "Received"
	fieldSenderAddress    = "SenderAddress"
	fieldRecipientAddress = "RecipientAddress"
	fieldFromIP           = "FromIP"
	fieldToIP             = "ToIP"
	fieldSubject          = "Subject"
	fieldStatus           = "Status"
	fieldSize             = "Size"
)

// wireTimeLayout is the .NET round-trip timestamp shape the service both emits
// and accepts ("2026-07-23T22:01:22.0480000Z", seven fractional digits). Only
// the window bounds are formatted with it — a continuation EndDate is the
// previous page's Received string passed back VERBATIM, never reformatted
// (#142).
const wireTimeLayout = "2006-01-02T15:04:05.0000000Z"

// Schedule tuning. Neither lag nor overlap is measured: the delay between a
// message being handled and its trace record becoming queryable was never
// timed on this transport. Both are therefore set generously, which costs
// nothing but a re-read the dedupe absorbs, where setting them short would lose
// records silently.
const (
	interval = 10 * time.Minute
	lag      = 15 * time.Minute
	// initialLookback is the cold-start backfill. Deliberately short for a
	// firehose: a first run should not ship a day of mail before an operator has
	// seen what one hour costs.
	initialLookback = time.Hour
	// maxWindow caps a single tick's catch-up after an outage, so recovery is
	// spread across ticks rather than one unbounded keyset walk.
	maxWindow = 2 * time.Hour
	// overlapWindow is how far behind the scheduler's `from` each tick re-reads,
	// so a record that reached the trace index after the previous window closed
	// is still collected. It is also the SeenIDs eviction horizon, so the two
	// cannot drift apart.
	overlapWindow = 30 * time.Minute
	// maxPages bounds the keyset walk so a pathological window cannot spin
	// forever. Hitting it means the OLDEST part of the window was never read,
	// which is a hole in the data — see rulePageCap.
	maxPages = 200
)

// Metric names (m365.* domain namespace). Both are labeled by Status ONLY, a
// small closed enum, so the series count is fixed by this file and cannot grow
// with mail traffic or tenant size.
const (
	// metricMessages counts messages ingested. Prometheus normalization appends
	// _total: m365_message_trace_messages_total.
	metricMessages = "m365.message_trace.messages"
	// metricBytes totals their Size. Named with the _bytes suffix to match the
	// tree's convention (m365.storage.used_bytes,
	// intune.hardware_inventory.storage_bytes).
	metricBytes = "m365.message_trace.bytes"
	// unitMessage is the annotation unit for a countable message.
	unitMessage = "{message}"
	// unitBytes is UCUM bytes.
	unitBytes = "By"
)

// knownStatuses is the Status value set this collector was BUILT AGAINST, which
// is a deliberately different question from "the set Microsoft documents".
//
// Three members are live-measured over one 24h window on m7kni (2026-07-23):
// Delivered (18), FilteredAsSpam (6) and Resolved (4). Resolved is NOT in the
// list #254's body guessed, which is the whole reason this watch exists.
//
// The remaining five are `docs-only`, and they are here because the severity map
// below NAMES them: a status this collector explicitly handles is one it was
// built against, whatever the evidence for its existence. That makes the
// watchdog fire exactly when the severity map has a hole, rather than firing on
// correct data the moment a real Failed appears — the failure mode #234 warns
// about.
//
// Status is a METRIC LABEL, so a member Microsoft adds later silently creates a
// new series and moves every ratio computed off these counters. That is #234's
// priority-1 case.
var knownStatuses = wirecheck.NewEnum(
	"Delivered", "FilteredAsSpam", "Resolved", // live-measured 2026-07-23
	statusFailed, "Pending", "Quarantined", "Expanded", "GettingStatus", // docs-only, handled below
)

// statusFailed is the one status meaning the message did not reach where it was
// sent. It is the whole severity map — see severityFor.
const statusFailed = "Failed"

// The invariants this collector watches at runtime (#233/#234). Each is a
// silent-data-loss shape: the cmdlet keeps answering 200 and the counters keep
// looking plausible.
const (
	// rulePageCap fires when the keyset walk stops at maxPages. The walk runs
	// newest-first, so the records lost are the OLDEST end of the window and the
	// window advances past them regardless — see the note on CollectWindow.
	rulePageCap = "page_cap"
	// ruleCursorStall fires when the service reports more results but hands back
	// a page whose last record reproduces the cursor it was given. The next
	// request would be byte-identical, so the only outcomes are stop or spin.
	ruleCursorStall = "cursor_stall"
	// ruleTruncationCursor fires when the service reports more results but the
	// page carried no record to derive a cursor from.
	ruleTruncationCursor = "truncation_cursor"
)

// exoInvoker is the narrow Exchange Online seam THIS collector consumes.
//
// collectors.EXOClient declares only Invoke, which returns the "value" array and
// discards the envelope — and on this cmdlet the envelope is the only truncation
// signal there is (no nextLink, warnings only). So this package depends on
// InvokeFull through its own local interface, the same way every collector here
// depends on a narrow local seam rather than a concrete client: the fake in the
// tests implements exactly this and nothing else.
type exoInvoker interface {
	InvokeFull(ctx context.Context, cmdlet string, params map[string]any) (exoclient.InvokeResult, error)
}

// cursor is the keyset continuation: the last record of the previous page,
// carried as the RAW wire strings so EndDate is passed back byte-identical.
type cursor struct {
	received  string
	recipient string
}

// Collector walks the Exchange Online message trace for one tenant.
type Collector struct {
	c        exoInvoker
	store    *checkpoint.Store
	tenantID string
	watch    *wirecheck.Reporter
}

// New builds the message-trace collector over an already-narrowed client.
func New(c exoInvoker, d collectors.WindowDeps) *Collector {
	return &Collector{
		c:        c,
		store:    d.Store,
		tenantID: d.TenantID,
		watch:    wirecheck.New(collectorName, d.Logger),
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// Lag implements collector.WindowCollector.
func (c *Collector) Lag() time.Duration { return lag }

// HighVolume marks this collector opt-in: one record per message per recipient
// scales with mail traffic, so it must never be switched on by simply enabling
// graph2otel. See the package doc for why this is not Experimental.
func (c *Collector) HighVolume() bool { return true }

// IngestTransport reports the transport this collector ingests over (#141/#178).
// There is no engine on this path, so CollectWindow stamps the same value inline
// — the two agree by construction because they name one constant.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty: access is the two grants outside the Graph-scope
// vocabulary that the Exchange Online admin API needs (Exchange.ManageAsApp plus
// an Entra directory role), and the declaration surface models Graph scopes.
func (c *Collector) RequiredPermissions() []string { return nil }

// CheckpointState reports this collector's durable progress for the admin status
// page (#178 Part B). Like mdca.discovery_parse it owns its checkpoint directly
// rather than through an engine, so it implements this itself. A read failure
// returns nil rather than erroring the page — the failure already surfaces as
// the collector's own run error, since CollectWindow loads the same file.
func (c *Collector) CheckpointState() *collector.CheckpointState {
	cp, err := c.store.Load(c.tenantID, checkpointKey)
	if err != nil {
		return nil
	}
	return &collector.CheckpointState{
		Kind:      collector.CheckpointKindWindow,
		Watermark: cp.Watermark,
		SeenIDs:   len(cp.SeenIDs),
	}
}

// message is one mapped trace record.
type message struct {
	traceID   string
	messageID string
	received  string // verbatim wire string
	eventTime time.Time
	sender    string
	recipient string
	fromIP    string
	toIP      string
	subject   string
	status    string
	size      float64
	hasSize   bool
}

// CollectWindow implements collector.WindowCollector: it stamps its transport
// inline (no engine), walks the keyset backwards through [from-overlap, to],
// dedupes on MessageTraceId and emits one log twin per message plus the two
// bounded counters.
//
// It returns `to` on success — the window really was drained — and `to` even
// when the page cap stopped the walk early. That second case is deliberate and
// is why rulePageCap is reported as a broken invariant: the walk runs
// newest-first, so an early stop leaves a hole at the OLD end of the window, and
// NO high-water mark recovers it. Returning the cursor instead would re-read
// what was already shipped while still never reading the hole, and would leave
// the collector permanently behind. So the window advances and the loss is made
// loud rather than silent.
func (c *Collector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	// Stamp the transport HERE: with no ingest engine on this path the
	// Scheduler's baseline is TransportGraph, so without this every record from
	// the Exchange Online admin API would claim to be a Graph poll.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	cp, err := c.store.Load(c.tenantID, checkpointKey)
	if err != nil {
		return time.Time{}, err //nolint:wrapcheck // the store's error is already specific
	}
	cp.OverlapWindow = overlapWindow

	since := from.Add(-overlapWindow).UTC().Format(wireTimeLayout)
	end := to.UTC().Format(wireTimeLayout)

	counts := map[string]float64{}
	sizeTotals := map[string]float64{}

	var cur cursor
	var pages int
	for pages = 1; pages <= maxPages; pages++ {
		params := map[string]any{paramStartDate: since, paramEndDate: end}
		if cur.received != "" {
			params[paramEndDate] = cur.received
			params[paramStartingRecipient] = cur.recipient
		}

		res, err := c.c.InvokeFull(ctx, cmdletMessageTrace, params)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s page %d: %w", cmdletMessageTrace, pages, err)
		}

		var last cursor
		for _, r := range res.Records {
			m, ok := c.mapRecord(e, r)
			if !ok {
				continue
			}
			last = cursor{received: m.received, recipient: m.recipient}

			// An undedupeable record is DEGRADED, not wrong, so it still ships:
			// dropping it would lose a message that really happened. Only a
			// record that cannot be dated is dropped (see mapRecord).
			if m.traceID != "" {
				if cp.SeenIDs.Has(m.traceID) {
					continue
				}
				cp.SeenIDs.Add(m.traceID, m.eventTime)
			}

			e.LogEvent(logTwin(m))
			counts[m.status]++
			// Seed the byte total even for a record with no Size, so the two
			// counters always carry the same status label set and "average size"
			// is a division rather than a missing series.
			if _, seeded := sizeTotals[m.status]; !seeded {
				sizeTotals[m.status] = 0
			}
			if m.hasSize {
				sizeTotals[m.status] += m.size
			}
		}

		// Any warning is treated as "there may be more". Over-reading is free —
		// the dedupe absorbs it — while under-reading loses records silently, so
		// the asymmetry decides it. The prose is never parsed.
		if len(res.Warnings) == 0 {
			break
		}
		if last.received == "" {
			c.watch.Invariant(e, ruleTruncationCursor,
				"the service reported more results but the page carried no record to continue from")
			break
		}
		if last == cur {
			c.watch.Invariant(e, ruleCursorStall,
				fmt.Sprintf("the continuation did not advance past %s/%s; stopping rather than re-requesting the identical page",
					cur.received, cur.recipient))
			break
		}
		cur = last
	}
	if pages > maxPages {
		c.watch.Invariant(e, rulePageCap,
			fmt.Sprintf("stopped the keyset walk at %d pages with the cursor at %s; records older than that within [%s, %s] were not read and the window advances past them",
				maxPages, cur.received, since, end))
	}

	// The watermark is the DRAINED boundary, not the newest record's Received:
	// SeenIDs is evicted at watermark-overlap, which is exactly the floor the
	// next tick re-reads from, so an id can never be evicted while it is still
	// reachable.
	cp.Watermark = to
	cp.EvictStale()
	if err := c.store.Save(cp); err != nil {
		return time.Time{}, err //nolint:wrapcheck // the store's error is already specific
	}

	c.emitVolume(e, counts, sizeTotals)
	return to, nil
}

// emitVolume records the two bounded counters. Both are labeled by Status alone.
func (c *Collector) emitVolume(e telemetry.Emitter, counts, sizeTotals map[string]float64) {
	for status, n := range counts {
		e.Counter(metricMessages, unitMessage,
			"Messages ingested from the Exchange Online message trace, by delivery status. Per-message detail (sender, recipient, subject, message id) is on the m365.message_trace log twin, never here.",
			n, telemetry.Attrs{semconv.AttrStatus: status})
	}
	for status, n := range sizeTotals {
		e.Counter(metricBytes, unitBytes,
			"Total size of the messages ingested from the Exchange Online message trace, by delivery status.",
			n, telemetry.Attrs{semconv.AttrStatus: status})
	}
}

// mapRecord decodes one trace record. ok=false DROPS the record, for exactly one
// reason: no parseable Received. telemetry.Event treats a zero Timestamp as
// "now", so emitting an undateable record would silently claim it happened on
// arrival — misdated is wrong, and only wrong justifies a drop.
func (c *Collector) mapRecord(e telemetry.Emitter, r map[string]any) (message, bool) {
	received := str(r, fieldReceived)
	eventTime, err := time.Parse(time.RFC3339, received)
	if err != nil {
		c.watch.MissingField(e, fieldReceived)
		return message{}, false
	}

	m := message{
		traceID:   str(r, fieldMessageTraceId),
		messageID: str(r, fieldMessageId),
		received:  received,
		eventTime: eventTime.UTC(),
		sender:    str(r, fieldSenderAddress),
		recipient: str(r, fieldRecipientAddress),
		fromIP:    str(r, fieldFromIP),
		toIP:      str(r, fieldToIP),
		subject:   str(r, fieldSubject),
		status:    str(r, fieldStatus),
	}
	m.size, m.hasSize = r[fieldSize].(float64)

	if m.traceID == "" {
		// The dedupe key. Its absence does not cost the record, it costs the
		// guarantee that the record ships once.
		c.watch.MissingField(e, fieldMessageTraceId)
	}
	// Status is a metric label, so an unmapped value silently creates a series.
	c.watch.Value(e, fieldStatus, m.status, knownStatuses)
	return m, true
}

// logTwin renders one message as its log record. Every per-message field lives
// here and nowhere else (#112).
func logTwin(m message) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrMessageTraceId, m.traceID)
	// MessageId is the RFC 5322 Message-ID, and it is emitted under the SAME key
	// defender.quarantine and defender.email* use — that shared key is the join
	// #254 exists for.
	telemetry.SetStr(attrs, semconv.AttrInternetMessageId, m.messageID)
	// Received is carried verbatim alongside the parsed event time: the wire
	// string is what an operator sees in the admin center, and re-rendering it
	// would emit a value the API never sent (#142).
	telemetry.SetStr(attrs, semconv.AttrReceivedTime, m.received)
	telemetry.SetStr(attrs, semconv.AttrSenderAddress, m.sender)
	telemetry.SetStr(attrs, semconv.AttrRecipientAddress, m.recipient)
	telemetry.SetStr(attrs, semconv.AttrFromIp, m.fromIP)
	// ToIP is "" on inbound mail; SetStr omits it, so its presence marks the
	// outbound direction rather than an empty attribute claiming nothing.
	telemetry.SetStr(attrs, semconv.AttrToIp, m.toIP)
	telemetry.SetStr(attrs, semconv.AttrSubject, m.subject)
	telemetry.SetStr(attrs, semconv.AttrStatus, m.status)
	if m.hasSize {
		// A NUMBER, matching defender.quarantine on the same key: both read the
		// same wire field off the same transport, so a consumer must not have to
		// know which collector produced the record to read its size.
		attrs[semconv.AttrSize] = m.size
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      fmt.Sprintf("mail %s -> %s: %s", m.sender, m.recipient, m.status),
		Severity:  severityFor(m.status),
		Timestamp: m.eventTime,
		Attrs:     attrs,
	}
}

// severityFor maps a delivery status to a log severity.
//
// The question severity answers on this stream is "does this message's outcome
// need a human", and the only status meaning mail did NOT get where it was sent
// is Failed. Filtering and quarantine are the security stack working exactly as
// designed and firing constantly — rating them WARN would make WARN the dominant
// severity of a firehose and destroy the level's meaning, while telling an
// operator that a working spam filter is a problem. Failed is WARN rather than
// ERROR because the common cause is a bad recipient address, which is a fact
// about the sender, not an outage of the tenant.
//
// An UNMAPPED status stays INFO on purpose: it is a schema surprise, reported
// through wirecheck as graph2otel.api.unexpected, and inventing a severity for a
// value nobody has seen would put unexplained WARNs in front of an operator with
// no action attached.
func severityFor(status string) telemetry.Severity {
	if status == statusFailed {
		return telemetry.SeverityWarn
	}
	return telemetry.SeverityInfo
}

// str reads a string column, "" when absent or non-string. Reading by exact name
// ignores the "<Name>@data.type" sidecars that travel beside Received and Size.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// factory constructs the collector for one tenant, or declines.
//
// It declines — a zero RegisteredWindow, which the composition root skips — when
// either seam is missing: WindowDeps.EXO is nil for a tenant with no
// exchange_online block, and a nil Store leaves nowhere to persist the dedupe
// set, so every tick's overlap would re-ship every record it re-reads. It also
// declines if the client cannot supply InvokeFull, because on this cmdlet that
// is the only way to see truncation at all.
func factory(d collectors.WindowDeps) collectors.RegisteredWindow {
	if d.EXO == nil || d.Store == nil {
		return collectors.RegisteredWindow{}
	}
	inv, ok := d.EXO.(exoInvoker)
	if !ok {
		return collectors.RegisteredWindow{}
	}
	return collectors.RegisteredWindow{
		Collector:       New(inv, d),
		InitialLookback: initialLookback,
		MaxWindow:       maxWindow,
	}
}

func init() { collectors.RegisterWindow(factory) }

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector                          = (*Collector)(nil)
	_ collector.CheckpointReporter                       = (*Collector)(nil)
	_ collectors.HighVolume                              = (*Collector)(nil)
	_ interface{ IngestTransport() telemetry.Transport } = (*Collector)(nil)
)
