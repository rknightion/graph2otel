// Package quarantine is the Microsoft Defender for Office 365 quarantine
// queue-depth collector (#233): how many messages are held right now, and which
// ones.
//
// # Why this is not a Graph collector
//
// There is no Graph endpoint for quarantine queue depth. None. The only way to
// ask "what is currently held" is the Exchange Online admin API's app-only
// PowerShell transport (internal/exoclient), which is why this package is the
// only member of the EXO registration path (collectors.EXODeps). Graph's
// nearest surfaces answer different questions: security/collaboration/
// analyzedEmails returns a ~20-hour rolling window it will not let you filter,
// and the Defender advanced-hunting tables record message EVENTS, not the
// standing contents of the queue.
//
// # The three-part quarantine model
//
// This collector owns exactly one third of graph2otel's quarantine coverage,
// and deliberately does not reach for the other two:
//
//   - STATE — this package. How many are held right now, by type.
//   - MOVEMENT — defender.email_post_delivery. A message entering or leaving
//     quarantine (ZAP, remediation, redelivery).
//   - HISTORY — m365.unified_audit's quarantine record types. Held, released,
//     previewed, deleted, plus quarantine-policy changes.
//
// All three key on network_message_id, so they join into one dataset. That
// split is what makes each part cheap: nothing here has to reconstruct history
// from a state snapshot, because the audit log already carries it.
//
// # Both sides of the cardinality boundary, from one fetch
//
// Per cycle, from a single paged fetch (the entra/risk shape):
//
//   - a bounded GAUGE counted by quarantine_type x direction x entity_type —
//     eleven quarantine types, two directions, a handful of entity types, so the
//     series count is fixed by Microsoft's enums and never grows with tenant
//     size or message volume;
//   - one LOG record per held message carrying everything the gauge cannot —
//     sender, recipients, subject, the quarantine policy and tag, expiry, and
//     the per-message permission flags.
//
// The twin is not garnish. "Not a metric label" means "log twin", never
// "dropped" (#114): a collector that counts held messages but cannot say WHICH
// ones answers the wrong question. The permission flags in particular are
// emitted even when false, because permission_to_release=false — the recipient
// cannot self-release this message — is precisely the interesting case.
//
// # A STATE feed, not an event stream
//
// A held message is re-emitted every cycle for as long as it stays held, which
// is what makes "what was in quarantine at 14:00" answerable. Log records are
// therefore stamped at POLL time (Timestamp left zero) rather than with
// ReceivedTime, which would pile every repeat onto the message's arrival
// instant; the wire time is preserved as the received_time attribute. Same
// reasoning, and the same shape, as entra/risk's twin.
//
// Volume scales with the held population — small by nature, since a healthy
// tenant's quarantine drains — times the poll interval, not with mail volume.
package quarantine

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable key used for config (enable/interval),
	// self-observability, and the admin status page.
	collectorName = "defender.quarantine"
	// eventName is the OTLP LogRecord EventName every held-message twin carries.
	eventName = "defender.quarantine"
	// metricHeld counts messages CURRENTLY HELD, by bounded enum labels. Named
	// for what it counts: released messages remain visible to the API for the
	// rest of their retention, and counting those would make the number drift
	// upward for a fortnight after an incident rather than returning to zero.
	metricHeld = "defender.quarantine.held_messages.total"
	// cmdlet is the Exchange Online cmdlet this collector runs.
	cmdlet = "Get-QuarantineMessage"
	// heldOnly restricts the query to messages still held. This is THE
	// queue-depth filter and it works server-side: measured 2026-07-23 on m7kni,
	// RELEASED returned the 2 released messages and NOTRELEASED returned 0 —
	// complementary, so it genuinely filters rather than being ignored.
	heldOnly = "NOTRELEASED"
	// pageSize is rows per request. It must never be 0: PageSize=0 returns HTTP
	// 200 with ZERO rows instead of erroring (live-measured 2026-07-23), so a
	// zero here is permanent silence indistinguishable from an empty
	// quarantine. 1000 is the documented maximum; the real ceiling could not be
	// confirmed on a tenant holding 2 messages, and a value above it was
	// accepted rather than rejected, so do not raise this without measuring on a
	// tenant that can actually fill a page. [unmeasured ceiling]
	pageSize = 1000
	// maxPages bounds the paging loop so a server that never returns a short
	// page cannot spin forever. At pageSize rows each this is a million held
	// messages — far past the point where the tenant has a bigger problem than
	// telemetry.
	maxPages = 100
	// interval: quarantine state changes on the timescale of mail delivery and
	// admin action, not seconds, and each tick costs a full re-list. The EXO
	// throttling ceiling for adminapi is undocumented and unmeasured, which is
	// another reason to stay coarse.
	interval = 15 * time.Minute
)

// Collector polls Exchange Online for the messages currently held in
// quarantine.
type Collector struct {
	c      collectors.EXOClient
	logger *slog.Logger
}

// New builds the quarantine collector. A nil logger falls back to
// slog.Default().
func New(d collectors.EXODeps) *Collector {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{c: d.Client, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// IngestTransport marks every record this collector emits as having come from
// the Exchange Online admin API rather than Graph (#141). It is stamped here
// because there is no ingest engine on this path — the same position
// mdca.discovery_parse is in.
func (c *Collector) IngestTransport() telemetry.Transport {
	return telemetry.TransportExchangeOnline
}

// RequiredPermissions is empty because this collector needs no GRAPH scope, and
// the declaration surface models Graph scopes. Its access is two grants that
// live outside that vocabulary and cannot be requested by consent alone:
//
//   - the app role Exchange.ManageAsApp (dc50a0fb-09a3-484d-be87-e023b12c6440)
//     on the Office 365 Exchange Online service principal — authentication;
//   - an Entra DIRECTORY role on the service principal, Security Reader being
//     the least-privileged sufficient one — authorization.
//
// Neither alone grants anything: live-measured 2026-07-23, 401 with neither,
// 403 with the app role only, 200 with both. Both are read-only. The
// requirement is documented in the collector reference and in
// config.ExchangeOnlineConfig, which is what an operator actually reads.
func (c *Collector) RequiredPermissions() []string { return nil }

// gaugeKey is the bounded label tuple the held-message gauge is counted by.
type gaugeKey struct {
	quarantineType string
	direction      string
	entityType     string
}

// Collect pages the held-message query and emits both sides of the cardinality
// boundary: the bounded gauge, and one log twin per held message.
//
// GaugeSnapshot (not Gauge) is used deliberately: it is an observable
// instrument, so a (type, direction, entity) combination that no longer appears
// on a later tick drops out of the export instead of ghosting forever under
// Grafana Cloud's forced cumulative temporality. The corollary is that an empty
// quarantine emits NO series at all rather than a zero — so alert on the series
// exceeding a threshold, never on its absence.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	// Stamp the transport HERE, not just in IngestTransport(). There is no
	// ingest engine on this path to do it, and the Scheduler's baseline is
	// telemetry.TransportGraph — so without this wrapper every record from the
	// Exchange Online admin API would claim to be a Graph poll. IngestTransport()
	// below only feeds the admin status page (collector.TransportOf); it does not
	// stamp anything. The two must agree, which is why they name one constant.
	// Same position, and the same fix, as mdca.discovery_parse and the Intune
	// report-export collectors.
	e = telemetry.WithTransport(e, telemetry.TransportExchangeOnline)

	counts := map[gaugeKey]int64{}

	for page := 1; page <= maxPages; page++ {
		recs, err := c.c.Invoke(ctx, cmdlet, map[string]any{
			"PageSize":      pageSize,
			"Page":          page,
			"ReleaseStatus": heldOnly,
		})
		if err != nil {
			return fmt.Errorf("%s page %d: %w", cmdlet, page, err)
		}
		for _, r := range recs {
			counts[gaugeKey{
				quarantineType: str(r, "QuarantineTypes"),
				direction:      str(r, "Direction"),
				entityType:     str(r, "EntityType"),
			}]++
			e.LogEvent(logTwin(r))
		}
		// A short page is the end of the result set. The API exposes no total
		// count and no next-link, so this is the only termination signal.
		if len(recs) < pageSize {
			break
		}
		if page == maxPages {
			c.logger.Warn("quarantine listing hit the page cap; the gauge undercounts",
				"collector", collectorName, "max_pages", maxPages, "page_size", pageSize)
		}
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(v),
			Attrs: telemetry.Attrs{
				semconv.AttrQuarantineType: k.quarantineType,
				semconv.AttrDirection:      k.direction,
				semconv.AttrEntityType:     k.entityType,
			},
		})
	}
	e.GaugeSnapshot(metricHeld, semconv.UnitDimensionless,
		"Messages currently held in Microsoft Defender for Office 365 quarantine, by quarantine type, direction and entity type.",
		points)
	return nil
}

// quarantineStrFields maps the row's string columns to their attribute keys.
// PolicyName/PolicyType/TagName together identify WHICH policy held the
// message, which is the difference between "quarantine is filling up" and "this
// one rule is over-matching".
var quarantineStrFields = []struct{ attr, src string }{
	{semconv.AttrInternetMessageId, "MessageId"},
	{semconv.AttrSenderAddress, "SenderAddress"},
	{semconv.AttrSubject, "Subject"},
	{semconv.AttrQuarantineType, "QuarantineTypes"},
	{semconv.AttrPolicyType, "PolicyType"},
	{semconv.AttrPolicyName, "PolicyName"},
	{semconv.AttrTagName, "TagName"},
	{semconv.AttrReleaseStatus, "ReleaseStatus"},
	{semconv.AttrDirection, "Direction"},
	{semconv.AttrEntityType, "EntityType"},
	{semconv.AttrOverrideReason, "OverrideReason"},
	{semconv.AttrReceivedTime, "ReceivedTime"},
	{semconv.AttrExpires, "Expires"},
}

// quarantineNumFields maps the row's numeric columns.
var quarantineNumFields = []struct{ attr, src string }{
	{semconv.AttrSize, "Size"},
	{semconv.AttrRecipientCount, "RecipientCount"},
	{semconv.AttrReleasedCount, "ReleasedCount"},
}

// quarantineBoolFields maps the row's boolean columns, including all eight
// permission flags. They are emitted even when false: unlike an empty string,
// false is an ANSWER here — permission_to_release=false means the recipient
// cannot release this message themselves, which is the case an operator wants
// to filter for.
var quarantineBoolFields = []struct{ attr, src string }{
	{semconv.AttrReleased, "Released"},
	{semconv.AttrSystemReleased, "SystemReleased"},
	{semconv.AttrReported, "Reported"},
	{semconv.AttrPermissionToRelease, "PermissionToRelease"},
	{semconv.AttrPermissionToRequestRelease, "PermissionToRequestRelease"},
	{semconv.AttrPermissionToDelete, "PermissionToDelete"},
	{semconv.AttrPermissionToPreview, "PermissionToPreview"},
	{semconv.AttrPermissionToDownload, "PermissionToDownload"},
	{semconv.AttrPermissionToViewHeader, "PermissionToViewHeader"},
	{semconv.AttrPermissionToBlockSender, "PermissionToBlockSender"},
	{semconv.AttrPermissionToAllowSender, "PermissionToAllowSender"},
}

// logTwin renders one held message as an OTLP log record.
//
// Timestamp is deliberately left zero ("now", i.e. poll time) rather than set to
// ReceivedTime — see the package doc on why a state feed must not stamp its
// source time. ReceivedTime is preserved as an attribute.
func logTwin(r map[string]any) telemetry.Event {
	attrs := telemetry.Attrs{}
	// Identity is "<NetworkMessageId>\<recipient-guid>". Its leading segment is
	// the join key onto defender.email, defender.email_post_delivery,
	// defender.email_url and the m365.unified_audit quarantine records — every
	// quarantine-relevant signal graph2otel emits keys on the same id. A row
	// with no parseable Identity still counts toward the gauge (it occupies
	// quarantine either way); it simply loses its join key rather than being
	// dropped.
	telemetry.SetStr(attrs, semconv.AttrNetworkMessageId, networkMessageID(str(r, "Identity")))
	for _, f := range quarantineStrFields {
		telemetry.SetStr(attrs, f.attr, str(r, f.src))
	}
	for _, f := range quarantineNumFields {
		telemetry.SetNum(attrs, f.attr, r, f.src)
	}
	for _, f := range quarantineBoolFields {
		if b, ok := r[f.src].(bool); ok {
			telemetry.SetBool(attrs, f.attr, b)
		}
	}
	telemetry.SetStrs(attrs, semconv.AttrRecipientAddress, strSlice(r, "RecipientAddress"))
	telemetry.SetStrs(attrs, semconv.AttrRecipientTag, strSlice(r, "RecipientTag"))
	telemetry.SetStrs(attrs, semconv.AttrReleasedBy, strSlice(r, "ReleasedBy"))

	return telemetry.Event{
		Name:     eventName,
		Body:     body(r),
		Severity: telemetry.SeverityInfo,
		Attrs:    attrs,
	}
}

// body builds a short human-readable summary line for a held message.
func body(r map[string]any) string {
	kind := str(r, "QuarantineTypes")
	if kind == "" {
		kind = "message"
	}
	return fmt.Sprintf("%s held from %s: %q", kind, str(r, "SenderAddress"), str(r, "Subject"))
}

// networkMessageID extracts the leading segment of a quarantine Identity. The
// separator is a literal backslash. An Identity that is empty or carries no
// separator yields "", which SetStr then omits rather than emitting a
// half-parsed value.
func networkMessageID(identity string) string {
	id, _, ok := strings.Cut(identity, `\`)
	if !ok {
		return ""
	}
	return id
}

// str reads a string column, "" when absent or non-string. The API decorates
// several columns with sidecar "<Name>@data.type" / "<Name>@odata.type" keys;
// reading by exact name ignores them.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// strSlice reads a JSON array-of-strings column, dropping any non-string
// element. An absent or non-array column yields an empty slice, which SetStrs
// omits.
func strSlice(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	collectors.RegisterEXO(func(d collectors.EXODeps) collector.SnapshotCollector { return New(d) })
}

var _ collector.SnapshotCollector = (*Collector)(nil)
