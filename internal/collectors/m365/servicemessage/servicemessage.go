// Package servicemessage is the Microsoft 365 message-center collector (#182,
// follow-up to #119): it polls /admin/serviceAnnouncement/messages — the
// upcoming-change announcements ("plan for change", "prevent or fix issue",
// "stay informed") the M365 admin center surfaces — so change-management posts
// land in the same log store as the rest of the tenant's telemetry.
//
// This is a different question from service HEALTH (#119's servicehealth
// collector, current up/down state): message-center posts are forward-looking
// announcements, they need a SECOND scope (ServiceMessage.Read.All), and they are
// far more numerous, so this is a SEPARATE, Experimental + default-off collector
// — an operator opts in per tenant. From one paged fetch it emits:
//
//   - a bounded GAUGE of message counts by category x severity (the aggregate);
//   - one LOG record per message (m365.service_message) carrying the per-message
//     detail — title, body, affected services, dates — that a metric label must
//     never hold.
//
// Snapshot read: no delta query and no time filter exist, so the twin re-emits
// the active message set every cycle. actionRequiredByDateTime is null on most
// messages (only "prevent or fix" posts carry one), so it is emitted only when
// present and no deadline is derived from its absence.
package servicemessage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	collectorName  = "m365.servicemessages"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
	messagesPath   = "/admin/serviceAnnouncement/messages"

	metricMessagesTotal = "m365.service_messages.total"
	eventMessage        = "m365.service_message"
)

// message is one serviceUpdateMessage. body is {content, contentType}; details,
// tags, and viewPoint are intentionally not decoded — the twin carries the
// header fields + the body content, and the rest is per-cycle bulk with no
// aggregate value.
type message struct {
	ID                       string   `json:"id"`
	Title                    string   `json:"title"`
	Category                 string   `json:"category"`
	Severity                 string   `json:"severity"`
	IsMajorChange            bool     `json:"isMajorChange"`
	HasAttachments           bool     `json:"hasAttachments"`
	StartDateTime            string   `json:"startDateTime"`
	EndDateTime              string   `json:"endDateTime"`
	ActionRequiredByDateTime string   `json:"actionRequiredByDateTime"`
	LastModifiedDateTime     string   `json:"lastModifiedDateTime"`
	Services                 []string `json:"services"`
	Body                     itemBody `json:"body"`
}

type itemBody struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"`
}

// Collector polls the message-center surface.
type Collector struct {
	g       collectors.GraphClient
	baseURL string
	logger  *slog.Logger
}

// New builds the collector. A nil logger falls back to slog.Default().
func New(g collectors.GraphClient, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{g: g, baseURL: defaultBaseURL, logger: logger}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector. Message-center content changes
// on the order of hours-to-days; a slow cadence keeps the (potentially hundreds
// of messages) twin volume sane.
func (c *Collector) DefaultInterval() time.Duration { return time.Hour }

// Experimental marks the collector opt-in: it needs a second scope
// (ServiceMessage.Read.All) beyond the health collector and is the higher-volume
// half of the surface, so it is off unless a tenant explicitly enables it (#182).
func (c *Collector) Experimental() bool { return true }

// RequiredPermissions declares exactly ServiceMessage.Read.All.
func (c *Collector) RequiredPermissions() []string {
	return []string{"ServiceMessage.Read.All"}
}

// Collect fetches the paged message set and emits the bounded count gauge plus
// one log per message.
func (c *Collector) Collect(ctx context.Context, e telemetry.Emitter) error {
	raws, err := collectors.GetAllValues(ctx, c.g, c.baseURL+messagesPath, nil)
	if err != nil {
		return err
	}

	counts := map[[2]string]int64{}
	for _, raw := range raws {
		var m message
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("decode serviceUpdateMessage: %w", err)
		}
		counts[[2]string{m.Category, m.Severity}]++
		e.LogEvent(messageTwin(m))
	}

	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, n := range counts {
		points = append(points, telemetry.GaugePoint{
			Value: float64(n),
			Attrs: telemetry.Attrs{semconv.AttrCategory: k[0], semconv.AttrSeverity: k[1]},
		})
	}
	e.GaugeSnapshot(metricMessagesTotal, "{message}", "Count of active M365 message-center posts by category and severity.", points)
	return nil
}

// messageTwin renders one message-center post as an OTLP log record. Timestamp is
// left zero ("now", poll time): a snapshot twin re-emitted each cycle, so the
// post's own dates are attributes, not the record time. isMajorChange escalates
// severity to Warn — a major change is the one an operator must not miss.
func messageTwin(m message) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, m.ID)
	telemetry.SetStr(attrs, semconv.AttrTitle, m.Title)
	telemetry.SetStr(attrs, semconv.AttrCategory, m.Category)
	telemetry.SetStr(attrs, semconv.AttrSeverity, m.Severity)
	telemetry.SetBool(attrs, semconv.AttrIsMajorChange, m.IsMajorChange)
	telemetry.SetBool(attrs, semconv.AttrHasAttachments, m.HasAttachments)
	telemetry.SetStr(attrs, semconv.AttrStartDateTime, m.StartDateTime)
	telemetry.SetStr(attrs, semconv.AttrEndDateTime, m.EndDateTime)
	telemetry.SetStr(attrs, semconv.AttrActionRequiredByDateTime, m.ActionRequiredByDateTime)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, m.LastModifiedDateTime)
	telemetry.SetStrs(attrs, semconv.AttrServices, m.Services)
	telemetry.SetStr(attrs, semconv.AttrMessageBody, m.Body.Content)

	sev := telemetry.SeverityInfo
	if m.IsMajorChange {
		sev = telemetry.SeverityWarn
	}

	return telemetry.Event{
		Name:     eventMessage,
		Body:     fmt.Sprintf("%s [%s]: %s", m.ID, m.Category, m.Title),
		Severity: sev,
		Attrs:    attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return New(d.Graph, d.Logger)
	})
}

var (
	_ collector.SnapshotCollector = (*Collector)(nil)
	_ collectors.Experimental     = (*Collector)(nil)
)
