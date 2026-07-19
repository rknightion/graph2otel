// Package discoveryparse polls the Microsoft Defender for Cloud Apps (MDCA)
// Cloud Discovery governance log and emits the parse-health signal nothing else
// on this tenant can see (#145).
//
// # The gap this closes
//
// A Cloud Discovery upload (upload_url -> PUT blob -> done_upload) returns
// 200 {"success":true} the moment the blob lands and a parse task is QUEUED.
// The parse then runs asynchronously and writes its verdict ONLY to the
// governance log, as a DiscoveryParseLogTask record. So every uploader is
// structurally blind to whether its data actually parsed — on m7kni (2026-07-17)
// a malformed CEF line produced 22 consecutive silent parse failures while every
// hourly upload reported green, and zero transactions landed. This collector is
// the missing poll: it emits one log twin per task plus bounded parse-health
// gauges, so both "parses are failing" and "uploads have stopped" become
// alertable.
//
// # Why a self-contained WindowCollector (no engine)
//
// The governance log is a single POST endpoint with a timestamp and a stable id
// — the WindowCollector contract exactly — so unlike the multi-step
// subscribe/list/fetch Management Activity API (o365pipeline) it needs no engine.
// It manages its own checkpoint (watermark + seen-ids + parse-health) directly,
// the way the blob SnapshotCollectors manage a BlobCursor, and stamps its
// transport inline because there is no engine to do it.
//
// # The two traps this collector is built around (both live-measured #145)
//
//   - A task's status MUTATES after creation: it is queued (no status) at
//     `timestamp`, then a verdict is written ~seconds-to-minutes later at
//     `updateTimestamp` (observed up to ~16 min). A naive dedupe on `_id` alone
//     ships only the queued record and PERMANENTLY hides every verdict. So the
//     dedupe key is `_id + updateTimestamp`, and the overlap window is sized
//     past the parse latency so the settled record is re-read.
//   - Server-side filtering is a trap: only `timestamp gte` works; `taskName`
//     and `status` filters SILENTLY return an empty set (not an error), which is
//     indistinguishable from a healthy-but-quiet tenant. So taskName is filtered
//     CLIENT-SIDE (see TestFiltersTaskNameClientSide).
package discoveryparse

import (
	"context"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/mdcaclient"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	// collectorName is the stable collector key / config key.
	collectorName = "mdca.discovery_parse"
	// eventName is the OTLP LogRecord EventName every task record carries.
	eventName = "mdca.discovery_parse"
	// checkpointKey namespaces this collector's cursor. The '#' segment keeps it
	// distinct from any Graph endpoint sharing the path prefix.
	checkpointKey = "/api/v1/governance#mdca.discovery_parse"

	// taskNameFilter is the only governance record type this collector maps. It
	// is applied CLIENT-SIDE: a server-side taskName filter returns an empty set
	// silently (#145).
	taskNameFilter = "DiscoveryParseLogTask"
	// successTemplate is the one templateMessage.template value that means a clean
	// parse. Every other terminal template is a failure of some kind.
	successTemplate = "REPOOPER_COMPLETION_STATUS_BASELOGPARSER_PARSED_LOG_FILE_ALL_RELEVANT"
)

// Schedule tuning. The governance log lists a verdict ~seconds-to-minutes after
// the event, so the cadence is set by usefulness, not throttling (the 30/min
// quota is spent by the client's own paging, gated by mdcaclient.Limiter).
const (
	interval        = 10 * time.Minute
	lag             = 5 * time.Minute
	initialLookback = 4 * time.Hour
	// maxWindow bounds a single tick's catch-up after an outage. The API has no
	// documented hard window cap; 24h keeps one tick to a bounded page walk.
	maxWindow = 24 * time.Hour
	// overlapWindow is how far behind the watermark each tick re-reads, so a task
	// whose status settled after the watermark passed its `timestamp` is re-read
	// and its verdict emitted. Sized past the ~16 min max parse latency observed
	// live (#145), with margin.
	overlapWindow = 30 * time.Minute
)

// Metric names (mdca.* DOMAIN namespace). All bounded to input_stream_id ×
// template — streams are single-digit per tenant and templates a small closed
// enum, so cardinality is bounded by tenant shape, not tenant size (#112).
const (
	// metricLastSuccessAge is THE alert-on-silence signal: seconds since a stream
	// last parsed successfully, emitted every tick from persistent state so it
	// keeps climbing when uploads STOP (a dead uploader emits no failed tasks, so
	// a failure counter cannot see this). Named without a `_seconds` suffix: the
	// unit is UnitSeconds and OTLP→Prometheus normalization appends `_seconds`, so
	// the Prom series is mdca_discovery_parse_last_success_age_seconds (matching
	// graph2otel.scrape.staleness → graph2otel_scrape_staleness_seconds).
	metricLastSuccessAge = "mdca.discovery.parse.last_success.age"
	// metricTransactions / metricCloudServices are the last successful parse's
	// discovered counts per stream. A collapse to zero is the "parsed fine,
	// discovered nothing" case.
	metricTransactions  = "mdca.discovery.parse.transactions"
	metricCloudServices = "mdca.discovery.parse.cloud_services"
	// metricTasks counts terminal parse tasks by outcome. A Counter (not the
	// issue's suggested GaugeSnapshot) because "any failure in the last hour"
	// needs increase(), and its labels (input_stream_id × template × is_success)
	// are a bounded closed set with no per-entity churn — the churn GaugeSnapshot
	// guards against does not apply here.
	metricTasks = "mdca.discovery.parse.tasks"
)

// Collector is the MDCA Cloud Discovery governance-log WindowCollector.
type Collector struct {
	client   *mdcaclient.Client
	store    *checkpoint.Store
	tenantID string
	// now is the clock, injectable for tests (the age gauge is now-relative).
	now func() time.Time
}

// New builds the collector for one tenant.
func New(d collectors.MDCADeps) *Collector {
	return &Collector{
		client:   d.Client,
		store:    d.Store,
		tenantID: d.TenantID,
		now:      time.Now,
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return collectorName }

// DefaultInterval implements collector.Collector.
func (c *Collector) DefaultInterval() time.Duration { return interval }

// Lag implements collector.WindowCollector.
func (c *Collector) Lag() time.Duration { return lag }

// Experimental marks this collector opt-in: the MDCA portal API is a legacy
// surface with no Graph successor and a real deprecation risk, so setting the
// tenant's mdca block is the honest opt-in.
func (c *Collector) Experimental() bool { return true }

// IngestTransport reports the transport this collector ingests over (#141/#178).
// It has no engine, so CollectWindow stamps this same value inline — the two
// agree by construction.
func (c *Collector) IngestTransport() telemetry.Transport { return telemetry.TransportMDCA }

// RequiredPermissions is empty: the MDCA portal API authenticates with a static
// token, not an Entra app role, so there is no Graph scope to declare. The auth
// path is documented in docs/permissions.md.
func (c *Collector) RequiredPermissions() []string { return nil }

// CheckpointState reports this collector's durable progress for the admin status
// page (#178 Part B): its governance-log watermark and overlap-dedupe set size,
// read read-only from the same checkpoint each tick persists. A read failure
// returns nil rather than erroring the page — the failure already surfaces as
// the collector's own run error, since CollectWindow loads the same file. Unlike
// the engine collectors this collector owns its checkpoint directly (it is a
// self-contained WindowCollector, no engine), so it implements this itself.
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

// taskMeta is the parsed, mapped facts about one governance record, shared
// between the log twin and the metrics.
type taskMeta struct {
	streamID           string
	template           string
	terminal           bool // has a status (queued records do not)
	success            bool
	transactionsCount  int64
	cloudServicesCount int64
	eventTime          time.Time // updateTimestamp — when this state was recorded
	createdTime        time.Time // timestamp — immutable, drives watermark/dedupe
	updateMillis       int64     // updateTimestamp, for the dedupe key
	id                 string
}

// CollectWindow implements collector.WindowCollector. It stamps its transport
// inline (no engine), fetches the governance window, maps + dedupes each task,
// and emits the per-stream parse-health gauges from persistent state every tick.
func (c *Collector) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter) (time.Time, error) {
	e = telemetry.WithTransport(e, telemetry.TransportMDCA)

	cp, err := c.store.Load(c.tenantID, checkpointKey)
	if err != nil {
		return time.Time{}, err //nolint:wrapcheck // the store's error is already specific
	}
	if cp.ParseHealth == nil {
		cp.ParseHealth = &checkpoint.ParseHealth{}
	}
	if cp.ParseHealth.Streams == nil {
		cp.ParseHealth.Streams = map[string]checkpoint.StreamHealth{}
	}
	cp.OverlapWindow = overlapWindow

	// Effective start: cold start honors the scheduler's cold-start `from`; a warm
	// tick re-reads from watermark-overlap so a late-settling verdict is caught.
	since := from
	if !cp.Watermark.IsZero() {
		since = cp.Watermark.Add(-overlapWindow)
	}

	page, err := c.client.Governance(ctx, mdcaclient.GovernanceQuery{SinceMillis: since.UnixMilli()})
	if err != nil {
		return time.Time{}, err //nolint:wrapcheck // mdcaclient's error is already specific
	}

	hwm := cp.Watermark
	for _, rec := range page.Records {
		// CLIENT-SIDE taskName filter — a server-side one returns empty silently.
		if str(rec, "taskName") != taskNameFilter {
			continue
		}
		m, ok := parseTask(rec)
		if !ok {
			continue // no usable timestamp: drop rather than mis-date (#135)
		}
		dedupeKey := m.id + ":" + strconv.FormatInt(m.updateMillis, 10)
		if cp.SeenIDs.Has(dedupeKey) {
			continue
		}
		cp.SeenIDs.Add(dedupeKey, m.createdTime)

		e.LogEvent(logTwin(m))

		if m.terminal {
			e.Counter(metricTasks, semconv.UnitDimensionless,
				"Count of terminal MDCA Cloud Discovery parse tasks, by stream, template and outcome.",
				1, telemetry.Attrs{
					semconv.AttrInputStreamId: m.streamID,
					semconv.AttrTemplate:      m.template,
					semconv.AttrIsSuccess:     strconv.FormatBool(m.success),
				})
			if m.success {
				cp.ParseHealth.Streams[m.streamID] = checkpoint.StreamHealth{
					LastSuccess:       m.eventTime,
					LastTransactions:  m.transactionsCount,
					LastCloudServices: m.cloudServicesCount,
				}
			}
		}
		if m.createdTime.After(hwm) {
			hwm = m.createdTime
		}
	}

	cp.Watermark = hwm
	cp.EvictStale()
	if err := c.store.Save(cp); err != nil {
		return time.Time{}, err //nolint:wrapcheck // the store's error is already specific
	}

	c.emitHealthGauges(e, cp.ParseHealth)
	return to, nil
}

// emitHealthGauges snapshots the per-stream parse-health metrics from persistent
// state, so they report every tick — including when a stream has gone silent,
// which is exactly when the age gauge matters most.
func (c *Collector) emitHealthGauges(e telemetry.Emitter, ph *checkpoint.ParseHealth) {
	now := c.now()
	age := make([]telemetry.GaugePoint, 0, len(ph.Streams))
	tx := make([]telemetry.GaugePoint, 0, len(ph.Streams))
	cs := make([]telemetry.GaugePoint, 0, len(ph.Streams))
	for streamID, sh := range ph.Streams {
		attrs := telemetry.Attrs{semconv.AttrInputStreamId: streamID}
		age = append(age, telemetry.GaugePoint{Value: now.Sub(sh.LastSuccess).Seconds(), Attrs: attrs})
		tx = append(tx, telemetry.GaugePoint{Value: float64(sh.LastTransactions), Attrs: attrs})
		cs = append(cs, telemetry.GaugePoint{Value: float64(sh.LastCloudServices), Attrs: attrs})
	}
	e.GaugeSnapshot(metricLastSuccessAge, semconv.UnitSeconds,
		"Seconds since a Cloud Discovery input stream last parsed successfully (alert-on-silence).", age)
	e.GaugeSnapshot(metricTransactions, semconv.UnitDimensionless,
		"Transactions discovered in a Cloud Discovery input stream's last successful parse.", tx)
	e.GaugeSnapshot(metricCloudServices, semconv.UnitDimensionless,
		"Distinct cloud apps discovered in a Cloud Discovery input stream's last successful parse.", cs)
}

// logTwin renders one governance task as its per-entity log event. A queued
// (pending) task carries state=pending, Info severity and NO is_success — it is
// explicitly NOT a failure. A terminal task carries is_success + Error severity
// on failure.
func logTwin(m taskMeta) telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, m.id)
	telemetry.SetStr(attrs, semconv.AttrInputStreamId, m.streamID)
	telemetry.SetStr(attrs, semconv.AttrTemplate, m.template)

	sev := telemetry.SeverityInfo
	var body string
	if m.terminal {
		attrs[semconv.AttrState] = "completed"
		attrs[semconv.AttrIsSuccess] = m.success
		if m.success {
			attrs[semconv.AttrTransactionsCount] = strconv.FormatInt(m.transactionsCount, 10)
			attrs[semconv.AttrCloudServicesCount] = strconv.FormatInt(m.cloudServicesCount, 10)
			body = "Cloud Discovery parse succeeded"
		} else {
			sev = telemetry.SeverityError
			body = "Cloud Discovery parse FAILED"
		}
	} else {
		attrs[semconv.AttrState] = "pending"
		body = "Cloud Discovery parse queued"
	}

	return telemetry.Event{
		Name:      eventName,
		Body:      body,
		Severity:  sev,
		Timestamp: m.eventTime,
		Attrs:     attrs,
	}
}

// parseTask decodes the fields this collector needs from a raw governance
// record. ok=false drops the record, for exactly one reason: no usable event
// time — a record with no updateTimestamp/timestamp cannot be dated, and a
// zero Timestamp means "now" to telemetry.Event, so emitting it would silently
// misdate it (#135). Every real record carries both, so this is a
// should-never-happen guard.
func parseTask(rec map[string]any) (taskMeta, bool) {
	created := millisToTime(rec["timestamp"])
	updateMillis, _ := numOf(rec["updateTimestamp"])
	eventTime := millisToTime(rec["updateTimestamp"])
	if eventTime.IsZero() {
		eventTime = created
	}
	if eventTime.IsZero() {
		return taskMeta{}, false
	}
	if created.IsZero() {
		created = eventTime
	}

	m := taskMeta{
		id:           str(rec, "_id"),
		streamID:     str(rec, "inputStreamId"),
		eventTime:    eventTime,
		createdTime:  created,
		updateMillis: updateMillis,
	}

	// status is absent while the task is queued — a real third "pending" state,
	// NOT a failure.
	status, hasStatus := rec["status"].(map[string]any)
	if !hasStatus {
		return m, true
	}
	m.terminal = true
	m.success, _ = status["isSuccess"].(bool)
	if tmpl, ok := status["templateMessage"].(map[string]any); ok {
		m.template = str(tmpl, "template")
		if params, ok := tmpl["parameters"].(map[string]any); ok {
			m.transactionsCount, _ = numOf(params["transactionsCount"])
			m.cloudServicesCount, _ = numOf(params["cloudServicesCount"])
		}
	}
	// A terminal task with no template but isSuccess:false is still a failure; the
	// success predicate is the template when present, else isSuccess.
	if m.template != "" {
		m.success = m.template == successTemplate
	}
	return m, true
}

// --- small defensive accessors for untyped JSON ---

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// numOf coerces a JSON number to int64. encoding/json decodes every JSON number
// into map[string]any as float64, so that is the case that actually happens; the
// rest are defense against Microsoft's field types not being stable.
func numOf(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

// millisToTime converts a JSON epoch-millis value to a UTC time, or zero if it
// is absent/unparsable.
func millisToTime(v any) time.Time {
	ms, ok := numOf(v)
	if !ok || ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func init() {
	collectors.RegisterMDCA(func(d collectors.MDCADeps) collectors.RegisteredWindow {
		return collectors.RegisteredWindow{
			Collector:       New(d),
			InitialLookback: initialLookback,
			MaxWindow:       maxWindow,
		}
	})
}

// Compile-time checks that the collector satisfies every interface the
// composition root type-asserts on.
var (
	_ collector.WindowCollector                          = (*Collector)(nil)
	_ collector.CheckpointReporter                       = (*Collector)(nil)
	_ interface{ Experimental() bool }                   = (*Collector)(nil)
	_ interface{ IngestTransport() telemetry.Transport } = (*Collector)(nil)
)
