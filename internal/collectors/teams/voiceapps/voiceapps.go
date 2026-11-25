// Package voiceapps tails Teams AA/CQ call analytics over the opt-in VAAC
// user transport. The interval and lag match the reference Teams
// observability agent's 5-minute collection cycle and 15-minute processing
// delay. They, the overlap and the row cap are not live timing or quota
// measurements. See the collector reference.
package voiceapps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/vaacclient"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	name     = "teams.voice_apps"
	aaEvent  = "teams.auto_attendant_call"
	cqEvent  = "teams.call_queue_call"
	interval = 5 * time.Minute
	lag      = 15 * time.Minute
	// Each poll rescans this much behind the watermark, so legs VAAC
	// publishes later than the lag are still read; SeenIDs drops repeats.
	overlap   = 6 * time.Hour
	maxWindow = time.Hour
)

type voiceApps struct {
	client   *vaacclient.Client
	store    *checkpoint.Store
	tenantID string
	watch    *wirecheck.Reporter
}

func (*voiceApps) Name() string                         { return name }
func (*voiceApps) DefaultInterval() time.Duration       { return interval }
func (*voiceApps) Lag() time.Duration                   { return lag }
func (*voiceApps) Profiles() collector.ProfileSet       { return collector.ProfileTeams }
func (*voiceApps) IngestTransport() telemetry.Transport { return telemetry.TransportVAAC }
func (*voiceApps) RequiredPermissions() []string        { return nil }

func factory(d collectors.WindowDeps) collectors.RegisteredWindow {
	// The definition exists even without a transport so all three inventory
	// consumers can see it. Runtime selection requires explicit VAAC opt-in.
	return collectors.RegisteredWindow{
		Collector:       &voiceApps{client: d.VAAC, store: d.Store, tenantID: d.TenantID, watch: wirecheck.New(name, d.Logger)},
		InitialLookback: time.Hour, MaxWindow: maxWindow,
	}
}

func init() { collectors.RegisterWindow(factory) }

func (c *voiceApps) CheckpointState() *collector.CheckpointState {
	if c.store == nil {
		return nil
	}
	cp, err := c.store.Load(c.tenantID, name)
	if err != nil {
		return nil
	}
	return &collector.CheckpointState{Kind: collector.CheckpointKindWindow, Watermark: cp.Watermark, SeenIDs: len(cp.SeenIDs)}
}

func (c *voiceApps) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
	if c.client == nil || c.store == nil {
		return time.Time{}, errors.New("VAAC transport is not configured")
	}
	if from.IsZero() || to.Before(from) || to.Sub(from) > maxWindow {
		return time.Time{}, errors.New("VAAC collector window is out of bounds")
	}
	cp, err := c.store.Load(c.tenantID, name)
	if err != nil {
		return time.Time{}, fmt.Errorf("load VAAC checkpoint: %w", err)
	}
	// The source uses whole-second filter values. Resume at the inclusive
	// boundary, including any calls at that instant that arrived since the
	// previous read. SeenIDs covers the shared boundary across restarts.
	lo, hi := from.Truncate(time.Second), to.Truncate(time.Second)
	if cp.VAACScan != nil {
		lo, hi = cp.VAACScan.Through, cp.VAACScan.Target
	} else if !cp.Watermark.IsZero() {
		if !hi.After(cp.Watermark) {
			return cp.Watermark, nil // the scheduler may not have saved its own copy
		}
		lo = cp.Watermark.Add(-overlap)
		if limit := cp.Watermark.Add(maxWindow); hi.After(limit) {
			hi = limit
		}
	}

	batch, readErr := c.readPrefix(ctx, lo, hi)
	if readErr != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		if !batch.through.After(lo) {
			return time.Time{}, readErr
		}
	}
	// Publish only what both streams drained. Hold the scheduler watermark and
	// the dedupe horizon until the pinned overlap sweep reaches its end.
	e = telemetry.WithTransport(e, telemetry.TransportVAAC)
	queues := make(map[string]queueCounts)
	c.emitRows(e, outcomes, cp, aaEvent, batch.aa, lo, batch.through, queues)
	c.emitRows(e, outcomes, cp, cqEvent, batch.cq, lo, batch.through, queues)
	if batch.through.Equal(hi) {
		cp.VAACScan = nil
		cp.Watermark, cp.OverlapWindow = hi, overlap
		cp.EvictStale()
	} else {
		cp.VAACScan = &checkpoint.VAACScan{Through: batch.through, Target: hi}
	}
	if err := c.store.Save(cp); err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return time.Time{}, fmt.Errorf("save VAAC checkpoint: %w", err)
	}
	c.emitQueueRates(e, time.Now().UTC(), queues)
	if readErr != nil {
		// A successful CollectWindow (even with a partial watermark) can clear
		// the scheduler's cold-start target. Report the incomplete read until
		// the entire sweep is durable.
		return time.Time{}, readErr
	}
	return hi, nil
}

type prefix struct {
	aa, cq  []vaacclient.Row
	through time.Time
}

func (c *voiceApps) readPrefix(ctx context.Context, lo, hi time.Time) (prefix, error) {
	aa, aaEnd, aaErr := c.client.FetchPrefix(ctx, vaacclient.AutoAttendant, lo, hi)
	if aaErr != nil {
		aaErr = fmt.Errorf("read auto attendant analytics: %w", aaErr)
		if !aaEnd.After(lo) {
			return prefix{}, aaErr
		}
	}
	cq, through, cqErr := c.client.FetchPrefix(ctx, vaacclient.CallQueue, lo, aaEnd)
	if cqErr != nil {
		cqErr = fmt.Errorf("read call queue analytics: %w", cqErr)
	}
	return prefix{aa: aa, cq: cq, through: through}, errors.Join(aaErr, cqErr)
}

func (c *voiceApps) emitRows(e telemetry.Emitter, outcomes *recordoutcome.Recorder, cp *checkpoint.Checkpoint,
	event string, rows []vaacclient.Row, lo, hi time.Time, queues map[string]queueCounts,
) {
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
	for _, row := range rows {
		ts := eventTime(text(row, "EndTime"))
		if ts.IsZero() {
			outcomes.Add(recordoutcome.OutcomeDropped, 1)
			outcomes.Cause(recordoutcome.CauseMissingEventTime)
			continue
		}
		if ts.Before(lo) || ts.After(hi) {
			outcomes.Add(recordoutcome.OutcomeFiltered, 1)
			continue
		}
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		id := dedupeKey(event, row)
		if id != "" && cp.SeenIDs.Has(id) {
			outcomes.Add(recordoutcome.OutcomeDeduped, 1)
			continue
		}
		attrs := logAttrs(event, row)
		// Loki can collapse equal timestamps and bodies before comparing
		// metadata. Scope the discriminator by tenant without printing IDs.
		var bodyKey any = id
		if id == "" {
			bodyKey = row // preserve differences even in non-keyable wire values
		}
		e.LogEvent(telemetry.Event{Name: event, Body: c.eventBody(event, bodyKey), Timestamp: ts, Severity: telemetry.SeverityInfo, Attrs: attrs})
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
		if id == "" {
			c.watch.MissingField(e, "voice_call_dedupe_key")
			continue // still keep the twin; overlap duplicates must not inflate metrics
		}
		cp.SeenIDs.Add(id, ts)
		c.recordMetrics(e, event, row, queues)
	}
}

func eventTime(value string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC()
	}
	// The report template reads date/time values as UTC; the source's
	// ISO-shaped values can omit the suffix in the reference parser.
	if t, err := time.Parse("2006-01-02T15:04:05", value); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func text(r vaacclient.Row, key string) string {
	v, _ := r[key].(string)
	return v
}

func dedupeKey(event string, r vaacclient.Row) string {
	var parts []any
	if event == aaEvent {
		if text(r, "ConferenceId") == "" || text(r, "AutoAttendantId") == "" || r["AutoAttendantChainIndex"] == nil {
			return ""
		}
		parts = []any{event, r["ConferenceId"], r["AutoAttendantId"], r["AutoAttendantChainIndex"]}
	} else {
		if text(r, "DialogId") == "" || text(r, "CallQueueId") == "" {
			return ""
		}
		parts = []any{event, r["DialogId"], r["CallQueueId"]}
	}
	// Keep the checkpoint key format stable across upgrades.
	return digest(parts)
}

func (c *voiceApps) eventBody(event string, key any) string {
	return event + " (" + digest([]any{c.tenantID, event, key}) + ")"
}

func digest(key any) string {
	data, _ := json.Marshal(key) // callers pass JSON-decoded values and strings
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

var commonAttrs = map[string]string{
	"ConferenceId": semconv.AttrConferenceId, "Duration": semconv.AttrCallDuration,
	"EndTime": semconv.AttrEndDateTime, "FirstIsCaller": semconv.AttrFirstIsCaller,
	"FirstUPN": semconv.AttrFirstUPN, "PSTNCallType": semconv.AttrPSTNCallType,
	"PSTNConnectivityType": semconv.AttrPSTNConnectivityType, "PSTNCallDuration": semconv.AttrPSTNCallDuration,
	"Timestamp": semconv.AttrRecordTimestamp, "UserStartTimeUTC": semconv.AttrStartDateTime,
	"TotalCallCount": semconv.AttrCallCount,
}

var aaAttrs = map[string]string{
	"AutoAttendantId": semconv.AttrAutoAttendant, "AutoAttendantIdentity": semconv.AttrAutoAttendantIdentity,
	"AutoAttendantCallFlow": semconv.AttrAutoAttendantCallFlow, "AutoAttendantCallResult": semconv.AttrResult,
	"AutoAttendantCallerActionCounts":  semconv.AttrAutoAttendantCallerActionCounts,
	"AutoAttendantChainDurationInSecs": semconv.AttrAutoAttendantChainDurationSeconds,
	"AutoAttendantChainIndex":          semconv.AttrAutoAttendantChainIndex, "AutoAttendantChainStartTime": semconv.AttrAutoAttendantChainStartTime,
	"AutoAttendantCount": semconv.AttrAutoAttendantCount, "AutoAttendantDirectorySearchMethod": semconv.AttrAutoAttendantDirectorySearchMethod,
	"AutoAttendantTransferAction":          semconv.AttrAutoAttendantTransferAction,
	"AvgAutoAttendantChainDurationSeconds": semconv.AttrAverageAutoAttendantChainDurationSeconds,
	"AvgCallDuration":                      semconv.AttrAverageCallDuration, "TotalAudioStreamDuration": semconv.AttrTotalAudioStreamDuration,
}

var cqAttrs = map[string]string{
	"CallQueueId": semconv.AttrQueue, "CallQueueIdentity": semconv.AttrCallQueueIdentity,
	"DialogId": semconv.AttrDialogId, "SecondUPN": semconv.AttrSecondUPN,
	"CallQueueDurationSeconds": semconv.AttrCallQueueDurationSeconds, "CallQueueCallResult": semconv.AttrResult,
	"CallQueueAgentCount": semconv.AttrCallQueueAgentCount, "CallQueueAgentOptInCount": semconv.AttrCallQueueAgentOptInCount,
	"CallQueueFinalStateAction": semconv.AttrCallQueueFinalStateAction, "CallQueueTargetType": semconv.AttrCallQueueTargetType,
}

func logAttrs(event string, row vaacclient.Row) telemetry.Attrs {
	attrs := make(telemetry.Attrs)
	specific := aaAttrs
	if event == cqEvent {
		specific = cqAttrs
	}
	for _, fields := range []map[string]string{commonAttrs, specific} {
		for field, attr := range fields {
			switch v := row[field].(type) {
			case string:
				if v != "" {
					attrs[attr] = v
				}
			case bool:
				if attr != semconv.AttrQueue && attr != semconv.AttrDialogId {
					attrs[attr] = v
				}
			case json.Number:
				if attr == semconv.AttrQueue || attr == semconv.AttrDialogId {
					continue // CQ key fields must stay strings all the way into Loki
				}
				if n, err := v.Int64(); err == nil {
					attrs[attr] = n
				} else if n, err := v.Float64(); err == nil {
					attrs[attr] = n
				}
			}
		}
	}
	if event == cqEvent {
		// The Microsoft AgentTimeline template selects the nonempty first UPN
		// when FirstIsCaller is true, otherwise the second, with a first fallback
		// if the second is absent. A missing discriminator is not false.
		if firstIsCaller, ok := row["FirstIsCaller"].(bool); ok {
			first, second := text(row, "FirstUPN"), text(row, "SecondUPN")
			agent := second
			if second == "" || (firstIsCaller && first != "") {
				agent = first
			}
			if agent != "" {
				attrs[semconv.AttrAgentName] = agent
			}
		}
	}
	return attrs
}
