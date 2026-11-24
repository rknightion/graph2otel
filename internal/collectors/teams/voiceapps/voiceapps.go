// Package voiceapps tails Teams AA/CQ call analytics over the opt-in VAAC
// user transport. The lag, overlap, and row cap are conservative bounds,
// not live timing or quota measurements. See the collector reference.
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
	name      = "teams.voice_apps"
	aaEvent   = "teams.auto_attendant_call"
	cqEvent   = "teams.call_queue_call"
	lag       = time.Hour
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
func (*voiceApps) DefaultInterval() time.Duration       { return 15 * time.Minute }
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
	// The source uses whole-second filter values. Persist that exact drained
	// boundary. The first read starts without a trailing overlap.
	lo, hi := from.Truncate(time.Second), to.Truncate(time.Second)
	if !cp.Watermark.IsZero() {
		lo = lo.Add(-overlap)
	}
	aa, err := c.client.Fetch(ctx, vaacclient.AutoAttendant, lo, hi)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return time.Time{}, fmt.Errorf("read auto attendant analytics: %w", err)
	}
	cq, err := c.client.Fetch(ctx, vaacclient.CallQueue, lo, hi)
	if err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return time.Time{}, fmt.Errorf("read call queue analytics: %w", err)
	}
	// Neither stream emits before both reads have drained. A cap, malformed
	// response or auth error leaves the retryable checkpoint untouched.
	e = telemetry.WithTransport(e, telemetry.TransportVAAC)
	queues := make(map[string]queueCounts)
	c.emitRows(e, outcomes, cp, aaEvent, aa, lo, hi, queues)
	c.emitRows(e, outcomes, cp, cqEvent, cq, lo, hi, queues)
	cp.Watermark, cp.OverlapWindow = hi, overlap
	cp.EvictStale()
	if err := c.store.Save(cp); err != nil {
		outcomes.Cause(recordoutcome.CauseSourceError)
		return time.Time{}, fmt.Errorf("save VAAC checkpoint: %w", err)
	}
	emitRates(e, queues)
	return hi, nil
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
		e.LogEvent(telemetry.Event{Name: event, Body: event, Timestamp: ts, Severity: telemetry.SeverityInfo, Attrs: attrs})
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
	// Store opaque digests, not call or account identifiers, on disk.
	data, _ := json.Marshal(parts) // parts contain decoded JSON values only
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
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
				attrs[attr] = v
			case json.Number:
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
