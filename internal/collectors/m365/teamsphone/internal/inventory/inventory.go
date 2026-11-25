// Package inventory shares the snapshot declarations and decoding used by the
// two Teams Phone collectors.
package inventory

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// GraphV1 is the stable API root for both inventory endpoints.
const GraphV1 = "https://graph.microsoft.com/v1.0"

// Snapshot holds the common declaration for both independently scoped polls.
type Snapshot struct {
	Graph       collectors.GraphClient
	name, scope string
	watch       *wirecheck.Reporter
}

// New builds the shared snapshot declarations for a single endpoint.
func New(g collectors.GraphClient, name, scope string, logger *slog.Logger) Snapshot {
	return Snapshot{Graph: g, name: name, scope: scope, watch: wirecheck.New(name, logger)}
}

// Name identifies the collector in config and preflight.
func (s Snapshot) Name() string { return s.name }

// Profiles opts the snapshot into both Graph and Teams.
func (Snapshot) Profiles() collector.ProfileSet {
	return collector.ProfileGraph | collector.ProfileTeams
}

// DefaultInterval limits how often unchanged inventory is read and emitted.
func (Snapshot) DefaultInterval() time.Duration { return time.Hour }

// RequiredPermissions returns the collector's single application read role.
func (s Snapshot) RequiredPermissions() []string { return []string{s.scope} }

// Bucket reports an unexpected value and keeps it out of metric labels.
func (s Snapshot) Bucket(e telemetry.Emitter, field, value string, allowed wirecheck.Enum) string {
	s.watch.Value(e, field, value, allowed)
	if !allowed.Has(value) {
		return "unknown"
	}
	return value
}

// DecodeRows validates the whole snapshot before publishing it. A broken row
// must not turn a population cut into a successful partial inventory.
func DecodeRows[T any](raws []json.RawMessage, outcomes *recordoutcome.Recorder) ([]T, error) {
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(raws)))
	rows := make([]T, len(raws))
	for i, raw := range raws {
		row := &rows[i]
		err := json.Unmarshal(raw, &row)
		if err == nil && row == nil {
			err = errors.New("null row")
		}
		if err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, uint64(len(raws)))
			outcomes.Cause(recordoutcome.CauseDecodeError)
			return nil, fmt.Errorf("decode Teams Phone inventory row %d: %w", i, err)
		}
	}
	return rows, nil
}

// CompletionEvent names a fully fetched and mapped inventory poll.
const CompletionEvent = "m365.teams.phone_inventory_snapshot"

// Poll identifies the twins and completion from one collection, not one entity.
type Poll struct {
	emitter telemetry.Emitter
	name    string
	id      string
	count   uint64
}

// BeginPoll creates a fixed-size identity after all pages and rows validate.
func (s Snapshot) BeginPoll(e telemetry.Emitter) *Poll {
	var id [16]byte
	_, _ = rand.Read(id[:]) // Always fills the buffer or terminates the process.
	return &Poll{emitter: e, name: s.name, id: hex.EncodeToString(id[:])}
}

// LogTwin stamps and emits a mapped row without changing its observation time.
func (p *Poll) LogTwin(ev telemetry.Event) {
	ev.Attrs[semconv.AttrInventorySnapshotID] = p.id
	p.emitter.LogEvent(ev)
	p.count++
}

// Complete emits one marker after the twins, even if there were none. It proves
// source-walk completion, not atomic delivery to Loki. Only twins count as rows.
func (p *Poll) Complete(outcomes *recordoutcome.Recorder) {
	p.emitter.LogEvent(telemetry.Event{
		Name: CompletionEvent, Body: "Teams Phone inventory poll complete", Severity: telemetry.SeverityInfo,
		Attrs: telemetry.Attrs{semconv.AttrCollector: p.name, semconv.AttrInventorySnapshotID: p.id,
			semconv.AttrInventoryEntityCount: strconv.FormatUint(p.count, 10)},
	})
	outcomes.Add(recordoutcome.OutcomeMapped, p.count)
	outcomes.Add(recordoutcome.OutcomeEmitted, p.count)
}
