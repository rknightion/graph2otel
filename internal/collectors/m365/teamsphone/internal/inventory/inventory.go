// Package inventory shares the snapshot declarations and decoding used by the
// two Teams Phone collectors.
package inventory

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
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
		if err := json.Unmarshal(raw, &rows[i]); err != nil {
			outcomes.Add(recordoutcome.OutcomeErrored, uint64(len(raws)))
			outcomes.Cause(recordoutcome.CauseDecodeError)
			return nil, fmt.Errorf("decode Teams Phone inventory row %d: %w", i, err)
		}
	}
	return rows, nil
}

// RecordTwins accounts for one mapped and emitted log twin per completed row.
func RecordTwins(outcomes *recordoutcome.Recorder, n uint64) {
	outcomes.Add(recordoutcome.OutcomeMapped, n)
	outcomes.Add(recordoutcome.OutcomeEmitted, n)
}
