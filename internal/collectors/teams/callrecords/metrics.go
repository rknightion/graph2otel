package callrecords

import (
	"maps"
	"math"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	metricCalls       = "teams.calls"
	metricTransitions = "teams.call.health_transitions"
	metricSkipped     = "teams.call.metrics_skipped"
	metricStreams     = "teams.streams"
	metricRTT         = "teams.stream.rtt"
	metricJitter      = "teams.stream.jitter"
	metricLoss        = "teams.stream.packet_loss"
	metricTransport   = "teams.stream.transport"
	metricFeedback    = "teams.stream.feedback"
	metricFailures    = "teams.call.failures"
	metricVersions    = "teams.client_versions"

	maxMetricCalls = 250_000
)

var (
	latencyBounds = []float64{0.001, 0.003, 0.01, 0.02, 0.03, 0.05, 0.1, 0.2, 0.5, 1, 2, 5}
	lossBounds    = []float64{0, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1}
)

func maintainMetrics(cp *checkpoint.Checkpoint, floor time.Time) {
	state := cp.TeamsCallMetrics
	if state == nil {
		state = &checkpoint.TeamsCallMetrics{}
		cp.TeamsCallMetrics = state
	}
	if state.Calls == nil {
		state.Calls = make(map[string]checkpoint.TeamsCallMetricState)
	}
	if state.Sites == nil {
		state.Sites = make(map[string]bool)
	}
	if floor.After(state.Floor) {
		state.Floor = floor
		maps.DeleteFunc(state.Calls, func(_ string, call checkpoint.TeamsCallMetricState) bool {
			return call.Start.Before(floor)
		})
	}
}

// stageMetrics runs for a newly hydrated log key. Only the first complete
// version contributes observations, and only an increasing version can change
// its tracked health. The returned batch is released after the atomic save.
func (c *Collector) stageMetrics(cp *checkpoint.Checkpoint, e telemetry.Emitter, call Call, observedAt time.Time) func() {
	state := cp.TeamsCallMetrics
	if call.Start.Before(state.Floor) || call.Start.After(observedAt) {
		return nil
	}
	// Direct ingestion carries no version hint. Do not replace a known
	// higher pending version with metrics from a stale detail response.
	for _, pending := range cp.DeferredRecords {
		if pending.ID == call.ID && pending.Version > call.Version {
			return nil
		}
	}
	prev, seen := state.Calls[call.ID]
	if seen && call.Version <= prev.Version {
		return nil
	}
	var batch metricBatch
	switch {
	case seen && !call.Start.Equal(prev.Start):
		batch.skip("source_time_changed")
	case !seen && len(state.Calls) >= maxMetricCalls:
		// Never evict an active ID to make room: its next version would
		// silently increment totals again. Keep delivering raw logs.
		batch.skip("capacity")
	default:
		next := checkpoint.TeamsCallMetricState{Start: call.Start, Version: call.Version, Health: prev.Health}
		if call.End.IsZero() || call.End.Before(call.Start) || call.End.After(observedAt) {
			// Remember the version even when its log is usable but it is not
			// a complete call. A stale read must not supply its missing end.
			state.Calls[call.ID] = next
			return nil
		}
		next.Health = string(call.quality.health)
		state.Calls[call.ID] = next
		if prev.Health == "" {
			batch = firstMetrics(e, state, call)
			end, buckets := call.End, clientBuckets(e, call.clients)
			return func() {
				batch.emit(e)
				c.versions.add(end, observedAt, buckets)
			}
		}
		switch health(prev.Health) {
		case good, poor, unclassified:
			if next.Health != prev.Health {
				batch.counter(metricTransitions, "{transition}", "Health changes between successive accepted versions of an already counted Teams call.", telemetry.Attrs{
					semconv.AttrTeamsFromHealth: prev.Health, semconv.AttrTeamsToHealth: next.Health,
				})
			}
		}
	}
	if len(batch) == 0 {
		return nil
	}
	return func() { batch.emit(e) }
}

// A deferred batch holds only projected numbers and labels, never hydrated
// records, participant IDs or raw wire text, while the window keeps draining.
type metricBatch []func(telemetry.Emitter)

func (b metricBatch) emit(e telemetry.Emitter) {
	for _, record := range b {
		record(e)
	}
}

func (b *metricBatch) counter(name, unit, desc string, attrs telemetry.Attrs) {
	*b = append(*b, func(e telemetry.Emitter) { e.Counter(name, unit, desc, 1, attrs) })
}

func (b *metricBatch) histogram(name, unit, desc string, value *float64, scale, maxValue float64, bounds []float64, attrs telemetry.Attrs) {
	if value == nil || math.IsNaN(*value) || *value < 0 || *value > maxValue {
		return
	}
	sample := *value * scale
	*b = append(*b, func(e telemetry.Emitter) { e.Histogram(name, unit, desc, sample, bounds, attrs) })
}

func (b *metricBatch) skip(reason string) {
	b.counter(metricSkipped, "{call}", "Completed Teams call versions omitted from call metrics despite log delivery.", telemetry.Attrs{semconv.AttrTeamsReasonBucket: reason})
}

func firstMetrics(e telemetry.Emitter, state *checkpoint.TeamsCallMetrics, call Call) metricBatch {
	var batch metricBatch
	batch.counter(metricCalls, "{call}", "Teams calls by health and modalities in their first accepted complete version.", call.callDimensions(e))
	seenFeedback := make(map[feedbackKey]bool)
	for _, s := range call.Streams {
		if s.Start.IsZero() { // same source-time rule as the stream log
			continue
		}
		media := mediaLabels.watch(e, "media.label", s.MediaLabel)
		direction := directions.watch(e, "streamDirection", s.Direction)
		var sender Side
		switch direction {
		case "caller_to_callee":
			sender = s.Caller
		case "callee_to_caller":
			sender = s.Callee
		}
		transport := transports.watch(e, "networkTransportProtocol", sender.Network.Transport)
		connection := connections.watch(e, "connectionType", sender.Network.ConnectionType)
		site := metricSite(state, sender.Site.Name)
		attrs := telemetry.Attrs{
			semconv.AttrMedia: media, semconv.AttrDirection: direction,
			semconv.AttrTeamsSite: site, semconv.AttrTeamsConnectionType: connection,
		}
		streamAttrs := maps.Clone(attrs)
		streamAttrs[semconv.AttrStreamHealth] = string(s.quality.health)
		streamAttrs[semconv.AttrStreamHealthCause] = first(string(s.quality.cause), "none")
		streamAttrs[semconv.AttrTeamsTransport] = transport
		streamAttrs[semconv.AttrPlatform] = platforms.watch(e, "platform", sender.Agent.Platform)
		batch.counter(metricStreams, "{stream}", "Dated directional Teams media streams from first accepted call versions.", streamAttrs)

		m := s.Metrics
		loss := m.AverageLoss
		if loss == nil && media == "video" {
			loss = m.VideoPacketLoss
		}
		batch.histogram(metricRTT, semconv.UnitSeconds, "Distribution of observed Teams stream average round-trip time.", m.AverageRTTMs, 0.001, math.MaxFloat64, latencyBounds, attrs)
		batch.histogram(metricJitter, semconv.UnitSeconds, "Distribution of observed Teams stream average jitter.", m.AverageJitterMs, 0.001, math.MaxFloat64, latencyBounds, attrs)
		batch.histogram(metricLoss, semconv.UnitDimensionless, "Distribution of observed Teams stream average packet loss fractions.", loss, 1, 1, lossBounds, attrs)
		if media == "audio" && (transport == "tcp" || transport == "udp") {
			batch.counter(metricTransport, "{stream}", "Dated Teams audio streams with observed sender TCP or UDP, for site transport share.", telemetry.Attrs{
				semconv.AttrTeamsSite: site, semconv.AttrTeamsTransport: transport,
			})
		}
		batch.feedback(e, seenFeedback, s.SessionID, media, true, s.Caller.Feedback)
		batch.feedback(e, seenFeedback, s.SessionID, media, false, s.Callee.Feedback)
	}
	batch.failures(e, call.failures)
	return batch
}

type feedbackKey struct {
	session, media string
	caller         bool
}

func (b *metricBatch) feedback(e telemetry.Emitter, seen map[feedbackKey]bool, session, media string, caller bool, f *Feedback) {
	if f == nil || f.Rating == "" || session == "" {
		return
	}
	rating := ratings.watch(e, "rating", f.Rating)
	if rating == "notrated" {
		return
	}
	key := feedbackKey{session, media, caller}
	if !seen[key] {
		seen[key] = true
		b.counter(metricFeedback, "{rating}", "Teams endpoint feedback once per session side and media in a first accepted call version.", telemetry.Attrs{
			semconv.AttrMedia: media, semconv.AttrTeamsRating: rating,
		})
	}
}

func (b *metricBatch) failures(e telemetry.Emitter, failures []Failure) {
	seen := make(map[[2]string]bool)
	for _, failure := range failures {
		if failure.Stage == "" && failure.Reason == "" {
			continue
		}
		stage := failureStages.watch(e, "failureInfo.stage", failure.Stage)
		// Graph supplies free text, not a code. Do not infer root cause.
		reason := "unspecified"
		if failure.Reason != "" {
			reason = other
		}
		key := [2]string{stage, reason}
		if !seen[key] {
			seen[key] = true
			b.counter(metricFailures, "{call}", "Teams calls with session or segment failure evidence, once per stage and reason bucket.", telemetry.Attrs{
				semconv.AttrTeamsFailureStage: stage, semconv.AttrTeamsReasonBucket: reason,
			})
		}
	}
}
