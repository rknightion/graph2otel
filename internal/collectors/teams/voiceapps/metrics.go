package voiceapps

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/vaacclient"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	abandonRate = "teams.call_queue.abandon_rate"
	answerRate  = "teams.call_queue.answer_rate"
	waitTime    = "teams.call_queue.wait_time"
	aaOutcome   = "teams.auto_attendant.calls"
	answered    = "answered"
	abandoned   = "abandoned"
	other       = "other"
)

// Classification is docs-derived from the CallQueue and AutoAttendant report
// legends in Microsoft's VAAC template v3.3.2. The watchdog never logs raw
// values: the original values are available only in the structured twins.
var cqResults = map[string]string{
	"agent_joined_conference": answered, "transferred_to_agent": answered,
	"transferred_to_callback_caller": answered, "disconnected": abandoned,
	"overflown": other, "timed_out": other, "callback_call_timed_out": other, "no_agent": other,
}
var aaResults = map[string]string{
	"service_terminated": "terminated", "terminated_automatic_selection": "terminated",
	"terminated_no_operator": "terminated", "terminated_transfer_failed": "transfer_failed",
	"transfer_in_progress": "transferred", "transferred_to_aa": "transferred",
	"transferred_to_cq": "transferred", "transferred_to_receptionist": "transferred",
	"transferred_to_self": "transferred", "transferred_to_user": "transferred",
}
var cqEnum = wirecheck.NewEnum(slices.Collect(maps.Keys(cqResults))...)
var aaEnum = wirecheck.NewEnum(slices.Collect(maps.Keys(aaResults))...)
var waitBuckets = []float64{1, 5, 10, 20, 30, 60, 120, 300, 600}

type queueCounts struct{ total, answered, abandoned float64 }

func resourceID(s string) string {
	// Microsoft reports queue and AA GUIDs. Do not fall back to a display
	// value or UPN (which the service may send in the Identity dimension).
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != strings.ToLower(s) {
		return ""
	}
	return id.String()
}

func (c *voiceApps) recordMetrics(e telemetry.Emitter, event string, row vaacclient.Row, queues map[string]queueCounts) {
	if event == aaEvent {
		id := resourceID(text(row, "AutoAttendantId"))
		if id == "" {
			return
		}
		result := text(row, "AutoAttendantCallResult")
		outcome := aaResults[result]
		if outcome == "" {
			if result != "" {
				c.watch.Value(e, "AutoAttendantCallResult", "unknown", aaEnum)
			}
			outcome = other
		}
		e.Counter(aaOutcome, semconv.UnitDimensionless, "Auto attendant call legs by bounded outcome.", 1,
			telemetry.Attrs{semconv.AttrAutoAttendant: id, semconv.AttrVoiceOutcome: outcome})
		return
	}
	id := resourceID(text(row, "CallQueueId"))
	if id == "" {
		return
	}
	attrs := telemetry.Attrs{semconv.AttrQueue: id}
	if value, ok := row["CallQueueDurationSeconds"].(json.Number); ok {
		if n, err := value.Float64(); err == nil && n >= 0 {
			e.Histogram(waitTime, semconv.UnitSeconds, "Time a call leg waited in the Teams queue.", n, waitBuckets, attrs)
		}
	}
	result := text(row, "CallQueueCallResult")
	bucket := cqResults[result]
	if bucket == "" {
		if result != "" {
			c.watch.Value(e, "CallQueueCallResult", "unknown", cqEnum)
		}
		return // unknown result is not evidence of a non-answer or non-abandon
	}
	q := queues[id]
	q.total++
	switch bucket {
	case answered:
		q.answered++
	case abandoned:
		if target := text(row, "CallQueueTargetType"); target == "" || target == "Disconnect" {
			q.abandoned++
		}
	}
	queues[id] = q
}

func emitRates(e telemetry.Emitter, queues map[string]queueCounts) {
	abandons := make([]telemetry.GaugePoint, 0, len(queues))
	answers := make([]telemetry.GaugePoint, 0, len(queues))
	for id, q := range queues {
		attrs := telemetry.Attrs{semconv.AttrQueue: id}
		abandons = append(abandons, telemetry.GaugePoint{Value: q.abandoned / q.total, Attrs: attrs})
		answers = append(answers, telemetry.GaugePoint{Value: q.answered / q.total, Attrs: attrs})
	}
	e.GaugeSnapshot(abandonRate, semconv.UnitDimensionless, "Share of newly seen queue legs with known results that abandoned.", abandons)
	e.GaugeSnapshot(answerRate, semconv.UnitDimensionless, "Share of newly seen queue legs with known results that were answered.", answers)
}
