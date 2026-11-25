// Package directroutingcalls ingests v1.0 Teams Direct Routing attempts. A
// failed attempt carries startDateTime null and an invite and failure time
// (live-measured), so the event time falls back from start to invite to failure.
package directroutingcalls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/teams/phonewindow"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const name = "teams.direct_routing_calls"

var (
	fqdn   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)$`)
	fields = map[string]string{
		"id": semconv.AttrId, "correlationId": semconv.AttrCorrelationId, "userId": semconv.AttrUserId,
		"userPrincipalName": semconv.AttrUserPrincipalName, "userDisplayName": semconv.AttrUserDisplayName,
		"callType": semconv.AttrCallType, "callerNumber": semconv.AttrCallerNumber, "calleeNumber": semconv.AttrCalleeNumber,
		"startDateTime": semconv.AttrStartTime, "inviteDateTime": semconv.AttrInviteTime, "endDateTime": semconv.AttrEndTime,
		"failureDateTime": semconv.AttrFailureTime, "duration": semconv.AttrDurationSeconds, "successfulCall": semconv.AttrSuccessfulCall,
		"finalSipCode": semconv.AttrFinalSIPCode, "callEndSubReason": semconv.AttrCallEndSubReason, "finalSipCodePhrase": semconv.AttrFinalSIPCodePhrase,
		"trunkFullyQualifiedDomainName": semconv.AttrTrunkFQDN, "mediaBypassEnabled": semconv.AttrMediaBypassEnabled,
		"mediaPathLocation": semconv.AttrMediaPathLocation, "signalingLocation": semconv.AttrSignalingLocation,
	}
)

type poller struct{ *phonewindow.Window }

func (*poller) Profiles() collector.ProfileSet { return collector.ProfileTeams }

func newPoller(d collectors.WindowDeps) *poller {
	return &poller{phonewindow.New(d, name, "getDirectRoutingCalls", mapRow)}
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return phonewindow.Registration(newPoller(d))
	})
}

func mapRow(row map[string]any) (string, telemetry.Event) {
	attrs := phonewindow.Fields(row, fields)
	id, _ := attrs[semconv.AttrId].(string)
	return id, telemetry.Event{Name: "teams.direct_routing_call", Body: "Teams Direct Routing call", Attrs: attrs, Timestamp: eventTime(row)}
}

// eventTime is the attempt's start, then invite, then failure. A row with
// none of the three parseable stays zero, so the pipeline drops it rather
// than stamping arrival time.
func eventTime(row map[string]any) time.Time {
	for _, field := range [...]string{"startDateTime", "inviteDateTime", "failureDateTime"} {
		raw, _ := row[field].(string)
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil && !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

type dimensions struct{ trunk, outcome, sipClass string }

type effectiveness struct{ effective, attempts, sourceSuccess4xx float64 }

func (c *poller) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
	counts := make(map[dimensions]float64)
	ratios := make(map[string]effectiveness)
	observer := phonewindow.EventEmitter{Emitter: e, OnEvent: func(ev telemetry.Event) {
		rawTrunk, _ := ev.Attrs[semconv.AttrTrunkFQDN].(string)
		trunk := normalizeTrunk(rawTrunk)
		outcome, sipClass := classify(ev.Attrs)
		counts[dimensions{trunk, outcome, sipClass}]++
		ratio := ratios[trunk]
		// The denominator includes every newly accepted attempt, even unknown outcomes.
		ratio.attempts++
		if outcome == "answered" || outcome == "busy" {
			ratio.effective++
		}
		if outcome == "answered" && sipClass == "4xx" {
			ratio.sourceSuccess4xx++
		}
		ratios[trunk] = ratio
	}}
	hw, err := c.Window.CollectWindow(ctx, from, to, observer, outcomes)
	if err != nil {
		return hw, err
	}
	for key, count := range counts {
		e.Counter("teams.direct_routing.calls", "{call}", "New Teams Direct Routing attempts", count,
			telemetry.Attrs{semconv.AttrTrunkFQDN: key.trunk, semconv.AttrOutcome: key.outcome, semconv.AttrSIPClass: key.sipClass})
	}
	points := make([]telemetry.GaugePoint, 0, len(ratios))
	finished := time.Now().UTC()
	for trunk, ratio := range ratios {
		points = append(points, telemetry.GaugePoint{Value: ratio.effective / ratio.attempts, Attrs: telemetry.Attrs{semconv.AttrTrunkFQDN: trunk}})
		// Keep all three counts in one observation so series admission cannot
		// retain the numerator and discard or fold its denominator separately.
		// Loki can coalesce equal timestamps and bodies in a stream regardless
		// of metadata. Keep the trunk in metadata and use its digest in the body.
		body := fmt.Sprintf("Teams Direct Routing poll effectiveness (%x)", sha256.Sum256([]byte(trunk)))
		e.LogEvent(telemetry.Event{Name: "teams.direct_routing_poll", Body: body, Timestamp: finished,
			Attrs: telemetry.Attrs{semconv.AttrTrunkFQDN: trunk, semconv.AttrPollAttempts: int64(ratio.attempts),
				semconv.AttrEffectiveAttempts: int64(ratio.effective), semconv.AttrSourceSuccessSIP4xx: int64(ratio.sourceSuccess4xx)}})
	}
	e.GaugeSnapshot("teams.direct_routing.network_effectiveness_ratio", semconv.UnitDimensionless,
		"Fraction of new Teams Direct Routing attempts that answered or reached a busy user, in the latest successful poll", points)
	return hw, nil
}

// normalizeTrunk validates the source label; the emitter owns series admission.
func normalizeTrunk(raw string) string {
	trunk := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(trunk) > 253 || !fqdn.MatchString(trunk) {
		return "unknown"
	}
	return trunk
}

func classify(attrs telemetry.Attrs) (outcome, sipClass string) {
	code, _ := attrs[semconv.AttrFinalSIPCode].(float64)
	sipClass = "unknown"
	if code >= 100 && code <= 699 && float64(int(code)) == code {
		sipClass = strconv.Itoa(int(code)/100) + "xx"
	}
	success, hasSuccess := attrs[semconv.AttrSuccessfulCall].(bool)
	switch {
	case success:
		// The source flag defines this outcome even when SIP disagrees. The
		// SIP class and raw final code remain separate evidence.
		outcome = "answered"
	case code == 486 || code == 600: // Busy Here or Busy Everywhere (RFC 3261).
		outcome = "busy"
	case hasSuccess || sipClass == "4xx" || sipClass == "5xx" || sipClass == "6xx":
		outcome = "failed"
	default:
		outcome = "unknown"
	}
	return outcome, sipClass
}
