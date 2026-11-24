// Package pstncalls ingests v1.0 PSTN usage rows. Its wire shape is docs-derived;
// neither call delivery lag nor connectivityType values are live-verified.
package pstncalls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/teams/phonewindow"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const name = "teams.pstn_calls"

var fields = map[string]string{
	"id": semconv.AttrId, "callId": semconv.AttrCallId, "conferenceId": semconv.AttrConferenceId, "userId": semconv.AttrUserId,
	"userPrincipalName": semconv.AttrUserPrincipalName, "userDisplayName": semconv.AttrUserDisplayName,
	"callType": semconv.AttrCallType, "callerNumber": semconv.AttrCallerNumber, "calleeNumber": semconv.AttrCalleeNumber,
	"startDateTime": semconv.AttrStartTime, "endDateTime": semconv.AttrEndTime, "duration": semconv.AttrDurationSeconds,
	"charge": semconv.AttrCharge, "currency": semconv.AttrCurrency, "destinationName": semconv.AttrDestinationName,
	"destinationContext": semconv.AttrDestinationContext, "operator": semconv.AttrOperator, "licenseCapability": semconv.AttrLicenseCapability,
	"inventoryType": semconv.AttrInventoryType, "connectivityType": semconv.AttrConnectivityType,
}

// The PSTN usage report documents these call types. Unknown values keep their
// log detail, but cannot open up a new series.
var callTypes = wirecheck.NewEnum(
	"user_in", "user_out", "user_out_conf", "user_out_transfer", "user_out_forwarding",
	"conf_in", "conf_out", "unassigned_in", "emergency_in", "emergency_out", "fmc_in", "fmc_out",
	"ucap_in", "ucap_out", "ucap_out_conf",
)

type poller struct{ *phonewindow.Window }

func (*poller) Profiles() collector.ProfileSet { return collector.ProfileTeams }

func newPoller(d collectors.WindowDeps) *poller {
	return &poller{phonewindow.New(d, name, "getPstnCalls", mapRow)}
}

func init() {
	collectors.RegisterWindow(func(d collectors.WindowDeps) collectors.RegisteredWindow {
		return phonewindow.Registration(newPoller(d))
	})
}

func mapRow(row map[string]any) (string, telemetry.Event) {
	attrs := phonewindow.Fields(row, fields)
	if _, present := attrs[semconv.AttrConnectivityType]; !present {
		attrs[semconv.AttrConnectivityType] = connectivity(attrs)
	}
	ev := telemetry.Event{Name: "teams.pstn_call", Body: "Teams PSTN call", Attrs: attrs}
	id, _ := attrs[semconv.AttrId].(string)
	callID, _ := attrs[semconv.AttrCallId].(string)
	start, _ := attrs[semconv.AttrStartTime].(string)
	ts, err := time.Parse(time.RFC3339Nano, start)
	if err != nil || (id == "" && callID == "") {
		return "", ev
	}
	// Both identifiers are log-only; hash a canonical tuple for checkpoints.
	// A reused identifier at another start time is a different row. Billing
	// and duration fields can change without changing this key.
	key, _ := json.Marshal([3]string{id, callID, ts.UTC().Format(time.RFC3339Nano)})
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:]), ev
}

type dimensions struct{ callType, connectivity string }

func (c *poller) CollectWindow(ctx context.Context, from, to time.Time, e telemetry.Emitter, outcomes *recordoutcome.Recorder) (time.Time, error) {
	counts := make(map[dimensions]float64)
	var seconds float64
	var hasDuration bool
	observer := phonewindow.EventEmitter{Emitter: e, OnEvent: func(ev telemetry.Event) {
		callType, _ := ev.Attrs[semconv.AttrCallType].(string)
		callType = strings.ToLower(strings.TrimSpace(callType))
		if !callTypes.Has(callType) {
			wirecheck.Shared(name).Value(e, semconv.AttrCallType, callType, callTypes)
			callType = "unknown"
		}
		counts[dimensions{callType, connectivity(ev.Attrs)}]++
		if n, ok := ev.Attrs[semconv.AttrDurationSeconds].(float64); ok && n >= 0 {
			seconds += n
			hasDuration = true
		}
	}}
	hw, err := c.Window.CollectWindow(ctx, from, to, observer, outcomes)
	if err != nil {
		return hw, err
	}
	for key, count := range counts {
		e.Counter("teams.pstn.calls", "{call}", "New Teams PSTN calls", count,
			telemetry.Attrs{semconv.AttrCallType: key.callType, semconv.AttrConnectivityType: key.connectivity})
	}
	if hasDuration {
		e.Counter("teams.pstn.minutes", "min", "Connected minutes of new Teams PSTN calls", seconds/60, nil)
	}
	return hw, nil
}

func connectivity(attrs telemetry.Attrs) string {
	raw, _ := attrs[semconv.AttrConnectivityType].(string)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "callingplan", "calling plan", "calling_plan":
		return "calling_plan"
	case "operatorconnect", "operator connect", "operator_connect":
		return "operator_connect"
	case "":
		// v1.0 does not document a connectivityType property. The PSTN
		// report documents Microsoft as the Calling Plan operator and
		// carrier names for Operator Connect. Never label by carrier name.
		operator, _ := attrs[semconv.AttrOperator].(string)
		if operator = strings.TrimSpace(operator); operator != "" {
			if strings.EqualFold(operator, "microsoft") {
				return "calling_plan"
			}
			return "operator_connect"
		}
	}
	return "unknown"
}
