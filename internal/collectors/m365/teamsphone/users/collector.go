// Package users collects current Teams user voice configuration over Graph.
// Field shapes were checked in the poller's v1.0 response (#663, Teams Phone inventory).
package users

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/inventory"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	usersName     = "teams.user_configuration"
	usersScope    = "TeamsUserConfiguration.Read.All"
	usersEndpoint = inventory.GraphV1 + "/admin/teams/userConfigurations"
)

var (
	accountTypes = wirecheck.NewEnum("user", "resourceAccount", "guest", "sfbOnPremUser", "unknown", "unknownFutureValue", "ineligibleUser")
	policyKinds  = []string{"TeamsCallingPolicy", "OnlineVoiceRoutingPolicy"}
	policyTypes  = wirecheck.NewEnum(policyKinds...)
)

// The two nested arrays were populated in the poller's v1.0 list response
// (live-measured 2026-11-25, #708 (Teams observability review)).
type userConfiguration struct {
	ID                         string                      `json:"id"`
	UserPrincipalName          string                      `json:"userPrincipalName"`
	AccountType                string                      `json:"accountType"`
	EnterpriseVoiceEnabled     *bool                       `json:"isEnterpriseVoiceEnabled"`
	FeatureTypes               []string                    `json:"featureTypes"`
	CreatedDateTime            string                      `json:"createdDateTime"`
	ModifiedDateTime           string                      `json:"modifiedDateTime"`
	EffectivePolicyAssignments []effectivePolicyAssignment `json:"effectivePolicyAssignments"`
	TelephoneNumbers           []telephoneAssignment       `json:"telephoneNumbers"`
}

type effectivePolicyAssignment struct {
	PolicyType       string            `json:"policyType,omitempty"`
	PolicyAssignment *policyAssignment `json:"policyAssignment,omitempty"`
}

type policyAssignment struct {
	AssignmentType string `json:"assignmentType,omitempty"`
	DisplayName    string `json:"displayName,omitempty"`
	PolicyID       string `json:"policyId,omitempty"`
}

type telephoneAssignment struct {
	AssignmentCategory string `json:"assignmentCategory,omitempty"`
	TelephoneNumber    string `json:"telephoneNumber,omitempty"`
}

type users struct{ inventory.Snapshot }

type userBucket struct{ accountType, voiceEnabled string }

func (c users) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := collectors.GetAllValuesRecorded(ctx, c.Graph, usersEndpoint, nil, outcomes)
	if err != nil {
		return err
	}
	rows, err := inventory.DecodeRows[userConfiguration](raws, outcomes)
	if err != nil {
		return err
	}
	poll := c.BeginPoll(e)
	counts := map[userBucket]int{}
	// A complete empty poll must supersede old samples still in the
	// backend lookback. Emit zero for the fixed buckets, not for entity IDs.
	policies := map[string]int{"unknown": 0}
	for _, kind := range policyKinds {
		policies[kind] = 0
	}
	for _, u := range rows {
		enabled := "unknown"
		if u.EnterpriseVoiceEnabled != nil {
			enabled = strconv.FormatBool(*u.EnterpriseVoiceEnabled)
		}
		counts[userBucket{c.Bucket(e, "accountType", u.AccountType, accountTypes), enabled}]++
		for _, row := range u.EffectivePolicyAssignments {
			if row.PolicyAssignment != nil && *row.PolicyAssignment != (policyAssignment{}) {
				policies[c.Bucket(e, "effectivePolicyAssignments.policyType", row.PolicyType, policyTypes)]++
			}
		}
		poll.LogTwin(u.twin())
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{
			semconv.AttrAccountType: k.accountType, semconv.AttrEnterpriseVoiceEnabled: k.voiceEnabled,
		}})
	}
	e.GaugeSnapshot("m365.teams.user_configuration.users", "{user}", "Teams users by account type and enterprise voice state.", points)
	policyPoints := make([]telemetry.GaugePoint, 0, len(policies))
	for kind, count := range policies {
		policyPoints = append(policyPoints, telemetry.GaugePoint{Value: float64(count), Attrs: telemetry.Attrs{semconv.AttrPolicyType: kind}})
	}
	e.GaugeSnapshot("m365.teams.user_configuration.effective_policy_assignments", "{policy}", "Reported Teams user effective policy assignments by policy type.", policyPoints)
	poll.Complete(outcomes)
	return nil
}

func (u userConfiguration) twin() telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, u.ID)
	telemetry.SetStr(attrs, semconv.AttrUserPrincipalName, u.UserPrincipalName)
	telemetry.SetStr(attrs, semconv.AttrAccountType, u.AccountType)
	if u.EnterpriseVoiceEnabled != nil {
		telemetry.SetBool(attrs, semconv.AttrEnterpriseVoiceEnabled, *u.EnterpriseVoiceEnabled)
	}
	telemetry.SetStrs(attrs, semconv.AttrFeatureTypes, u.FeatureTypes)
	telemetry.SetStr(attrs, semconv.AttrCreatedDateTime, u.CreatedDateTime)
	telemetry.SetStr(attrs, semconv.AttrModifiedDateTime, u.ModifiedDateTime)
	if len(u.EffectivePolicyAssignments) != 0 {
		// These wire structs contain only strings and pointers to strings-only structs.
		encoded, _ := json.Marshal(u.EffectivePolicyAssignments)
		telemetry.SetStr(attrs, semconv.AttrEffectivePolicyAssignments, string(encoded))
	}
	if len(u.TelephoneNumbers) != 0 {
		encoded, _ := json.Marshal(u.TelephoneNumbers)
		telemetry.SetStr(attrs, semconv.AttrTelephoneNumbers, string(encoded))
	}
	// This is a current inventory observation, not a past change event.
	// Keep source dates as attributes so old accounts still have log twins.
	return telemetry.Event{
		Name: "m365.teams.user_configuration", Body: "Teams Phone user configuration", Severity: telemetry.SeverityInfo,
		Attrs: attrs,
	}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return users{inventory.New(d.Graph, usersName, usersScope, d.Logger)}
	})
}
