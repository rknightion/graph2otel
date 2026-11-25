// Package numbers collects the current Teams Phone number inventory over Graph.
// Field shapes were checked in the poller's v1.0 response (#663, Teams Phone inventory).
package numbers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/collectors/m365/teamsphone/internal/inventory"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

const (
	numbersName     = "teams.phone_numbers"
	numbersScope    = "TeamsTelephoneNumber.Read.All"
	numbersEndpoint = inventory.GraphV1 + "/admin/teams/telephoneNumberManagement/numberAssignments"
	numbersPageSize = 1000
	numbersMaxPages = 1000
	unassigned      = "unassigned"
)

// The documented enums bound the gauge. Unexpected values remain verbatim
// on the twin and are reported through wirecheck, not used as series labels.
var (
	numberTypes        = wirecheck.NewEnum("internalError", "directRouting", "callingPlan", "operatorConnect", "unknownFutureValue")
	assignmentStatuses = wirecheck.NewEnum(unassigned, "internalError", "userAssigned", "conferenceAssigned", "voiceApplicationAssigned",
		"thirdPartyAppAssigned", "policyAssigned", "unknownFutureValue")
	activationStates   = wirecheck.NewEnum("activated", "assignmentPending", "assignmentFailed", "updatePending", "updateFailed", "unknownFutureValue")
	numberCapabilities = wirecheck.NewEnum("conferenceAssignment", "voiceApplicationAssignment", "userAssignment", "teamsPhoneMobile", "unknownFutureValue")
)

type numberAssignment struct {
	ActivationState            string   `json:"activationState"`
	AssignmentCategory         string   `json:"assignmentCategory"`
	AssignmentStatus           string   `json:"assignmentStatus"`
	AssignmentTargetID         string   `json:"assignmentTargetId"`
	Capabilities               []string `json:"capabilities"`
	City                       string   `json:"city"`
	CivicAddressID             string   `json:"civicAddressId"`
	ID                         string   `json:"id"`
	ISOCountryCode             string   `json:"isoCountryCode"`
	LocationID                 string   `json:"locationId"`
	NetworkSiteID              string   `json:"networkSiteId"`
	NumberSource               string   `json:"numberSource"`
	NumberType                 string   `json:"numberType"`
	OperatorID                 string   `json:"operatorId"`
	PortInStatus               string   `json:"portInStatus"`
	ReverseNumberLookupOptions []string `json:"reverseNumberLookupOptions"`
	SupportedCustomerActions   []string `json:"supportedCustomerActions"`
	TelephoneNumber            string   `json:"telephoneNumber"`
}

type numbers struct{ inventory.Snapshot }

type numberBucket struct{ numberType, assignmentStatus, activationState, capability string }

func (c numbers) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	raws, err := c.fetch(ctx, outcomes)
	if err != nil {
		return err
	}
	rows, err := inventory.DecodeRows[numberAssignment](raws, outcomes)
	if err != nil {
		return err
	}
	poll := c.BeginPoll(e)
	counts := map[numberBucket]int{}
	unused := 0
	for _, n := range rows {
		if n.AssignmentStatus == unassigned {
			unused++
		}
		key := numberBucket{
			numberType:       c.Bucket(e, "numberType", n.NumberType, numberTypes),
			assignmentStatus: c.Bucket(e, "assignmentStatus", n.AssignmentStatus, assignmentStatuses),
			activationState:  c.Bucket(e, "activationState", n.ActivationState, activationStates),
		}
		// Capabilities overlap. Count a number at most once per bucket and
		// keep the unassigned gauge independent of the capability dimension.
		seen := make(map[string]bool, len(n.Capabilities))
		if len(n.Capabilities) == 0 {
			key.capability = "none"
			counts[key]++
		}
		for _, capability := range n.Capabilities {
			key.capability = c.Bucket(e, "capabilities", capability, numberCapabilities)
			if !seen[key.capability] {
				seen[key.capability] = true
				counts[key]++
			}
		}
		poll.LogTwin(n.twin())
	}
	points := make([]telemetry.GaugePoint, 0, len(counts))
	for k, v := range counts {
		points = append(points, telemetry.GaugePoint{Value: float64(v), Attrs: telemetry.Attrs{
			semconv.AttrNumberType: k.numberType, semconv.AttrAssignmentStatus: k.assignmentStatus,
			semconv.AttrActivationState: k.activationState, semconv.AttrCapability: k.capability,
		}})
	}
	e.GaugeSnapshot("m365.teams.phone_numbers.total", "{number_capability}", "Teams Phone numbers by type, assignment status, activation state and capability. A number can have several capabilities.", points)
	e.GaugeSnapshot("m365.teams.phone_numbers.unassigned", "{number}", "Teams Phone numbers with unassigned status.", []telemetry.GaugePoint{{Value: float64(unused)}})
	poll.Complete(outcomes)
	return nil
}

// Number assignments documents $top/$skip pagination, unlike the user
// configuration collection. Respect a server-issued nextLink if present;
// otherwise keep stepping by offset until a short page proves exhaustion.
func (c numbers) fetch(ctx context.Context, outcomes *recordoutcome.Recorder) ([]json.RawMessage, error) {
	var rows []json.RawMessage
	fail := func(cause recordoutcome.Cause, err error) ([]json.RawMessage, error) {
		outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
		outcomes.Add(recordoutcome.OutcomeErrored, uint64(len(rows)))
		outcomes.Cause(cause)
		return nil, err
	}
	first := fmt.Sprintf("%s?$top=%d", numbersEndpoint, numbersPageSize)
	next, linkPaging := first, false
	for range numbersMaxPages {
		body, err := c.Graph.RawGet(ctx, next)
		if err != nil {
			return fail(recordoutcome.CauseForError(err), err)
		}
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fail(recordoutcome.CauseDecodeError, fmt.Errorf("decode number assignments page: %w", err))
		}
		if page.Value == nil {
			return fail(recordoutcome.CauseDecodeError, errors.New("number assignments page is missing non-null value"))
		}
		rows = append(rows, page.Value...)
		switch {
		case page.NextLink != "":
			next, linkPaging = page.NextLink, true
		case linkPaging || len(page.Value) < numbersPageSize:
			return rows, nil
		default:
			next = fmt.Sprintf("%s&$skip=%d", first, len(rows))
		}
	}
	return fail(recordoutcome.CauseSourceError, fmt.Errorf("number assignments pagination exceeded %d pages", numbersMaxPages))
}

func (n numberAssignment) twin() telemetry.Event {
	attrs := telemetry.Attrs{}
	telemetry.SetStr(attrs, semconv.AttrId, n.ID)
	telemetry.SetStr(attrs, semconv.AttrTelephoneNumber, n.TelephoneNumber)
	telemetry.SetStr(attrs, semconv.AttrActivationState, n.ActivationState)
	telemetry.SetStr(attrs, semconv.AttrAssignmentCategory, n.AssignmentCategory)
	telemetry.SetStr(attrs, semconv.AttrAssignmentStatus, n.AssignmentStatus)
	telemetry.SetStr(attrs, semconv.AttrAssignmentTargetId, n.AssignmentTargetID)
	telemetry.SetStrs(attrs, semconv.AttrCapabilities, n.Capabilities)
	telemetry.SetStr(attrs, semconv.AttrCity, n.City)
	telemetry.SetStr(attrs, semconv.AttrCivicAddressId, n.CivicAddressID)
	telemetry.SetStr(attrs, semconv.AttrCountryCode, n.ISOCountryCode)
	telemetry.SetStr(attrs, semconv.AttrLocationId, n.LocationID)
	telemetry.SetStr(attrs, semconv.AttrNetworkSiteId, n.NetworkSiteID)
	telemetry.SetStr(attrs, semconv.AttrNumberSource, n.NumberSource)
	telemetry.SetStr(attrs, semconv.AttrNumberType, n.NumberType)
	telemetry.SetStr(attrs, semconv.AttrOperatorId, n.OperatorID)
	telemetry.SetStr(attrs, semconv.AttrPortInStatus, n.PortInStatus)
	telemetry.SetStrs(attrs, semconv.AttrReverseNumberLookupOptions, n.ReverseNumberLookupOptions)
	telemetry.SetStrs(attrs, semconv.AttrSupportedCustomerActions, n.SupportedCustomerActions)
	// This inventory row has no source timestamp. Leave it unset rather
	// than claiming the number was assigned at observation time.
	return telemetry.Event{Name: "m365.teams.phone_number", Body: "Teams Phone number assignment", Severity: telemetry.SeverityInfo, Attrs: attrs}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector {
		return numbers{inventory.New(d.Graph, numbersName, numbersScope, d.Logger)}
	})
}
