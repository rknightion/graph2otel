// Package sipdevices snapshots Teams SIP device inventory and connection health.
// The poller's beta reads on 2026-11-25 (live-measured) returned two SIP rows
// and a health object for each, with all software update fields null. This is
// not a software compliance, provisioning policy or user-assignment feed.
package sipdevices

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	name     = "teams.sip_devices"
	endpoint = "https://graph.microsoft.com/beta/teamwork/devices"
	event    = "m365.teams.sip_device"
)

type snapshot struct{ graph collectors.GraphClient }

func (snapshot) Name() string                   { return name }
func (snapshot) DefaultInterval() time.Duration { return time.Hour }
func (snapshot) Experimental() bool             { return true }
func (snapshot) Profiles() collector.ProfileSet {
	return collector.ProfileGraph | collector.ProfileTeams
}
func (snapshot) RequiredPermissions() []string { return []string{"TeamworkDevice.Read.All"} }

type device struct {
	ID                   string `json:"id"`
	Type                 string `json:"deviceType"`
	HealthStatus         string `json:"healthStatus"`
	LastModifiedDateTime string `json:"lastModifiedDateTime"`
	HardwareDetail       struct {
		Manufacturer string `json:"manufacturer"`
		Model        string `json:"model"`
	} `json:"hardwareDetail"`
}

// updateStatus detects a non-null status object without decoding its values.
type updateStatus struct{}

type deviceHealth struct {
	ID         string `json:"id"`
	Connection struct {
		Status               string `json:"connectionStatus"`
		LastModifiedDateTime string `json:"lastModifiedDateTime"`
	} `json:"connection"`
	Updates struct {
		AdminAgent      *updateStatus `json:"adminAgentSoftwareUpdateStatus"`
		CompanyPortal   *updateStatus `json:"companyPortalSoftwareUpdateStatus"`
		Firmware        *updateStatus `json:"firmwareSoftwareUpdateStatus"`
		OperatingSystem *updateStatus `json:"operatingSystemSoftwareUpdateStatus"`
		PartnerAgent    *updateStatus `json:"partnerAgentSoftwareUpdateStatus"`
		TeamsClient     *updateStatus `json:"teamsClientSoftwareUpdateStatus"`
	} `json:"softwareUpdateHealth"`
}

// Only presence was measured. Do not interpret populated update values as
// current, outdated or healthy without a populated wire sample.
func (h deviceHealth) updateReadout() string {
	u := h.Updates
	if u.AdminAgent != nil || u.CompanyPortal != nil || u.Firmware != nil ||
		u.OperatingSystem != nil || u.PartnerAgent != nil || u.TeamsClient != nil {
		return "reported"
	}
	return "not_reported"
}

func (c snapshot) Collect(ctx context.Context, e telemetry.Emitter, outcomes *recordoutcome.Recorder) error {
	// Retain the measured unfiltered list request and follow Graph's next links.
	// Only SIP devices need a health read; no activity or configuration fan-out.
	rows, err := collectors.GetAllValuesRecorded(ctx, c.graph, endpoint, nil, outcomes)
	if err != nil {
		return err
	}
	outcomes.Add(recordoutcome.OutcomeFetched, uint64(len(rows)))
	for _, row := range rows {
		var d device
		if err := json.Unmarshal(row, &d); err != nil {
			recordError(outcomes, recordoutcome.CauseDecodeError)
			continue
		}
		if d.Type == "" {
			recordError(outcomes, recordoutcome.CauseMappingError)
			continue
		}
		if d.Type != "sip" {
			outcomes.Add(recordoutcome.OutcomeFiltered, 1)
			continue
		}
		if d.ID == "" || d.ID == "." || d.ID == ".." {
			recordError(outcomes, recordoutcome.CauseMappingError)
			continue
		}
		raw, err := c.graph.RawGet(ctx, endpoint+"/"+url.PathEscape(d.ID)+"/health")
		if err != nil {
			recordError(outcomes, recordoutcome.CauseForError(err))
			continue
		}
		var h deviceHealth
		if err := json.Unmarshal(raw, &h); err != nil {
			recordError(outcomes, recordoutcome.CauseDecodeError)
			continue
		}
		if h.ID != d.ID {
			recordError(outcomes, recordoutcome.CauseMappingError)
			continue
		}
		e.LogEvent(d.observation(h))
		outcomes.Add(recordoutcome.OutcomeMapped, 1)
		outcomes.Add(recordoutcome.OutcomeEmitted, 1)
	}
	return ctx.Err()
}

func recordError(outcomes *recordoutcome.Recorder, cause recordoutcome.Cause) {
	outcomes.Add(recordoutcome.OutcomeErrored, 1)
	outcomes.Cause(cause)
}

func (d device) observation(h deviceHealth) telemetry.Event {
	attrs := telemetry.Attrs{
		semconv.AttrDeviceId:                 d.ID,
		semconv.AttrDeviceType:               d.Type,
		semconv.AttrSIPSoftwareUpdateReadout: h.updateReadout(),
	}
	telemetry.SetStr(attrs, semconv.AttrManufacturer, d.HardwareDetail.Manufacturer)
	telemetry.SetStr(attrs, semconv.AttrModel, d.HardwareDetail.Model)
	telemetry.SetStr(attrs, semconv.AttrLastModifiedDateTime, d.LastModifiedDateTime)
	telemetry.SetStr(attrs, semconv.AttrSIPHealthStatus, d.HealthStatus)
	telemetry.SetStr(attrs, semconv.AttrSIPConnectionStatus, h.Connection.Status)
	telemetry.SetStr(attrs, semconv.AttrSIPConnectionLastModifiedDateTime, h.Connection.LastModifiedDateTime)
	// This is a current observation, not a connection or configuration change
	// event. Keep source change times as attributes, not the log timestamp.
	return telemetry.Event{Name: event, Body: "Teams SIP device snapshot", Severity: telemetry.SeverityInfo, Attrs: attrs}
}

func init() {
	collectors.Register(func(d collectors.Deps) collector.SnapshotCollector { return snapshot{graph: d.Graph} })
}
