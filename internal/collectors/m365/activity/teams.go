package activity

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	maxTeamsAuditRows      = 50
	maxTeamsAuditRowsBytes = 8 * 1024
)

// addTeamsAttrs projects the live-measured Audit.General fields (#665). Every
// key read here was seen on a live MicrosoftTeams record; nothing is taken
// from the schema documentation alone.
//
// Live-measured joins (2026-11-26, #665):
//   - MeetingParticipantDetail.MeetingDetailId equals the Id of the
//     MeetingDetail record for the same meeting (8 of 8 sampled pairs), so it
//     joins to that record's id attribute.
//   - CallParticipantDetail.CallId equals call_id on teams.call (2 of 2 calls
//     checked), so it is emitted under the same name.
//
// The other GUIDs stay opaque. AddOnGuid is a bare GUID on AppDeleted and
// "tab::<guid>" on TabAdded; it is not validated against Graph's Teams app
// catalog, so it is named for the field rather than as a Graph app id.
func addTeamsAttrs(attrs telemetry.Attrs, rec map[string]any) {
	// FetchContent decodes wire numbers as float64. Only the measured Teams
	// schema (type 25) has these fields; type 57 stays on the generic envelope.
	if str(rec, "Workload") != "MicrosoftTeams" || rec["RecordType"] != float64(25) {
		return
	}
	telemetry.SetStr(attrs, semconv.AttrTeamGuid, str(rec, "TeamGuid"))
	telemetry.SetStr(attrs, semconv.AttrTeamName, str(rec, "TeamName"))
	telemetry.SetStr(attrs, semconv.AttrChannelGuid, str(rec, "ChannelGuid"))
	telemetry.SetStr(attrs, semconv.AttrChannelName, str(rec, "ChannelName"))
	if members, ok := rec["Members"].([]any); ok {
		attrs[semconv.AttrTeamsMembersCount] = itoa(int64(len(members)))
		setBoundedRows(attrs, semconv.AttrTeamsMembersJSON, semconv.AttrTeamsMembersTruncated, members, teamsMemberRow)
	}

	telemetry.SetStr(attrs, semconv.AttrTeamsCommunicationType, str(rec, "CommunicationType"))
	addTeamsMeetingAttrs(attrs, rec)
	addTeamsAppAttrs(attrs, rec)
	addTeamsParticipantInfo(attrs, nestedMap(rec, "ParticipantInfo"))
	telemetry.SetStr(attrs, semconv.AttrTeamsDeviceId, str(rec, "DeviceId"))
	telemetry.SetStr(attrs, semconv.AttrTeamsDeviceInformation, str(rec, "DeviceInformation"))
}

// addTeamsMeetingAttrs covers MeetingDetail, MeetingParticipantDetail and
// CallParticipantDetail. The record's CreationTime is when the audit record
// was written, hours after the meeting on the live sample, so the meeting and
// join times are emitted separately.
func addTeamsMeetingAttrs(attrs telemetry.Attrs, rec map[string]any) {
	telemetry.SetStr(attrs, semconv.AttrTeamsMeetingDetailId, str(rec, "MeetingDetailId"))
	telemetry.SetStr(attrs, semconv.AttrCallId, str(rec, "CallId"))
	setWireTime(attrs, semconv.AttrTeamsJoinTime, rec, "JoinTime")
	setWireTime(attrs, semconv.AttrTeamsLeaveTime, rec, "LeaveTime")
	setWireTime(attrs, semconv.AttrTeamsMeetingStartTime, rec, "StartTime")
	setWireTime(attrs, semconv.AttrTeamsMeetingEndTime, rec, "EndTime")
	if v, ok := rec["IsJoinedFromLobby"].(bool); ok {
		telemetry.SetBool(attrs, semconv.AttrTeamsJoinedFromLobby, v)
	}
	// MeetingURL is served without a scheme. It is kept as served.
	telemetry.SetStr(attrs, semconv.AttrTeamsMeetingUrl, str(rec, "MeetingURL"))
	telemetry.SetStr(attrs, semconv.AttrTeamsCommunicationSubType, str(rec, "CommunicationSubType"))
	telemetry.SetStr(attrs, semconv.AttrTeamsModalities, str(rec, "Modalities"))
	telemetry.SetStr(attrs, semconv.AttrTeamsProviderTypes, str(rec, "ProviderTypes"))
	if org := nestedMap(rec, "Organizer"); org != nil {
		telemetry.SetStr(attrs, semconv.AttrTeamsOrganizerObjectId, str(org, "UserObjectId"))
		telemetry.SetStr(attrs, semconv.AttrTeamsOrganizerOrganizationId, str(org, "OrganizationId"))
	}
	if attendees, ok := rec["Attendees"].([]any); ok {
		attrs[semconv.AttrTeamsAttendeesCount] = itoa(int64(len(attendees)))
		setBoundedRows(attrs, semconv.AttrTeamsAttendeesJSON, semconv.AttrTeamsAttendeesTruncated, attendees, teamsAttendeeRow)
	}

	// ExtraProperties is a Key/Value list, unlike ExtendedProperties'
	// Name/Value. Only the three keys seen live are read.
	extra, _ := rec["ExtraProperties"].([]any)
	for _, e := range extra {
		p, ok := e.(map[string]any)
		if !ok {
			continue
		}
		v := str(p, "Value")
		switch str(p, "Key") {
		case "UserAgent":
			telemetry.SetStr(attrs, semconv.AttrUserAgent, v)
		case "UsersInvitedDuringMeeting":
			setWireBool(attrs, semconv.AttrTeamsUsersInvitedDuringMeeting, v)
		case "RTMPInEnabled":
			setWireBool(attrs, semconv.AttrTeamsRtmpInEnabled, v)
		}
	}
}

// addTeamsAppAttrs covers AppDeleted and TabAdded. AddOnType is an
// unnamed wire number: no live sample pins its names.
func addTeamsAppAttrs(attrs telemetry.Attrs, rec map[string]any) {
	telemetry.SetStr(attrs, semconv.AttrTeamsAddonId, str(rec, "AddOnGuid"))
	if n, ok := rec["AddOnType"].(float64); ok && math.Trunc(n) == n {
		attrs[semconv.AttrTeamsAddonTypeId] = itoa(int64(n))
	}
	telemetry.SetStr(attrs, semconv.AttrTeamsAddonName, str(rec, "AddOnName"))
	telemetry.SetStr(attrs, semconv.AttrTeamsTabType, str(rec, "TabType"))
}

// addTeamsParticipantInfo maps the external-participation summary. The flags
// are emitted only when present, so an absent flag never reads as false.
func addTeamsParticipantInfo(attrs telemetry.Attrs, info map[string]any) {
	if info == nil {
		return
	}
	for key, attr := range map[string]string{
		"HasForeignTenantUsers":   semconv.AttrTeamsHasForeignTenantUsers,
		"HasGuestUsers":           semconv.AttrTeamsHasGuestUsers,
		"HasOtherGuestUsers":      semconv.AttrTeamsHasOtherGuestUsers,
		"HasUnauthenticatedUsers": semconv.AttrTeamsHasUnauthenticatedUsers,
	} {
		if v, ok := info[key].(bool); ok {
			telemetry.SetBool(attrs, attr, v)
		}
	}
	telemetry.SetStrs(attrs, semconv.AttrTeamsParticipatingTenantIds, stringsOf(info, "ParticipatingTenantIds"))
	// ParticipatingDomains and ParticipatingSIPDomains were empty on every
	// live record, so their element shape is unmeasured and they are not read.
}

// setWireTime emits a zone-less UTC wire time as RFC 3339 UTC, the same way
// CreationTime is read. An unparseable value is omitted rather than guessed.
func setWireTime(attrs telemetry.Attrs, attr string, rec map[string]any, key string) {
	raw := str(rec, key)
	if raw == "" {
		return
	}
	for _, layout := range creationTimeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			attrs[attr] = t.UTC().Format(time.RFC3339Nano)
			return
		}
	}
}

// setWireBool reads the "True"/"False" strings ExtraProperties carries.
func setWireBool(attrs telemetry.Attrs, attr, raw string) {
	if v, err := strconv.ParseBool(raw); err == nil {
		telemetry.SetBool(attrs, attr, v)
	}
}

// A JSON array keeps each row's fields together even when some are missing.
// Only observed keys are copied. Role is the wire number, not an inferred role
// name; a pointer keeps a present zero distinct from an absent or invalid role.
type teamsAuditMember struct {
	DisplayName    string   `json:"display_name,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	Role           *float64 `json:"role,omitempty"`
	UPN            string   `json:"upn,omitempty"`
}

func teamsMemberRow(m map[string]any) (any, bool) {
	member := teamsAuditMember{
		DisplayName:    str(m, "DisplayName"),
		OrganizationID: str(m, "OrganizationId"),
		Role:           wholeNumber(m, "Role"),
		UPN:            str(m, "UPN"),
	}
	return member, member != (teamsAuditMember{})
}

// teamsAuditAttendee holds the union of attendee keys seen live: a tenant
// user on a meeting, a bot invited into one (with InviterInfo), and a PSTN or
// Teams party to a call. A PSTN attendee's DisplayName is its phone number.
type teamsAuditAttendee struct {
	DisplayName    string             `json:"display_name,omitempty"`
	OrganizationID string             `json:"organization_id,omitempty"`
	RecipientType  string             `json:"recipient_type,omitempty"`
	UserObjectID   string             `json:"user_object_id,omitempty"`
	Role           *float64           `json:"role,omitempty"`
	UPN            string             `json:"upn,omitempty"`
	IsAADGuest     *bool              `json:"is_aad_guest,omitempty"`
	IsOrganizer    *bool              `json:"is_organizer,omitempty"`
	ProviderType   string             `json:"provider_type,omitempty"`
	UserIDType     string             `json:"user_id_type,omitempty"`
	Inviter        *teamsAuditInviter `json:"inviter,omitempty"`
}

// teamsAuditInviter keeps InviteTime as served, like the rest of the row.
type teamsAuditInviter struct {
	InviteTime     string `json:"invite_time,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	UserType       string `json:"user_type,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
	UPN            string `json:"upn,omitempty"`
	UserIdentifier string `json:"user_identifier,omitempty"`
}

func teamsAttendeeRow(m map[string]any) (any, bool) {
	a := teamsAuditAttendee{
		DisplayName:    str(m, "DisplayName"),
		OrganizationID: str(m, "OrganizationId"),
		RecipientType:  str(m, "RecipientType"),
		UserObjectID:   str(m, "UserObjectId"),
		Role:           wholeNumber(m, "Role"),
		UPN:            str(m, "UPN"),
		IsAADGuest:     boolPtr(m, "IsAADGuest"),
		IsOrganizer:    boolPtr(m, "IsOrganizer"),
		ProviderType:   str(m, "ProviderType"),
		UserIDType:     str(m, "UserIdType"),
	}
	if inv := nestedMap(m, "InviterInfo"); inv != nil {
		i := teamsAuditInviter{
			InviteTime:     str(inv, "InviteTime"),
			OrganizationID: str(inv, "OrganizationId"),
			UserType:       str(inv, "UserType"),
			DisplayName:    str(inv, "DisplayName"),
			UPN:            str(inv, "UPN"),
			UserIdentifier: str(inv, "UserIdentifier"),
		}
		if i != (teamsAuditInviter{}) {
			a.Inviter = &i
		}
	}
	return a, a != (teamsAuditAttendee{})
}

func wholeNumber(m map[string]any, key string) *float64 {
	if n, ok := m[key].(float64); ok && math.Trunc(n) == n {
		return &n
	}
	return nil
}

func boolPtr(m map[string]any, key string) *bool {
	if v, ok := m[key].(bool); ok {
		return &v
	}
	return nil
}

// setBoundedRows writes rows as one JSON array attribute. It bounds both the
// number of source entries examined and the bytes emitted, and keeps whole
// row objects in wire order, never a partial JSON value. The caller emits the
// wire count separately, so a truncated list still says how many there were.
func setBoundedRows(attrs telemetry.Attrs, key, truncatedKey string, rows []any, row func(map[string]any) (any, bool)) {
	truncated := len(rows) > maxTeamsAuditRows
	var list strings.Builder
	for _, r := range rows[:min(len(rows), maxTeamsAuditRows)] {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		value, ok := row(m)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			continue
		}
		// Include the delimiters in the budget check.
		if list.Len()+len(encoded)+2 > maxTeamsAuditRowsBytes {
			truncated = true
			break
		}
		if list.Len() == 0 {
			list.WriteByte('[')
		} else {
			list.WriteByte(',')
		}
		list.Write(encoded)
	}
	if list.Len() > 0 {
		list.WriteByte(']')
		telemetry.SetStr(attrs, key, list.String())
	}
	if truncated {
		telemetry.SetBool(attrs, truncatedKey, true)
	}
}
