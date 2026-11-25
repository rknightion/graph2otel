package activity

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
)

const (
	maxTeamsAuditMembers      = 50
	maxTeamsAuditMembersBytes = 8 * 1024
)

// addTeamsAttrs projects the live-measured Audit.General fields (#665). The
// audit GUIDs are opaque values, not validated joins to Graph inventory. The
// capture did not establish what ObjectId or AddOnGuid could join to.
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
	members, _ := rec["Members"].([]any)
	addTeamsMembers(attrs, members)
}

// A JSON array keeps each member's fields together even when some are missing.
// Only observed keys are copied. Role is the wire number, not an inferred role
// name; a pointer keeps a present zero distinct from an absent or invalid role.
type teamsAuditMember struct {
	DisplayName    string   `json:"display_name,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	Role           *float64 `json:"role,omitempty"`
	UPN            string   `json:"upn,omitempty"`
}

func addTeamsMembers(attrs telemetry.Attrs, members []any) {
	// Bound both the number of source entries examined and bytes emitted.
	// Keep whole member objects in wire order, never a partial JSON value.
	truncated := len(members) > maxTeamsAuditMembers
	var list strings.Builder
	for _, row := range members[:min(len(members), maxTeamsAuditMembers)] {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		member := teamsAuditMember{
			DisplayName:    str(m, "DisplayName"),
			OrganizationID: str(m, "OrganizationId"),
			UPN:            str(m, "UPN"),
		}
		if n, ok := m["Role"].(float64); ok && math.Trunc(n) == n {
			member.Role = &n
		}
		if member == (teamsAuditMember{}) {
			continue
		}
		// Avoid encoding a large source string that cannot fit even before
		// JSON escaping. Check the encoded length as well, including delimiters.
		if len(member.DisplayName)+len(member.OrganizationID)+len(member.UPN) > maxTeamsAuditMembersBytes {
			truncated = true
			break
		}
		encoded, err := json.Marshal(member)
		if err != nil {
			continue
		}
		if list.Len()+len(encoded)+2 > maxTeamsAuditMembersBytes {
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
		telemetry.SetStr(attrs, semconv.AttrTeamsMembersJSON, list.String())
	}
	if truncated {
		telemetry.SetBool(attrs, semconv.AttrTeamsMembersTruncated, true)
	}
}
