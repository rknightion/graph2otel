// Package livecontract is the read-only live API contract layer (#562).
//
// It holds the part of the live suite that needs no credentials: the manifest of
// Microsoft Graph v1.0 endpoints the default collectors depend on, the response
// fields their mappers read, and the checker that compares a response body with
// that manifest. The network half is live_test.go behind the live build tag.
//
// Keeping the checker untagged is what lets just check prove it: a broken shape
// assumption fails TestCheckShape on every push, while the tagged suite proves the
// same assumptions against the real tenant on a schedule.
//
// Three outcomes are kept apart on purpose:
//
//   - OutcomeMisconfigured: the request was refused (401/403) or could not be
//     authenticated. The credentials or scopes are wrong; the API said nothing about
//     shape. Never reported as a pass.
//   - OutcomeEmpty: the call succeeded and the collection is empty. The tenant has no
//     such resource, so no shape can be checked. Reported, never a failure.
//   - OutcomeChecked: at least one item was compared with the manifest.
//
// Anything else (a 4xx/5xx other than 401/403, undecodable JSON, a missing or
// mistyped field) is an error: that is the drift this layer exists to catch.
package livecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rknightion/graph2otel/internal/graphclient"
)

// BaseURL is the Graph v1.0 root every manifest path hangs off.
const BaseURL = "https://graph.microsoft.com/v1.0"

// Kind is the JSON type a mapper expects for a field.
type Kind string

// The JSON kinds a field can be.
const (
	String Kind = "string"
	Number Kind = "number"
	Bool   Kind = "bool"
	Object Kind = "object"
	Array  Kind = "array"
)

// Field is one response property a mapper reads. Nullable fields may be JSON null;
// every field must still be present, because the manifest queries use $select (or
// the endpoint always serializes the property) and a vanished key is drift.
type Field struct {
	Name     string
	Kind     Kind
	Nullable bool
}

// Endpoint is one read-only GET the collectors depend on.
type Endpoint struct {
	// ID is a stable name for test output.
	ID string
	// Path is relative to BaseURL and includes any query string.
	Path string
	// Headers are sent in addition to the bearer token.
	Headers map[string]string
	// Fields are checked on every returned item (the first MaxItems).
	Fields []Field
	// Count marks a bare-integer $count endpoint: there is no collection to check.
	Count bool
	// UsedBy names the collectors that rely on the endpoint, for failure messages.
	UsedBy string
}

// MaxItems bounds how many items per endpoint are compared. The queries below
// already request one page of at most a few items.
const MaxItems = 5

// Outcome classifies a probe result.
type Outcome string

// The probe outcomes; see the package comment.
const (
	OutcomeChecked       Outcome = "checked"
	OutcomeEmpty         Outcome = "empty"
	OutcomeMisconfigured Outcome = "misconfigured"
)

// Manifest is the representative read-only set. Every field below is one a mapper
// reads today; the collector named in UsedBy is where to look when one drifts.
func Manifest() []Endpoint {
	eventual := map[string]string{"ConsistencyLevel": "eventual"}
	return []Endpoint{
		{
			ID: "organization", Path: "/organization", UsedBy: "entra.organization, entra.syncerrors",
			Fields: []Field{
				{"id", String, false},
				{"tenantType", String, true},
				{"createdDateTime", String, true},
				{"onPremisesSyncEnabled", Bool, true},
				{"verifiedDomains", Array, false},
			},
		},
		{
			ID: "subscribedSkus", Path: "/subscribedSkus", UsedBy: "entra.licensing",
			Fields: []Field{
				{"id", String, false},
				{"skuPartNumber", String, false},
				{"consumedUnits", Number, false},
				{"capabilityStatus", String, false},
				{"prepaidUnits", Object, false},
			},
		},
		{
			ID: "conditionalAccessPolicies", Path: "/identity/conditionalAccess/policies?$top=5", UsedBy: "entra.conditional_access",
			Fields: []Field{
				{"id", String, false},
				{"displayName", String, false},
				{"state", String, false},
				{"conditions", Object, false},
				{"grantControls", Object, true},
			},
		},
		{
			ID: "namedLocations", Path: "/identity/conditionalAccess/namedLocations?$top=5", UsedBy: "entra.conditional_access",
			Fields: []Field{
				{"id", String, false},
				{"displayName", String, false},
				{"@odata.type", String, false},
			},
		},
		{
			ID:     "managedDevices",
			Path:   "/deviceManagement/managedDevices?$top=5&$select=id,deviceName,complianceState,operatingSystem,isEncrypted,lastSyncDateTime",
			UsedBy: "intune.managed_devices, intune.hardware_inventory",
			Fields: []Field{
				{"id", String, false},
				{"deviceName", String, true},
				{"complianceState", String, false},
				{"operatingSystem", String, false},
				{"isEncrypted", Bool, false},
				{"lastSyncDateTime", String, true},
			},
		},
		{
			ID: "directoryAudits", Path: "/auditLogs/directoryAudits?$top=3", UsedBy: "entra.directory_audits",
			Fields: []Field{
				{"id", String, false},
				{"activityDateTime", String, false},
				{"activityDisplayName", String, false},
				{"loggedByService", String, true},
				{"correlationId", String, true},
			},
		},
		{
			ID: "signIns", Path: "/auditLogs/signIns?$top=3", UsedBy: "entra.signins",
			Fields: []Field{
				{"id", String, false},
				{"createdDateTime", String, false},
				{"userPrincipalName", String, true},
				{"appDisplayName", String, true},
				{"correlationId", String, true},
			},
		},
		{
			ID: "securityAlerts", Path: "/security/alerts_v2?$top=3", UsedBy: "entra.security_alerts",
			Fields: []Field{
				{"id", String, false},
				{"createdDateTime", String, false},
				{"severity", String, false},
				{"serviceSource", String, true},
			},
		},
		{
			ID: "usersCount", Path: "/users/$count", Headers: eventual, Count: true, UsedBy: "entra.directory_counts",
		},
	}
}

// Classify maps a request error to OutcomeMisconfigured (401/403) or returns ok
// false for any other error, which the caller must treat as a failure. A nil error
// is not classified.
func Classify(err error) (Outcome, bool) {
	var he *graphclient.HTTPStatusError
	if errors.As(err, &he) && (he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusForbidden) {
		return OutcomeMisconfigured, true
	}
	return "", false
}

// CheckShape compares one response body with an endpoint's manifest entry. It
// reports field names, never field values, so its errors are safe in a public log.
func CheckShape(ep Endpoint, body []byte) (Outcome, error) {
	if ep.Count {
		s := strings.TrimSpace(string(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))))
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return "", fmt.Errorf("%s: $count body is not a bare integer (used by %s)", ep.ID, ep.UsedBy)
		}
		return OutcomeChecked, nil
	}
	var page struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return "", fmt.Errorf("%s: body is not a JSON object (used by %s)", ep.ID, ep.UsedBy)
	}
	if len(page.Value) == 0 {
		return "", fmt.Errorf("%s: response has no \"value\" array (used by %s)", ep.ID, ep.UsedBy)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(page.Value, &items); err != nil {
		return "", fmt.Errorf("%s: \"value\" is not an array of objects (used by %s)", ep.ID, ep.UsedBy)
	}
	if len(items) == 0 {
		return OutcomeEmpty, nil
	}
	if len(items) > MaxItems {
		items = items[:MaxItems]
	}
	problems := map[string]struct{}{}
	for _, item := range items {
		for _, f := range ep.Fields {
			if p := checkField(item, f); p != "" {
				problems[p] = struct{}{}
			}
		}
	}
	if len(problems) > 0 {
		list := make([]string, 0, len(problems))
		for p := range problems {
			list = append(list, p)
		}
		sort.Strings(list)
		return "", fmt.Errorf("%s: shape drift: %s (used by %s)", ep.ID, strings.Join(list, "; "), ep.UsedBy)
	}
	return OutcomeChecked, nil
}

func checkField(item map[string]json.RawMessage, f Field) string {
	raw, ok := item[f.Name]
	if !ok {
		return fmt.Sprintf("%q missing", f.Name)
	}
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		if f.Nullable {
			return ""
		}
		return fmt.Sprintf("%q is null, want %s", f.Name, f.Kind)
	}
	if got := kindOf(raw); got != f.Kind {
		return fmt.Sprintf("%q is %s, want %s", f.Name, got, f.Kind)
	}
	return ""
}

func kindOf(raw []byte) Kind {
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		return String
	case '{':
		return Object
	case '[':
		return Array
	case 't', 'f':
		return Bool
	default:
		return Number
	}
}
