package graphactivity

import (
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

func TestNormalizeGraphPath(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		// UPN/email segment -> {id}; resource-type and action segments kept.
		{"https://graph.microsoft.com/beta/users/rob@m7kni.io/informationProtection/batchClassifyAndEvaluate",
			"/beta/users/{id}/informationProtection/batchClassifyAndEvaluate"},
		// GUID segment -> {id}; $count kept.
		{"https://graph.microsoft.com/v1.0/groups/12345678-1234-1234-1234-123456789abc/members/$count",
			"/v1.0/groups/{id}/members/$count"},
		// bare GUID
		{"https://graph.microsoft.com/v1.0/users/87d30957-9758-4040-949e-9e9fe9c7cfcf", "/v1.0/users/{id}"},
		// all-numeric id
		{"https://graph.microsoft.com/v1.0/devices/12345", "/v1.0/devices/{id}"},
		// long opaque token (mail item id) -> {id}; a long action name with no
		// digit (batchClassifyAndEvaluate, informationProtection above) is kept.
		{"https://graph.microsoft.com/v1.0/me/messages/AQMkADAwATM0MDAAMS0yN2ZlLTk2ZTAAAAgBGAAAD", "/v1.0/me/messages/{id}"},
		// OData function with args -> args dropped
		{"https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')",
			"/v1.0/reports/getEmailActivityUserDetail()"},
		// query string stripped
		{"https://graph.microsoft.com/v1.0/users?$top=5&$select=id", "/v1.0/users"},
		// no host (already a path)
		{"/v1.0/servicePrincipals", "/v1.0/servicePrincipals"},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			if got := normalizeGraphPath(tc.uri); got != tc.want {
				t.Errorf("normalizeGraphPath(%q) = %q, want %q", tc.uri, got, tc.want)
			}
		})
	}
}

func TestStatusClass(t *testing.T) {
	cases := map[int]string{200: "2xx", 204: "2xx", 302: "3xx", 400: "4xx", 404: "4xx", 429: "4xx", 500: "5xx", 0: "other"}
	for code, want := range cases {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

// Beyond the distinct-path cap, new paths collapse to "other" so the label can
// never blow up active series (#185) — while already-seen paths still pass.
func TestActivityDeriver_PathCapCollapsesToOther(t *testing.T) {
	a := &activityDeriver{seen: map[string]struct{}{}, cap: 2}
	if got := a.cappedPath("/a"); got != "/a" {
		t.Fatalf("first path = %q, want /a", got)
	}
	if got := a.cappedPath("/b"); got != "/b" {
		t.Fatalf("second path = %q, want /b", got)
	}
	if got := a.cappedPath("/c"); got != "other" {
		t.Fatalf("third distinct path = %q, want other (cap=2)", got)
	}
	// An already-seen path still returns itself even past the cap.
	if got := a.cappedPath("/a"); got != "/a" {
		t.Fatalf("seen path after cap = %q, want /a", got)
	}
}

// The endpoint deriver adds the bounded endpoint_requests counter with exactly
// normalized_path/request_method/response_status_class, plus the paths gauge.
func TestActivityDeriver_EmitsEndpointCounter(t *testing.T) {
	a := newActivityDeriver()
	pts := a.derive(decode(t, realRecord), telemetry.Event{})
	byName := map[string]telemetry.Attrs{}
	for _, p := range pts {
		byName[p.Name] = p.Attrs
	}
	ep, ok := byName["entra.graph_activity.endpoint_requests"]
	if !ok {
		t.Fatal("missing entra.graph_activity.endpoint_requests")
	}
	want := map[string]any{
		"normalized_path":       "/beta/users/{id}/informationProtection/batchClassifyAndEvaluate",
		"request_method":        "POST",
		"response_status_class": "2xx",
	}
	if len(ep) != len(want) {
		t.Fatalf("endpoint attrs = %v, want exactly %v", ep, want)
	}
	for k, w := range want {
		if fmt.Sprint(ep[k]) != fmt.Sprint(w) {
			t.Errorf("endpoint attr %q = %v, want %v", k, ep[k], w)
		}
	}
	if _, ok := byName["graph2otel.blob.endpoint_paths"]; !ok {
		t.Error("missing graph2otel.blob.endpoint_paths gauge")
	}
}
