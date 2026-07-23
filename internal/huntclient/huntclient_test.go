package huntclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/rknightion/graph2otel/internal/auth"
)

// fakeCred is a token credential that returns a fixed token without any network
// I/O, mirroring the sibling transport-package tests.
type fakeCred struct{ err error }

func (f fakeCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "test-token"}, nil
}

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	ta := &auth.TenantAuth{TenantID: "test-tenant", Cred: fakeCred{}}
	c, err := NewClient(ta, Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// liveEnvelope is the verbatim wire shape of a runHuntingQuery success response
// captured from the m7kni tenant as graph2otel-poller on 2026-07-23. The
// `@odata.type` sidecar keys ride alongside the real columns and every boolean
// column (IsExploitAvailable) arrives as an SByte number, never a JSON bool —
// both are kept here so the transport proves it hands them back untouched for
// the collector to interpret.
const liveEnvelope = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.security.huntingQueryResults",
  "schema": [
    {"name": "CveId", "type": "String"},
    {"name": "IsExploitAvailable", "type": "SByte"},
    {"name": "CvssScore", "type": "Double"}
  ],
  "results": [
    {"CveId": "CVE-2026-33829", "IsExploitAvailable@odata.type": "#SByte", "IsExploitAvailable": 1, "CvssScore": 4.3},
    {"CveId": "CVE-2026-00001", "IsExploitAvailable@odata.type": "#SByte", "IsExploitAvailable": 0, "CvssScore": 9.8}
  ]
}`

func TestQuery_DecodesResults(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1.0/security/runHuntingQuery" {
			t.Errorf("path = %s, want /v1.0/security/runHuntingQuery", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(liveEnvelope))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	rows, err := c.Query(context.Background(), "vuln_test", "DeviceTvmSoftwareVulnerabilities | take 2")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if gotBody["Query"] != "DeviceTvmSoftwareVulnerabilities | take 2" {
		t.Errorf("request body Query = %v", gotBody["Query"])
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// The SByte boolean arrives as a JSON number and must be handed back as one,
	// not coerced — the collector decides what 0/1 means.
	if v, ok := rows[0]["IsExploitAvailable"].(float64); !ok || v != 1 {
		t.Errorf("IsExploitAvailable = %v (%T), want float64 1", rows[0]["IsExploitAvailable"], rows[0]["IsExploitAvailable"])
	}
	if rows[0]["CveId"] != "CVE-2026-33829" {
		t.Errorf("CveId = %v", rows[0]["CveId"])
	}
}

func TestQuery_EmptyResultsNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":[],"results":[]}`))
	}))
	defer srv.Close()

	rows, err := newTestClient(t, srv).Query(context.Background(), "empty", "T | take 0")
	if err != nil {
		t.Fatalf("empty result should not error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("want 0 rows, got %d", len(rows))
	}
}

func TestQuery_NullResultsIsEmptyNotNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":[]}`))
	}))
	defer srv.Close()

	rows, err := newTestClient(t, srv).Query(context.Background(), "nullres", "T")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if rows == nil {
		t.Error("want non-nil empty slice, got nil")
	}
}

func TestQuery_EmptyKQLRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("empty KQL should be rejected before any request")
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv).Query(context.Background(), "x", ""); err == nil {
		t.Fatal("want error for empty KQL")
	}
}

func TestQuery_ErrorStatusBecomesTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv).Query(context.Background(), "vuln", "T")
	if err == nil {
		t.Fatal("want error on 403")
	}
	var he *QueryError
	if !errors.As(err, &he) {
		t.Fatalf("want *QueryError, got %T: %v", err, err)
	}
	if he.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", he.StatusCode)
	}
	if he.Code != "Authorization_RequestDenied" {
		t.Errorf("Code = %q", he.Code)
	}
	if he.Label != "vuln" {
		t.Errorf("Label = %q, want vuln", he.Label)
	}
}

func TestNewClient_Validation(t *testing.T) {
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Error("nil TenantAuth should error")
	}
	if _, err := NewClient(&auth.TenantAuth{Cred: fakeCred{}}, Options{}); err == nil {
		t.Error("empty tenant ID should error")
	}
}
