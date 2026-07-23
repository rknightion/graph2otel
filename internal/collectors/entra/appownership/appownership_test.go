package appownership

import (
	"context"
	"fmt"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("fakeGraph: no body stubbed for %s", url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const (
	v1   = "https://graph.microsoft.com/v1.0"
	beta = "https://graph.microsoft.com/beta"
)

// liveApps is VERBATIM from m7kni `[live-measured 2026-07-23, #244]`: three
// applications, all ownerless (owners: []). A synthetic fourth app with an owner
// is appended to exercise the has_owner=true path the live tenant cannot.
const liveApps = `{
  "value": [
    {"id": "067cdb04-d9df-4760-befa-bc05a4014a99", "appId": "5dd3b862-260c-497d-b872-91571a643a91", "displayName": "intuneomator-automation", "signInAudience": "AzureADMyOrg", "createdDateTime": "2025-01-01T00:00:00Z", "owners": []},
    {"id": "a2", "appId": "app-2", "displayName": "PH - OTEL Demo", "signInAudience": "AzureADMyOrg", "owners": []},
    {"id": "a3", "appId": "app-3", "displayName": "Postman", "signInAudience": "AzureADMultipleOrgs", "owners": []},
    {"id": "a4", "appId": "app-4", "displayName": "Owned App", "signInAudience": "AzureADMyOrg", "owners": [{"userPrincipalName": "admin@m7kni.io", "displayName": "Admin"}]}
  ]
}`

// liveSPs is VERBATIM: three service principals, all Application type, all
// ownerless.
const liveSPs = `{
  "value": [
    {"id": "012a652a-fb9f-44cd-940e-6ffaf620a54c", "appId": "e933bd07-d2ee-4f1d-933c-3752b819567b", "displayName": "Azure Monitor Control Service", "servicePrincipalType": "Application", "owners": []},
    {"id": "s2", "appId": "sp-2", "displayName": "SP Two", "servicePrincipalType": "Application", "owners": []},
    {"id": "s3", "appId": "sp-3", "displayName": "SP Three", "servicePrincipalType": "ManagedIdentity", "owners": []}
  ]
}`

// liveFICsEmpty is VERBATIM: the beta federatedIdentityCredentials $expand
// returns the container present but EMPTY on m7kni (zero FICs).
const liveFICsEmpty = `{
  "value": [
    {"id": "067cdb04-d9df-4760-befa-bc05a4014a99", "appId": "5dd3b862-260c-497d-b872-91571a643a91", "displayName": "intuneomator-automation", "federatedIdentityCredentials@odata.context": "x", "federatedIdentityCredentials": []}
  ]
}`

// ficsWithGitHub is SYNTHETIC (m7kni has zero FICs, so the record shape cannot be
// wire-validated): one GitHub-OIDC federated credential, the supply-chain trust
// edge this collector exists to surface.
const ficsWithGitHub = `{
  "value": [
    {"id": "a1", "appId": "app-1", "displayName": "ci-deployer", "federatedIdentityCredentials": [
      {"name": "gh-main", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:org/repo:ref:refs/heads/main", "audiences": ["api://AzureADTokenExchange"]}
    ]}
  ]
}`

func graphWith(fics string) *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		v1 + appsOwnersPath: liveApps,
		v1 + spsOwnersPath:  liveSPs,
		beta + appsFICPath:  fics,
	}}
}

// TestAppOwnershipCountsAndWarn pins the ownership gauge (three ownerless live
// apps + one owned synthetic) and the Warn-on-ownerless twin.
func TestAppOwnershipCountsAndWarn(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(graphWith(liveFICsEmpty), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricAppOwnership) {
		got[p.Attrs["has_owner"]+"|"+p.Attrs["sign_in_audience"]] = p.Value
	}
	if got["false|AzureADMyOrg"] != 2 || got["false|AzureADMultipleOrgs"] != 1 || got["true|AzureADMyOrg"] != 1 {
		t.Errorf("app ownership counts wrong: %v", got)
	}
	// Warn on each ownerless app; Info on the owned one.
	warn, info := 0, 0
	for _, r := range rec.LogRecords() {
		if r.EventName != eventApplication {
			continue
		}
		switch r.SeverityText {
		case "WARN":
			warn++
		case "INFO":
			info++
		}
	}
	if warn != 3 || info != 1 {
		t.Errorf("app twin severities: warn=%d info=%d, want 3/1", warn, info)
	}
}

// TestSPOwnershipCounts pins the service-principal ownership gauge by type.
func TestSPOwnershipCounts(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(graphWith(liveFICsEmpty), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]float64{}
	for _, p := range rec.MetricPoints(metricSPOwnership) {
		got[p.Attrs["has_owner"]+"|"+p.Attrs["service_principal_type"]] = p.Value
	}
	if got["false|Application"] != 2 || got["false|ManagedIdentity"] != 1 {
		t.Errorf("SP ownership counts wrong: %v", got)
	}
}

// TestFICEmptyOnTenant pins that the empty live FIC container emits no FIC twin
// and a zero-series gauge — an empty collection is not a bug.
func TestFICEmptyOnTenant(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(graphWith(liveFICsEmpty), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range rec.LogRecords() {
		if r.EventName == eventFIC {
			t.Error("no FIC twin should be emitted when the tenant has zero FICs")
		}
	}
}

// TestFICTwinFromGitHubOIDC pins the FIC twin shape (synthetic — m7kni has zero
// FICs) and its issuer_host gauge bucket.
func TestFICTwinFromGitHubOIDC(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(graphWith(ficsWithGitHub), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var fic *telemetrytest.LogRecord
	for _, r := range rec.LogRecords() {
		if r.EventName == eventFIC {
			rr := r
			fic = &rr
		}
	}
	if fic == nil {
		t.Fatal("no FIC twin emitted")
	}
	if fic.SeverityText != "WARN" {
		t.Errorf("FIC severity = %q, want WARN", fic.SeverityText)
	}
	if fic.Attrs["subject"] != "repo:org/repo:ref:refs/heads/main" {
		t.Errorf("subject = %q", fic.Attrs["subject"])
	}
	if fic.Attrs["credential_name"] != "gh-main" {
		t.Errorf("credential_name = %q", fic.Attrs["credential_name"])
	}
	var hosts []string
	for _, p := range rec.MetricPoints(metricFIC) {
		hosts = append(hosts, p.Attrs["issuer_host"])
	}
	if len(hosts) != 1 || hosts[0] != "token.actions.githubusercontent.com" {
		t.Errorf("FIC issuer_host gauge = %v, want [token.actions.githubusercontent.com]", hosts)
	}
}

func TestNameAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.app_ownership" {
		t.Errorf("Name = %q", c.Name())
	}
	if perms := c.RequiredPermissions(); len(perms) != 1 || perms[0] != "Application.Read.All" {
		t.Errorf("RequiredPermissions = %v", perms)
	}
}
