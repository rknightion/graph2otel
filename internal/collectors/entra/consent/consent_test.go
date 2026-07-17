package consent

import (
	"context"
	"encoding/json"
	"errors"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned JSON bodies (or errors). Pagination is
// modeled by chaining bodies through "@odata.nextLink"; an unmapped URL returns
// an empty collection, which is how a followed nextLink terminates.
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
		return []byte(`{"value":[]}`), nil
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const grantsURL = base + "/oauth2PermissionGrants"

func spFilterURL(appID string) string {
	// Mirrors the collector's URL-encoded $filter (spaces/quotes percent-encoded,
	// required or Graph returns HTTP 400).
	filter := "appId eq '" + appID + "'"
	return base + "/servicePrincipals?$filter=" + neturl.QueryEscape(filter) + "&$select=id,appRoles"
}

func assignedToURL(spID string) string {
	return base + "/servicePrincipals/" + spID + "/appRoleAssignedTo"
}

// emptyResourceLookups returns bodies for both well-known resource SP filter
// lookups resolving to "not provisioned in this tenant" (empty collection),
// so tests that only care about delegated grants don't need to fake the
// application side too.
func emptyResourceLookups() map[string]string {
	out := map[string]string{}
	for _, ra := range resourceApps {
		out[spFilterURL(ra.appID)] = `{"value":[]}`
	}
	return out
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// Verbatim live captures  [live-measured 2026-07-17, #165]
//
// All three bodies below are the EXACT wire responses this collector's Graph
// calls returned from the m7kni tenant, read as graph2otel-poller on
// 2026-07-17, preserving field names, nesting, and values. They replace the
// docs-derived placeholders this test used to carry (c1/c2 clients, "Contoso
// Sync", graph-sp-id, role-directory-rw) — the same class of unverified fixture
// that let #142's `"platform": "windows"` and #153's invented `riskType` key
// survive green.
//
// The collector drives a three-endpoint, two-level fetch, and each capture is
// one of those endpoints:
//
//  1. liveGrantsBody           GET /oauth2PermissionGrants
//  2. liveGraphSPBody          GET /servicePrincipals?$filter=appId eq
//                              '00000003-0000-0000-c000-000000000000'&$select=id,appRoles
//                              (the $filter value is neturl.QueryEscape-encoded
//                              on the wire — see resolveResourceServicePrincipal)
//  3. liveGraphAssignedToBody  GET /servicePrincipals/{sp.id}/appRoleAssignedTo
//
// # The finding this capture pins: m7kni's consent surface holds NO high-privilege grant or assignment
//
// Every one of the 5 delegated grants classifies "standard" (none carries a
// scope in highPrivilegeDelegatedScopes — the closest, grant #5, holds
// DeviceManagement*.ReadWrite.All, which is deliberately NOT on the delegated
// allowlist), and every one of the 5 app-role assignments resolves to a
// standard role (User.Read.All, Application.Read.All,
// TeamsAppInstallation.ReadWriteSelfForTeam.All, TeamSettings.Read.All). This
// is the healthy steady state, and it is exactly the empty-collection trap the
// risk collectors hit (#129): the high-privilege classification and twin path
// cannot be exercised by this tenant's real data. So the high-privilege tests
// below use CONSTRUCTED grant/assignment records — built on REAL wire
// components (the real Microsoft Graph SP object id, and the real, verbatim
// Directory.ReadWrite.All app-role definition off this same capture) — clearly
// labeled as constructed. The pattern mirrors entra/roles, whose live capture
// held only user members, so its service-principal / sparse-member branches
// stayed on constructed fixtures.
//
// Note the wire fields the collector deliberately does NOT map (#112 — identity
// is the log twin's job, not a full record): principalId is `null` on every
// AllPrincipals grant (JSON null decodes to Go "", which setStr omits); each
// appRoleAssignment carries createdDateTime and deletedDateTime, and each
// appRole carries allowedMemberTypes/description/displayName/isEnabled/origin,
// none of which reach a metric or a twin.

// liveGrantsBody is the verbatim GET /oauth2PermissionGrants response. principalId
// is null on the three AllPrincipals grants and a real user GUID on the two
// Principal grants.
const liveGrantsBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#oauth2PermissionGrants",
  "value": [
    {
      "clientId": "a551c556-8de2-49cc-b289-ce3ab7938167",
      "consentType": "AllPrincipals",
      "id": "VsVRpeKNzEmyic46t5OBZ-cXy2Je0lZDrVGoYVhfhjQ",
      "principalId": null,
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "scope": "User.Read"
    },
    {
      "clientId": "dd54d741-8c33-43ff-b6ca-bb7c03d84361",
      "consentType": "AllPrincipals",
      "id": "QddU3TOM_0O2yrt8A9hDYecXy2Je0lZDrVGoYVhfhjQ",
      "principalId": null,
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "scope": " openid profile email Domain.Read.All AuditLog.Read.All Directory.Read.All offline_access"
    },
    {
      "clientId": "dd54d741-8c33-43ff-b6ca-bb7c03d84361",
      "consentType": "Principal",
      "id": "QddU3TOM_0O2yrt8A9hDYecXy2Je0lZDrVGoYVhfhjTFw8-7kws1QZ75GEd6n7UE",
      "principalId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "scope": " openid profile email Domain.Read.All AuditLog.Read.All Directory.Read.All offline_access"
    },
    {
      "clientId": "f2706b1d-b062-467c-85dd-ceb3f7fb48be",
      "consentType": "AllPrincipals",
      "id": "HWtw8mKwfEaF3c6z9_tIvucXy2Je0lZDrVGoYVhfhjQ",
      "principalId": null,
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "scope": " openid profile User.Read offline_access"
    },
    {
      "clientId": "f2706b1d-b062-467c-85dd-ceb3f7fb48be",
      "consentType": "Principal",
      "id": "HWtw8mKwfEaF3c6z9_tIvucXy2Je0lZDrVGoYVhfhjTFw8-7kws1QZ75GEd6n7UE",
      "principalId": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "scope": " DeviceManagementServiceConfig.Read.All openid profile offline_access DeviceManagementConfiguration.Read.All DeviceManagementConfiguration.ReadWrite.All DeviceManagementServiceConfig.ReadWrite.All Directory.Read.All Device.Read.All"
    }
  ]
}`

// liveGraphSPID is the real object id of the Microsoft Graph service principal
// in the m7kni tenant, as returned by the $filter lookup below. The
// appRoleAssignedTo listing is keyed on this id.
const liveGraphSPID = "62cb17e7-d25e-4356-ad51-a861585f8634"

// liveGraphSPBody is the verbatim GET /servicePrincipals?$filter=...&$select=id,appRoles
// response for Microsoft Graph, trimmed from 707 app-role definitions to the 5
// this test resolves against — verbatim, full objects (the collector reads only
// id+value, but keeping allowedMemberTypes/description/displayName/isEnabled/
// origin documents the fields it drops). The first four are the roles the real
// assignments below reference; the fifth, Directory.ReadWrite.All, is the real
// high-privilege role the constructed high-privilege assignment resolves to —
// present on the wire, held by no assignment in this tenant.
const liveGraphSPBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals(id,appRoles)",
  "value": [
    {
      "id": "62cb17e7-d25e-4356-ad51-a861585f8634",
      "appRoles": [
        {
          "allowedMemberTypes": [
            "Application"
          ],
          "description": "Allows the app to read user profiles without a signed in user.",
          "displayName": "Read all users' full profiles",
          "id": "df021288-bdef-4463-88db-98f22de89214",
          "isEnabled": true,
          "origin": "Application",
          "value": "User.Read.All"
        },
        {
          "allowedMemberTypes": [
            "Application"
          ],
          "description": "Allows the app to read all applications and service principals without a signed-in user.",
          "displayName": "Read all applications",
          "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
          "isEnabled": true,
          "origin": "Application",
          "value": "Application.Read.All"
        },
        {
          "allowedMemberTypes": [
            "Application"
          ],
          "description": "Allows a Teams app to read, install, upgrade, and uninstall itself in any team, without a signed-in user.",
          "displayName": "Allow the Teams app to manage itself for all teams",
          "id": "9f67436c-5415-4e7f-8ac1-3014a7132630",
          "isEnabled": true,
          "origin": "Application",
          "value": "TeamsAppInstallation.ReadWriteSelfForTeam.All"
        },
        {
          "allowedMemberTypes": [
            "Application"
          ],
          "description": "Read all team's settings, without a signed-in user.",
          "displayName": "Read all teams' settings",
          "id": "242607bd-1d2c-432c-82eb-bdb27baa23ab",
          "isEnabled": true,
          "origin": "Application",
          "value": "TeamSettings.Read.All"
        },
        {
          "allowedMemberTypes": [
            "Application"
          ],
          "description": "Allows the app to read and write data in your organization's directory, such as users, and groups, without a signed-in user.  Does not allow user or group deletion.",
          "displayName": "Read and write directory data",
          "id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
          "isEnabled": true,
          "origin": "Application",
          "value": "Directory.ReadWrite.All"
        }
      ]
    }
  ]
}`

// liveGraphAssignedToBody is the verbatim first page of
// GET /servicePrincipals/62cb17e7.../appRoleAssignedTo (the live listing held 104
// assignments across pages; trimmed to the first 5 representative records). Its
// @odata.nextLink is preserved verbatim: the collector follows it, and the
// fake's default empty response terminates the walk — exercising the real
// pagination path on a real skiptoken. Every appRoleId resolves to a STANDARD
// role via liveGraphSPBody; principalDisplayName / resourceDisplayName are the
// real inline names Graph returns on this resource.
const liveGraphAssignedToBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#appRoleAssignments",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/servicePrincipals/62cb17e7-d25e-4356-ad51-a861585f8634/appRoleAssignedTo?$skiptoken=RFNwdAoAAQAAAAAAAAAAFAAAANQTZ7_TB4lJsbAbpF2f_tsBAAAAAAAAAAAAAAAAAAAXMS4yLjg0MC4xMTM1NTYuMS40LjIzMzEGAAAAAAABhvTRb3j5mkOMcwOFM1w0iAE6AQAAAQAAAAA",
  "value": [
    {
      "appRoleId": "df021288-bdef-4463-88db-98f22de89214",
      "createdDateTime": "2025-09-11T14:25:30.0756405Z",
      "deletedDateTime": null,
      "id": "VsVRpeKNzEmyic46t5OBZz4qn4i5cj5LsLp-K69dN1s",
      "principalDisplayName": "Meraki-IdP-Sync",
      "principalId": "a551c556-8de2-49cc-b289-ce3ab7938167",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634"
    },
    {
      "appRoleId": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
      "createdDateTime": "2025-09-11T14:25:30.0076418Z",
      "deletedDateTime": null,
      "id": "VsVRpeKNzEmyic46t5OBZzjSHQA0pyJGvixof14O_4o",
      "principalDisplayName": "Meraki-IdP-Sync",
      "principalId": "a551c556-8de2-49cc-b289-ce3ab7938167",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634"
    },
    {
      "appRoleId": "9f67436c-5415-4e7f-8ac1-3014a7132630",
      "createdDateTime": "2025-10-20T12:55:05.4193042Z",
      "deletedDateTime": null,
      "id": "GC00Epn5uEOkVMo3ftLGpHGb1cJ_jk1FmPoIJoiH0Qw",
      "principalDisplayName": "Grafana IRM",
      "principalId": "12342d18-f999-43b8-a454-ca377ed2c6a4",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634"
    },
    {
      "appRoleId": "df021288-bdef-4463-88db-98f22de89214",
      "createdDateTime": "2025-10-20T12:55:05.221292Z",
      "deletedDateTime": null,
      "id": "GC00Epn5uEOkVMo3ftLGpA5KXaMJA-BBn-nNa_BFtrY",
      "principalDisplayName": "Grafana IRM",
      "principalId": "12342d18-f999-43b8-a454-ca377ed2c6a4",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634"
    },
    {
      "appRoleId": "242607bd-1d2c-432c-82eb-bdb27baa23ab",
      "createdDateTime": "2025-10-20T12:55:05.3583005Z",
      "deletedDateTime": null,
      "id": "GC00Epn5uEOkVMo3ftLGpMbrqqBC8hFOpcHaOnmcOtk",
      "principalDisplayName": "Grafana IRM",
      "principalId": "12342d18-f999-43b8-a454-ca377ed2c6a4",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "62cb17e7-d25e-4356-ad51-a861585f8634"
    }
  ]
}`

// liveGraph wires the three verbatim captures into the two-level fetch the
// collector drives: the delegated grants list, the Microsoft Graph SP $filter
// lookup, and that SP's appRoleAssignedTo listing. Exchange Online (the second
// well-known resourceApp) resolves to an empty collection — no capture was
// taken for it, and this tenant's Exchange app-role assignments are out of this
// fixture's scope, so it models the "not provisioned / nothing to scan" path.
func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		grantsURL:                          liveGrantsBody,
		spFilterURL(resourceApps[0].appID): liveGraphSPBody, // microsoft_graph, 00000003-...
		assignedToURL(liveGraphSPID):       liveGraphAssignedToBody,
		spFilterURL(resourceApps[1].appID): `{"value":[]}`, // office365_exchange_online, 00000002-...
	}}
}

// TestCollectorEmitsLiveConsentSurfaceEndToEnd drives all three verbatim #165
// captures through Collect into a Recorder — the whole two-level fetch (grants,
// SP $filter resolution, appRoleAssignedTo paging over a real skiptoken
// nextLink), classifying real records rather than calling a classifier
// directly.
//
// It pins the real finding: m7kni's consent surface holds ZERO high-privilege
// grants and ZERO high-privilege assignments, so the bounded gauge reads all
// 10 grants+assignments as "standard" and NO log twin is emitted. The
// application "standard" count being 5 (not 0) is the proof the SP resolved and
// its appRoleAssignedTo page was fetched and classified — the exact path the
// old graph-sp-id/role-directory-rw placeholders faked.
func TestCollectorEmitsLiveConsentSurfaceEndToEnd(t *testing.T) {
	rec := telemetrytest.New()
	if err := New(liveGraph(), nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := seriesMap(t, rec, metricName)
	want := map[[2]string]float64{
		{"delegated", "privileged"}:   0,
		{"delegated", "standard"}:     5, // all 5 real grants classify standard
		{"application", "privileged"}: 0,
		{"application", "standard"}:   5, // all 5 real Microsoft Graph assignments classify standard
	}
	assertSeries(t, got, want)

	// No high-privilege record on the wire ⇒ no twin. If this ever fails, the
	// tenant grew a high-privilege consent grant — a real signal, not a test bug.
	if twins := logsNamed(rec.LogRecords(), eventConsentGrant); len(twins) != 0 {
		t.Fatalf("emitted %d %s twins from the live capture, want 0 (no high-privilege consent exists on this tenant): %+v", len(twins), eventConsentGrant, twins)
	}
}

// ----------------------------------------------------------------------------
// High-privilege classification and twin coverage.
//
// CONSTRUCTED, not measured. The live m7kni consent surface holds no
// high-privilege grant or assignment (see the capture provenance above), so
// these fixtures build the high-privilege branch by hand — but on REAL wire
// components: the delegated grant carries the real Directory.ReadWrite.All scope
// token, and the assignment carries the real Directory.ReadWrite.All appRoleId
// (19dbc75e-...) resolved against the verbatim liveGraphSPBody. Their client /
// principal ids are placeholders, not tenant identities; do not read them as
// measured (mirrors entra/roles' constructed service-principal and sparse-member
// fixtures).

// constructedHighPrivGrant is a delegated grant whose scope includes a real
// high-privilege token (Directory.ReadWrite.All); its ids are placeholders.
const constructedHighPrivGrant = `{"id":"hp-grant-1","clientId":"11111111-1111-1111-1111-111111111111","consentType":"AllPrincipals","resourceId":"62cb17e7-d25e-4356-ad51-a861585f8634","scope":"User.Read Directory.ReadWrite.All"}`

// constructedHighPrivAssignment references the real Directory.ReadWrite.All
// appRoleId from liveGraphSPBody, on the real Microsoft Graph resource; its
// principal is a placeholder over-privileged app.
const constructedHighPrivAssignment = `{"id":"hp-assign-1","appRoleId":"19dbc75e-c2e2-444c-a770-ec69d8559fc7","principalId":"22222222-2222-2222-2222-222222222222","principalDisplayName":"Legacy Sync App","principalType":"ServicePrincipal","resourceId":"62cb17e7-d25e-4356-ad51-a861585f8634","resourceDisplayName":"Microsoft Graph"}`

// grantsBodyWith wraps grant JSON objects into an oauth2PermissionGrants page.
func grantsBodyWith(grants ...string) string {
	return `{"value":[` + strings.Join(grants, ",") + `]}`
}

// assignedToBodyWith wraps appRoleAssignment JSON objects into a single
// appRoleAssignedTo page (no nextLink).
func assignedToBodyWith(assignments ...string) string {
	return `{"value":[` + strings.Join(assignments, ",") + `]}`
}

// liveGrantValues returns the 5 verbatim grant objects as separate JSON strings,
// so a test can splice a constructed high-privilege grant alongside the real
// standard ones.
func liveGrantValues(t *testing.T) []string {
	t.Helper()
	return rawValues(t, liveGrantsBody)
}

// liveAssignmentValues returns the 5 verbatim appRoleAssignment objects as
// separate JSON strings.
func liveAssignmentValues(t *testing.T) []string {
	t.Helper()
	return rawValues(t, liveGraphAssignedToBody)
}

// rawValues extracts the elements of an OData "value" array as verbatim JSON
// strings (json.RawMessage re-emitted unmodified — no field is normalized).
func rawValues(t *testing.T, body string) []string {
	t.Helper()
	var env struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode value array: %v", err)
	}
	out := make([]string, 0, len(env.Value))
	for _, v := range env.Value {
		out = append(out, string(v))
	}
	return out
}

func TestCollectClassifiesDelegatedGrantsByPrivilege(t *testing.T) {
	// The 5 real standard grants + 1 constructed high-privilege grant.
	grants := append(liveGrantValues(t), constructedHighPrivGrant)
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: grantsBodyWith(grants...),
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := seriesMap(t, rec, metricName)
	want := map[[2]string]float64{
		{"delegated", "privileged"}:   1, // the constructed Directory.ReadWrite.All grant
		{"delegated", "standard"}:     5, // all 5 real grants
		{"application", "privileged"}: 0,
		{"application", "standard"}:   0,
	}
	assertSeries(t, got, want)
}

func TestCollectClassifiesAppRoleAssignmentsByPrivilege(t *testing.T) {
	graphSP := resourceApps[0]
	otherSP := resourceApps[1]

	// The 5 real standard assignments + 1 constructed high-privilege assignment,
	// resolved against the verbatim Microsoft Graph SP app-role map.
	assignments := append(liveAssignmentValues(t), constructedHighPrivAssignment)

	bodies := map[string]string{
		grantsURL:                    `{"value":[]}`,
		spFilterURL(graphSP.appID):   liveGraphSPBody,
		assignedToURL(liveGraphSPID): assignedToBodyWith(assignments...),
		spFilterURL(otherSP.appID):   `{"value":[]}`,
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := seriesMap(t, rec, metricName)
	want := map[[2]string]float64{
		{"delegated", "privileged"}:   0,
		{"delegated", "standard"}:     0,
		{"application", "privileged"}: 1, // Directory.ReadWrite.All (19dbc75e-...)
		{"application", "standard"}:   5, // User.Read.All x2, Application.Read.All, TeamsAppInstallation..., TeamSettings.Read.All
	}
	assertSeries(t, got, want)
}

func TestCollectSkipsResourceNotProvisionedInTenant(t *testing.T) {
	// Both well-known resource service principals resolve to an empty
	// collection (e.g. Exchange Online isn't provisioned in this tenant) --
	// this must be treated as "nothing to count", not an error.
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: `{"value":[]}`,
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err != nil {
		t.Fatalf("Collect: %v, want nil (unprovisioned resource is not a failure)", err)
	}
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series, want 4 (all-zero bounded set)", len(pts))
	}
}

func TestCollectIsResilientToPartialFailure(t *testing.T) {
	bodies := merge(emptyResourceLookups(), map[string]string{})
	g := &fakeGraph{
		bodies: bodies,
		errs:   map[string]error{grantsURL: errors.New("throttled")},
	}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the oauth2PermissionGrants failure as an error")
	}
	// The application-side counts must still be emitted (bounded, all zero here).
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series, want 4 even under partial failure", len(pts))
	}
}

func TestCollectEmitsOnlyBoundedSeriesRegardlessOfGrantVolume(t *testing.T) {
	// Cardinality guard: build a large synthetic grant list and assert the
	// emitted series count never grows past the fixed 2x2 classification set,
	// and that no attribute carries a per-grant identifier (clientId, id, ...).
	var sb strings.Builder
	sb.WriteString(`{"value":[`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"clientId":"c` + strconv.Itoa(i) + `","consentType":"Principal","scope":"User.Read"}`)
	}
	sb.WriteString(`]}`)

	bodies := merge(emptyResourceLookups(), map[string]string{grantsURL: sb.String()})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricName)
	if len(pts) != 4 {
		t.Fatalf("got %d series for 500 grants, want 4 (bounded)", len(pts))
	}
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "consent_type" && k != "privilege" {
				t.Errorf("unexpected attribute key %q on emitted series (potential cardinality leak)", k)
			}
		}
	}
}

// logsNamed returns the recorded log records carrying the given EventName.
func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectTwinsOnlyHighPrivilegeDelegatedGrants is the scoping guard for the
// delegated side: the 5 real standard grants must NOT produce a log; the one
// constructed Directory.ReadWrite.All grant must produce exactly one, carrying
// the raw identifying fields the metric can never hold. The scope token is real;
// the client/resource ids are the constructed record's.
func TestCollectTwinsOnlyHighPrivilegeDelegatedGrants(t *testing.T) {
	grants := append(liveGrantValues(t), constructedHighPrivGrant)
	bodies := merge(emptyResourceLookups(), map[string]string{
		grantsURL: grantsBodyWith(grants...),
	})
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	all := logsNamed(rec.LogRecords(), eventConsentGrant)
	var delegated []telemetrytest.LogRecord
	for _, r := range all {
		if r.Attrs["consent_type"] == consentTypeDelegated {
			delegated = append(delegated, r)
		}
	}
	if len(delegated) != 1 {
		t.Fatalf("emitted %d delegated %s logs, want 1 (the 5 standard-scope grants must not be twinned)", len(delegated), eventConsentGrant)
	}

	r := delegated[0]
	want := map[string]string{
		"id":           "hp-grant-1",
		"consent_type": "delegated",
		"privilege":    "privileged",
		"client_id":    "11111111-1111-1111-1111-111111111111",
		"resource_id":  "62cb17e7-d25e-4356-ad51-a861585f8634",
		"scope":        "User.Read Directory.ReadWrite.All",
	}
	for k, v := range want {
		if r.Attrs[k] != v {
			t.Errorf("delegated grant log attr %q = %q, want %q", k, r.Attrs[k], v)
		}
	}
	if v, ok := r.Attrs["principal_id"]; ok {
		t.Errorf("AllPrincipals grant (empty principalId) emitted principal_id attr %q, want omitted", v)
	}
}

// TestCollectTwinsOnlyHighPrivilegeAppRoleAssignments is the scoping guard for
// the application side: the 5 real standard assignments must NOT produce logs;
// the one constructed Directory.ReadWrite.All assignment must, carrying the
// resolved app role value plus the display names Graph returns inline. The app
// role id and value are real, off liveGraphSPBody; the principal is constructed.
func TestCollectTwinsOnlyHighPrivilegeAppRoleAssignments(t *testing.T) {
	graphSP := resourceApps[0]
	otherSP := resourceApps[1]

	assignments := append(liveAssignmentValues(t), constructedHighPrivAssignment)

	bodies := map[string]string{
		grantsURL:                    `{"value":[]}`,
		spFilterURL(graphSP.appID):   liveGraphSPBody,
		assignedToURL(liveGraphSPID): assignedToBodyWith(assignments...),
		spFilterURL(otherSP.appID):   `{"value":[]}`,
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	all := logsNamed(rec.LogRecords(), eventConsentGrant)
	var application []telemetrytest.LogRecord
	for _, r := range all {
		if r.Attrs["consent_type"] == consentTypeApplication {
			application = append(application, r)
		}
	}
	if len(application) != 1 {
		t.Fatalf("emitted %d application %s logs, want 1 (the 5 standard assignments must not be twinned)", len(application), eventConsentGrant)
	}

	r := application[0]
	want := map[string]string{
		"id":                     "hp-assign-1",
		"consent_type":           "application",
		"privilege":              "privileged",
		"resource_label":         "microsoft_graph",
		"resource_id":            "62cb17e7-d25e-4356-ad51-a861585f8634",
		"resource_display_name":  "Microsoft Graph",
		"app_role_id":            "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
		"app_role":               "Directory.ReadWrite.All",
		"principal_id":           "22222222-2222-2222-2222-222222222222",
		"principal_display_name": "Legacy Sync App",
		"principal_type":         "ServicePrincipal",
	}
	for k, v := range want {
		if r.Attrs[k] != v {
			t.Errorf("app role assignment log attr %q = %q, want %q", k, r.Attrs[k], v)
		}
	}
}

// TestLogTwinNeverReachesMetricAttrs re-runs the mixed high/standard fixtures
// above and asserts that none of the per-entity fields carried by the log
// twin (id, client_id, principal_id, resource_id, scope, app_role_id, ...)
// ever leak onto a metric point's attributes -- the metric stays bounded to
// (consent_type, privilege) regardless of what the log twin now carries.
func TestLogTwinNeverReachesMetricAttrs(t *testing.T) {
	graphSP := resourceApps[0]
	otherSP := resourceApps[1]

	grants := append(liveGrantValues(t), constructedHighPrivGrant)
	assignments := append(liveAssignmentValues(t), constructedHighPrivAssignment)

	bodies := map[string]string{
		grantsURL:                    grantsBodyWith(grants...),
		spFilterURL(graphSP.appID):   liveGraphSPBody,
		assignedToURL(liveGraphSPID): assignedToBodyWith(assignments...),
		spFilterURL(otherSP.appID):   `{"value":[]}`,
	}
	g := &fakeGraph{bodies: bodies}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, p := range rec.MetricPoints(metricName) {
		for k := range p.Attrs {
			if k != "consent_type" && k != "privilege" {
				t.Errorf("metric %s has unexpected attribute %q (per-entity leak from the log twin?): %v", metricName, k, p.Attrs)
			}
		}
	}
}

// TestConsentGrantLogTwinSeverityIsWarn drives the log-twin builders directly
// (the risk-collector idiom) so the assertion compares telemetry.Severity
// values rather than the recorder's already-translated OTEL wire numbers.
// Every twinned grant is, by definition, already classified high-privilege --
// there is no lower-severity case to branch on here (contrast risk.logTwin,
// which twins every risk level and escalates only "high").
func TestConsentGrantLogTwinSeverityIsWarn(t *testing.T) {
	delegatedEv := delegatedGrantLogTwin(oauth2Grant{ID: "g1", ClientID: "c1", Scope: "Directory.ReadWrite.All"})
	if delegatedEv.Severity != telemetry.SeverityWarn {
		t.Errorf("delegated grant twin severity = %v, want SeverityWarn", delegatedEv.Severity)
	}
	if delegatedEv.Name != eventConsentGrant {
		t.Errorf("delegated grant twin EventName = %q, want %q", delegatedEv.Name, eventConsentGrant)
	}

	appEv := appRoleAssignmentLogTwin(appRoleAssignment{ID: "a1", AppRoleID: "role1"}, resourceApps[0], "Directory.ReadWrite.All")
	if appEv.Severity != telemetry.SeverityWarn {
		t.Errorf("app role assignment twin severity = %v, want SeverityWarn", appEv.Severity)
	}
	if appEv.Name != eventConsentGrant {
		t.Errorf("app role assignment twin EventName = %q, want %q", appEv.Name, eventConsentGrant)
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.consent" {
		t.Errorf("Name = %q, want entra.consent", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Error("DefaultInterval must be positive")
	}
	perms := c.RequiredPermissions()
	want := map[string]bool{"Directory.Read.All": true, "Application.Read.All": true}
	if len(perms) != len(want) {
		t.Fatalf("RequiredPermissions = %v, want %v", perms, want)
	}
	for _, p := range perms {
		if !want[p] {
			t.Errorf("unexpected permission %q", p)
		}
	}
}

// seriesMap flattens the recorded points for metric into a
// (consent_type, privilege) -> value map, failing the test on any unexpected
// attribute shape.
func seriesMap(t *testing.T, rec *telemetrytest.Recorder, metric string) map[[2]string]float64 {
	t.Helper()
	pts := rec.MetricPoints(metric)
	out := map[[2]string]float64{}
	for _, p := range pts {
		key := [2]string{p.Attrs["consent_type"], p.Attrs["privilege"]}
		out[key] = p.Value
	}
	return out
}

func assertSeries(t *testing.T, got map[[2]string]float64, want map[[2]string]float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d series, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %v = %v, want %v", k, got[k], v)
		}
	}
}
