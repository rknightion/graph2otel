package signinactivity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
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
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/beta"

// now is a fixed test clock. Every live sign-in in the captures below is dated
// 2026-07-16 (a healthy tenant's active workloads are all recently used), so a
// clock ~45 days after makes every entity stale past the 30d threshold but not
// the 90d one — which is what lets the aggregate test assert a non-zero, but
// bounded, stale gauge from real data. See TestBucketStaleCumulativeAndSentinel
// for the fresh/never-signed-in ends of the bucketing math the captures cannot
// reach.
var now = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// VERBATIM live captures, read as graph2otel-poller against the m7kni tenant on
// 2026-07-17 `[live-measured 2026-07-17, #165]`. Each is the exact wire body of
// one of this collector's three BETA fetches:
//
//   - liveSPBody              GET /beta/reports/servicePrincipalSignInActivities
//   - liveAppCredBody         GET /beta/reports/appCredentialSignInActivities
//   - liveAppSummaryBody      GET /beta/reports/getAzureADApplicationSignInSummary(period='D7')
//
// They replace the earlier docs-derived placeholders (sp-a/sp-b, appId a/b/c and
// an ago()-synthesized timestamp grid). Trimmed to 5 records each, preserving the
// distinct shapes the real report returns — nothing else is altered: field
// names, nesting, casing, GUIDs and timestamps are byte-for-byte the wire.
//
// Wire facts a mapper must survive, pinned here rather than asserted from docs:
//
//   - `id` is a base64 blob (the URL-safe encoded appId/keyId), NOT the GUID —
//     appId/keyId are separate fields.
//   - servicePrincipalObjectId is `null` on every appCredentialSignInActivity
//     record (N=5); JSON null decodes to "" and is correctly omitted.
//   - servicePrincipalSignInActivity carries FOUR per-flow breakdown objects
//     (applicationAuthentication{Client,Resource}SignInActivity,
//     delegated{Client,Resource}SignInActivity) the collector deliberately
//     ignores in favor of the aggregate lastSignInActivity. The application-only
//     record (appId 4ba261ce) has delegatedClientSignInActivity == null, the
//     shape distinction the trim preserves.
//   - lastSignInActivity/signInActivity carry only lastSignInDateTime +
//     lastSignInRequestId on the wire (N=10) — the other four signInActivity
//     sub-fields the mapper can decode (lastNonInteractive*, lastSuccessful*)
//     never appear on this tenant, so the emitted golden does not carry them.
//   - the D7 summary rows carry appDisplayName/id/successPercentage the mapper
//     ignores (it sums only the two counts), and one row has appDisplayName "".
const (
	liveSPBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#reports/servicePrincipalSignInActivities",
  "value": [
    {
      "appId": "32d104a5-589f-4e8c-9a70-b90d47f8722d",
      "applicationAuthenticationClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:59:55.212Z",
        "lastSignInRequestId": "dba5b88f-e99d-4f85-9729-590149764400"
      },
      "applicationAuthenticationResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T21:59:57.035Z",
        "lastSignInRequestId": "Aggregated"
      },
      "delegatedResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "id": "MzJkMTA0YTUtNTg5Zi00ZThjLTlhNzAtYjkwZDQ3Zjg3MjJk",
      "lastSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:59:55.212Z",
        "lastSignInRequestId": "dba5b88f-e99d-4f85-9729-590149764400"
      }
    },
    {
      "appId": "5f7d3d24-9d94-4f04-b2ce-546b927b3ba7",
      "applicationAuthenticationClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:58:01.64Z",
        "lastSignInRequestId": "4d75a177-0b7c-494e-805a-9677901c4300"
      },
      "applicationAuthenticationResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T21:55:45.414Z",
        "lastSignInRequestId": "c3bcca37-29b9-4cea-887a-a8c29e0c4400"
      },
      "delegatedResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "id": "NWY3ZDNkMjQtOWQ5NC00ZjA0LWIyY2UtNTQ2YjkyN2IzYmE3",
      "lastSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:58:01.64Z",
        "lastSignInRequestId": "4d75a177-0b7c-494e-805a-9677901c4300"
      }
    },
    {
      "appId": "4ba261ce-287a-459c-93eb-7047bab3cfb9",
      "applicationAuthenticationClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:50:24.726Z",
        "lastSignInRequestId": "52573f55-a86a-4f8b-af8d-5603138c4d00"
      },
      "applicationAuthenticationResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedClientSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "id": "NGJhMjYxY2UtMjg3YS00NTljLTkzZWItNzA0N2JhYjNjZmI5",
      "lastSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:50:24.726Z",
        "lastSignInRequestId": "52573f55-a86a-4f8b-af8d-5603138c4d00"
      }
    },
    {
      "appId": "6ca55f56-d6fe-4c92-ad67-c30e5d3fe433",
      "applicationAuthenticationClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:44:01.601Z",
        "lastSignInRequestId": "e4aaf274-8f56-4340-aa04-d257a3d64c00"
      },
      "applicationAuthenticationResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T21:49:30.086Z",
        "lastSignInRequestId": "Aggregated"
      },
      "delegatedResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "id": "NmNhNTVmNTYtZDZmZS00YzkyLWFkNjctYzMwZTVkM2ZlNDMz",
      "lastSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:44:01.601Z",
        "lastSignInRequestId": "e4aaf274-8f56-4340-aa04-d257a3d64c00"
      }
    },
    {
      "appId": "2c92ce28-126c-47c1-82b0-410b64502989",
      "applicationAuthenticationClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:42:14.262Z",
        "lastSignInRequestId": "46620e46-578e-4242-905a-e00bc14c2e00"
      },
      "applicationAuthenticationResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "delegatedClientSignInActivity": {
        "lastSignInDateTime": "2026-07-16T21:51:50.806Z",
        "lastSignInRequestId": "Aggregated"
      },
      "delegatedResourceSignInActivity": {
        "lastSignInDateTime": null,
        "lastSignInRequestId": null
      },
      "id": "MmM5MmNlMjgtMTI2Yy00N2MxLTgyYjAtNDEwYjY0NTAyOTg5",
      "lastSignInActivity": {
        "lastSignInDateTime": "2026-07-16T23:42:14.262Z",
        "lastSignInRequestId": "46620e46-578e-4242-905a-e00bc14c2e00"
      }
    }
  ]
}`

	liveAppCredBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#reports/appCredentialSignInActivities",
  "value": [
    {
      "appId": "32d104a5-589f-4e8c-9a70-b90d47f8722d",
      "appObjectId": "d99b393e-2b21-491d-ba2e-d4bce6fe1bd0",
      "createdDateTime": "2026-07-15T22:03:48.075Z",
      "credentialOrigin": "application",
      "expirationDateTime": "2027-05-15T00:00:00Z",
      "id": "NmZiYjFjZDItZmM3MC00ZTRjLWIzYWUtZGE1NzY1ODBhMjQw",
      "keyId": "6fbb1cd2-fc70-4e4c-b3ae-da576580a240",
      "keyType": "certificate",
      "keyUsage": "verify",
      "resourceId": "04687a56-4fc2-4e36-b274-b862fb649733",
      "servicePrincipalObjectId": null,
      "signInActivity": {
        "lastSignInDateTime": "2026-07-16T23:59:55.212Z",
        "lastSignInRequestId": "dba5b88f-e99d-4f85-9729-590149764400"
      }
    },
    {
      "appId": "5f7d3d24-9d94-4f04-b2ce-546b927b3ba7",
      "appObjectId": "20310cfa-a958-4e78-92f1-6094aace59c6",
      "createdDateTime": "2026-06-05T18:50:53.146Z",
      "credentialOrigin": "application",
      "expirationDateTime": "2028-06-04T17:36:33Z",
      "id": "ODhjZGI4MjktZmZjYy00M2Q5LWI3OGMtMmViM2JhMTc5NWRk",
      "keyId": "88cdb829-ffcc-43d9-b78c-2eb3ba1795dd",
      "keyType": "password",
      "keyUsage": "verify",
      "resourceId": "00000003-0000-0000-c000-000000000000",
      "servicePrincipalObjectId": null,
      "signInActivity": {
        "lastSignInDateTime": "2026-07-16T23:58:01.64Z",
        "lastSignInRequestId": "4d75a177-0b7c-494e-805a-9677901c4300"
      }
    },
    {
      "appId": "6ca55f56-d6fe-4c92-ad67-c30e5d3fe433",
      "appObjectId": "32ddc40b-195b-4727-9b63-999650bfe84c",
      "createdDateTime": "2025-09-11T15:02:05.637Z",
      "credentialOrigin": "application",
      "expirationDateTime": "2027-09-11T14:22:57.465Z",
      "id": "Njg1NTU3M2ItZDkzZS00NGQzLWIyODktYTcwOGFlZGRkOGJl",
      "keyId": "6855573b-d93e-44d3-b289-a708aeddd8be",
      "keyType": "password",
      "keyUsage": "verify",
      "resourceId": "00000003-0000-0000-c000-000000000000",
      "servicePrincipalObjectId": null,
      "signInActivity": {
        "lastSignInDateTime": "2026-07-16T23:44:01.601Z",
        "lastSignInRequestId": "e4aaf274-8f56-4340-aa04-d257a3d64c00"
      }
    },
    {
      "appId": "2c92ce28-126c-47c1-82b0-410b64502989",
      "appObjectId": "a56d47cd-85aa-4972-b085-8c5a012b7111",
      "createdDateTime": "2026-07-15T23:23:54.594Z",
      "credentialOrigin": "application",
      "expirationDateTime": "2028-07-14T22:10:14Z",
      "id": "ZWQzM2RhNzktNzQ2Mi00ZmE2LWFhMzUtMzM1ZTI3MmI1NDdl",
      "keyId": "ed33da79-7462-4fa6-aa35-335e272b547e",
      "keyType": "certificate",
      "keyUsage": "verify",
      "resourceId": "c5393580-f805-4401-95e8-94b7a6ef2fc2",
      "servicePrincipalObjectId": null,
      "signInActivity": {
        "lastSignInDateTime": "2026-07-16T23:42:14.262Z",
        "lastSignInRequestId": "46620e46-578e-4242-905a-e00bc14c2e00"
      }
    },
    {
      "appId": "6ad1b334-8853-414e-9dab-5d7ab7659c40",
      "appObjectId": "67b9d3dd-3e5a-4a89-803a-17a967d3a86a",
      "createdDateTime": "2026-06-05T21:29:20.654Z",
      "credentialOrigin": "application",
      "expirationDateTime": "2028-06-05T21:16:50.652Z",
      "id": "NWVkZjdhOGQtMDZhMC00MDMxLTg1YmUtMDRhMzFlMWY2NTBh",
      "keyId": "5edf7a8d-06a0-4031-85be-04a31e1f650a",
      "keyType": "password",
      "keyUsage": "verify",
      "resourceId": "00000003-0000-0000-c000-000000000000",
      "servicePrincipalObjectId": null,
      "signInActivity": {
        "lastSignInDateTime": "2026-07-16T23:00:39.318Z",
        "lastSignInRequestId": "b47497be-74e7-49ac-a965-b12d75a52200"
      }
    }
  ]
}`

	liveAppSummaryBody = `{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#Collection(microsoft.graph.applicationSignInSummary)",
  "value": [
    {
      "appDisplayName": "Tailscale",
      "failedSignInCount": 0,
      "id": "ffbad51a-97b4-452b-adba-e68c06bcc206",
      "successPercentage": 100.0,
      "successfulSignInCount": 2
    },
    {
      "appDisplayName": "Microsoft Exchange REST API Based Powershell",
      "failedSignInCount": 3,
      "id": "fb78d390-0c51-40cd-8e17-fdbfab77341b",
      "successPercentage": 50.0,
      "successfulSignInCount": 3
    },
    {
      "appDisplayName": "SharePoint Framework Azure AD Helper",
      "failedSignInCount": 0,
      "id": "e29b5c86-b9ab-4a86-9a20-d10842007599",
      "successPercentage": 100.0,
      "successfulSignInCount": 1
    },
    {
      "appDisplayName": "",
      "failedSignInCount": 1,
      "id": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
      "successPercentage": 0.0,
      "successfulSignInCount": 0
    },
    {
      "appDisplayName": "Security Copilot Portal",
      "failedSignInCount": 0,
      "id": "bb5ffd56-39eb-458c-a53a-775ba21277da",
      "successPercentage": 100.0,
      "successfulSignInCount": 4
    }
  ]
}`
)

func fixtureBodies() map[string]string {
	return map[string]string{
		base + "/reports/servicePrincipalSignInActivities":                liveSPBody,
		base + "/reports/appCredentialSignInActivities":                   liveAppCredBody,
		base + "/reports/getAzureADApplicationSignInSummary(period='D7')": liveAppSummaryBody,
	}
}

func p2caps() license.Capabilities { return license.Capabilities{license.CapEntraP2: true} }

func TestCollectEmitsBoundedStaleAndSummaryAggregates(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	spStale := map[string]float64{}
	for _, pt := range rec.MetricPoints(spStaleMetric) {
		spStale[pt.Attrs["threshold_days"]] = pt.Value
	}
	// All five live service principals last signed in 2026-07-16; at the fixed
	// clock (~45d later) each is past the 30d threshold but short of 90d, so the
	// cumulative buckets are 30->5, 90->0.
	if spStale["30"] != 5 {
		t.Errorf("sp stale-30 = %v, want 5", spStale["30"])
	}
	if spStale["90"] != 0 {
		t.Errorf("sp stale-90 = %v, want 0", spStale["90"])
	}

	credStale := map[string]float64{}
	for _, pt := range rec.MetricPoints(credStaleMetric) {
		credStale[pt.Attrs["threshold_days"]] = pt.Value
	}
	// Same for the five app credentials.
	if credStale["30"] != 5 || credStale["90"] != 0 {
		t.Errorf("cred stale 30/90 = %v/%v, want 5/0", credStale["30"], credStale["90"])
	}

	summary := map[string]float64{}
	for _, pt := range rec.MetricPoints(summaryMetric) {
		summary[pt.Attrs["result"]] = pt.Value
	}
	// success = 2+3+1+0+4 = 10; failure = 0+3+0+1+0 = 4.
	if summary["success"] != 10 || summary["failure"] != 4 {
		t.Errorf("summary success/failure = %v/%v, want 10/4", summary["success"], summary["failure"])
	}
}

func TestCollectNoPerEntitySeries(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	allowed := map[string]bool{"threshold_days": true, "result": true}
	for _, name := range rec.MetricNames() {
		for _, pt := range rec.MetricPoints(name) {
			for k := range pt.Attrs {
				if !allowed[k] {
					t.Errorf("metric %s has disallowed per-entity attr %q", name, k)
				}
			}
		}
	}
}

func TestExperimentalAndCapabilityAndPerms(t *testing.T) {
	c := New(&fakeGraph{}, license.Capabilities{}, nil)
	if !c.Experimental() {
		t.Error("signinactivity is beta; Experimental() must be true")
	}
	if c.RequiredCapability() != license.CapEntraP1 {
		t.Errorf("RequiredCapability = %v, want CapEntraP1", c.RequiredCapability())
	}
	if got := c.RequiredPermissions(); len(got) != 2 ||
		got[0] != "AuditLog.Read.All" || got[1] != "Reports.Read.All" {
		t.Errorf("RequiredPermissions = %v", got)
	}
	if c.Name() != "entra.signin_activity" {
		t.Errorf("Name = %q", c.Name())
	}
}

func TestCollectResilientToPerEndpointError(t *testing.T) {
	b := fixtureBodies()
	delete(b, base+"/reports/appCredentialSignInActivities")
	g := &fakeGraph{
		bodies: b,
		errs:   map[string]error{base + "/reports/appCredentialSignInActivities": errors.New("boom")},
	}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }
	// The credential half fails, but SP stale + summary must still emit and the
	// error is surfaced.
	if err := c.Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected the per-endpoint failure to surface as an error")
	}
	if len(rec.MetricPoints(spStaleMetric)) == 0 {
		t.Error("SP stale metric should still emit when the credential half fails")
	}
	// The credential half short-circuited before its twin: zero
	// entra.app_signin_activity logs should carry a key_id attr.
	for _, r := range logsNamed(rec.LogRecords(), eventSignInActivity) {
		if r.Attrs["key_id"] != "" {
			t.Errorf("credential half failed but its log twin still emitted: %+v", r)
		}
	}
}

func logsNamed(recs []telemetrytest.LogRecord, name string) []telemetrytest.LogRecord {
	var out []telemetrytest.LogRecord
	for _, r := range recs {
		if r.EventName == name {
			out = append(out, r)
		}
	}
	return out
}

// TestCollectEmitsLogTwinPerEntity is the core of #114 for this collector AND
// the #165 end-to-end drive: every service principal AND every app credential
// from the single existing fetch must also produce one entra.app_signin_activity
// log record, in addition to the bounded stale-count gauge — and the assertions
// are pinned against the VERBATIM live records, so a mapper that read a
// misnamed/null field would show up here.
func TestCollectEmitsLogTwinPerEntity(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := logsNamed(rec.LogRecords(), eventSignInActivity)
	// 5 service principals + 5 app credentials = 10 log records.
	if len(got) != 10 {
		t.Fatalf("emitted %d %s logs, want 10 (one per SP/credential)", len(got), eventSignInActivity)
	}

	byID := map[string]*telemetrytest.LogRecord{}
	for i := range got {
		byID[got[i].Attrs["id"]] = &got[i]
	}

	// Service principal twin, keyed by the verbatim base64 id of the
	// application-only record (appId 4ba261ce, delegatedClientSignInActivity
	// null): appId + the two signInActivity sub-fields that are actually on the
	// wire, and nothing more.
	spRec := byID["NGJhMjYxY2UtMjg3YS00NTljLTkzZWItNzA0N2JhYjNjZmI5"]
	if spRec == nil {
		t.Fatal("no log record for the application-only service principal (id NGJh...)")
	}
	wantSP := map[string]string{
		"id":                      "NGJhMjYxY2UtMjg3YS00NTljLTkzZWItNzA0N2JhYjNjZmI5",
		"app_id":                  "4ba261ce-287a-459c-93eb-7047bab3cfb9",
		"last_sign_in_date_time":  "2026-07-16T23:50:24.726Z",
		"last_sign_in_request_id": "52573f55-a86a-4f8b-af8d-5603138c4d00",
	}
	for k, want := range wantSP {
		if got := spRec.Attrs[k]; got != want {
			t.Errorf("sp attr %s = %q, want %q", k, got, want)
		}
	}
	// The four extended signInActivity sub-fields are absent on the wire (N=10);
	// they must not be emitted. app_display_name never exists on this resource.
	for _, k := range []string{
		"last_non_interactive_sign_in_date_time", "last_non_interactive_sign_in_request_id",
		"last_successful_sign_in_date_time", "last_successful_sign_in_request_id",
		"app_display_name",
	} {
		if _, ok := spRec.Attrs[k]; ok {
			t.Errorf("sp twin carries %q, absent from every live servicePrincipalSignInActivity record", k)
		}
	}

	// App credential twin, keyed by the verbatim base64 id of the password-key
	// credential on Microsoft Graph (appId 5f7d3d24): the full identifying +
	// credential-origin field set.
	credRec := byID["ODhjZGI4MjktZmZjYy00M2Q5LWI3OGMtMmViM2JhMTc5NWRk"]
	if credRec == nil {
		t.Fatal("no log record for app credential id ODhj...")
	}
	wantCred := map[string]string{
		"id":                      "ODhjZGI4MjktZmZjYy00M2Q5LWI3OGMtMmViM2JhMTc5NWRk",
		"app_id":                  "5f7d3d24-9d94-4f04-b2ce-546b927b3ba7",
		"app_object_id":           "20310cfa-a958-4e78-92f1-6094aace59c6",
		"resource_id":             "00000003-0000-0000-c000-000000000000",
		"key_id":                  "88cdb829-ffcc-43d9-b78c-2eb3ba1795dd",
		"key_type":                "password",
		"key_usage":               "verify",
		"credential_origin":       "application",
		"created_date_time":       "2026-06-05T18:50:53.146Z",
		"expiration_date_time":    "2028-06-04T17:36:33Z",
		"last_sign_in_date_time":  "2026-07-16T23:58:01.64Z",
		"last_sign_in_request_id": "4d75a177-0b7c-494e-805a-9677901c4300",
	}
	for k, want := range wantCred {
		if got := credRec.Attrs[k]; got != want {
			t.Errorf("cred attr %s = %q, want %q", k, got, want)
		}
	}
	// servicePrincipalObjectId is null on every live appCredentialSignInActivity
	// record (N=5), so the attribute must be omitted, not emitted empty.
	if _, ok := credRec.Attrs["service_principal_object_id"]; ok {
		t.Errorf("cred twin carries service_principal_object_id, but it is null on every live record")
	}
}

// TestSignInActivitySeverityEscalatesOnStaleness pins the severity rule this
// collector chose: escalate to Warn once an entity crosses the SAME 90-day
// threshold the stale-count gauge buckets on (or has never signed in at
// all), so the log severity and the metric agree on what "stale" means.
// Routine, recently-active workloads/credentials stay Info. Drives the
// mapper directly (the entra/risk idiom) rather than round-tripping through
// the recorder, since telemetrytest.LogRecord.Severity is the raw OTel
// numeric severity, not this package's telemetry.Severity enum.
func TestSignInActivitySeverityEscalatesOnStaleness(t *testing.T) {
	tests := []struct {
		ageDays float64
		want    telemetry.Severity
		why     string
	}{
		{5, telemetry.SeverityInfo, "used 5d ago: routine"},
		{45, telemetry.SeverityInfo, "used 45d ago: within the 90d threshold"},
		{90, telemetry.SeverityInfo, "used exactly 90d ago: not yet beyond threshold"},
		{200, telemetry.SeverityWarn, "used 200d ago: beyond the 90d threshold"},
		{1 << 30, telemetry.SeverityWarn, "never signed in: maximally stale"},
	}
	for _, tc := range tests {
		if got := stalenessSeverity(tc.ageDays); got != tc.want {
			t.Errorf("ageDays=%v: severity = %v, want %v (%s)", tc.ageDays, got, tc.want, tc.why)
		}
	}

	// And end-to-end through spLogTwin/credLogTwin, confirming the Event
	// carries the mapper's output.
	if ev := spLogTwin(spActivity{AppID: "c"}, 200); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("spLogTwin age=200: severity = %v, want Warn", ev.Severity)
	}
	if ev := spLogTwin(spActivity{AppID: "a"}, 5); ev.Severity != telemetry.SeverityInfo {
		t.Errorf("spLogTwin age=5: severity = %v, want Info", ev.Severity)
	}
	if ev := credLogTwin(credActivity{KeyID: "k2"}, 100); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("credLogTwin age=100: severity = %v, want Warn", ev.Severity)
	}
}

// TestBucketStaleCumulativeAndSentinel exercises the age-bucketing math the live
// captures cannot reach: every live record signed in on the same day
// (2026-07-16, a healthy tenant's active workloads are all fresh), so the
// fixtures prove the emit path but not the fresh end, the 30/90 cumulative
// boundary spread, or the never-signed-in sentinel. This drives those directly,
// through the same functions Collect uses.
func TestBucketStaleCumulativeAndSentinel(t *testing.T) {
	ref := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	// A never-used entity (empty timestamp) is maximally stale, not zero-age.
	if got := ageInDays(ref, ""); got < float64(1<<29) {
		t.Errorf("ageInDays(now, \"\") = %v, want the large never-used sentinel", got)
	}

	counts := map[int]int{}
	bucketStale(counts, ageInDays(ref, ref.AddDate(0, 0, -5).Format(time.RFC3339)))   // fresh: neither bucket
	bucketStale(counts, ageInDays(ref, ref.AddDate(0, 0, -45).Format(time.RFC3339)))  // stale-30 only
	bucketStale(counts, ageInDays(ref, ref.AddDate(0, 0, -200).Format(time.RFC3339))) // stale-30 and stale-90
	bucketStale(counts, ageInDays(ref, ""))                                           // never: stale-30 and stale-90
	if counts[30] != 3 {
		t.Errorf("stale-30 = %d, want 3 (45d, 200d, never)", counts[30])
	}
	if counts[90] != 2 {
		t.Errorf("stale-90 = %d, want 2 (200d, never)", counts[90])
	}

	pts := staleGaugePoints(counts)
	if len(pts) != len(staleThresholdsDays) {
		t.Fatalf("staleGaugePoints returned %d points, want %d", len(pts), len(staleThresholdsDays))
	}

	// A never-signed-in entity omits last_sign_in_date_time (and an empty id is
	// not emitted as an attribute) — the omit-absent path no live record hits.
	ev := spLogTwin(spActivity{AppID: "x"}, 1<<30)
	if _, ok := ev.Attrs["last_sign_in_date_time"]; ok {
		t.Errorf("never-signed-in SP has last_sign_in_date_time attr: %q", ev.Attrs["last_sign_in_date_time"])
	}
	if _, ok := ev.Attrs["id"]; ok {
		t.Errorf("SP with empty id emitted an id attr: %q", ev.Attrs["id"])
	}
}

// TestSignInActivityLogTwinTimestampIsZero pins the STATE-feed convention: the
// Timestamp is left zero (poll time), never set to a source-reported sign-in
// date, because this entity is re-emitted every cycle for as long as it
// exists in the report — stamping it with a fixed source date would pile
// every cycle's repeat onto one instant. See entra/risk's logTwin for the
// precedent.
func TestSignInActivityLogTwinTimestampIsZero(t *testing.T) {
	g := &fakeGraph{bodies: fixtureBodies()}
	rec := telemetrytest.New()
	c := New(g, p2caps(), nil)
	c.now = func() time.Time { return now }

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, r := range logsNamed(rec.LogRecords(), eventSignInActivity) {
		if !r.Timestamp.IsZero() {
			t.Errorf("log record for %+v has non-zero Timestamp %v, want zero (poll time)", r.Attrs, r.Timestamp)
		}
	}
}
