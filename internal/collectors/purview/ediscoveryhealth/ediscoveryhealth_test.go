package ediscoveryhealth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
	"github.com/rknightion/graph2otel/internal/wirecheck"
)

// fakeGraph is a canned-response GraphClient: bodies keyed by exact URL, or
// an error keyed by exact URL. It also records every URL requested, so tests
// can assert on what was (and was not) fetched — see
// TestUnifiedGroupSourcesIsNeverFetched and TestCaseCapBoundsFanOut.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error

	mu        sync.Mutex
	requested []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.mu.Lock()
	f.requested = append(f.requested, url)
	f.mu.Unlock()

	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	b, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("no canned body for " + url)
	}
	return []byte(b), nil
}

func (f *fakeGraph) requestedURLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requested...)
}

func (f *fakeGraph) requestedAny(substr string) bool {
	for _, u := range f.requestedURLs() {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

// --- URL builders and case/hold ids, matching the live m7kni capture -------

const casesURL = "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases"

const (
	case1ID = "ed1518bd-2f9f-4227-af55-9f1061cf9c32" // "Content Search", zero holds
	case2ID = "26179e8a-06b8-4f66-88e2-aa613207b0da" // "case2", 2 holds
	case3ID = "28ce2eda-c64f-4d13-a715-ce7ae78f086f" // "custod", 2 holds

	hold2aID = "0d3ec7d2-dbb0-42b6-92d7-088ee85087fa" // case2 hold "sdsasadsa"
	hold2bID = "e0bf0e41-2a4b-4845-8985-1c8a504fc8cc" // case2 hold "preseve"
	hold3aID = "717d032e-4790-41eb-afec-46045fc5e33d" // case3 hold "othertemp" (sources NOT captured live)
	hold3bID = "a9b5ac86-92a1-4fb2-9986-806d7b365560" // case3 hold "holdcust"
)

func caseURL(id string) string           { return casesURL + "/" + id }
func holdsURL(caseID string) string      { return caseURL(caseID) + "/legalHolds" }
func custodiansURL(caseID string) string { return caseURL(caseID) + "/custodians" }
func noncustodialURL(caseID string) string {
	return caseURL(caseID) + "/noncustodialDataSources"
}
func operationsURL(caseID string) string { return caseURL(caseID) + "/operations" }
func userSourcesURL(caseID, holdID string) string {
	return caseURL(caseID) + "/legalHolds/" + holdID + "/userSources"
}
func siteSourcesURL(caseID, holdID string) string {
	return caseURL(caseID) + "/legalHolds/" + holdID + "/siteSources"
}

// --- verbatim fixtures, read as graph2otel-poller against m7kni 2026-07-28 -
//
// Sourced from recheck2.json (case list + all six child routes across all
// three cases), deep.json (case3 hold "a9b5ac86"'s userSources/siteSources)
// and case2.json (case2's two holds' userSources/siteSources). No field is
// invented; every body below is copied byte-for-byte from those captures.

// liveCases is the verbatim GET /security/cases/ediscoveryCases response
// (recheck2.json's "cases" key), all three live cases.
const liveCases = `{
 "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/cases/ediscoveryCases",
 "@odata.count": 3,
 "value": [
  {
   "description": "This case contains all content searches from Microsoft Purview compliance portal.",
   "lastModifiedDateTime": "2026-07-28T10:41:06.776Z",
   "status": "active",
   "closedDateTime": null,
   "externalId": "",
   "id": "ed1518bd-2f9f-4227-af55-9f1061cf9c32",
   "displayName": "Content Search",
   "createdDateTime": "2026-07-28T10:41:06.776Z"
  },
  {
   "description": "",
   "lastModifiedDateTime": "2026-07-28T16:00:18.893Z",
   "status": "active",
   "closedDateTime": null,
   "externalId": "",
   "id": "26179e8a-06b8-4f66-88e2-aa613207b0da",
   "displayName": "case2",
   "createdDateTime": "2026-07-28T16:00:18.893Z"
  },
  {
   "description": "",
   "lastModifiedDateTime": "2026-07-28T15:32:49.986Z",
   "status": "active",
   "closedDateTime": null,
   "externalId": "",
   "id": "28ce2eda-c64f-4d13-a715-ce7ae78f086f",
   "displayName": "custod",
   "createdDateTime": "2026-07-28T15:32:49.986Z"
  }
 ]
}`

const emptyCollection = `{"@odata.count":0,"value":[]}`
const emptyOperations = `{"value":[]}`

// case2Holds is the verbatim GET .../26179e8a.../legalHolds response
// (recheck2.json), 2 holds, every one with isEnabled=true, errors=[],
// status=null (the trap the null-hold-status test pins).
const case2Holds = `{
 "@odata.count": 2,
 "value": [
  {
   "isEnabled": true,
   "errors": [],
   "contentQuery": "",
   "description": "",
   "createdDateTime": "2026-07-28T16:03:54Z",
   "lastModifiedDateTime": "2026-07-28T16:03:54Z",
   "status": null,
   "id": "0d3ec7d2-dbb0-42b6-92d7-088ee85087fa",
   "displayName": "sdsasadsa",
   "createdBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   },
   "lastModifiedBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   }
  },
  {
   "isEnabled": true,
   "errors": [],
   "contentQuery": "",
   "description": "",
   "createdDateTime": "2026-07-28T16:02:49Z",
   "lastModifiedDateTime": "2026-07-28T16:02:50Z",
   "status": null,
   "id": "e0bf0e41-2a4b-4845-8985-1c8a504fc8cc",
   "displayName": "preseve",
   "createdBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   },
   "lastModifiedBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   }
  }
 ]
}`

// case3Holds is the verbatim GET .../28ce2eda.../legalHolds response
// (recheck2.json), 2 holds.
const case3Holds = `{
 "@odata.count": 2,
 "value": [
  {
   "isEnabled": true,
   "errors": [],
   "contentQuery": "",
   "description": "",
   "createdDateTime": "2026-07-28T15:42:41Z",
   "lastModifiedDateTime": "2026-07-28T15:42:43Z",
   "status": null,
   "id": "717d032e-4790-41eb-afec-46045fc5e33d",
   "displayName": "othertemp",
   "createdBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   },
   "lastModifiedBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   }
  },
  {
   "isEnabled": true,
   "errors": [],
   "contentQuery": "",
   "description": "",
   "createdDateTime": "2026-07-28T15:38:32Z",
   "lastModifiedDateTime": "2026-07-28T15:38:32Z",
   "status": null,
   "id": "a9b5ac86-92a1-4fb2-9986-806d7b365560",
   "displayName": "holdcust",
   "createdBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   },
   "lastModifiedBy": {
    "application": null,
    "user": { "id": "Rob Knight", "displayName": null }
   }
  }
 ]
}`

// case2Ops is the verbatim GET .../26179e8a.../operations response
// (recheck2.json / case2.json): 2 holdPolicySync ops, createdBy null (trap 5).
const case2Ops = `{
 "value": [
  {
   "createdDateTime": "2026-07-28T16:03:55.2331561Z",
   "completedDateTime": "2026-07-28T16:05:21.4617245Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "holdPolicySync",
   "id": "57a7394f8f174fe3a52008deecc1d335",
   "createdBy": null
  },
  {
   "createdDateTime": "2026-07-28T16:02:50.736149Z",
   "completedDateTime": "2026-07-28T16:05:28.2172863Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "holdPolicySync",
   "id": "da49d845fd87466a216f08deecc1acc5",
   "createdBy": null
  }
 ]
}`

// case3Ops is the verbatim GET .../28ce2eda.../operations response
// (recheck2.json): 5 ops, mixing null createdBy (system) and populated
// createdBy (user) — the operations/searches identitySet shape (id=guid,
// displayName populated).
const case3Ops = `{
 "value": [
  {
   "createdDateTime": "2026-07-28T15:42:44.4668235Z",
   "completedDateTime": "2026-07-28T15:44:10.3139988Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "holdPolicySync",
   "id": "a10590b977b34d7b920f08deecbedd9c",
   "createdBy": null
  },
  {
   "createdDateTime": "2026-07-28T15:40:52.9480569Z",
   "completedDateTime": "2026-07-28T15:43:13.5140772Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "addToReviewSet",
   "id": "36caf7cb42bf422a9f63c073e451d61c",
   "createdBy": {
    "application": null,
    "user": {
     "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
     "displayName": "Rob Knight",
     "userPrincipalName": "rob@m7kni.io"
    }
   }
  },
  {
   "createdDateTime": "2026-07-28T15:40:43.9011203Z",
   "completedDateTime": "2026-07-28T15:41:58.8567097Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "estimateStatistics",
   "id": "a4b134ae96424bdb8dd0c46e7895cca4",
   "createdBy": {
    "application": null,
    "user": {
     "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
     "displayName": "Rob Knight",
     "userPrincipalName": "rob@m7kni.io"
    }
   }
  },
  {
   "createdDateTime": "2026-07-28T15:38:33.1529849Z",
   "completedDateTime": "2026-07-28T15:40:51.9138228Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "holdPolicySync",
   "id": "653d5144ec674fb207bb08deecbe4800",
   "createdBy": null
  },
  {
   "createdDateTime": "2026-07-28T15:36:26.9875432Z",
   "completedDateTime": "2026-07-28T15:37:40.2755611Z",
   "percentProgress": 100,
   "status": "succeeded",
   "action": "estimateStatistics",
   "id": "4b9f609ddb0f49cd88ecaacc735f21b6",
   "createdBy": {
    "application": null,
    "user": {
     "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
     "displayName": "Rob Knight",
     "userPrincipalName": "rob@m7kni.io"
    }
   }
  }
 ]
}`

// hold2aUserSources is the verbatim GET .../legalHolds/0d3ec7d2.../userSources
// response (case2.json): 2 rows, the second with the non-GUID id trap.
const hold2aUserSources = `{
 "value": [
  {
   "displayName": "vmuser",
   "createdDateTime": "2026-07-28T16:03:54.467Z",
   "holdStatus": "applied",
   "id": "7957928c-3cd2-4bbb-98c8-cfc8466f490a",
   "email": "vmuser@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  },
  {
   "displayName": ".vmuser@m7kni.io",
   "createdDateTime": "2026-07-28T16:03:54.467Z",
   "holdStatus": "applied",
   "id": "00000000-0000-0000-0000-000000000000.vmuser@m7kni.io",
   "email": "vmuser@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  }
 ]
}`

// hold2aSiteSources is the verbatim GET .../legalHolds/0d3ec7d2.../siteSources
// response (case2.json): 1 row, site.createdDateTime is the .NET zero
// sentinel (trap 4).
const hold2aSiteSources = `{
 "value": [
  {
   "displayName": "vmuser",
   "createdDateTime": "2026-07-28T16:03:54.467Z",
   "holdStatus": "applied",
   "id": "4fcca8d7-f3f9-463e-b387-baebb12e74c2",
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   },
   "site": {
    "webUrl": "https://m7knio-my.sharepoint.com/personal/vmuser_m7kni_io",
    "id": "4fcca8d7-f3f9-463e-b387-baebb12e74c2",
    "displayName": null,
    "createdDateTime": "0001-01-01T00:00:00Z"
   }
  }
 ]
}`

// hold2bUserSources is the verbatim GET .../legalHolds/e0bf0e41.../userSources
// response (case2.json).
const hold2bUserSources = `{
 "value": [
  {
   "displayName": "vmuser",
   "createdDateTime": "2026-07-28T16:02:49.913Z",
   "holdStatus": "applied",
   "id": "7957928c-3cd2-4bbb-98c8-cfc8466f490a",
   "email": "vmuser@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  },
  {
   "displayName": ".vmuser@m7kni.io",
   "createdDateTime": "2026-07-28T16:02:49.913Z",
   "holdStatus": "applied",
   "id": "00000000-0000-0000-0000-000000000000.vmuser@m7kni.io",
   "email": "vmuser@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  }
 ]
}`

// hold2bSiteSources is the verbatim GET .../legalHolds/e0bf0e41.../siteSources
// response (case2.json): the zero-date sentinel again.
const hold2bSiteSources = `{
 "value": [
  {
   "displayName": "vmuser",
   "createdDateTime": "2026-07-28T16:02:49.913Z",
   "holdStatus": "applied",
   "id": "4fcca8d7-f3f9-463e-b387-baebb12e74c2",
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   },
   "site": {
    "webUrl": "https://m7knio-my.sharepoint.com/personal/vmuser_m7kni_io",
    "id": "4fcca8d7-f3f9-463e-b387-baebb12e74c2",
    "displayName": null,
    "createdDateTime": "0001-01-01T00:00:00Z"
   }
  }
 ]
}`

// hold3bUserSources is the verbatim GET .../legalHolds/a9b5ac86.../userSources
// response (deep.json's "hold1.userSources"): 2 rows, both real GUID ids.
const hold3bUserSources = `{
 "value": [
  {
   "displayName": "Rob Knight",
   "createdDateTime": "2026-07-28T15:38:32.207Z",
   "holdStatus": "applied",
   "id": "bbcfc3c5-0b93-4135-9ef9-18477a9fb504",
   "email": "rob@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  },
  {
   "displayName": "IRM",
   "createdDateTime": "2026-07-28T15:38:32.207Z",
   "holdStatus": "applied",
   "id": "907e7f1e-7fc0-4b7a-a279-cf628b835818",
   "email": "IRM@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   }
  }
 ]
}`

// hold3bSiteSources is the verbatim GET .../legalHolds/a9b5ac86.../siteSources
// response (deep.json's "hold1.siteSources"): 2 rows, both site.createdDateTime
// the zero sentinel.
const hold3bSiteSources = `{
 "value": [
  {
   "displayName": "Rob Knight",
   "createdDateTime": "2026-07-28T15:38:32.207Z",
   "holdStatus": "applied",
   "id": "71603498-72de-4c30-a6bd-a1e6019c3fc5",
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   },
   "site": {
    "webUrl": "https://m7knio-my.sharepoint.com/personal/rob_m7kni_io",
    "id": "71603498-72de-4c30-a6bd-a1e6019c3fc5",
    "displayName": null,
    "createdDateTime": "0001-01-01T00:00:00Z"
   }
  },
  {
   "displayName": "IRM",
   "createdDateTime": "2026-07-28T15:38:32.207Z",
   "holdStatus": "applied",
   "id": "270639cc-5298-4e19-8b16-29dd832488e5",
   "createdBy": {
    "application": null,
    "user": { "id": null, "displayName": "Rob Knight" }
   },
   "site": {
    "webUrl": "https://m7knio.sharepoint.com/sites/IRM",
    "id": "270639cc-5298-4e19-8b16-29dd832488e5",
    "displayName": null,
    "createdDateTime": "0001-01-01T00:00:00Z"
   }
  }
 ]
}`

// liveGraph builds a fakeGraph wired with every verbatim fixture above,
// covering the full three-case capture end to end. hold3aID
// (case3's "othertemp" hold) has no captured userSources/siteSources in any
// of the three source files, so those two URLs are deliberately left
// unregistered: fakeGraph returns "no canned body" for them, exercising the
// same per-route degrade path as a genuine fetch failure rather than
// fabricating a shape that was never observed live.
func liveGraph() *fakeGraph {
	return &fakeGraph{bodies: map[string]string{
		casesURL: liveCases,

		holdsURL(case1ID):        emptyCollection,
		custodiansURL(case1ID):   emptyCollection,
		noncustodialURL(case1ID): emptyCollection,
		operationsURL(case1ID):   emptyOperations,

		holdsURL(case2ID):                 case2Holds,
		custodiansURL(case2ID):            emptyCollection,
		noncustodialURL(case2ID):          emptyCollection,
		operationsURL(case2ID):            case2Ops,
		userSourcesURL(case2ID, hold2aID): hold2aUserSources,
		siteSourcesURL(case2ID, hold2aID): hold2aSiteSources,
		userSourcesURL(case2ID, hold2bID): hold2bUserSources,
		siteSourcesURL(case2ID, hold2bID): hold2bSiteSources,

		holdsURL(case3ID):                 case3Holds,
		custodiansURL(case3ID):            emptyCollection,
		noncustodialURL(case3ID):          emptyCollection,
		operationsURL(case3ID):            case3Ops,
		userSourcesURL(case3ID, hold3bID): hold3bUserSources,
		siteSourcesURL(case3ID, hold3bID): hold3bSiteSources,
	}}
}

// --- test 1: full three-case capture end to end ----------------------------

func TestCollectAgainstLiveCases(t *testing.T) {
	g := liveGraph()
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// legal_holds: every hold observed live is isEnabled=true, errors=[] — one
	// bucket, 4 holds total (0 + 2 + 2).
	holdPts := rec.MetricPoints(metricLegalHolds)
	if len(holdPts) != 1 {
		t.Fatalf("legal_holds points = %d, want 1: %+v", len(holdPts), holdPts)
	}
	if holdPts[0].Attrs["enabled"] != "true" || holdPts[0].Attrs["has_errors"] != "false" || holdPts[0].Value != 4 {
		t.Errorf("legal_holds point = %+v, want {enabled=true has_errors=false value=4}", holdPts[0])
	}

	// hold_sources: user/applied=6 (2+2+2), site/applied=4 (1+1+2). hold3a's
	// sources are unfetchable (no fixture) so contribute nothing.
	wantSource := map[string]float64{"user|applied": 6, "site|applied": 4}
	gotSource := map[string]float64{}
	for _, p := range rec.MetricPoints(metricHoldSources) {
		gotSource[p.Attrs["source_type"]+"|"+p.Attrs["hold_status"]] = p.Value
	}
	if len(gotSource) != len(wantSource) {
		t.Fatalf("hold_sources buckets = %v, want %v", gotSource, wantSource)
	}
	for k, want := range wantSource {
		if gotSource[k] != want {
			t.Errorf("hold_sources[%s] = %v, want %v", k, gotSource[k], want)
		}
	}

	// case_operations: holdPolicySync/succeeded=4, addToReviewSet/succeeded=1,
	// estimateStatistics/succeeded=2.
	wantOps := map[string]float64{
		"holdPolicySync|succeeded":     4,
		"addToReviewSet|succeeded":     1,
		"estimateStatistics|succeeded": 2,
	}
	gotOps := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCaseOperations) {
		gotOps[p.Attrs["action"]+"|"+p.Attrs["status"]] = p.Value
	}
	if len(gotOps) != len(wantOps) {
		t.Fatalf("case_operations buckets = %v, want %v", gotOps, wantOps)
	}
	for k, want := range wantOps {
		if gotOps[k] != want {
			t.Errorf("case_operations[%s] = %v, want %v", k, gotOps[k], want)
		}
	}

	assertSinglePoint(t, rec, metricCustodians, 0)
	assertSinglePoint(t, rec, metricNoncustodial, 0)
	assertSinglePoint(t, rec, metricCasesCovered, 3)
	assertSinglePoint(t, rec, metricCasesTotal, 3)

	// Exact log-twin counts for each of the three event names.
	counts := map[string]int{}
	for _, lr := range rec.LogRecords() {
		counts[lr.EventName]++
	}
	wantCounts := map[string]int{
		legalHoldEventName:     4,
		holdSourceEventName:    10,
		caseOperationEventName: 7,
	}
	for name, want := range wantCounts {
		if counts[name] != want {
			t.Errorf("log records[%s] = %d, want %d (all: %v)", name, counts[name], want, counts)
		}
	}
}

func assertSinglePoint(t *testing.T, rec *telemetrytest.Recorder, metric string, want float64) {
	t.Helper()
	pts := rec.MetricPoints(metric)
	if len(pts) != 1 {
		t.Fatalf("%s points = %d, want 1: %+v", metric, len(pts), pts)
	}
	if pts[0].Value != want {
		t.Errorf("%s value = %v, want %v", metric, pts[0].Value, want)
	}
}

// --- test 2: null legalHold.status never reaches the gauge ------------------

func TestNullHoldStatusDoesNotReachTheGauge(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		casesURL:                 singleCaseList(case2ID, "case2"),
		holdsURL(case2ID):        case2Holds,
		custodiansURL(case2ID):   emptyCollection,
		noncustodialURL(case2ID): emptyCollection,
		operationsURL(case2ID):   emptyOperations,
		// Both holds' sources are irrelevant to this test; leave unfetchable.
	}}
	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricLegalHolds)
	if len(pts) != 1 {
		t.Fatalf("legal_holds points = %d, want 1: %+v", len(pts), pts)
	}
	// Assert the FULL label set AND the label values of the one emitted point
	// (assertion-discipline requirement: a key-set-only check would pass even
	// if "status" leaked in under the right value).
	if len(pts[0].Attrs) != 2 {
		t.Fatalf("legal_holds point attrs = %+v, want exactly 2 keys (enabled, has_errors)", pts[0].Attrs)
	}
	if pts[0].Attrs["enabled"] != "true" {
		t.Errorf("enabled = %q, want %q", pts[0].Attrs["enabled"], "true")
	}
	if pts[0].Attrs["has_errors"] != "false" {
		t.Errorf("has_errors = %q, want %q", pts[0].Attrs["has_errors"], "false")
	}
	if pts[0].Value != 2 {
		t.Errorf("value = %v, want 2", pts[0].Value)
	}
	if _, present := pts[0].Attrs["status"]; present {
		t.Error("legal_holds point carries a \"status\" label; it must not — legalHold.status is null on every healthy hold")
	}

	// No point anywhere on this metric carries has_errors="unknown" — there is
	// only ever the one point checked above, but re-assert explicitly per the
	// brief's wording.
	for _, p := range pts {
		if p.Attrs["has_errors"] == "unknown" {
			t.Errorf("found a has_errors=unknown point: %+v", p)
		}
	}

	// The log twin DOES carry the raw null status — as an absent attribute
	// (SetStr omits ""), which is what "null" decodes to.
	for _, lr := range rec.LogRecords() {
		if lr.EventName != legalHoldEventName {
			continue
		}
		if v, present := lr.Attrs["hold_state"]; present && v != "" {
			t.Errorf("hold_state = %q, want absent (status is null on the wire)", v)
		}
	}
}

func singleCaseList(id, displayName string) string {
	return `{"value":[{"id":"` + id + `","displayName":"` + displayName + `"}]}`
}

// --- test 3: non-GUID source id survives, never becomes a metric label -----

func TestNonGuidSourceIdSurvivesAndStaysOutOfMetrics(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		casesURL:                          singleCaseList(case2ID, "case2"),
		holdsURL(case2ID):                 case2Holds,
		custodiansURL(case2ID):            emptyCollection,
		noncustodialURL(case2ID):          emptyCollection,
		operationsURL(case2ID):            emptyOperations,
		userSourcesURL(case2ID, hold2aID): hold2aUserSources,
		siteSourcesURL(case2ID, hold2aID): emptyCollection,
		userSourcesURL(case2ID, hold2bID): emptyCollection,
		siteSourcesURL(case2ID, hold2bID): emptyCollection,
	}}
	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	const nonGUID = "00000000-0000-0000-0000-000000000000.vmuser@m7kni.io"

	// Present verbatim on the log twin as an attribute VALUE.
	found := false
	for _, lr := range rec.LogRecords() {
		if lr.EventName == holdSourceEventName && lr.Attrs["id"] == nonGUID {
			found = true
		}
	}
	if !found {
		t.Fatal("non-GUID source id not found verbatim on any hold_source log record")
	}

	// Appears on no metric point: hold_sources is only ever labeled
	// source_type/hold_status, so assert the VALUE never shows up under any
	// attribute of any point on this metric.
	for _, p := range rec.MetricPoints(metricHoldSources) {
		for k, v := range p.Attrs {
			if v == nonGUID {
				t.Errorf("non-GUID source id leaked onto metric attribute %q: %+v", k, p)
			}
		}
	}
}

// --- test 4: createdByName across all three real identitySet shapes --------

func TestCreatedByNameAcrossAllThreeShapes(t *testing.T) {
	tests := []struct {
		name string
		is   identitySet
		want string
	}{
		{
			// legalHolds shape (case2Holds, case3Holds): human name IN the id
			// field, displayName null/empty.
			name: "legalHolds shape: name in id field",
			is:   identitySet{User: identityUser{ID: "Rob Knight", DisplayName: ""}},
			want: "Rob Knight",
		},
		{
			// operations/searches shape (case3Ops): guid id, populated
			// displayName.
			name: "operations shape: guid id, real displayName",
			is:   identitySet{User: identityUser{ID: "bbcfc3c5-0b93-4135-9ef9-18477a9fb504", DisplayName: "Rob Knight"}},
			want: "Rob Knight",
		},
		{
			// case object / hold-source shape (liveCases, hold2aUserSources):
			// id null, displayName populated.
			name: "case/source shape: null id, real displayName",
			is:   identitySet{User: identityUser{ID: "", DisplayName: "Rob Knight"}},
			want: "Rob Knight",
		},
		{
			// The trap: a GUID-shaped id with an empty displayName must NOT
			// leak the GUID into AttrCreatedByDisplayName.
			name: "guid id, empty displayName resolves to empty (never leak a GUID)",
			is:   identitySet{User: identityUser{ID: "bbcfc3c5-0b93-4135-9ef9-18477a9fb504", DisplayName: ""}},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := createdByName(tc.is); got != tc.want {
				t.Errorf("createdByName(%+v) = %q, want %q", tc.is, got, tc.want)
			}
		})
	}
}

// --- test 5: the .NET zero-date sentinel is dropped, with a positive control

func TestZeroDateSentinelIsDropped(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		casesURL:                          singleCaseList(case3ID, "custod"),
		holdsURL(case3ID):                 case3Holds,
		custodiansURL(case3ID):            emptyCollection,
		noncustodialURL(case3ID):          emptyCollection,
		operationsURL(case3ID):            emptyOperations,
		userSourcesURL(case3ID, hold3bID): hold3bUserSources,
		siteSourcesURL(case3ID, hold3bID): hold3bSiteSources,
		userSourcesURL(case3ID, hold3aID): emptyCollection,
		siteSourcesURL(case3ID, hold3aID): emptyCollection,
	}}
	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var siteRecords, userRecords []map[string]string
	for _, lr := range rec.LogRecords() {
		if lr.EventName != holdSourceEventName {
			continue
		}
		switch lr.Attrs["source_type"] {
		case "site":
			siteRecords = append(siteRecords, lr.Attrs)
		case "user":
			userRecords = append(userRecords, lr.Attrs)
		}
	}

	// Negative: site.createdDateTime is the zero sentinel on BOTH hold3b
	// siteSource rows (deep.json) — created_date_time must be genuinely
	// ABSENT, not empty-string-present.
	if len(siteRecords) == 0 {
		t.Fatal("no site hold_source records captured")
	}
	for _, attrs := range siteRecords {
		if v, present := attrs["created_date_time"]; present {
			t.Errorf("site source created_date_time = %q, want the key absent (site.createdDateTime is the .NET zero sentinel)", v)
		}
	}

	// Positive control: the SAME mapper, applied to a userSource row whose own
	// createdDateTime is a real value, DOES produce the key — proving this
	// assertion could actually fail if the mapper were broken.
	if len(userRecords) == 0 {
		t.Fatal("no user hold_source records captured")
	}
	foundRealDate := false
	for _, attrs := range userRecords {
		if attrs["created_date_time"] == "2026-07-28T15:38:32.207Z" {
			foundRealDate = true
		}
	}
	if !foundRealDate {
		t.Error("positive control failed: no user hold_source record carries the real created_date_time value — the assertion above cannot be trusted")
	}
}

// --- test 6: a child-route failure degrades independently (#240) -----------
//
// The injected failure is the live wire trap documented in the package doc:
// an unmaterialized case's child routes return HTTP 500 with a body saying
// the compliance case doesn't exist. This test keys ONLY on the failure
// being an error at all (generic per-route degrade), never on the exact
// Microsoft wording, per the brief.
func TestChildRouteFailureDegradesIndependently(t *testing.T) {
	unmaterializedCase500 := errors.New(`graphclient: GET https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/` + case2ID + `/legalHolds: status 500: {"error":{"code":"UnknownError","message":"The compliance case \"` + case2ID + `\" doesn't exist. Please create the case."}}`)

	g := &fakeGraph{
		bodies: map[string]string{
			casesURL: liveCases,

			holdsURL(case1ID):        emptyCollection,
			custodiansURL(case1ID):   emptyCollection,
			noncustodialURL(case1ID): emptyCollection,
			operationsURL(case1ID):   emptyOperations,

			// case2's legalHolds route fails; its OTHER routes still succeed.
			custodiansURL(case2ID):   emptyCollection,
			noncustodialURL(case2ID): emptyCollection,
			operationsURL(case2ID):   case2Ops,

			holdsURL(case3ID):                 case3Holds,
			custodiansURL(case3ID):            emptyCollection,
			noncustodialURL(case3ID):          emptyCollection,
			operationsURL(case3ID):            case3Ops,
			userSourcesURL(case3ID, hold3bID): hold3bUserSources,
			siteSourcesURL(case3ID, hold3bID): hold3bSiteSources,
			userSourcesURL(case3ID, hold3aID): emptyCollection,
			siteSourcesURL(case3ID, hold3aID): emptyCollection,
		},
		errs: map[string]error{
			holdsURL(case2ID): unmaterializedCase500,
		},
	}

	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), outcomes); err != nil {
		t.Fatalf("Collect must not fail on a per-case child-route error, got: %v", err)
	}

	// case2 contributed zero legal holds (its legalHolds route failed), but
	// case3's 2 holds still landed — never a zero point standing in for the
	// failed route, and the surviving case is unaffected.
	holdPts := rec.MetricPoints(metricLegalHolds)
	if len(holdPts) != 1 {
		t.Fatalf("legal_holds points = %d, want 1: %+v", len(holdPts), holdPts)
	}
	if holdPts[0].Value != 2 {
		t.Errorf("legal_holds value = %v, want 2 (only case3's holds; case2's legalHolds route failed)", holdPts[0].Value)
	}

	// case2's operations (a route independent of its failed legalHolds
	// fetch) still landed: 2 holdPolicySync/succeeded from case2, plus
	// case3's own operations.
	wantOps := map[string]float64{
		"holdPolicySync|succeeded":     4, // 2 from case2 + 2 from case3
		"addToReviewSet|succeeded":     1,
		"estimateStatistics|succeeded": 2,
	}
	gotOps := map[string]float64{}
	for _, p := range rec.MetricPoints(metricCaseOperations) {
		gotOps[p.Attrs["action"]+"|"+p.Attrs["status"]] = p.Value
	}
	for k, want := range wantOps {
		if gotOps[k] != want {
			t.Errorf("case_operations[%s] = %v, want %v (case2's operations route must survive its sibling legalHolds failure)", k, gotOps[k], want)
		}
	}

	// cases_covered/cases_total are unaffected by a child-route failure — all
	// 3 cases were still counted and covered.
	assertSinglePoint(t, rec, metricCasesCovered, 3)
	assertSinglePoint(t, rec, metricCasesTotal, 3)
}

// --- test 7: the case cap bounds fan-out, with no request for the rest -----

func TestCaseCapBoundsFanOut(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		casesURL: liveCases,

		holdsURL(case1ID):        emptyCollection,
		custodiansURL(case1ID):   emptyCollection,
		noncustodialURL(case1ID): emptyCollection,
		operationsURL(case1ID):   emptyOperations,

		holdsURL(case2ID):                 case2Holds,
		custodiansURL(case2ID):            emptyCollection,
		noncustodialURL(case2ID):          emptyCollection,
		operationsURL(case2ID):            case2Ops,
		userSourcesURL(case2ID, hold2aID): hold2aUserSources,
		siteSourcesURL(case2ID, hold2aID): hold2aSiteSources,
		userSourcesURL(case2ID, hold2bID): hold2bUserSources,
		siteSourcesURL(case2ID, hold2bID): hold2bSiteSources,

		// case3's routes are deliberately NOT registered: if the cap logic is
		// broken and case3 gets fetched anyway, the fake returns a "no canned
		// body" error rather than silently succeeding, which would make this
		// test's request-set assertion below the thing that actually catches
		// it.
	}}

	c := &HealthCollector{g: g, baseURL: defaultBaseURL, logger: slog.Default(), maxCases: 2, watch: wirecheck.New(healthName, nil)}
	rec := telemetrytest.New()
	if err := c.Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	assertSinglePoint(t, rec, metricCasesCovered, 2)
	assertSinglePoint(t, rec, metricCasesTotal, 3)

	if g.requestedAny(case3ID) {
		t.Errorf("case3 (%s) was requested despite the cap; requested URLs: %v", case3ID, g.requestedURLs())
	}
}

// --- test 8: unifiedGroupSources, searches, tags, reviewSets, caseMembers --
// -- are never fetched -------------------------------------------------------

func TestUnifiedGroupSourcesIsNeverFetched(t *testing.T) {
	g := liveGraph()
	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, forbidden := range []string{"unifiedGroupSources", "searches", "tags", "reviewSets", "caseMembers"} {
		if g.requestedAny(forbidden) {
			t.Errorf("a request URL contained forbidden segment %q; requested: %v", forbidden, g.requestedURLs())
		}
	}
}

// --- test 9: an unmapped enum value is report-only, never dropped ----------
//
// holdStatus/action/status values below are deliberately NOT from the live
// captures (every live value observed is a known EDM member) — this test
// exists specifically to prove behavior for a value nobody has seen yet,
// which by definition cannot come from a capture. Every OTHER field on these
// rows is copied verbatim from the corresponding live fixture; only the
// three watched enum values are substituted, following the same pattern as
// sensitivitylabels' TestSensitivityUnmappedTargetIsReported.
func TestUnmappedEnumValueIsReported(t *testing.T) {
	unmappedHold := `{
 "value": [
  {
   "isEnabled": true,
   "errors": [],
   "contentQuery": "",
   "description": "",
   "createdDateTime": "2026-07-28T16:03:54Z",
   "lastModifiedDateTime": "2026-07-28T16:03:54Z",
   "status": null,
   "id": "0d3ec7d2-dbb0-42b6-92d7-088ee85087fa",
   "displayName": "sdsasadsa",
   "createdBy": { "application": null, "user": { "id": "Rob Knight", "displayName": null } }
  }
 ]
}`
	unmappedUserSource := `{
 "value": [
  {
   "displayName": "vmuser",
   "createdDateTime": "2026-07-28T16:03:54.467Z",
   "holdStatus": "aFutureHoldStatus",
   "id": "7957928c-3cd2-4bbb-98c8-cfc8466f490a",
   "email": "vmuser@m7kni.io",
   "includedSources": "mailbox",
   "siteWebUrl": null,
   "createdBy": { "application": null, "user": { "id": null, "displayName": "Rob Knight" } }
  }
 ]
}`
	unmappedOps := `{
 "value": [
  {
   "createdDateTime": "2026-07-28T16:03:55.2331561Z",
   "completedDateTime": "2026-07-28T16:05:21.4617245Z",
   "percentProgress": 100,
   "status": "aFutureStatus",
   "action": "aFutureAction",
   "id": "57a7394f8f174fe3a52008deecc1d335",
   "createdBy": null
  }
 ]
}`

	g := &fakeGraph{bodies: map[string]string{
		casesURL:                          singleCaseList(case2ID, "case2"),
		holdsURL(case2ID):                 unmappedHold,
		custodiansURL(case2ID):            emptyCollection,
		noncustodialURL(case2ID):          emptyCollection,
		operationsURL(case2ID):            unmappedOps,
		userSourcesURL(case2ID, hold2aID): unmappedUserSource,
		siteSourcesURL(case2ID, hold2aID): emptyCollection,
	}}

	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	findings := map[string]float64{}
	for _, p := range rec.MetricPoints(wirecheck.MetricUnexpected) {
		findings[p.Attrs["kind"]+"/"+p.Attrs["field"]] += p.Value
	}
	for _, field := range []string{"hold_status", "action", "status"} {
		key := wirecheck.KindUnmappedValue + "/" + field
		if findings[key] != 1 {
			t.Errorf("findings[%s] = %v, want 1; all=%v", key, findings[key], findings)
		}
	}

	// Report-only: the records are still emitted, not dropped.
	var sawSource, sawOp bool
	for _, lr := range rec.LogRecords() {
		switch lr.EventName {
		case holdSourceEventName:
			sawSource = true
			if lr.Attrs["hold_status"] != "unknown" {
				t.Errorf("hold_source hold_status = %q, want \"unknown\" (unmapped value still bucketed, never dropped)", lr.Attrs["hold_status"])
			}
		case caseOperationEventName:
			sawOp = true
			if lr.Attrs["action"] != "unknown" || lr.Attrs["status"] != "unknown" {
				t.Errorf("case_operation action/status = %q/%q, want unknown/unknown", lr.Attrs["action"], lr.Attrs["status"])
			}
		}
	}
	if !sawSource {
		t.Error("hold_source record was dropped for an unmapped hold_status; must be report-only")
	}
	if !sawOp {
		t.Error("case_operation record was dropped for an unmapped action/status; must be report-only")
	}
}

// --- misc coverage: gating metadata, mirroring the sibling package's style -

func TestExperimentalAndScope(t *testing.T) {
	c := NewHealth(&fakeGraph{}, nil)
	if !c.Experimental() {
		t.Error("eDiscovery case-health collector must be Experimental (opt-in: needs the S&C data-plane registration)")
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "eDiscovery.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [eDiscovery.Read.All]", perms)
	}
	if c.Name() != healthName {
		t.Errorf("Name = %q, want %q", c.Name(), healthName)
	}
}

// TestUnregisteredDataPlaneFailsLoud pins that a 401 on the top-level case
// list (the S&C data-plane registration missing, despite eDiscovery.Read.All
// being granted) fails the collector loudly and names the fix, mirroring
// ediscoverycases' identical test.
func TestUnregisteredDataPlaneFailsLoud(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{
		casesURL: errors.New(`status 401: {"error":{"code":"Authentication_MissingOrMalformed","message":"Access token validation failure."}}`),
	}}
	rec := telemetrytest.New()
	outcomes := recordoutcome.NewRecorder()
	err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), outcomes)
	if err == nil {
		t.Fatal("expected an error on 401, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "registration") {
		t.Errorf("401 error must name the S&C data-plane registration fix, got: %v", err)
	}
	if n := len(rec.LogRecords()); n != 0 {
		t.Errorf("emitted %d logs on error, want 0", n)
	}
}

// --- test 10: a route that failed on EVERY case must not publish a zero ----

// TestTotalRouteFailurePublishesNoCount pins the one place the aggregate-only
// custodians / noncustodialDataSources gauges could violate #240. Their totals
// accumulate across cases from a zero-valued counter, so if EVERY case's fetch
// on one of those routes fails, the counter is still 0 and a naive
// implementation publishes a confident 0 over a total read failure — a GAP
// reported as a measured zero, which is exactly what #240 forbids.
//
// The distinction this test draws is between "no case succeeded on this route"
// (unknown — publish nothing) and "cases succeeded and genuinely had no rows"
// (a real measured zero — publish it). Both halves are asserted, because an
// implementation that simply never publishes the gauge would pass the first
// half alone while losing the honest zero the live tenant actually reports.
func TestTotalRouteFailurePublishesNoCount(t *testing.T) {
	t.Run("every case fails on the route: no point at all", func(t *testing.T) {
		g := liveGraph()
		// Remove every custodians body so all three cases error on that route.
		// noncustodialDataSources is left intact as the in-test control: it
		// must still publish its honest zero.
		for _, id := range []string{case1ID, case2ID, case3ID} {
			delete(g.bodies, custodiansURL(id))
		}

		rec := telemetrytest.New()
		if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
			t.Fatalf("Collect: %v", err)
		}

		if pts := rec.MetricPoints(metricCustodians); len(pts) != 0 {
			t.Errorf("%s published %d point(s) after EVERY case's fetch failed: %+v — a failed read is a GAP, not a measured zero (#240)",
				metricCustodians, len(pts), pts)
		}
		// Positive control in the same test: without it, an implementation that
		// never publishes either gauge would pass the assertion above.
		assertSinglePoint(t, rec, metricNoncustodial, 0)
	})

	t.Run("one case succeeds with zero rows: the honest zero is published", func(t *testing.T) {
		g := liveGraph()
		delete(g.bodies, custodiansURL(case1ID))
		delete(g.bodies, custodiansURL(case2ID))
		// case3 still answers 200 with an empty collection.

		rec := telemetrytest.New()
		if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		assertSinglePoint(t, rec, metricCustodians, 0)
	})
}

// --- test 11: an ABSENT percentProgress must not publish a fabricated 0% ----

// TestAbsentPercentProgressIsNotPublishedAsZero pins the absent-field trap.
// percentProgress carries no Nullable="false" in the v1.0 $metadata EDM, so
// Graph may omit it — and 0 is a MEANINGFUL value for this field ("nothing has
// happened yet"), not an obviously-wrong sentinel. Decoding into a bare float64
// would therefore publish a confident "0% complete" for an operation whose
// progress is simply unknown, and nothing downstream could tell the two apart.
//
// The positive control is not optional here: an implementation that dropped the
// attribute unconditionally would pass the absence assertion while losing the
// real value on every operation the live tenant reports.
func TestAbsentPercentProgressIsNotPublishedAsZero(t *testing.T) {
	const ops = `{"value":[
	  {"id":"op-absent","action":"holdPolicySync","status":"running",
	   "createdDateTime":"2026-07-28T15:42:44.4668235Z","createdBy":null},
	  {"id":"op-present","action":"holdPolicySync","status":"succeeded","percentProgress":100,
	   "createdDateTime":"2026-07-28T15:42:44.4668235Z",
	   "completedDateTime":"2026-07-28T15:44:10.3139988Z","createdBy":null}
	]}`

	g := &fakeGraph{bodies: map[string]string{
		casesURL:                 singleCaseList(case2ID, "case2"),
		holdsURL(case2ID):        emptyCollection,
		custodiansURL(case2ID):   emptyCollection,
		noncustodialURL(case2ID): emptyCollection,
		operationsURL(case2ID):   ops,
	}}

	rec := telemetrytest.New()
	if err := NewHealth(g, nil).Collect(context.Background(), rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var sawAbsent, sawPresent bool
	for _, r := range rec.LogRecords() {
		if r.EventName != caseOperationEventName {
			continue
		}
		switch r.Attrs["id"] {
		case "op-absent":
			sawAbsent = true
			if v, ok := r.Attrs["percent_progress"]; ok {
				t.Errorf("absent percentProgress published percent_progress = %q; an omitted field must stay omitted, not become a fabricated 0%%", v)
			}
		case "op-present":
			sawPresent = true
			// Positive control: without this the assertion above is vacuous
			// against an implementation that never emits the attribute.
			if got, ok := r.Attrs["percent_progress"]; !ok || got != "100" {
				t.Errorf("present percentProgress = %q (present=%v), want \"100\"", got, ok)
			}
		}
	}
	if !sawAbsent || !sawPresent {
		t.Fatalf("expected both operation log records; sawAbsent=%v sawPresent=%v", sawAbsent, sawPresent)
	}
}
