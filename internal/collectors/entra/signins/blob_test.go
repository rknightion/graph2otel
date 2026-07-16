package signins

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/blobpipeline"
	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/license"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// realBlobFailure is a verbatim MicrosoftServicePrincipalSignInLogs record
// pulled from the live m7kni storage account on 2026-07-16. It is pinned rather
// than hand-written because this shape is documented nowhere, and this
// particular record is worth its length: it demonstrates BOTH of this file's
// traps in one payload.
//
//  1. envelope "time"          = 15:34:08.5339262Z
//     properties.createdDateTime = 15:31:34.1881867+00:00  <- 154 SECONDS EARLIER
//  2. "level": "4" on a record whose status.errorCode is 7000113 (a FAILURE).
//
// Trimmed of nothing; the fields graph2otel ignores are left in on purpose, so
// this stays a faithful sample of what actually lands.
const realBlobFailure = `{
  "time": "2026-07-16T15:34:08.5339262Z",
  "resourceId": "/tenants/4b8c18bd-2f9f-4227-af55-9f1061cf9c32/providers/Microsoft.aadiam",
  "operationName": "Sign-in activity",
  "operationVersion": "1.0",
  "category": "MicrosoftServicePrincipalSignInLogs",
  "tenantId": "4b8c18bd-2f9f-4227-af55-9f1061cf9c32",
  "resultType": "7000113",
  "resultSignature": "FAILURE",
  "resultDescription": "Application '{appIdentifier}' is not authorized to make application on-behalf-of calls.",
  "durationMs": 0,
  "callerIpAddress": "135.225.184.235",
  "correlationId": "0a1b338b-22bc-44ee-90e3-330012bdcffc",
  "level": "4",
  "location": "SE",
  "properties": {
    "id": "5762b741-b128-4e73-80d4-f05a660c3b00",
    "createdDateTime": "2026-07-16T15:31:34.1881867+00:00",
    "userDisplayName": "",
    "userPrincipalName": "",
    "userId": "",
    "appId": "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7",
    "appDisplayName": "AADReporting",
    "ipAddress": "135.225.184.235",
    "status": {
      "errorCode": 7000113,
      "failureReason": "Application '{appIdentifier}' is not authorized to make application on-behalf-of calls."
    },
    "clientAppUsed": "Unknown",
    "deviceDetail": {
      "deviceId": "",
      "operatingSystem": "Linux",
      "browser": "",
      "isCompliant": false,
      "isManaged": false,
      "trustType": "Azure AD registered"
    },
    "location": {
      "city": "Gavle",
      "state": "Gavleborgs Lan",
      "countryOrRegion": "SE",
      "geoCoordinates": {"latitude": 60.68408966064453, "longitude": 17.20281982421875}
    },
    "correlationId": "0a1b338b-22bc-44ee-90e3-330012bdcffc",
    "conditionalAccessStatus": "notApplied",
    "riskLevelDuringSignIn": "none",
    "riskState": "none",
    "resourceDisplayName": "Microsoft Graph",
    "resourceId": "00000003-0000-0000-c000-000000000000",
    "servicePrincipalName": "AADReporting",
    "signInEventTypes": ["servicePrincipal"],
    "servicePrincipalId": "29f4d705-d0bf-42fa-ad8f-e7bd308e94cb",
    "appOwnerTenantId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
  }
}`

func decodeBlobRecord(t *testing.T, raw string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("decoding the pinned record: %v", err)
	}
	return rec
}

// TestMapBlobSignInBindsTimestampToCreatedDateTimeNotEnvelopeTime is THE
// regression test for this file's reason to exist (#135).
//
// The diagnostic-settings envelope's "time" is when Azure INGESTED the record,
// not when the sign-in happened. Across live samples of all three sign-in
// categories the two were NEVER equal (0 of 700 records) and the gap was
// variable — 28s to 1077s — so it cannot even be corrected by subtracting a
// constant. Binding to "time" backdates nothing and post-dates every sign-in by
// a random couple of minutes, with no error and no warning: every dashboard and
// every alert silently lands in the wrong bucket.
//
// MicrosoftGraphActivityLogs binds to the envelope "time" and is CORRECT to —
// there, time and properties.timeGenerated are byte-identical. That is exactly
// the trap: the shipped neighboring collector models the opposite rule. If this
// test fails, someone has copied it.
func TestMapBlobSignInBindsTimestampToCreatedDateTimeNotEnvelopeTime(t *testing.T) {
	rec := decodeBlobRecord(t, realBlobFailure)

	ev, ok := mapBlobSignIn(rec)
	if !ok {
		t.Fatal("mapBlobSignIn rejected a valid record")
	}

	want := time.Date(2026, 7, 16, 15, 31, 34, 188186700, time.UTC)
	if !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %s, want %s (properties.createdDateTime)",
			ev.Timestamp.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}

	// State the failure mode explicitly rather than only implying it: the
	// envelope time is the value a copied MGAL mapper would produce.
	envelope := time.Date(2026, 7, 16, 15, 34, 8, 533926200, time.UTC)
	if ev.Timestamp.Equal(envelope) {
		t.Error("timestamp is bound to the envelope `time` — that is the ingestion " +
			"time, 154s after this sign-in. Bind to properties.createdDateTime.")
	}
}

// TestMapBlobSignInDerivesSeverityFromStatusNotLevel pins that `level` is not
// consulted. It is the string "4" on 100% of records in all three sign-in
// categories — including this one, which is a failure. A mapper that trusted it
// would mark every failed sign-in with the same severity as every successful
// one, forever.
func TestMapBlobSignInDerivesSeverityFromStatusNotLevel(t *testing.T) {
	rec := decodeBlobRecord(t, realBlobFailure)

	ev, ok := mapBlobSignIn(rec)
	if !ok {
		t.Fatal("mapBlobSignIn rejected a valid record")
	}

	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("severity = %v, want Warn: status.errorCode is 7000113 (a failure), "+
			"even though level is %q", ev.Severity, rec["level"])
	}
	if got := ev.Attrs["status_error_code"]; got != 7000113 {
		t.Errorf("status_error_code = %v, want 7000113", got)
	}
}

// TestMapBlobSignInUnwrapsTheEnvelopeAndReusesTheCanonicalAttributes checks that
// the blob path produces the same attributes as the polled path: the
// diagnostic-settings `properties` object IS the Graph signIn resource (verified
// field-for-field against live samples of all four sign-in categories), so both
// sources must be indistinguishable downstream apart from the timestamp fix.
func TestMapBlobSignInUnwrapsTheEnvelopeAndReusesTheCanonicalAttributes(t *testing.T) {
	rec := decodeBlobRecord(t, realBlobFailure)

	ev, ok := mapBlobSignIn(rec)
	if !ok {
		t.Fatal("mapBlobSignIn rejected a valid record")
	}

	if ev.Name != eventName {
		t.Errorf("event name = %q, want %q — a blob-sourced sign-in is the same "+
			"signal as a polled one and must not be distinguishable by name", ev.Name, eventName)
	}

	// Attributes must come from the INNER properties object, not the envelope.
	// The envelope has a resourceId too ("/tenants/.../Microsoft.aadiam"), and
	// reading it instead would be a plausible, silent mis-map.
	want := map[string]any{
		"id":                         "5762b741-b128-4e73-80d4-f05a660c3b00",
		"app_id":                     "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7",
		"app_display_name":           "AADReporting",
		"service_principal_id":       "29f4d705-d0bf-42fa-ad8f-e7bd308e94cb",
		"service_principal_name":     "AADReporting",
		"resource_id":                "00000003-0000-0000-c000-000000000000",
		"resource_display_name":      "Microsoft Graph",
		"ip_address":                 "135.225.184.235",
		"conditional_access_status":  "notApplied",
		"location_country_or_region": "SE",
	}
	for k, v := range want {
		if got := ev.Attrs[k]; got != v {
			t.Errorf("attrs[%q] = %v, want %v", k, got, v)
		}
	}

	// A service-principal sign-in carries no user; the shared mapper omits empty
	// attributes rather than emitting them blank.
	if _, ok := ev.Attrs["user_principal_name"]; ok {
		t.Error("user_principal_name is set on a service-principal sign-in; " +
			"empty attributes should be omitted")
	}
}

// TestMapBlobSignInRejectsARecordWithNoProperties covers the only structural way
// a record can be useless here. Returning false drops it while blobpipeline
// still consumes its bytes, so a junk line never stalls the cursor.
func TestMapBlobSignInRejectsARecordWithNoProperties(t *testing.T) {
	for _, raw := range []string{
		`{"time":"2026-07-16T15:34:08Z","category":"MicrosoftServicePrincipalSignInLogs"}`,
		`{"time":"2026-07-16T15:34:08Z","properties":"not-an-object"}`,
	} {
		rec := decodeBlobRecord(t, raw)
		if _, ok := mapBlobSignIn(rec); ok {
			t.Errorf("mapBlobSignIn accepted a record with no usable properties: %s", raw)
		}
	}
}

// TestMapBlobSignInWithoutACreatedDateTimeIsDropped: a sign-in with no event
// time is not mappable. Emitting it with a zero timestamp would make the emitter
// stamp it at ingest time — silently reintroducing the exact error this file
// exists to prevent, on the records least able to survive it. Dropping it is
// loud (it shows up as a skipped record) where a wrong timestamp is not.
func TestMapBlobSignInWithoutACreatedDateTimeIsDropped(t *testing.T) {
	for _, raw := range []string{
		`{"time":"2026-07-16T15:34:08Z","properties":{"id":"x"}}`,
		`{"time":"2026-07-16T15:34:08Z","properties":{"id":"x","createdDateTime":"not-a-time"}}`,
	} {
		rec := decodeBlobRecord(t, raw)
		if _, ok := mapBlobSignIn(rec); ok {
			t.Errorf("mapBlobSignIn accepted a record with no parseable createdDateTime: %s", raw)
		}
	}
}

// TestBlobSpecsDoNotCollideWithThePolledStreams guards the config/self-obs key
// space. A blob stream and its polled twin are separate collectors with separate
// intervals and separate enable flags; if their names collided, a user's
// override would silently hit whichever registered first.
func TestBlobSpecsDoNotCollideWithThePolledStreams(t *testing.T) {
	polled := map[string]bool{}
	for _, s := range specs {
		polled[s.name] = true
	}

	seenName := map[string]bool{}
	seenContainer := map[string]bool{}
	for _, b := range blobSpecs {
		if polled[b.name] {
			t.Errorf("blob spec %q collides with a polled stream's name", b.name)
		}
		if seenName[b.name] {
			t.Errorf("duplicate blob spec name %q", b.name)
		}
		// The cursor namespace defaults to the container, so two blob specs
		// sharing one would dedupe each other's records away — the failure
		// mode logpipeline needs an explicit CheckpointKey to avoid.
		if seenContainer[b.container] {
			t.Errorf("blob spec %q reuses container %q; they would share a cursor", b.name, b.container)
		}
		seenName[b.name] = true
		seenContainer[b.container] = true
	}
}

// TestBlobCollectorsAreDefaultOnAndNeedP1 pins the two gating decisions (#135).
// Not Experimental: blob_ingest.account_url is already the explicit opt-in, and
// these are v1.0-stable sources — the opposite of the polled beta twins.
func TestBlobCollectorsAreDefaultOnAndNeedP1(t *testing.T) {
	for _, s := range blobSpecs {
		t.Run(s.name, func(t *testing.T) {
			c := newBlobCollector(s, collectors.BlobDeps{
				TenantID: "t1",
				Store:    checkpoint.NewStore(t.TempDir()),
			})
			if exp, ok := any(c).(collectors.Experimental); ok && exp.Experimental() {
				t.Error("blob sign-in collectors must not be Experimental: configuring " +
					"blob_ingest.account_url is already the opt-in, and these are v1.0-stable")
			}
			if c.RequiredCapability() != license.CapEntraP1 {
				t.Errorf("RequiredCapability = %q, want entra_p1", c.RequiredCapability())
			}
			if c.Name() != s.name {
				t.Errorf("Name = %q, want %q", c.Name(), s.name)
			}
		})
	}
}

// staticSource is a blobpipeline.Source serving one in-memory blob, so the
// collector can be driven end-to-end without Azure.
type staticSource struct {
	name string
	data []byte
}

func (s *staticSource) List(_ context.Context, _, prefix string) ([]blobpipeline.BlobInfo, error) {
	if !strings.HasPrefix(s.name, prefix) {
		return nil, nil
	}
	return []blobpipeline.BlobInfo{{Name: s.name, Size: int64(len(s.data))}}, nil
}

func (s *staticSource) ReadRange(_ context.Context, _, _ string, offset, count int64) ([]byte, error) {
	end := min(offset+count, int64(len(s.data)))
	if offset >= end {
		return nil, nil
	}
	return s.data[offset:end], nil
}

// TestBlobCollectorDrainsARealRecordEndToEnd drives a whole collector over the
// pinned live record — JSON Lines with the CRLF terminators Azure actually
// writes — and checks what reaches the emitter. It is the integration-level
// counterpart to the mapper tests: it would catch a collector wired to the wrong
// container prefix, which no unit test of mapBlobSignIn can see.
func TestBlobCollectorDrainsARealRecordEndToEnd(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		// The real layout: tenantId=<guid>/ … /PT1H.json, CRLF-terminated.
		name: "tenantId=" + tenant + "/y=2026/m=07/d=16/h=15/m=00/PT1H.json",
		data: []byte(compactJSON(t, realBlobFailure) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newBlobCollector(blobSpecs[0], collectors.BlobDeps{
		TenantID: tenant,
		Source:   src,
		Store:    checkpoint.NewStore(t.TempDir()),
		Logger:   slog.New(slog.DiscardHandler),
	})

	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	logs := rec.LogRecords()
	if len(logs) != 1 {
		t.Fatalf("emitted %d records, want 1 — check the tenantId= listing prefix", len(logs))
	}
	want := time.Date(2026, 7, 16, 15, 31, 34, 188186700, time.UTC)
	if !logs[0].Timestamp.Equal(want) {
		t.Errorf("emitted timestamp = %s, want %s (properties.createdDateTime)",
			logs[0].Timestamp.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}

	// A second Collect against an unchanged blob must emit nothing: the cursor
	// persisted, so a restart does not re-ship what it already has.
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if got := len(rec.LogRecords()); got != 1 {
		t.Errorf("after a second tick over an unchanged blob: %d records, want 1 (duplicate emission)", got)
	}
}

// compactJSON strips the pinned record's formatting, since a JSON Lines record
// is one line by definition.
func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		t.Fatalf("compacting the pinned record: %v", err)
	}
	return buf.String()
}
