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
	"github.com/rknightion/graph2otel/internal/logpipeline"
	"github.com/rknightion/graph2otel/internal/semconv"
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
// TestBlobSelfAppIDMatchesTheEmittedAppID ties the exclude_self extractor (#154)
// to the mapper: blobSelfAppID must read the SAME properties.appId that
// mapBlobSignIn labels the record with, so the self-filter compares the field
// that actually ships.
func TestBlobSelfAppIDMatchesTheEmittedAppID(t *testing.T) {
	rec := decodeBlobRecord(t, realBlobFailure)
	got := blobSelfAppID(rec)
	if got == "" {
		t.Fatal("blobSelfAppID returned empty for a record with properties.appId set")
	}
	ev, ok := mapBlobSignIn(rec)
	if !ok {
		t.Fatal("mapBlobSignIn rejected a valid record")
	}
	if want := ev.Attrs["app_id"]; got != want {
		t.Errorf("blobSelfAppID = %q, want %q (the appId the mapper emits)", got, want)
	}
	if got != "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7" {
		t.Errorf("blobSelfAppID = %q, want the record's properties.appId", got)
	}
}

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

// pageFetcherFunc adapts a plain function to logpipeline.PageFetcher, so the
// equivalence gate below can drive the real polled engine without a Graph client.
type pageFetcherFunc func(ctx context.Context, pageURL string) ([]map[string]any, string, error)

func (f pageFetcherFunc) FetchPage(ctx context.Context, pageURL string) ([]map[string]any, string, error) {
	return f(ctx, pageURL)
}

// TestBlobAndPolledSignInDifferOnlyByIngestTransport is #141's load-bearing
// gate, and the reason the provenance attribute exists at all.
//
// It drives BOTH real engines from ONE live-pinned record: the blob side gets
// the full diagnostic-settings envelope, and the polled side gets that
// envelope's inner `properties` object — which IS the Graph signIn resource,
// verified field-for-field against live samples of all four sign-in categories.
// So this is not two fixtures asserted to agree; it is one record arriving two
// ways, which is exactly the production case.
//
// Two properties are pinned together, and they are in tension:
//
//  1. The two records differ by ingest_transport. Without this the transports
//     are indistinguishable and an operator cannot measure the blob-vs-poll
//     split, or attribute a duplicate to #138's at-least-once blob delivery
//     rather than to both lanes running at once.
//  2. They differ by NOTHING ELSE — same event name, same id, same every
//     attribute. This is what keeps them dedupe-able on `id` (blob.go:138-146),
//     and it is the property a careless "fix" breaks: forking mapSignIn into a
//     blob variant and a polled variant would satisfy (1) and silently destroy
//     (2). CLAUDE.md pins the single shared mapper for this reason.
func TestBlobAndPolledSignInDifferOnlyByIngestTransport(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"

	// --- blob transport: the full envelope, through the real blob engine.
	blobRec := telemetrytest.New()
	bc := newBlobCollector(blobSpecs[0], collectors.BlobDeps{
		TenantID: tenant,
		Source: &staticSource{
			name: "tenantId=" + tenant + "/y=2026/m=07/d=16/h=15/m=00/PT1H.json",
			data: []byte(compactJSON(t, realBlobFailure) + "\r\n"),
		},
		Store:  checkpoint.NewStore(t.TempDir()),
		Logger: slog.New(slog.DiscardHandler),
	})
	if err := bc.Collect(context.Background(), blobRec.Emitter()); err != nil {
		t.Fatalf("blob Collect: %v", err)
	}

	// --- graph transport: the SAME record's inner properties (the signIn
	// resource Graph itself would return), through the real polled engine.
	inner := innerProperties(t, realBlobFailure)
	polledRec := telemetrytest.New()
	cfg := logpipeline.EndpointConfig{
		Path:            signInsPath,
		TimeField:       "createdDateTime",
		Flavor:          logpipeline.FlavorGeLe,
		OrderByReliable: true,
		Map:             mapSignIn,
	}
	from := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	fetcher := pageFetcherFunc(func(context.Context, string) ([]map[string]any, string, error) {
		return []map[string]any{inner}, "", nil
	})
	cp := &checkpoint.Checkpoint{TenantID: tenant, Endpoint: cfg.Path, SeenIDs: checkpoint.NewSeenIDs()}
	if _, err := logpipeline.Poll(context.Background(), cfg, cp, from, from.Add(time.Hour), fetcher, polledRec.Emitter()); err != nil {
		t.Fatalf("polled Poll: %v", err)
	}

	blobLogs, polledLogs := blobRec.LogRecords(), polledRec.LogRecords()
	if len(blobLogs) != 1 || len(polledLogs) != 1 {
		t.Fatalf("emitted blob=%d polled=%d records, want 1 each", len(blobLogs), len(polledLogs))
	}
	b, p := blobLogs[0], polledLogs[0]

	// (1) They differ by the provenance attribute.
	if got := b.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportBlob) {
		t.Errorf("blob record %s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportBlob)
	}
	if got := p.Attrs[semconv.AttrIngestTransport]; got != string(telemetry.TransportGraph) {
		t.Errorf("polled record %s = %q, want %q", semconv.AttrIngestTransport, got, telemetry.TransportGraph)
	}
	if b.Attrs[semconv.AttrIngestTransport] == p.Attrs[semconv.AttrIngestTransport] {
		t.Fatal("the two transports are indistinguishable — the whole point of #141")
	}

	// (2) They differ by nothing else. Same event name, same dedupe key, and
	// every other attribute identical in both directions.
	if b.EventName != p.EventName {
		t.Errorf("event name differs: blob %q vs polled %q — a blob-sourced sign-in is the "+
			"same signal as a polled one and must not be separable by name", b.EventName, p.EventName)
	}
	if b.Attrs["id"] != p.Attrs["id"] || b.Attrs["id"] == "" {
		t.Errorf("dedupe key differs: blob id=%q vs polled id=%q — they must stay dedupe-able on `id`",
			b.Attrs["id"], p.Attrs["id"])
	}
	for k, bv := range b.Attrs {
		if k == semconv.AttrIngestTransport {
			continue
		}
		if pv, ok := p.Attrs[k]; !ok {
			t.Errorf("attr %q present on the blob record (%q) but absent on the polled one", k, bv)
		} else if bv != pv {
			t.Errorf("attr %q differs: blob %q vs polled %q", k, bv, pv)
		}
	}
	for k := range p.Attrs {
		if k == semconv.AttrIngestTransport {
			continue
		}
		if _, ok := b.Attrs[k]; !ok {
			t.Errorf("attr %q present on the polled record but absent on the blob one", k)
		}
	}
}

// innerProperties pulls the `properties` object out of a diagnostic-settings
// envelope — the object Graph's /auditLogs/signIns would have returned for the
// same event.
func innerProperties(t *testing.T, raw string) map[string]any {
	t.Helper()
	env := decodeBlobRecord(t, raw)
	inner, ok := env["properties"].(map[string]any)
	if !ok {
		t.Fatalf("pinned record has no properties object")
	}
	return inner
}

// TestDeriveSignin_BoundedLabelsOnly is #187 (F3)'s cardinality gate (#112):
// deriveSignin must carry ONLY bounded, tenant-shaped labels — result,
// conditional_access_status, risk_level_during_sign_in, client_app_used.
// Any per-entity field (id, appId, servicePrincipalId, ipAddress, UPN,
// appDisplayName, resourceDisplayName) leaking into a metric label is the
// exact bug the cardinality rule forbids. Tested against the pinned live
// failure record, not a hand-authored map — it exercises the failure branch
// of the result derivation (status.errorCode 7000113, non-zero).
func TestDeriveSignin_BoundedLabelsOnly(t *testing.T) {
	pts := deriveSignin(decodeBlobRecord(t, realBlobFailure), telemetry.Event{})
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	p := pts[0]
	if p.Name != "entra.signin.count" || p.Kind != blobpipeline.MetricCounter || p.Value != 1 {
		t.Fatalf("bad point: %+v", p)
	}
	want := map[string]any{
		"result":                     "failure",
		"conditional_access_status":  "notApplied",
		"risk_level_during_sign_in":  "none",
		"client_app_used":            "Unknown",
	}
	if len(p.Attrs) != len(want) {
		t.Fatalf("attrs = %v, want exactly the 4 bounded labels %v", p.Attrs, want)
	}
	for k, w := range want {
		if p.Attrs[k] != w {
			t.Errorf("attr %q = %#v, want %#v", k, p.Attrs[k], w)
		}
	}
}

// realSignInSuccess is a minimal pinned-shape success record (errorCode 0, or
// absent) so the result derivation's success branch is exercised against a
// real field layout too, not inferred.
const realSignInSuccessProps = `{
  "id": "a1b2c3d4-1111-2222-3333-444455556666",
  "createdDateTime": "2026-07-16T15:31:34.1881867+00:00",
  "userPrincipalName": "rob@m7kni.io",
  "appId": "c98e5057-edde-4666-b301-186a01b4dc58",
  "status": {"errorCode": 0},
  "clientAppUsed": "Browser",
  "conditionalAccessStatus": "success",
  "riskLevelDuringSignIn": "none",
  "riskState": "none"
}`

func TestDeriveSignin_SuccessWhenErrorCodeIsZero(t *testing.T) {
	env := map[string]any{"properties": decodeBlobRecord(t, realSignInSuccessProps)}
	pts := deriveSignin(env, telemetry.Event{})
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	if got := pts[0].Attrs["result"]; got != "success" {
		t.Errorf("result = %#v, want \"success\"", got)
	}
}

// freshBlobSignin clones realBlobFailure with a within-window
// properties.createdDateTime, so the derived counter is not gated by
// RecencyWindow and reaches the recorder — the pinned realBlobFailure record
// is always gated (its date is 2026-07-16) and never would.
func freshBlobSignin(t *testing.T, at time.Time) string {
	t.Helper()
	rec := decodeBlobRecord(t, realBlobFailure)
	ts := at.UTC().Format(time.RFC3339Nano)
	if props, ok := rec["properties"].(map[string]any); ok {
		props["createdDateTime"] = ts
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal fresh record: %v", err)
	}
	return string(b)
}

// TestCollectorDerivesSigninCounterForFreshRecord drives a within-window
// record through the real blob collector (mirroring graphactivity's
// TestCollectorDerivesRequestCounterForFreshRecord), so the signal-drift
// golden actually sees what deriveSignin ships end to end, not just what the
// unit-level test above pins.
func TestCollectorDerivesSigninCounterForFreshRecord(t *testing.T) {
	const tenant = "4b8c18bd-2f9f-4227-af55-9f1061cf9c32"
	src := &staticSource{
		name: "tenantId=" + tenant + "/y=2026/m=07/d=19/h=10/m=00/PT1H.json",
		data: []byte(freshBlobSignin(t, time.Now().Add(-5*time.Minute)) + "\r\n"),
	}
	rec := telemetrytest.New()
	c := newBlobCollector(blobSpecs[0], collectors.BlobDeps{
		TenantID:            tenant,
		Source:              src,
		Store:               checkpoint.NewStore(t.TempDir()),
		Logger:              slog.New(slog.DiscardHandler),
		MetricRecencyWindow: 20 * time.Minute,
	})
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints("entra.signin.count")
	if len(pts) != 1 || pts[0].Value != 1 {
		t.Fatalf("entra.signin.count = %+v, want a single point value 1", pts)
	}
	got := pts[0].Attrs
	want := map[string]bool{
		"result": true, "conditional_access_status": true,
		"risk_level_during_sign_in": true, "client_app_used": true,
	}
	for k := range got {
		if !want[k] {
			t.Errorf("per-entity label leaked into metric: %q", k)
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing bounded label %q", k)
		}
	}
	for _, forbidden := range []string{
		"id", "app_id", "service_principal_id", "ip_address",
		"user_principal_name", "app_display_name", "resource_display_name", "error_code",
	} {
		if _, present := got[forbidden]; present {
			t.Errorf("forbidden per-entity label on metric: %q", forbidden)
		}
	}
}
