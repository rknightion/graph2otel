package networkaccesstraffic

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/checkpoint"
	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// testdata/traffic.json holds 15 rows selected from a 3,000-row live sample
// taken as graph2otel-poller on 2026-07-29, chosen to cover every observed
// combination of (trafficType, action, deviceCategory, transportProtocol) plus
// the rows carrying the rarely-populated fields (a destinationIp, a non-zero
// sentBytes, the one microsoft365 row where isAgentic is null rather than
// false).
//
// Five values are substituted because they identify a real person, device and
// network: the tenant id, the client's public egress IP, the user's UPN, and
// the userId/deviceId GUIDs. Substitutes are realistic rather than
// documentation placeholders, per the #318 amendment — a doc-range value
// exercises the mapper against a shape the wire never sends. EVERY other byte
// is verbatim, including all ~20 empty-string fields and every JSON null,
// because those two encodings of absence are what this mapper has to get right.
//
// Not represented: a populated destinationUrl (9 of 3,000 live rows have one)
// and any Private Access row — m7kni's private profile is enabled but carried
// no traffic in the sample. Both are recorded gaps rather than invented rows.
func liveRows(t *testing.T) []map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/traffic.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var page struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(page.Value) != 15 {
		t.Fatalf("fixture has %d rows, want 15", len(page.Value))
	}
	return page.Value
}

// rowWhere returns the first fixture row satisfying pred.
func rowWhere(t *testing.T, rows []map[string]any, what string, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	for _, r := range rows {
		if pred(r) {
			return r
		}
	}
	t.Fatalf("fixture no longer contains a row where %s; this test guards that case", what)
	return nil
}

// recordingFetcher is a logpipeline.PageFetcher serving the fixture once and
// recording every requested page URL, so the query the collector builds can be
// asserted rather than assumed.
type recordingFetcher struct {
	records  []map[string]any
	seenURLs []string
}

func (f *recordingFetcher) FetchPage(_ context.Context, pageURL string) ([]map[string]any, string, error) {
	f.seenURLs = append(f.seenURLs, pageURL)
	return f.records, "", nil
}

func depsWith(t *testing.T, f *recordingFetcher) collectors.WindowDeps {
	t.Helper()
	return collectors.WindowDeps{
		TenantID: "t1",
		Fetcher:  f,
		Store:    checkpoint.NewStore(t.TempDir()),
	}
}

// poll drives the real engine over the fixture and returns what was emitted.
func poll(t *testing.T, rows []map[string]any) (*telemetrytest.Recorder, *recordingFetcher) {
	t.Helper()
	f := &recordingFetcher{records: rows}
	c := newCollector(depsWith(t, f))
	rec := telemetrytest.New()
	from := time.Date(2026, 7, 29, 18, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	if _, err := c.CollectWindow(context.Background(), from, to, rec.Emitter(), recordoutcome.NewRecorder()); err != nil {
		t.Fatalf("CollectWindow: %v", err)
	}
	return rec, f
}

// TestLiveCaptureEmitsOneRecordPerConnection is the baseline: every fetched row
// becomes exactly one log record, dedupe-keyed on transactionId.
func TestLiveCaptureEmitsOneRecordPerConnection(t *testing.T) {
	rows := liveRows(t)
	rec, _ := poll(t, rows)

	got := rec.LogRecords()
	if len(got) != len(rows) {
		t.Fatalf("emitted %d records for %d rows", len(got), len(rows))
	}
	for _, r := range got {
		if r.EventName != eventName {
			t.Errorf("EventName = %q, want %q", r.EventName, eventName)
		}
	}
}

// TestDedupeKeyIsTheTransactionId pins the dedupe identity. connectionId is the
// tempting alternative and is WRONG: it carries a trailing ordinal and repeats
// across a client's connections, so deduping on it would discard real records.
func TestDedupeKeyIsTheTransactionId(t *testing.T) {
	rows := liveRows(t)
	r := rows[0]
	id, _ := mapTrafficRecord(r)
	if want := r["transactionId"]; id != want {
		t.Errorf("dedupe id = %q, want the transactionId %v", id, want)
	}
	if id == r["connectionId"] {
		t.Error("dedupe id is the connectionId, which is not unique per record")
	}
}

// TestBlockedConnectionsAreWarn: a block is the security-relevant event, and
// severity is what makes it selectable without knowing the attribute
// vocabulary. It is the majority action on the live tenant, which is why the
// collector is volume-gated rather than why the severity should be lowered.
func TestBlockedConnectionsAreWarn(t *testing.T) {
	rows := liveRows(t)

	blocked := rowWhere(t, rows, `action == "block"`, func(r map[string]any) bool { return r["action"] == "block" })
	if _, ev := mapTrafficRecord(blocked); ev.Severity != telemetry.SeverityWarn {
		t.Errorf("blocked connection severity = %v, want Warn", ev.Severity)
	}
	allowed := rowWhere(t, rows, `action == "allow"`, func(r map[string]any) bool { return r["action"] == "allow" })
	if _, ev := mapTrafficRecord(allowed); ev.Severity != telemetry.SeverityInfo {
		t.Errorf("allowed connection severity = %v, want Info", ev.Severity)
	}
}

// TestUnknownActionIsNotFoldedIntoAllowOrBlock: an action Microsoft adds later
// must be visible as itself in the body, not silently rendered as one of the
// two this tenant happens to produce. The attribute already carries it
// verbatim; this guards the human-readable half.
func TestUnknownActionIsNotFoldedIntoAllowOrBlock(t *testing.T) {
	_, ev := mapTrafficRecord(map[string]any{
		"transactionId":   "t1",
		"action":          "quarantine",
		"trafficType":     "internet",
		"destinationFQDN": "example.test",
	})
	if !strings.Contains(ev.Body, "quarantine") {
		t.Errorf("body %q does not name the unrecognized action", ev.Body)
	}
	if strings.Contains(ev.Body, "allowed") || strings.Contains(ev.Body, "blocked") {
		t.Errorf("body %q folded an unrecognized action into allow/block", ev.Body)
	}
	if ev.Attrs[semconv.AttrAction] != "quarantine" {
		t.Errorf("action attribute = %v, want the raw wire value", ev.Attrs[semconv.AttrAction])
	}
}

// TestEmptyStringFieldsEmitNoKey is the first of the two absence encodings.
// Asserted on the MAPPER'S OWN returned attrs, not on a rendered record:
// telemetry.SetStr filters empties on the way in, so a rendered record cannot
// tell "the mapper wrote nothing" from "the mapper wrote an empty string" —
// the #322/#354 rendered-representation blindness this repo has now hit twice.
func TestEmptyStringFieldsEmitNoKey(t *testing.T) {
	rows := liveRows(t)
	r := rowWhere(t, rows, `sessionId == ""`, func(r map[string]any) bool { return r["sessionId"] == "" })

	_, ev := mapTrafficRecord(r)
	for _, key := range []string{semconv.AttrSessionId, semconv.AttrDestinationUrl} {
		if v, ok := ev.Attrs[key]; ok {
			t.Errorf("empty wire field published %s = %q; an empty string is Microsoft's 'no value' here", key, v)
		}
	}
}

// TestNullScalarsEmitNoKey is the second absence encoding, and the one that
// would fabricate data: responseCode is null on most rows, and a bare int
// would publish HTTP 0. isAgentic is null on the microsoft365 row and false on
// the internet ones — "GSA did not evaluate this" and "GSA decided no" are
// different facts and must not collapse.
func TestNullScalarsEmitNoKey(t *testing.T) {
	rows := liveRows(t)

	nullAgentic := rowWhere(t, rows, "isAgentic is null", func(r map[string]any) bool {
		v, present := r["isAgentic"]
		return present && v == nil
	})
	_, ev := mapTrafficRecord(nullAgentic)
	if v, ok := ev.Attrs[semconv.AttrIsAgentic]; ok {
		t.Errorf("null isAgentic published %v; a false here would claim GSA evaluated the connection", v)
	}
	if v, ok := ev.Attrs[semconv.AttrResponseCode]; ok && nullAgentic["responseCode"] == nil {
		t.Errorf("null responseCode published %v; a 0 would read as an HTTP status", v)
	}

	falseAgentic := rowWhere(t, rows, "isAgentic is false", func(r map[string]any) bool { return r["isAgentic"] == false })
	_, ev2 := mapTrafficRecord(falseAgentic)
	if v, ok := ev2.Attrs[semconv.AttrIsAgentic]; !ok || v != false {
		t.Errorf("isAgentic false was not emitted (got %v, present=%v); a measured false is data", v, ok)
	}
}

// TestByteCountersAreAlwaysEmittedIncludingZero: the opposite call from the
// nullable scalars above, and deliberate. A blocked connection transferred
// nothing, and that measured zero is the evidence the block took effect — an
// absent series would look like the bytes were unmeasured.
func TestByteCountersAreAlwaysEmittedIncludingZero(t *testing.T) {
	rows := liveRows(t)
	zero := rowWhere(t, rows, "sentBytes == 0", func(r map[string]any) bool { return r["sentBytes"] == float64(0) })

	_, ev := mapTrafficRecord(zero)
	for _, key := range []string{semconv.AttrSentBytes, semconv.AttrReceivedBytes} {
		v, ok := ev.Attrs[key]
		if !ok {
			t.Errorf("%s absent on a blocked connection; a measured zero is the evidence the block worked", key)
			continue
		}
		if v != float64(0) {
			t.Errorf("%s = %v, want 0", key, v)
		}
	}

	nonZero := rowWhere(t, rows, "sentBytes > 0", func(r map[string]any) bool {
		f, ok := r["sentBytes"].(float64)
		return ok && f > 0
	})
	_, ev2 := mapTrafficRecord(nonZero)
	if ev2.Attrs[semconv.AttrSentBytes] != nonZero["sentBytes"] {
		t.Errorf("sent_bytes = %v, want the wire value %v", ev2.Attrs[semconv.AttrSentBytes], nonZero["sentBytes"])
	}
}

// TestWebCategoryIsKeptCommaJoined: destinationWebCategory.name arrives as one
// comma-joined string ("ComputersAndTechnology,Business"). Splitting it would
// invent a structure Microsoft did not send, the same call
// entra.auth_strength made for its method combinations (#322).
//
// Asserted on the mapper's returned STRING rather than through the recorder,
// because a []string joined with "," renders byte-identically to the joined
// string — which is exactly how #322's first guard passed over a deliberately
// split mapper.
func TestWebCategoryIsKeptCommaJoined(t *testing.T) {
	rows := liveRows(t)
	r := rowWhere(t, rows, "destinationWebCategory.name contains a comma", func(r map[string]any) bool {
		cat, _ := r["destinationWebCategory"].(map[string]any)
		name, _ := cat["name"].(string)
		return strings.Contains(name, ",")
	})
	cat := r["destinationWebCategory"].(map[string]any)
	want := cat["name"].(string)

	_, ev := mapTrafficRecord(r)
	got, ok := ev.Attrs[semconv.AttrDestinationWebCategory]
	if !ok {
		t.Fatal("destination_web_category absent")
	}
	if s, isString := got.(string); !isString {
		t.Fatalf("destination_web_category is %T, not a string; the wire sends one joined value", got)
	} else if s != want {
		t.Errorf("destination_web_category = %q, want the verbatim wire value %q", s, want)
	}
}

// TestTlsDetailsAreMapped: the nested tlsDetails object is present on the large
// majority of live rows, so it is the common case rather than an edge one.
func TestTlsDetailsAreMapped(t *testing.T) {
	rows := liveRows(t)
	r := rowWhere(t, rows, "tlsDetails is populated", func(r map[string]any) bool {
		d, ok := r["tlsDetails"].(map[string]any)
		return ok && len(d) > 0
	})
	tls := r["tlsDetails"].(map[string]any)

	_, ev := mapTrafficRecord(r)
	for key, wire := range map[string]string{
		semconv.AttrTlsAction:     "action",
		semconv.AttrTlsStatus:     "status",
		semconv.AttrTlsPolicyId:   "policyId",
		semconv.AttrTlsPolicyName: "policyName",
		semconv.AttrTlsRuleId:     "ruleId",
		semconv.AttrTlsRuleName:   "ruleName",
	} {
		if ev.Attrs[key] != tls[wire] {
			t.Errorf("%s = %v, want tlsDetails.%s = %v", key, ev.Attrs[key], wire, tls[wire])
		}
	}
	// The TLS policy is a DIFFERENT object from the filtering policy; folding
	// them onto one key would make an inspection bypass look like a filtering
	// decision.
	if ev.Attrs[semconv.AttrTlsPolicyId] == ev.Attrs[semconv.AttrPolicyId] {
		t.Error("tls_policy_id and policy_id carry the same value; they are distinct policy objects")
	}
}

// TestNoRecordCarriesProcessArgumentsOrTheAgenticBlock is the content
// exclusion, held down by a SENTINEL rather than by a key-absence check.
// A key check only proves the mapper does not use the name it was told about;
// a sentinel proves the VALUE never reaches telemetry by any path, including a
// future generic passthrough.
//
// processArgs/processTree are excluded because a command line can carry a
// credential in an argument (#190) and both are empty on all 3,000 live rows,
// so there is no sample to review. The agentic block is excluded because it has
// no observed values at all.
func TestNoRecordCarriesProcessArgumentsOrTheAgenticBlock(t *testing.T) {
	const sentinel = "SENTINEL-DO-NOT-EMIT-9d41f2"
	rows := liveRows(t)
	r := map[string]any{}
	for k, v := range rows[0] {
		r[k] = v
	}
	for _, field := range []string{
		"processArgs", "processTree", "processId",
		"agenticSessionId", "agentVirtualId", "agentTypeId", "agentTypeName",
		"mcpPrimitiveName", "mcpProtocolVersion",
	} {
		r[field] = sentinel
	}
	r["aiAgentDetails"] = map[string]any{"prompt": sentinel}
	r["aiAgentDetectionDetails"] = map[string]any{"detail": sentinel}

	_, ev := mapTrafficRecord(r)
	if strings.Contains(ev.Body, sentinel) {
		t.Errorf("record body carries the sentinel: %q", ev.Body)
	}
	for k, v := range ev.Attrs {
		if s, ok := v.(string); ok && strings.Contains(s, sentinel) {
			t.Errorf("attribute %s carries the sentinel value %q; process arguments and the agentic block must never be emitted", k, s)
		}
	}
}

// TestNoMetricsAreEmitted: this collector is log-only by design (#112). A
// bounded counter was considered and rejected — LogQL count-by answers the same
// question free — and a metric appearing here would most likely mean someone
// labeled a series by a per-connection field.
func TestNoMetricsAreEmitted(t *testing.T) {
	rec, _ := poll(t, liveRows(t))
	if names := rec.MetricNames(); len(names) != 0 {
		t.Errorf("collector emitted metrics %v; it is log-only", names)
	}
}

// TestQueryIsBetaStrictlyBoundedAndUnordered pins the four query decisions that
// came out of live measurement, by asserting the URL the engine actually built.
func TestQueryIsBetaStrictlyBoundedAndUnordered(t *testing.T) {
	_, f := poll(t, liveRows(t))
	if len(f.seenURLs) == 0 {
		t.Fatal("no page was fetched")
	}
	url := f.seenURLs[0]

	if !strings.HasPrefix(url, betaBaseURL+path) {
		t.Errorf("first page URL = %q, want the beta root %q (there is no v1.0 form)", url, betaBaseURL+path)
	}
	// Strict gt/lt, because page order is not trusted.
	if !strings.Contains(url, "createdDateTime+gt+") && !strings.Contains(url, "createdDateTime gt ") {
		t.Errorf("URL %q does not carry a strict `gt` lower bound", url)
	}
	// No $orderby: accepting an $orderby is not evidence that page order is
	// stable under paging on a throttled firehose, so the window is sorted
	// client-side instead.
	if strings.Contains(url, "orderby") {
		t.Errorf("URL %q sets $orderby; this endpoint's paged ordering is unmeasured and the engine sorts client-side", url)
	}
	// $count is rejected by the endpoint (400), so it must never be requested.
	if strings.Contains(url, "count=true") {
		t.Errorf("URL %q requests $count, which this endpoint answers 400 for", url)
	}
	// The measured $top ceiling is exactly 1000; 1001 is a 400.
	if strings.Contains(url, "top=") && !strings.Contains(url, "top=1000") {
		t.Errorf("URL %q requests a page size other than the measured 1000 ceiling", url)
	}
}

// TestGatingIsBothExperimentalAndHighVolume: the two gates mean different
// things and an operator needs both facts. Experimental says the surface is
// Graph beta (#183); HighVolume says the rate scales with traffic (#254) —
// ~3,695 records/hour from one client, live-measured.
func TestGatingIsBothExperimentalAndHighVolume(t *testing.T) {
	c := newCollector(depsWith(t, &recordingFetcher{}))
	if !c.Experimental() {
		t.Error("collector is not Experimental; the endpoint exists only on Graph beta")
	}
	if !c.HighVolume() {
		t.Error("collector is not HighVolume; it emits ~88,700 records/day from a single client")
	}
	if got := c.RequiredPermissions(); len(got) != 1 || got[0] != "NetworkAccess.Read.All" {
		t.Errorf("RequiredPermissions = %v, want exactly the read-only scope", got)
	}
	for _, p := range c.RequiredPermissions() {
		if strings.Contains(p, "ReadWrite") {
			t.Errorf("declared a write scope %q; the endpoint's own 403 lists ReadWrite variants and read is sufficient", p)
		}
	}
}

// TestUserIdentityIsAbsentOnServiceTraffic: a connection with no user must not
// carry an empty-string principal, or a LogQL query for "connections with no
// user" would have to know to match "" as well as absence.
func TestUserIdentityIsAbsentOnServiceTraffic(t *testing.T) {
	_, ev := mapTrafficRecord(map[string]any{
		"transactionId":     "t2",
		"action":            "allow",
		"trafficType":       "microsoft365",
		"destinationFQDN":   "example.test",
		"userId":            "",
		"userPrincipalName": "",
	})
	for _, key := range []string{semconv.AttrUserId, semconv.AttrUserPrincipalName} {
		if v, ok := ev.Attrs[key]; ok {
			t.Errorf("service traffic published %s = %q, want the key absent", key, v)
		}
	}
}

// TestBodyNamesTheDestinationEvenWithoutAnFqdn: the FQDN is the field an
// investigation starts from, and it is empty on some rows. The body falls back
// to the IP rather than rendering a blank destination.
func TestBodyNamesTheDestinationEvenWithoutAnFqdn(t *testing.T) {
	_, ev := mapTrafficRecord(map[string]any{
		"transactionId": "t3",
		"action":        "block",
		"trafficType":   "internet",
		"destinationIp": "203.0.113.9",
	})
	if !strings.Contains(ev.Body, "203.0.113.9") {
		t.Errorf("body %q does not name the destination when the FQDN is empty", ev.Body)
	}
}
