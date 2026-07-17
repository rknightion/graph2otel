package domains

import (
	"context"
	"errors"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned page bodies (or errors) and records
// the ConsistencyLevel header seen on each request, mirroring the
// directorycounts/groups reference tests' fake.
type fakeGraph struct {
	bodies      map[string]string
	errs        map[string]error
	seenHeaders map[string]string // url -> ConsistencyLevel
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, headers map[string]string) ([]byte, error) {
	if f.seenHeaders == nil {
		f.seenHeaders = map[string]string{}
	}
	f.seenHeaders[url] = headers["ConsistencyLevel"]
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, errors.New("fakeGraph: no canned response for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const domainsURL = "https://graph.microsoft.com/v1.0/domains"

// liveDomains is a VERBATIM GET /domains capture from the m7kni tenant, read as
// graph2otel-poller on 2026-07-17 `[live-measured 2026-07-17, #165]`. It
// replaces the invented contoso.com/fabrikam.com/adatum.com fixture as the
// authority on this endpoint's real wire shape.
//
// The m7kni tenant's four domains are ALL Managed and ALL verified — the live
// tenant has no federated or unverified domain, so the federated/unverified
// posture combinations and the Warn-severity log path cannot be exercised by
// any live capture. Those branches are covered by the synthetic fourDomainsBody
// below, which is retained on purpose for exactly that reason. Every field here
// is verbatim (isRoot/isAdminManaged are true on the wire, which the docs
// fixture never carried), trimmed of nothing.
const liveDomains = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#domains",
  "value": [
    {
      "authenticationType": "Managed",
      "availabilityStatus": null,
      "id": "m7knio.onmicrosoft.com",
      "isAdminManaged": true,
      "isDefault": false,
      "isInitial": true,
      "isRoot": true,
      "isVerified": true,
      "passwordNotificationWindowInDays": 14,
      "passwordValidityPeriodInDays": 2147483647,
      "state": null,
      "supportedServices": [
        "Email",
        "OfficeCommunicationsOnline"
      ]
    },
    {
      "authenticationType": "Managed",
      "availabilityStatus": null,
      "id": "m7kni.io",
      "isAdminManaged": true,
      "isDefault": true,
      "isInitial": false,
      "isRoot": true,
      "isVerified": true,
      "passwordNotificationWindowInDays": 14,
      "passwordValidityPeriodInDays": 2147483647,
      "state": null,
      "supportedServices": [
        "Email",
        "Intune"
      ]
    },
    {
      "authenticationType": "Managed",
      "availabilityStatus": null,
      "id": "rob-knight.com",
      "isAdminManaged": true,
      "isDefault": false,
      "isInitial": false,
      "isRoot": true,
      "isVerified": true,
      "passwordNotificationWindowInDays": 14,
      "passwordValidityPeriodInDays": 2147483647,
      "state": null,
      "supportedServices": [
        "Intune"
      ]
    },
    {
      "authenticationType": "Managed",
      "availabilityStatus": null,
      "id": "m7kni.com",
      "isAdminManaged": true,
      "isDefault": false,
      "isInitial": false,
      "isRoot": true,
      "isVerified": true,
      "passwordNotificationWindowInDays": 14,
      "passwordValidityPeriodInDays": 2147483647,
      "state": null,
      "supportedServices": [
        "Email",
        "Intune"
      ]
    }
  ]
}`

// fourDomainsBody is a deliberately SYNTHETIC fixture covering all four
// (authentication_type, is_verified) posture combinations: managed/verified,
// managed/unverified, federated/verified, federated/unverified. The live m7kni
// tenant has only managed, verified domains (see liveDomains), so the
// federated and unverified branches — and the Warn-severity log escalation —
// have no live capture and are exercised here. isDefault and domain id/name are
// deliberately varied too, to prove they never leak into a metric attribute.
const fourDomainsBody = `{
  "value": [
    {"id": "contoso.com", "authenticationType": "Managed", "isVerified": true, "isDefault": true, "supportedServices": ["Email"]},
    {"id": "sub.contoso.com", "authenticationType": "Managed", "isVerified": false, "isDefault": false, "supportedServices": []},
    {"id": "fabrikam.com", "authenticationType": "Federated", "isVerified": true, "isDefault": false, "supportedServices": ["Email", "Intune"]},
    {"id": "adatum.com", "authenticationType": "Federated", "isVerified": false, "isDefault": false, "supportedServices": []}
  ]
}`

func TestCollectEmitsBoundedPostureCounts(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	c := New(g, nil)
	if err := c.Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) != 4 {
		t.Fatalf("got %d points for %s, want 4 (one per posture combination)", len(pts), metricTotal)
	}

	got := map[string]float64{}
	for _, p := range pts {
		if len(p.Attrs) != 2 {
			t.Fatalf("point has %d attrs, want exactly 2 (authentication_type, is_verified): %v", len(p.Attrs), p.Attrs)
		}
		key := p.Attrs["authentication_type"] + "/" + p.Attrs["is_verified"]
		got[key] = p.Value
	}
	want := map[string]float64{
		"managed/true":    1,
		"managed/false":   1,
		"federated/true":  1,
		"federated/false": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("series %s = %v, want %v (got map: %v)", k, got[k], v, got)
		}
	}

	fedPts := rec.MetricPoints(metricFederatedTotal)
	if len(fedPts) != 1 {
		t.Fatalf("got %d points for %s, want 1", len(fedPts), metricFederatedTotal)
	}
	if fedPts[0].Value != 2 {
		t.Errorf("%s = %v, want 2", metricFederatedTotal, fedPts[0].Value)
	}
	if len(fedPts[0].Attrs) != 0 {
		t.Errorf("%s has attrs %v, want none", metricFederatedTotal, fedPts[0].Attrs)
	}
}

func TestCollectEmitsNoPerDomainSeries(t *testing.T) {
	// Cardinality guard: however many domains exist, entra.domains.total must
	// stay bounded to at most 4 series (2 authentication types x 2 verification
	// states), never one series per domain (id/name must never be a label).
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) > 4 {
		t.Fatalf("got %d points, want <= 4 (bounded posture combinations, not per-domain)", len(pts))
	}
	for _, p := range pts {
		for k := range p.Attrs {
			if k != "authentication_type" && k != "is_verified" {
				t.Errorf("unexpected attribute key %q (possible cardinality/PII violation)", k)
			}
		}
	}
}

func TestCollectEmitsLogTwinPerDomain(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	recs := rec.LogRecords()
	if len(recs) != 4 {
		t.Fatalf("got %d log records, want 4 (one per domain)", len(recs))
	}

	byID := map[string]telemetrytest.LogRecord{}
	for _, r := range recs {
		if r.EventName != "entra.domain" {
			t.Errorf("EventName = %q, want entra.domain", r.EventName)
		}
		byID[r.Attrs["id"]] = r
	}

	contoso, ok := byID["contoso.com"]
	if !ok {
		t.Fatal("no log record for contoso.com")
	}
	want := map[string]string{
		"id":                  "contoso.com",
		"authentication_type": "managed",
		"is_verified":         "true",
		"is_default":          "true",
		"is_initial":          "false",
		"is_root":             "false",
		"is_admin_managed":    "false",
		"supported_services":  "Email",
	}
	for k, v := range want {
		if contoso.Attrs[k] != v {
			t.Errorf("contoso.com attr %s = %q, want %q (all: %v)", k, contoso.Attrs[k], v, contoso.Attrs)
		}
	}

	sub, ok := byID["sub.contoso.com"]
	if !ok {
		t.Fatal("no log record for sub.contoso.com")
	}
	if _, present := sub.Attrs["supported_services"]; present {
		t.Errorf("sub.contoso.com supported_services = %q, want absent (empty list omitted)", sub.Attrs["supported_services"])
	}
}

func TestCollectLogTwinSeverityEscalatesForUnverifiedOrFederatedDomain(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	bySeverity := map[string]string{}
	for _, r := range rec.LogRecords() {
		bySeverity[r.Attrs["id"]] = r.SeverityText
	}

	wantWarn := map[string]bool{
		"contoso.com":     false, // managed, verified -> Info
		"sub.contoso.com": true,  // managed, unverified -> Warn
		"fabrikam.com":    true,  // federated, verified -> Warn
		"adatum.com":      true,  // federated, unverified -> Warn
	}
	for id, warn := range wantWarn {
		got := bySeverity[id] == telemetry.SeverityWarn.String()
		if got != warn {
			t.Errorf("domain %s: severity=%s, want Warn=%v", id, bySeverity[id], warn)
		}
	}
}

func TestCollectSetsNoConsistencyLevelHeader(t *testing.T) {
	// GET /domains is a plain list with no $filter/$search/$count=true, so it
	// must NOT send ConsistencyLevel: eventual (that header is reserved for
	// advanced-query requests per the collectors.GetAllValues contract).
	g := &fakeGraph{bodies: map[string]string{domainsURL: fourDomainsBody}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cl, seen := g.seenHeaders[domainsURL]
	if !seen {
		t.Fatal("expected a request to /domains")
	}
	if cl != "" {
		t.Errorf("ConsistencyLevel header = %q, want empty (no advanced query used)", cl)
	}
}

func TestCollectIsResilientToMalformedDomainEntry(t *testing.T) {
	body := `{
  "value": [
    {"id": "contoso.com", "authenticationType": "Managed", "isVerified": true},
    [1,2,3],
    {"id": "fabrikam.com", "authenticationType": "Federated", "isVerified": true}
  ]
}`
	g := &fakeGraph{bodies: map[string]string{domainsURL: body}}
	rec := telemetrytest.New()

	err := New(g, nil).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Error("expected Collect to surface the malformed-entry failure as an error")
	}

	pts := rec.MetricPoints(metricTotal)
	if len(pts) != 2 {
		t.Fatalf("got %d points, want 2 (malformed entry skipped, other two survive)", len(pts))
	}
}

func TestCollectPropagatesListFailure(t *testing.T) {
	g := &fakeGraph{errs: map[string]error{domainsURL: errors.New("throttled")}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err == nil {
		t.Error("expected Collect to return an error when listing domains fails")
	}

	if pts := rec.MetricPoints(metricTotal); len(pts) != 0 {
		t.Errorf("got %d points for %s, want 0 when the list call failed", len(pts), metricTotal)
	}
	if pts := rec.MetricPoints(metricFederatedTotal); len(pts) != 0 {
		t.Errorf("got %d points for %s, want 0 when the list call failed", len(pts), metricFederatedTotal)
	}
}

// TestCollectorEmitsLiveRecordEndToEnd drives the verbatim /domains capture
// through Collect into a Recorder, pinning what the real m7kni tenant produces:
// all four domains bucket into the single managed/verified posture series,
// federated.total is 0, and each domain gets one log twin carrying its real
// identity/posture. It keeps testdata/signals.json honest — the golden records
// the union of what the package's tests emit, so the live record has to reach
// the emitter for the golden to reflect a real response.
func TestCollectorEmitsLiveRecordEndToEnd(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{domainsURL: liveDomains}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// All four live domains are managed + verified, so they collapse into a
	// single bounded posture series of value 4.
	pts := rec.MetricPoints(metricTotal)
	if len(pts) != 1 {
		t.Fatalf("got %d posture series, want 1 (all live domains are managed/verified): %+v", len(pts), pts)
	}
	if pts[0].Value != 4 || pts[0].Attrs["authentication_type"] != "managed" || pts[0].Attrs["is_verified"] != "true" {
		t.Errorf("posture series = %+v, want value=4 managed/verified", pts[0])
	}

	fed := rec.MetricPoints(metricFederatedTotal)
	if len(fed) != 1 || fed[0].Value != 0 {
		t.Errorf("federated.total = %+v, want single point value=0 (tenant has no federated domain)", fed)
	}

	recs := rec.LogRecords()
	if len(recs) != 4 {
		t.Fatalf("got %d log twins, want 4 (one per live domain)", len(recs))
	}
	byID := map[string]telemetrytest.LogRecord{}
	for _, r := range recs {
		if r.EventName != "entra.domain" {
			t.Errorf("EventName = %q, want entra.domain", r.EventName)
		}
		byID[r.Attrs["id"]] = r
	}

	initial, ok := byID["m7knio.onmicrosoft.com"]
	if !ok {
		t.Fatal("no log twin for m7knio.onmicrosoft.com")
	}
	wantInitial := map[string]string{
		"id":                  "m7knio.onmicrosoft.com",
		"authentication_type": "managed",
		"is_verified":         "true",
		"is_default":          "false",
		"is_initial":          "true",
		"is_root":             "true",
		"is_admin_managed":    "true",
		"supported_services":  "Email,OfficeCommunicationsOnline",
	}
	for k, v := range wantInitial {
		if initial.Attrs[k] != v {
			t.Errorf("m7knio.onmicrosoft.com attr %s = %q, want %q (all: %v)", k, initial.Attrs[k], v, initial.Attrs)
		}
	}

	def, ok := byID["m7kni.io"]
	if !ok {
		t.Fatal("no log twin for m7kni.io")
	}
	if def.Attrs["is_default"] != "true" {
		t.Errorf("m7kni.io is_default = %q, want true", def.Attrs["is_default"])
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.domains" {
		t.Errorf("Name = %q, want entra.domains", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval = %v, want > 0", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	if len(perms) != 1 || perms[0] != "Domain.Read.All" {
		t.Errorf("RequiredPermissions = %v, want [Domain.Read.All]", perms)
	}
}
