package syncerrors

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph maps request URLs to canned bodies (or errors) and records every
// URL it is asked for, so a test can assert the expensive /users page-walk is
// NOT issued when on-prem sync is disabled. Satisfies collectors.GraphClient.
type fakeGraph struct {
	bodies map[string]string
	errs   map[string]error
	seen   []string
}

func (f *fakeGraph) RawGet(ctx context.Context, url string) ([]byte, error) {
	return f.RawGetWithHeaders(ctx, url, nil)
}

func (f *fakeGraph) RawGetWithHeaders(_ context.Context, url string, _ map[string]string) ([]byte, error) {
	f.seen = append(f.seen, url)
	if err, ok := f.errs[url]; ok {
		return nil, err
	}
	b, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("unexpected url %q", url)
	}
	return []byte(b), nil
}

func (f *fakeGraph) requested(url string) bool {
	return slices.Contains(f.seen, url)
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

const base = "https://graph.microsoft.com/v1.0"

const (
	orgURL   = base + "/organization?$select=onPremisesSyncEnabled"
	usersURL = base + "/users?$select=id,userPrincipalName,onPremisesProvisioningErrors"
)

func orgBody(enabled string) string {
	// enabled is the raw JSON value for onPremisesSyncEnabled: "true", "false",
	// or "null" (the cloud-only default).
	return `{"value":[{"onPremisesSyncEnabled":` + enabled + `}]}`
}

// twoErroredUsers: alice has a UPN conflict, bob a ProxyAddress conflict, carol
// syncs cleanly (no errors) and must produce neither a bucket nor a log.
const twoErroredUsers = `{"value":[
	{"id":"u-alice","userPrincipalName":"alice@example.com","onPremisesProvisioningErrors":[
		{"category":"PropertyConflict","propertyCausingError":"UserPrincipalName","occurredDateTime":"2026-07-16T04:00:00Z","value":"alice@example.com"}
	]},
	{"id":"u-bob","userPrincipalName":"bob@example.com","onPremisesProvisioningErrors":[
		{"category":"PropertyConflict","propertyCausingError":"ProxyAddress","occurredDateTime":"2026-07-16T05:00:00Z","value":"smtp:bob@example.com"}
	]},
	{"id":"u-carol","userPrincipalName":"carol@example.com","onPremisesProvisioningErrors":[]}
]}`

const noErroredUsers = `{"value":[
	{"id":"u-carol","userPrincipalName":"carol@example.com","onPremisesProvisioningErrors":[]},
	{"id":"u-dave","userPrincipalName":"dave@example.com"}
]}`

func metricBuckets(pts []telemetrytest.MetricPoint) map[[3]string]float64 {
	got := map[[3]string]float64{}
	for _, p := range pts {
		got[[3]string{p.Attrs["object_type"], p.Attrs["category"], p.Attrs["property_causing_error"]}] = p.Value
	}
	return got
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

// TestSyncDisabledNoOps is the load-bearing cost guard: a cloud-only tenant
// (onPremisesSyncEnabled false or null) must no-op WITHOUT paging /users — the
// whole point of the cheap org probe. It emits nothing at all.
func TestSyncDisabledNoOps(t *testing.T) {
	for _, enabled := range []string{"false", "null"} {
		t.Run("sync="+enabled, func(t *testing.T) {
			g := &fakeGraph{bodies: map[string]string{orgURL: orgBody(enabled)}}
			rec := telemetrytest.New()

			if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if g.requested(usersURL) {
				t.Errorf("paged /users despite on-prem sync disabled — the org probe must skip the whole cost")
			}
			if pts := rec.MetricPoints(metricSyncErrors); len(pts) != 0 {
				t.Errorf("emitted %d metric points on a cloud-only tenant, want 0", len(pts))
			}
			if logs := logsNamed(rec.LogRecords(), eventSyncError); len(logs) != 0 {
				t.Errorf("emitted %d logs on a cloud-only tenant, want 0", len(logs))
			}
		})
	}
}

// TestSyncEnabledBucketsErrorsAndTwins covers the working case: bounded gauge
// bucketed by (object_type, category, property_causing_error), and one log twin
// per errored object carrying the per-entity detail. A clean user contributes
// nothing.
func TestSyncEnabledBucketsErrorsAndTwins(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: orgBody("true"), usersURL: twoErroredUsers}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := metricBuckets(rec.MetricPoints(metricSyncErrors))
	want := map[[3]string]float64{
		{"user", "PropertyConflict", "UserPrincipalName"}: 1,
		{"user", "PropertyConflict", "ProxyAddress"}:      1,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d buckets, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("bucket %v = %v, want %v", k, got[k], v)
		}
	}

	logs := logsNamed(rec.LogRecords(), eventSyncError)
	if len(logs) != 2 {
		t.Fatalf("emitted %d %s logs, want 2 (one per errored object)", len(logs), eventSyncError)
	}
	var alice *telemetrytest.LogRecord
	for i := range logs {
		if logs[i].Attrs["id"] == "u-alice" {
			alice = &logs[i]
		}
	}
	if alice == nil {
		t.Fatalf("no log for u-alice; got %v", logs)
	}
	wantAttrs := map[string]string{
		"id":                     "u-alice",
		"object_type":            "user",
		"user_principal_name":    "alice@example.com",
		"category":               "PropertyConflict",
		"property_causing_error": "UserPrincipalName",
		"occurred_date_time":     "2026-07-16T04:00:00Z",
		"conflicting_value":      "alice@example.com",
	}
	for k, v := range wantAttrs {
		if alice.Attrs[k] != v {
			t.Errorf("u-alice log attr %q = %q, want %q", k, alice.Attrs[k], v)
		}
	}
}

// TestMetricCarriesNoPerEntityData is the #112 boundary: only the three bounded
// enums may be metric labels; UPN/id/conflicting value live on the log twin.
func TestMetricCarriesNoPerEntityData(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: orgBody("true"), usersURL: twoErroredUsers}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	allowed := map[string]bool{"object_type": true, "category": true, "property_causing_error": true}
	for _, p := range rec.MetricPoints(metricSyncErrors) {
		for k := range p.Attrs {
			if !allowed[k] {
				t.Errorf("metric %s has unexpected attribute %q (per-entity leak?): %v", metricSyncErrors, k, p.Attrs)
			}
		}
	}
}

// TestZeroCaseEmitsExplicitZero pins that a healthy hybrid tenant (sync enabled,
// zero conflicts) emits an explicit zero-valued series, so "no errors" is never
// indistinguishable from "collector did not run". No logs in that case.
func TestZeroCaseEmitsExplicitZero(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{orgURL: orgBody("true"), usersURL: noErroredUsers}}
	rec := telemetrytest.New()

	if err := New(g, nil).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pts := rec.MetricPoints(metricSyncErrors)
	if len(pts) != 1 {
		t.Fatalf("got %d points in the zero case, want exactly 1 explicit-zero sentinel: %v", len(pts), pts)
	}
	if pts[0].Value != 0 {
		t.Errorf("zero-case sentinel value = %v, want 0", pts[0].Value)
	}
	if logs := logsNamed(rec.LogRecords(), eventSyncError); len(logs) != 0 {
		t.Errorf("emitted %d logs in the zero case, want 0", len(logs))
	}
}

func TestNamePermissionsAndOptIn(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "entra.syncerrors" {
		t.Errorf("Name = %q, want entra.syncerrors", c.Name())
	}
	if !c.Experimental() {
		t.Error("Experimental() = false, want true (opt-in/default-off — pages the full user collection)")
	}
	perms := map[string]bool{}
	for _, p := range c.RequiredPermissions() {
		perms[p] = true
	}
	for _, want := range []string{"User.Read.All", "Organization.Read.All"} {
		if !perms[want] {
			t.Errorf("RequiredPermissions missing %q; got %v", want, c.RequiredPermissions())
		}
	}
}
