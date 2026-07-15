package connectors

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// fakeGraph is an in-memory collectors.GraphClient: it maps request URLs to
// canned response bodies (or errors), mirroring the reference collectors'
// test fakes (entra/devices, entra/recommendations).
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
		return nil, errors.New("fakeGraph: no canned body for " + url)
	}
	return []byte(body), nil
}

var _ collectors.GraphClient = (*fakeGraph)(nil)

var (
	exchangeURL = defaultBaseURL + "/deviceManagement/exchangeConnectors"
	mtdURL      = defaultBaseURL + "/deviceManagement/mobileThreatDefenseConnectors"
	ndesURL     = betaBaseURL + "/deviceManagement/ndesConnectors"
)

var fixedNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func newTestCollector(g collectors.GraphClient) *Collector {
	c := New(g, nil)
	c.now = fixedClock
	return c
}

// pointByAttr finds the single recorded point whose attribute key equals
// want, failing the test if there is not exactly one match.
func pointByAttr(t *testing.T, pts []telemetrytest.MetricPoint, key, want string) telemetrytest.MetricPoint {
	t.Helper()
	var matches []telemetrytest.MetricPoint
	for _, p := range pts {
		if p.Attrs[key] == want {
			matches = append(matches, p)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%d points with %s=%s, want exactly 1: %+v", len(matches), key, want, pts)
	}
	return matches[0]
}

func findPoint(pts []telemetrytest.MetricPoint, attrs map[string]string) (telemetrytest.MetricPoint, bool) {
	for _, p := range pts {
		match := true
		for k, v := range attrs {
			if p.Attrs[k] != v {
				match = false
				break
			}
		}
		if match {
			return p, true
		}
	}
	return telemetrytest.MetricPoint{}, false
}

func TestCollectEmitsStateAndHeartbeatAcrossAllThreeConnectorTypes(t *testing.T) {
	g := &fakeGraph{bodies: map[string]string{
		exchangeURL: `{"value":[
			{"status":"connected","lastSyncDateTime":"2026-07-15T11:59:00Z"},
			{"status":"disconnected","lastSyncDateTime":"2026-07-15T10:00:00Z"}
		]}`,
		mtdURL: `{"value":[
			{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:55:00Z","androidEnabled":true,"iosEnabled":false,"windowsEnabled":true}
		]}`,
		ndesURL: `{"value":[
			{"state":"active","lastConnectionDateTime":"2026-07-15T11:00:00Z"}
		]}`,
	}}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	states := rec.MetricPoints(stateMetric)
	if p, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok || p.Value != 1 {
		t.Errorf("exchange connected state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "disconnected"}); !ok || p.Value != 1 {
		t.Errorf("exchange disconnected state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok || p.Value != 1 {
		t.Errorf("mtd enabled state point = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "ndes", "state": "active"}); !ok || p.Value != 1 {
		t.Errorf("ndes active state point = %+v, ok=%v", p, ok)
	}

	ages := rec.MetricPoints(heartbeatAgeMetric)
	// Exchange has two instances; the oldest (most stale) sync is 2h old and
	// must win over the 1-minute-old one, since the metric surfaces the worst
	// case per connector type, not an average or the newest instance.
	exAge := pointByAttr(t, ages, "connector_type", "exchange")
	if exAge.Value != (2 * time.Hour).Seconds() {
		t.Errorf("exchange heartbeat age = %v, want %v (oldest instance)", exAge.Value, (2 * time.Hour).Seconds())
	}
	mtdAge := pointByAttr(t, ages, "connector_type", "mtd")
	if mtdAge.Value != (5 * time.Minute).Seconds() {
		t.Errorf("mtd heartbeat age = %v, want %v", mtdAge.Value, (5 * time.Minute).Seconds())
	}
	ndesAge := pointByAttr(t, ages, "connector_type", "ndes")
	if ndesAge.Value != (1 * time.Hour).Seconds() {
		t.Errorf("ndes heartbeat age = %v, want %v", ndesAge.Value, (1 * time.Hour).Seconds())
	}

	platforms := rec.MetricPoints(mtdPlatformMetric)
	if len(platforms) != 6 {
		t.Fatalf("mtd platform points = %d, want 6 (3 platforms x enabled/disabled)", len(platforms))
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "android", "enabled": "true"}); !ok || p.Value != 1 {
		t.Errorf("android enabled = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "ios", "enabled": "false"}); !ok || p.Value != 1 {
		t.Errorf("ios disabled = %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(platforms, map[string]string{"platform": "windows", "enabled": "true"}); !ok || p.Value != 1 {
		t.Errorf("windows enabled = %+v, ok=%v", p, ok)
	}
}

func TestCollectSkipsExchangeGracefullyOn501AndStillEmitsMTDAndNDES(t *testing.T) {
	// Verified live: a tenant with no Exchange connector configured returns
	// HTTP 501 {"error":{"code":"NotSupported",...}} from
	// GET /deviceManagement/exchangeConnectors, not an empty list. That must
	// degrade like a 403/404 (graceful skip), not surface as a collector
	// failure on every scrape for every tenant lacking an Exchange connector.
	g := &fakeGraph{
		bodies: map[string]string{
			mtdURL:  `{"value":[{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:00:00Z","androidEnabled":true,"iosEnabled":true,"windowsEnabled":true}]}`,
			ndesURL: `{"value":[{"state":"active","lastConnectionDateTime":"2026-07-15T11:00:00Z"}]}`,
		},
		errs: map[string]error{
			exchangeURL: errors.New(`graphclient: GET https://graph.microsoft.com/v1.0/deviceManagement/exchangeConnectors: status 501: {"error":{"code":"NotSupported","message":"..."}}`),
		},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (501/NotSupported on exchangeConnectors is a graceful skip, not a failure)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange"}); ok {
		t.Errorf("exchange state point present despite the 501: %+v", states)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok || p.Value != 1 {
		t.Errorf("mtd state missing/wrong when exchange 501s: %+v, ok=%v", p, ok)
	}
	if p, ok := findPoint(states, map[string]string{"connector_type": "ndes", "state": "active"}); !ok || p.Value != 1 {
		t.Errorf("ndes state missing/wrong when exchange 501s: %+v, ok=%v", p, ok)
	}
}

func TestCollectSkipsNDESSilentlyOn403AndStillEmitsExchangeAndMTD(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			exchangeURL: `{"value":[{"status":"connected","lastSyncDateTime":"2026-07-15T11:00:00Z"}]}`,
			mtdURL:      `{"value":[]}`,
		},
		errs: map[string]error{
			ndesURL: errors.New("graphclient: GET https://graph.microsoft.com/beta/deviceManagement/ndesConnectors: status 403: forbidden"),
		},
	}
	rec := telemetrytest.New()

	if err := newTestCollector(g).Collect(context.Background(), rec.Emitter()); err != nil {
		t.Fatalf("Collect: %v, want nil (403 on the beta NDES endpoint is skip-and-log, not a failure)", err)
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok {
		t.Errorf("exchange state missing when NDES 403s: %+v", states)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "ndes"}); ok {
		t.Errorf("ndes state point present despite 403: %+v", states)
	}
	// mtd had zero connectors, so the optional platform metric must not be
	// emitted at all (not even as an empty snapshot with no series).
	if pts := rec.MetricPoints(mtdPlatformMetric); len(pts) != 0 {
		t.Errorf("mtd platform metric emitted with zero MTD connectors: %+v", pts)
	}
}

func TestCollectIsolatesNDESRealFailureFromExchangeAndMTD(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			exchangeURL: `{"value":[{"status":"connected","lastSyncDateTime":"2026-07-15T11:00:00Z"}]}`,
			mtdURL:      `{"value":[{"partnerState":"enabled","lastHeartbeatDateTime":"2026-07-15T11:00:00Z","androidEnabled":true,"iosEnabled":true,"windowsEnabled":true}]}`,
		},
		errs: map[string]error{
			ndesURL: errors.New("graphclient: GET https://graph.microsoft.com/beta/deviceManagement/ndesConnectors: status 500: boom"),
		},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("Collect: want a non-nil error surfacing the real (non-403/404) NDES failure")
	}

	states := rec.MetricPoints(stateMetric)
	if _, ok := findPoint(states, map[string]string{"connector_type": "exchange", "state": "connected"}); !ok {
		t.Errorf("exchange state missing when NDES fails with a real error: %+v", states)
	}
	if _, ok := findPoint(states, map[string]string{"connector_type": "mtd", "state": "enabled"}); !ok {
		t.Errorf("mtd state missing when NDES fails with a real error: %+v", states)
	}
}

func TestCollectHandlesExchangeFailureIndependentlyOfMTDAndNDES(t *testing.T) {
	g := &fakeGraph{
		bodies: map[string]string{
			mtdURL:  `{"value":[]}`,
			ndesURL: `{"value":[]}`,
		},
		errs: map[string]error{
			exchangeURL: errors.New("graphclient: GET .../exchangeConnectors: status 500: boom"),
		},
	}
	rec := telemetrytest.New()

	err := newTestCollector(g).Collect(context.Background(), rec.Emitter())
	if err == nil {
		t.Fatal("Collect: want a non-nil error when the exchange connectors list fails")
	}
	// mtd/ndes both returned empty lists successfully; Collect must not have
	// aborted before reaching (or recording) their empty state.
	if _, ok := findPoint(rec.MetricPoints(stateMetric), map[string]string{"connector_type": "exchange"}); ok {
		t.Errorf("exchange state point present despite the list call failing")
	}
}

func TestNameIntervalAndPermissions(t *testing.T) {
	c := New(&fakeGraph{}, nil)
	if c.Name() != "intune.connectors" {
		t.Errorf("Name() = %q, want intune.connectors", c.Name())
	}
	if c.DefaultInterval() <= 0 {
		t.Errorf("DefaultInterval() = %v, want positive", c.DefaultInterval())
	}
	perms := c.RequiredPermissions()
	sort.Strings(perms)
	if len(perms) != 1 || perms[0] != "DeviceManagementServiceConfig.Read.All" {
		t.Errorf("RequiredPermissions() = %v, want [DeviceManagementServiceConfig.Read.All]", perms)
	}
}
