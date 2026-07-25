package collectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/collectors"
	"github.com/rknightion/graph2otel/internal/recordoutcome"
)

// countingGraph is a collectors.GraphClient that records every RawGet URL, so a
// test can assert how many times the managedDevices fleet was actually paged.
type countingGraph struct {
	urls   []string
	body   []byte
	err    error
	bodies map[string][]byte
	errs   map[string]error
}

func (c *countingGraph) RawGet(_ context.Context, url string) ([]byte, error) {
	c.urls = append(c.urls, url)
	if err, ok := c.errs[url]; ok {
		return nil, err
	}
	if body, ok := c.bodies[url]; ok {
		return body, nil
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.body, nil
}

func (c *countingGraph) RawGetWithHeaders(ctx context.Context, url string, _ map[string]string) ([]byte, error) {
	return c.RawGet(ctx, url)
}

func (c *countingGraph) managedDevicesCalls() int {
	n := 0
	for _, u := range c.urls {
		if strings.Contains(u, "/deviceManagement/managedDevices?") {
			n++
		}
	}
	return n
}

// onePage is a single-page managedDevices collection response.
func onePage() []byte {
	return []byte(`{"value":[{"id":"d1","complianceState":"compliant","operatingSystem":"Windows"}]}`)
}

// TestCachingFleetFetcher_SharesOneFetchWithinTTL asserts two callers within the
// TTL page the fleet once, and a caller after the TTL re-fetches.
func TestCachingFleetFetcher_SharesOneFetchWithinTTL(t *testing.T) {
	g := &countingGraph{body: onePage()}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	f := collectors.NewCachingFleetFetcher(g, "https://graph.microsoft.com/v1.0", 30*time.Minute)
	// inject a controllable clock
	collectors.SetFleetClock(f, func() time.Time { return now })

	// Two callers within the TTL: intune.devices then intune.malware.
	r1, err := f.ManagedDevices(context.Background(), nil)
	if err != nil {
		t.Fatalf("first ManagedDevices: %v", err)
	}
	r2, err := f.ManagedDevices(context.Background(), nil)
	if err != nil {
		t.Fatalf("second ManagedDevices: %v", err)
	}
	if len(r1) != 1 || len(r2) != 1 {
		t.Fatalf("expected 1 device from each call, got %d and %d", len(r1), len(r2))
	}
	if got := g.managedDevicesCalls(); got != 1 {
		t.Fatalf("fleet paged %d times within TTL, want 1 (shared)", got)
	}
	// The shared fetch must use the union select so both collectors' fields are present.
	if !strings.Contains(g.urls[0], collectors.ManagedDevicesUnionSelect[1:]) { // drop leading '?'
		t.Errorf("fleet URL %q missing union select", g.urls[0])
	}

	// After the TTL, the next caller re-fetches.
	now = now.Add(31 * time.Minute)
	if _, err := f.ManagedDevices(context.Background(), nil); err != nil {
		t.Fatalf("post-TTL ManagedDevices: %v", err)
	}
	if got := g.managedDevicesCalls(); got != 2 {
		t.Fatalf("fleet paged %d times across TTL boundary, want 2", got)
	}
}

// TestCachingFleetFetcher_DoesNotCacheErrors asserts a failed fetch is not
// cached — the next caller retries rather than seeing a stuck error.
func TestCachingFleetFetcher_DoesNotCacheErrors(t *testing.T) {
	g := &countingGraph{err: errors.New("boom")}
	f := collectors.NewCachingFleetFetcher(g, "https://graph.microsoft.com/v1.0", time.Hour)

	if _, err := f.ManagedDevices(context.Background(), nil); err == nil {
		t.Fatal("want error on first fetch")
	}
	// Recover: subsequent call succeeds (error was not cached).
	g.err = nil
	g.body = onePage()
	if _, err := f.ManagedDevices(context.Background(), nil); err != nil {
		t.Fatalf("retry after error: %v", err)
	}
	if got := g.managedDevicesCalls(); got != 2 {
		t.Fatalf("fleet paged %d times, want 2 (error not cached → retry)", got)
	}
}

func TestCachingFleetFetcher_AccountsAndDoesNotCachePartialPageFailure(t *testing.T) {
	const (
		baseURL = "https://graph.microsoft.com/v1.0"
		page2   = baseURL + "/deviceManagement/managedDevices?$skiptoken=next"
	)
	page1 := baseURL + "/deviceManagement/managedDevices" + collectors.ManagedDevicesUnionSelect
	g := &countingGraph{
		bodies: map[string][]byte{
			page1: []byte(`{"value":[{"id":"d1"},{"id":"d2"}],"@odata.nextLink":"` + page2 + `"}`),
		},
		errs: map[string]error{page2: errors.New("later page failed")},
	}
	f := collectors.NewCachingFleetFetcher(g, baseURL, time.Hour)
	outcomes := recordoutcome.NewRecorder()

	if got, err := f.ManagedDevices(context.Background(), outcomes); err == nil || got != nil {
		t.Fatalf("first ManagedDevices = (%v, %v), want nil rows and later-page error", got, err)
	}
	if got := outcomes.Snapshot().Counts; got != (recordoutcome.Counts{Fetched: 2, Errored: 2}) {
		t.Fatalf("outcomes = %+v, want fetched=2 errored=2", got)
	}

	delete(g.errs, page2)
	g.bodies[page2] = []byte(`{"value":[{"id":"d3"}]}`)
	got, err := f.ManagedDevices(context.Background(), recordoutcome.NewRecorder())
	if err != nil {
		t.Fatalf("retry after partial-page failure: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("retry returned %d devices, want all 3", len(got))
	}
	if calls := g.managedDevicesCalls(); calls != 4 {
		t.Fatalf("managedDevices page requests = %d, want 4 across failed and retried walks", calls)
	}
}

// TestDirectFleetFetcher_PagesGivenURL asserts the uncached fetcher pages the
// exact URL it was built with (a collector's own $select) — so each collector's
// unit tests keep matching their own URL when no shared cache is injected.
func TestDirectFleetFetcher_PagesGivenURL(t *testing.T) {
	g := &countingGraph{body: onePage()}
	url := "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,operatingSystem"
	f := &collectors.DirectFleetFetcher{G: g, URL: url}
	got, err := f.ManagedDevices(context.Background(), nil)
	if err != nil {
		t.Fatalf("ManagedDevices: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1", len(got))
	}
	var d struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(got[0], &d)
	if d.ID != "d1" {
		t.Errorf("device id = %q, want d1", d.ID)
	}
	if len(g.urls) != 1 || g.urls[0] != url {
		t.Errorf("fetched %v, want exactly [%s]", g.urls, url)
	}
}
