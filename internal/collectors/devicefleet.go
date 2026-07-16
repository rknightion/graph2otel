package collectors

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// ManagedDevicesUnionSelect is the union of the $select field sets the
// intune.devices and intune.malware collectors each need from the
// /deviceManagement/managedDevices fleet list. One shared fetch with this
// select serves both: each collector unmarshals only its own fields and ignores
// the rest, so the union is transparent (intune.devices reads complianceState/
// operatingSystem/isEncrypted/lastSyncDateTime; intune.malware reads id/
// operatingSystem to target its per-device windowsProtectionState sweep).
const ManagedDevicesUnionSelect = "?$select=id,complianceState,operatingSystem,isEncrypted,lastSyncDateTime"

// FleetFetcher returns the full /deviceManagement/managedDevices list as raw
// JSON elements. intune.devices and intune.malware both page this same
// collection every cycle; sharing one fetch halves the fleet-list traffic on a
// large tenant (#87). It is NOT a throttling fix (managedDevices is on the
// elevated intune-devices tier, well inside its ceiling) — it's API etiquette,
// avoiding a redundant full-fleet page-walk.
type FleetFetcher interface {
	ManagedDevices(ctx context.Context) ([]json.RawMessage, error)
}

// DirectFleetFetcher is the uncached FleetFetcher: it pages URL through G on
// every call. It is each collector's built-in default (New wires one over the
// collector's OWN $select), so a collector's fetch behavior — and its unit
// tests — are unchanged when no shared cache is injected. The composition root
// overrides it with a CachingFleetFetcher for the real multi-collector run.
type DirectFleetFetcher struct {
	G   GraphClient
	URL string // absolute managedDevices list URL including the caller's own $select
}

// ManagedDevices implements FleetFetcher.
func (f *DirectFleetFetcher) ManagedDevices(ctx context.Context) ([]json.RawMessage, error) {
	return GetAllValues(ctx, f.G, f.URL, nil)
}

// CachingFleetFetcher pages the managedDevices fleet once (union $select) and
// serves the cached result to every caller within TTL. Built once per tenant in
// the composition root and injected into both device collectors via Deps.Fleet,
// so whichever collector ticks first warms the cache and the other reuses it.
// Safe for concurrent use; a fetch error is NOT cached (the next caller
// retries). The mutex is held across the underlying fetch on a cold/expired
// entry, so a concurrent second caller blocks until the fetch completes and
// then reads the fresh cache rather than issuing a duplicate fetch.
type CachingFleetFetcher struct {
	g   GraphClient
	url string
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	fetched time.Time
	cached  []json.RawMessage
}

// NewCachingFleetFetcher builds a caching fetcher over g for the tenant's
// managedDevices fleet (union $select against baseURL), serving a fetched
// result for up to ttl.
func NewCachingFleetFetcher(g GraphClient, baseURL string, ttl time.Duration) *CachingFleetFetcher {
	return &CachingFleetFetcher{
		g:   g,
		url: baseURL + "/deviceManagement/managedDevices" + ManagedDevicesUnionSelect,
		ttl: ttl,
		now: time.Now,
	}
}

// ManagedDevices implements FleetFetcher.
func (f *CachingFleetFetcher) ManagedDevices(ctx context.Context) ([]json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if !f.fetched.IsZero() && now.Sub(f.fetched) < f.ttl {
		return f.cached, nil
	}
	raws, err := GetAllValues(ctx, f.g, f.url, nil)
	if err != nil {
		return nil, err // don't cache errors — the next caller retries
	}
	f.cached = raws
	f.fetched = now
	return raws, nil
}
