package graphclient

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Per-workload token-bucket ceilings, from Microsoft's documented Graph
// throttling limits (none of these workloads reliably send Retry-After, so a
// proactive client-side gate is the only backstop):
//
//   - reporting:      5 requests / 10s per app per tenant.
//   - identity-protection: 1 request / second per TENANT, across ALL apps —
//     see the keying note on WorkloadLimiter below.
//   - directory:      coarse defensive backstop only (~50 / 10s per tenant);
//     this workload DOES send Retry-After so Kiota's retry handler already
//     covers the tight case.
//   - intune-general: ~1000 requests / 20s per app per tenant.
//   - intune-devices: ~2000 reads / 20s per app per tenant (elevated ceiling).
//   - intune-export:  48 requests / minute per app — the tightest Intune ceiling.
//   - unknown:        no limiter (permissive default).
var workloadRates = map[Workload]struct {
	every rate.Limit
	burst int
}{
	WorkloadReporting:     {every: rate.Every(10 * time.Second / 5), burst: 5},
	WorkloadIPC:           {every: rate.Every(time.Second), burst: 1},
	WorkloadDirectory:     {every: rate.Every(10 * time.Second / 50), burst: 50},
	WorkloadIntuneGeneral: {every: rate.Every(20 * time.Second / 1000), burst: 1000},
	WorkloadIntuneDevices: {every: rate.Every(20 * time.Second / 2000), burst: 2000},
	WorkloadIntuneExport:  {every: rate.Every(time.Minute / 48), burst: 48},
}

// limiterKey identifies one token bucket. Every workload is keyed per
// (tenantID, workload) EXCEPT WorkloadIPC, whose ceiling is documented by
// Microsoft as per-TENANT across all apps — since this key has no app
// dimension at all, keying IPC the same way as every other workload already
// produces the right "shared across apps" behavior (graph2otel also runs one
// app per process today; if that ever changes, IPC must stay keyed by tenant
// only while the others gain an app dimension).
type limiterKey struct {
	tenantID string
	workload Workload
}

// WorkloadLimiter holds one client-side token bucket per (tenant, workload),
// created lazily on first use. It is the proactive gate that keeps graph2otel
// under Graph's documented ceilings for the workloads that return 429 with no
// Retry-After (reporting, Identity Protection) — reactive retry alone is not
// enough there.
type WorkloadLimiter struct {
	mu       sync.Mutex
	limiters map[limiterKey]*rate.Limiter
}

// NewWorkloadLimiter returns an empty WorkloadLimiter; buckets are created on
// first Wait call for a given (tenant, workload) pair.
func NewWorkloadLimiter() *WorkloadLimiter {
	return &WorkloadLimiter{limiters: make(map[limiterKey]*rate.Limiter)}
}

// Wait blocks until a token is available for tenantID's wl bucket, or until
// ctx is done. WorkloadUnknown (and any workload with no configured ceiling)
// never blocks.
func (l *WorkloadLimiter) Wait(ctx context.Context, tenantID string, wl Workload) error {
	lim := l.limiterFor(tenantID, wl)
	if lim == nil {
		return nil
	}
	return lim.Wait(ctx)
}

func (l *WorkloadLimiter) limiterFor(tenantID string, wl Workload) *rate.Limiter {
	key := limiterKey{tenantID: tenantID, workload: wl}

	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[key]; ok {
		return lim
	}
	spec, ok := workloadRates[wl]
	if !ok {
		// No configured ceiling (e.g. WorkloadUnknown): cache a nil entry so
		// repeated lookups skip the map miss too.
		l.limiters[key] = nil
		return nil
	}
	lim := rate.NewLimiter(spec.every, spec.burst)
	l.limiters[key] = lim
	return lim
}
