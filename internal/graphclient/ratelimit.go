package graphclient

import (
	"context"
	"sort"
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
//   - intune-export:  Microsoft documents 48 requests / minute per app, but that
//     ceiling 429s in practice: at 48/min with a 48 burst, the ~22 export jobs
//     every 6h collector creates at once drew 46-57 429s per tick (live
//     2026-10-09). The limiter runs at HALF the documented rate with a burst of
//     4, so a startup or tick-aligned burst is metered out at 1 per 2.5s instead
//     of firing 48 back to back. Half is a safety margin, not a measured
//     ceiling; exportjob's concurrency cap (3 jobs) is the primary burst control,
//     and graph2otel.throttle.count{workload="intune-export"} is the check.
//   - teams-phone: Microsoft documents 200/min per app per tenant and
//     50/min per collection. A shared 50/min bucket with a burst of one
//     keeps either collection below both limits, including page requests.
//   - teams-call-records: provisional shared budget of 30 requests / 20s,
//     burst one, below Microsoft's documented 40 / 20s list and per-record limits.
//   - unknown:        no limiter (permissive default).
//
// intune-export is adaptive (#709): the 24/min figure still ran above the
// ceiling Microsoft enforces on a live tenant (136 429s in 24h, all absorbed by
// exportjob's in-tick retry, so no data lost but the alert fired). On an
// observed 429 its rate is halved down to a floor of a sixth of the base, and it
// recovers additively once the workload has been quiet. The current rate is
// published as graph2otel.throttle.effective_rate_per_minute. No other workload
// is adaptive.
var workloadRates = map[Workload]struct {
	every    rate.Limit
	burst    int
	adaptive *adaptiveSpec
}{
	WorkloadReporting:        {every: rate.Every(10 * time.Second / 5), burst: 5},
	WorkloadIPC:              {every: rate.Every(time.Second), burst: 1},
	WorkloadDirectory:        {every: rate.Every(10 * time.Second / 50), burst: 50},
	WorkloadIntuneGeneral:    {every: rate.Every(20 * time.Second / 1000), burst: 1000},
	WorkloadIntuneDevices:    {every: rate.Every(20 * time.Second / 2000), burst: 2000},
	WorkloadIntuneExport:     {every: rate.Every(time.Minute / 24), burst: 4, adaptive: &intuneExportAdaptive},
	WorkloadTeamsPhone:       {every: rate.Every(time.Minute / 50), burst: 1},
	WorkloadTeamsCallRecords: {every: rate.Every(20 * time.Second / 30), burst: 1},
}

// adaptiveSpec opts one workload into rate adaptation. All three tunables are
// fractions of the workload's configured base rate, so the same spec scales with
// the base (and with a scaled-down base in tests).
type adaptiveSpec struct {
	decrease    float64       // multiplier applied on an observed 429, in (0,1)
	floor       float64       // lowest rate, as a fraction of base
	recoverStep float64       // rate regained per quiet period, as a fraction of base
	quiet       time.Duration // a quiet period: no 429 and no change for this long
}

// intuneExportAdaptive halves on a 429, never drops below base/6 (4/min of 24),
// and regains base/12 (2/min) per 5 quiet minutes, so a full recovery from the
// floor takes about an hour.
var intuneExportAdaptive = adaptiveSpec{decrease: 0.5, floor: 1.0 / 6, recoverStep: 1.0 / 12, quiet: 5 * time.Minute}

// adaptiveState is one adaptive bucket's rate bookkeeping. Guarded by
// WorkloadLimiter.mu.
type adaptiveState struct {
	spec         adaptiveSpec
	base         rate.Limit
	baseBurst    int
	cur          rate.Limit
	lastChange   time.Time // last decrease or recovery step; recovery counts quiet time from here
	lastDecrease time.Time // 429s from requests issued before this reflect the old rate
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
	adaptive map[limiterKey]*adaptiveState
	now      func() time.Time
}

// NewWorkloadLimiter returns an empty WorkloadLimiter; buckets are created on
// first Wait call for a given (tenant, workload) pair.
func NewWorkloadLimiter() *WorkloadLimiter {
	return &WorkloadLimiter{
		limiters: make(map[limiterKey]*rate.Limiter),
		adaptive: make(map[limiterKey]*adaptiveState),
		now:      time.Now,
	}
}

// Wait blocks until a token is available for tenantID's wl bucket, or until
// ctx is done. WorkloadUnknown (and any workload with no configured ceiling)
// never blocks.
func (l *WorkloadLimiter) Wait(ctx context.Context, tenantID string, wl Workload) error {
	lim := l.limiterFor(tenantID, wl)
	if lim == nil {
		return nil
	}
	l.recover(limiterKey{tenantID: tenantID, workload: wl}, l.now())
	return lim.Wait(ctx)
}

// ObserveThrottle tells the limiter a request it admitted at issuedAt drew a
// 429. For an adaptive workload it multiplies the rate down (to the floor) and
// holds recovery off; for every other workload it does nothing. A 429 for a
// request issued before the last decrease is ignored: it reflects the old rate,
// and counting it would collapse a burst of concurrent 429s straight to the floor.
func (l *WorkloadLimiter) ObserveThrottle(tenantID string, wl Workload, issuedAt time.Time) {
	l.limiterFor(tenantID, wl)
	l.mu.Lock()
	defer l.mu.Unlock()
	key := limiterKey{tenantID: tenantID, workload: wl}
	st, lim := l.adaptive[key], l.limiters[key]
	if st == nil || lim == nil || issuedAt.Before(st.lastDecrease) {
		return
	}
	now := l.now()
	st.lastChange, st.lastDecrease = now, now
	next := rate.Limit(float64(st.cur) * st.spec.decrease)
	if floor := rate.Limit(float64(st.base) * st.spec.floor); next < floor {
		next = floor
	}
	l.applyLocked(st, lim, next)
}

// EffectiveRatePerMinute reports the current rate of an adaptive workload's
// bucket, in requests per minute. ok is false for a workload that is not adaptive.
func (l *WorkloadLimiter) EffectiveRatePerMinute(tenantID string, wl Workload) (perMinute float64, ok bool) {
	l.limiterFor(tenantID, wl)
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.adaptive[limiterKey{tenantID: tenantID, workload: wl}]
	if st == nil {
		return 0, false
	}
	return float64(st.cur) * 60, true
}

// recover raises an adaptive bucket one step per elapsed quiet period.
func (l *WorkloadLimiter) recover(key limiterKey, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, lim := l.adaptive[key], l.limiters[key]
	if st == nil || lim == nil || st.cur >= st.base || st.spec.quiet <= 0 {
		return
	}
	steps := int(now.Sub(st.lastChange) / st.spec.quiet)
	if steps <= 0 {
		return
	}
	st.lastChange = st.lastChange.Add(time.Duration(steps) * st.spec.quiet)
	next := rate.Limit(float64(st.cur) + float64(steps)*float64(st.base)*st.spec.recoverStep)
	if next > st.base {
		next = st.base
	}
	l.applyLocked(st, lim, next)
}

// applyLocked sets an adaptive bucket's rate. Below the base rate the burst is
// one, so a backlog is metered out instead of fired in a clump; at the base it
// returns to the configured burst.
func (l *WorkloadLimiter) applyLocked(st *adaptiveState, lim *rate.Limiter, next rate.Limit) {
	st.cur = next
	now := l.now()
	lim.SetLimitAt(now, next)
	if next < st.base {
		lim.SetBurstAt(now, 1)
	} else {
		lim.SetBurstAt(now, st.baseBurst)
	}
}

// WorkloadHeadroom is one (tenant, workload) token bucket's current state,
// for the admin throttle-headroom panel (#85).
type WorkloadHeadroom struct {
	TenantID    string
	Workload    Workload
	LimitPerSec float64 // rate.Limit as events/sec
	Burst       int
	Tokens      float64 // tokens available at the snapshot instant
}

// Snapshot returns the current headroom of every bucket that has actually been
// used since process start (lazy creation means idle (tenant,workload) pairs
// are absent — that is correct, not a bug). nil-limiter (WorkloadUnknown)
// entries are skipped. Ordered deterministically (by tenant, then workload).
func (l *WorkloadLimiter) Snapshot(now time.Time) []WorkloadHeadroom {
	l.mu.Lock()
	out := make([]WorkloadHeadroom, 0, len(l.limiters))
	for key, lim := range l.limiters {
		if lim == nil { // WorkloadUnknown / no configured ceiling
			continue
		}
		out = append(out, WorkloadHeadroom{
			TenantID:    key.tenantID,
			Workload:    key.workload,
			LimitPerSec: float64(lim.Limit()),
			Burst:       lim.Burst(),
			Tokens:      lim.TokensAt(now),
		})
	}
	l.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].Workload < out[j].Workload
	})
	return out
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
	if spec.adaptive != nil {
		l.adaptive[key] = &adaptiveState{spec: *spec.adaptive, base: spec.every, baseBurst: spec.burst, cur: spec.every}
	}
	return lim
}
