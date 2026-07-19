package graphclient

import (
	"context"
	"testing"
	"time"
)

// blockedQuickly asserts that a Wait call, made after the bucket's burst is
// already exhausted, is still blocked shortly after — proving the bucket is
// gating rather than admitting unboundedly. The context timeout is chosen
// far shorter than the workload's refill interval so the assertion never
// flakes on wall-clock scheduling jitter.
func blockedQuickly(t *testing.T, l *WorkloadLimiter, tenantID string, wl Workload, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := l.Wait(ctx, tenantID, wl); err == nil {
		t.Errorf("Wait(%s) admitted a request beyond burst capacity within %s; want blocked", wl, timeout)
	}
}

func TestWorkloadLimiterReportingBurst(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx := context.Background()

	// Burst capacity is 5 — all five must be admitted immediately.
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx, "tenant-a", WorkloadReporting); err != nil {
			t.Fatalf("Wait #%d within burst: %v", i+1, err)
		}
	}
	// The 6th request exceeds the burst; refill is one token per 2s, so it
	// must still be blocked a few milliseconds later.
	blockedQuickly(t, l, "tenant-a", WorkloadReporting, 20*time.Millisecond)
}

func TestWorkloadLimiterIPCSerializesPerTenant(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx := context.Background()

	// Burst is 1: the first call for a tenant is admitted immediately...
	if err := l.Wait(ctx, "tenant-a", WorkloadIPC); err != nil {
		t.Fatalf("first IPC wait for tenant-a: %v", err)
	}
	// ...and a second caller for the SAME tenant (a different "app", modeled
	// here as just another Wait call — the bucket has no app dimension) must
	// share the ceiling and block, since refill is only 1/s.
	blockedQuickly(t, l, "tenant-a", WorkloadIPC, 20*time.Millisecond)

	// A DIFFERENT tenant must not be affected by tenant-a's exhausted bucket.
	if err := l.Wait(ctx, "tenant-b", WorkloadIPC); err != nil {
		t.Fatalf("tenant-b IPC bucket was blocked by tenant-a's: %v", err)
	}
}

func TestWorkloadLimiterUnknownNeverBlocks(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	for i := 0; i < 1000; i++ {
		if err := l.Wait(ctx, "tenant-a", WorkloadUnknown); err != nil {
			t.Fatalf("WorkloadUnknown Wait #%d blocked: %v", i, err)
		}
	}
}

func TestWorkloadLimiterSnapshot(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx := context.Background()

	// Exercise two tenants across two workloads so the snapshot has several
	// buckets to order. WorkloadUnknown is used too — it must never appear.
	if err := l.Wait(ctx, "tenant-b", WorkloadReporting); err != nil {
		t.Fatalf("priming tenant-b/reporting: %v", err)
	}
	if err := l.Wait(ctx, "tenant-a", WorkloadReporting); err != nil {
		t.Fatalf("priming tenant-a/reporting: %v", err)
	}
	if err := l.Wait(ctx, "tenant-a", WorkloadIPC); err != nil {
		t.Fatalf("priming tenant-a/ipc: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx, "tenant-a", WorkloadUnknown); err != nil {
			t.Fatalf("priming tenant-a/unknown #%d: %v", i, err)
		}
	}

	now := time.Now()
	snap := l.Snapshot(now)

	// Exactly the three real buckets, WorkloadUnknown excluded.
	if len(snap) != 3 {
		t.Fatalf("Snapshot len = %d, want 3 (unknown excluded); got %+v", len(snap), snap)
	}
	for _, h := range snap {
		if h.Workload == WorkloadUnknown {
			t.Errorf("Snapshot contains WorkloadUnknown, want it skipped")
		}
		spec, ok := workloadRates[h.Workload]
		if !ok {
			t.Fatalf("Snapshot has an unconfigured workload %q", h.Workload)
		}
		if h.LimitPerSec != float64(spec.every) {
			t.Errorf("%s/%s LimitPerSec = %v, want %v", h.TenantID, h.Workload, h.LimitPerSec, float64(spec.every))
		}
		if h.Burst != spec.burst {
			t.Errorf("%s/%s Burst = %d, want %d", h.TenantID, h.Workload, h.Burst, spec.burst)
		}
		if h.Tokens < 0 || h.Tokens > float64(h.Burst) {
			t.Errorf("%s/%s Tokens = %v, want within [0, %d]", h.TenantID, h.Workload, h.Tokens, h.Burst)
		}
	}

	// Ordering is deterministic: by tenant, then workload. Two back-to-back
	// snapshots at the same instant must be identical in order.
	if !sortedByTenantThenWorkload(snap) {
		t.Errorf("Snapshot not ordered by (tenant, workload): %+v", snap)
	}
	snap2 := l.Snapshot(now)
	for i := range snap {
		if snap[i].TenantID != snap2[i].TenantID || snap[i].Workload != snap2[i].Workload {
			t.Errorf("Snapshot ordering not stable at %d: %v vs %v", i, snap[i], snap2[i])
		}
	}
}

func sortedByTenantThenWorkload(hs []WorkloadHeadroom) bool {
	for i := 1; i < len(hs); i++ {
		p, c := hs[i-1], hs[i]
		if p.TenantID > c.TenantID || (p.TenantID == c.TenantID && p.Workload > c.Workload) {
			return false
		}
	}
	return true
}

func TestWorkloadLimiterSnapshotEmpty(t *testing.T) {
	// A never-used limiter has no buckets, so Snapshot is empty (idle pairs are
	// absent by design, not a bug).
	if snap := NewWorkloadLimiter().Snapshot(time.Now()); len(snap) != 0 {
		t.Errorf("Snapshot of an unused limiter = %+v, want empty", snap)
	}
}

func TestWorkloadLimiterCtxCancelled(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Drain the IPC burst under a live context first so the NEXT call is the
	// one observing cancellation, not an immediately-admitted first token.
	if err := l.Wait(context.Background(), "tenant-a", WorkloadIPC); err != nil {
		t.Fatalf("priming wait: %v", err)
	}
	if err := l.Wait(ctx, "tenant-a", WorkloadIPC); err == nil {
		t.Error("Wait with a canceled context should return an error")
	}
}
