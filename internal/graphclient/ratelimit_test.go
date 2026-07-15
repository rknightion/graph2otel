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
