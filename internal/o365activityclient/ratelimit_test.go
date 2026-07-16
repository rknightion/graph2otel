package o365activityclient

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestDefaultRequestsPerMinute pins the documented per-tenant baseline quota.
// A silent change here is a silent change to how hard graph2otel hammers a
// customer's tenant, so it is worth a guard test.
func TestDefaultRequestsPerMinute(t *testing.T) {
	if DefaultRequestsPerMinute != 2000 {
		t.Errorf("DefaultRequestsPerMinute = %d, want 2000 (the documented per-tenant baseline)",
			DefaultRequestsPerMinute)
	}
}

// TestNewLimiterUsesDocumentedCeiling checks the default constructor actually
// wires the documented 2,000/min ceiling into its buckets, rather than the
// constant existing but going unused.
func TestNewLimiterUsesDocumentedCeiling(t *testing.T) {
	l := NewLimiter()
	lim := l.limiterFor("tenant-a")

	wantRate := rate.Limit(DefaultRequestsPerMinute) / rate.Limit(60)
	if got := lim.Limit(); !approxEqual(float64(got), float64(wantRate)) {
		t.Errorf("limiter rate = %v/s, want %v/s (%d per minute)", got, wantRate, DefaultRequestsPerMinute)
	}
	if got := lim.Burst(); got != DefaultRequestsPerMinute {
		t.Errorf("limiter burst = %d, want %d", got, DefaultRequestsPerMinute)
	}
}

// TestLimiterBlocksBeyondBurst proves the limiter actually gates: with a burst
// of 1 at 100/s, three Waits must span at least two refill intervals.
func TestLimiterBlocksBeyondBurst(t *testing.T) {
	l := newLimiterWithRate(rate.Every(10*time.Millisecond), 1)

	start := time.Now()
	for i := range 3 {
		if err := l.Wait(context.Background(), "tenant-a"); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// 3 requests, burst 1, one token per 10ms => the 2nd and 3rd each wait.
	if elapsed < 20*time.Millisecond {
		t.Errorf("3 Waits took %v, want >= 20ms — the limiter is not gating", elapsed)
	}
}

// TestLimiterIsPerTenant checks one tenant's exhausted bucket never blocks
// another's: the documented quota is per tenant, so sharing a bucket across
// tenants would throttle a multi-tenant process to a single tenant's ceiling.
func TestLimiterIsPerTenant(t *testing.T) {
	l := newLimiterWithRate(rate.Every(time.Hour), 1)

	// Drain tenant-a's single token.
	if err := l.Wait(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("Wait(tenant-a): %v", err)
	}

	// tenant-b has its own untouched bucket, so this must not block.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, "tenant-b"); err != nil {
		t.Errorf("Wait(tenant-b) = %v, want nil — buckets must be per tenant, not shared", err)
	}

	// ...while tenant-a, already drained, does block.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := l.Wait(ctx2, "tenant-a"); err == nil {
		t.Error("Wait(tenant-a) = nil, want a deadline error — the drained bucket did not gate")
	}
}

// TestLimiterReusesBucketPerTenant guards against creating a fresh (full)
// bucket on every call, which would make the limiter a no-op.
func TestLimiterReusesBucketPerTenant(t *testing.T) {
	l := NewLimiter()
	first, second := l.limiterFor("tenant-a"), l.limiterFor("tenant-a")
	if first != second {
		t.Error("limiterFor returned a new bucket for the same tenant — the quota would never be enforced")
	}
	other := l.limiterFor("tenant-b")
	if first == other {
		t.Error("limiterFor returned the same bucket for different tenants")
	}
}

// TestLimiterWaitHonorsContext checks a cancelled context aborts the wait
// rather than pinning the goroutine to a dead tick.
func TestLimiterWaitHonorsContext(t *testing.T) {
	l := newLimiterWithRate(rate.Every(time.Hour), 1)
	if err := l.Wait(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("priming Wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx, "tenant-a"); err == nil {
		t.Error("Wait with a cancelled context = nil, want an error")
	}
}

// TestNilLimiterNeverBlocks keeps the limiter optional: a nil *Limiter is the
// documented "no client-side gating" case and must not panic.
func TestNilLimiterNeverBlocks(t *testing.T) {
	var l *Limiter
	if err := l.Wait(context.Background(), "tenant-a"); err != nil {
		t.Errorf("(*Limiter)(nil).Wait = %v, want nil", err)
	}
}

func approxEqual(a, b float64) bool {
	const epsilon = 1e-9
	d := a - b
	return d < epsilon && d > -epsilon
}
