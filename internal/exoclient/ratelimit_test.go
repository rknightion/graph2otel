package exoclient

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestDefaultLimiterIsConservative pins the deliberately-slow default. The
// Exchange Online admin API's InvokeCommand ceiling is UNMEASURED — no published
// req/min figure, and no RateLimit-* or Retry-After header was observed — so
// this value is a guess chosen to be far below anything plausible, not a
// measured limit. A quarantine collector polls on a multi-minute interval, so it
// needs nothing near 1/s.
func TestDefaultLimiterIsConservative(t *testing.T) {
	l := DefaultLimiter()
	if l == nil {
		t.Fatal("DefaultLimiter() = nil, want a limiter")
	}
	if got := float64(l.Limit()); got != DefaultRequestsPerSecond {
		t.Errorf("Limit() = %v/s, want %v/s", got, DefaultRequestsPerSecond)
	}
	if got := l.Burst(); got != DefaultBurst {
		t.Errorf("Burst() = %d, want %d", got, DefaultBurst)
	}
	if DefaultRequestsPerSecond > 2 {
		t.Errorf("DefaultRequestsPerSecond = %v — the ceiling is unmeasured, so the default must stay conservative",
			DefaultRequestsPerSecond)
	}
}

// TestDefaultLimiterReturnsIndependentLimiters keeps one client's exhausted
// bucket from gating another's: a Client is per tenant, so two Clients must not
// share a bucket by accident.
func TestDefaultLimiterReturnsIndependentLimiters(t *testing.T) {
	first, second := DefaultLimiter(), DefaultLimiter()
	if first == second {
		t.Error("DefaultLimiter() returned the same limiter twice — two tenants would share one bucket")
	}
}

// TestLimiterGates proves the raw rate.Limiter this package accepts does gate,
// and that a cancelled context aborts the wait rather than pinning a goroutine.
func TestLimiterGates(t *testing.T) {
	l := rate.NewLimiter(rate.Every(10*time.Millisecond), 1)

	start := time.Now()
	for i := range 3 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("3 Waits took %v, want >= 20ms — the limiter is not gating", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait with a cancelled context = nil, want an error")
	}
}
