package graphclient

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestScaleReportingLimiterHoldsUnderLoad is the #32 soak-validation guard that
// the client-side reporting limiter actually ENFORCES the 5-requests/10s ceiling
// under a burst of demand (Graph sends no Retry-After on this workload, so the
// client-side limiter is the only thing keeping the exporter under budget). It
// exhausts the burst, then fires more and asserts the excess is paced to the
// token interval rather than let through — the failure mode being a limiter that
// is configured but not on the request path.
func TestScaleReportingLimiterHoldsUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("scale: real-time rate-limiter pacing (~4s); skipped under -short")
	}
	l := NewWorkloadLimiter()
	ctx := context.Background()

	// Reporting = burst 5, then one token every 2s. Fire burst+2 = 7 requests;
	// the 2 beyond the burst must wait ~2s each, so total >= ~4s. We assert a
	// conservative floor (>= 3.5s) to avoid flakiness while still proving the
	// ceiling is enforced (an un-limited path would return near-instantly).
	const n = 7
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := l.Wait(ctx, "tenant-1", WorkloadReporting); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 3500*time.Millisecond {
		t.Errorf("7 reporting requests took %v; expected >= ~4s (burst 5 + 2 paced @ 2s) — limiter not enforcing the 5/10s ceiling", elapsed)
	}
}

// TestScalePerTenantLimiterIsolation confirms each tenant gets its OWN budget:
// one tenant saturating the reporting ceiling must not stall another tenant's
// first (burst) request. This is the multi-tenant correctness the WorkloadLimiter
// promises (buckets keyed per tenant).
func TestScalePerTenantLimiterIsolation(t *testing.T) {
	l := NewWorkloadLimiter()
	ctx := context.Background()

	// Drain tenant A's reporting burst.
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx, "tenant-A", WorkloadReporting); err != nil {
			t.Fatalf("A Wait %d: %v", i, err)
		}
	}
	// Tenant B's first request should be instant (its own fresh burst).
	start := time.Now()
	if err := l.Wait(ctx, "tenant-B", WorkloadReporting); err != nil {
		t.Fatalf("B Wait: %v", err)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Errorf("tenant B's first request waited %v behind tenant A — per-tenant budgets not isolated", d)
	}
}

// TestScaleLimiterBudgetsMatchDocumentedCeilings pins the configured limiter
// rates to the documented Graph throttling budgets (CLAUDE.md gotchas). A change
// to a budget here is a deliberate act that should update the docs too; this
// catches an accidental drift. Fast (no real waiting).
func TestScaleLimiterBudgetsMatchDocumentedCeilings(t *testing.T) {
	cases := []struct {
		wl        Workload
		wantRate  rate.Limit
		wantBurst int
		desc      string
	}{
		{WorkloadReporting, rate.Every(10 * time.Second / 5), 5, "reporting 5/10s"},
		{WorkloadIPC, rate.Every(time.Second), 1, "identity-protection 1/s"},
		{WorkloadIntuneExport, rate.Every(time.Minute / 48), 48, "intune-export 48/min"},
	}
	for _, tc := range cases {
		spec, ok := workloadRates[tc.wl]
		if !ok {
			t.Errorf("%s: no limit configured for workload %q", tc.desc, tc.wl)
			continue
		}
		if spec.every != tc.wantRate {
			t.Errorf("%s: rate = %v, want %v", tc.desc, spec.every, tc.wantRate)
		}
		if spec.burst != tc.wantBurst {
			t.Errorf("%s: burst = %d, want %d", tc.desc, spec.burst, tc.wantBurst)
		}
	}
}
