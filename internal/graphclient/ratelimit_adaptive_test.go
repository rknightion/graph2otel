package graphclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetrytest"
)

// ceilingServer is a synthetic Graph that enforces a hard request ceiling: a
// request arriving less than gap after the last accepted one is answered 429
// with no Retry-After, as the throttled workloads do.
type ceilingServer struct {
	gap time.Duration

	mu       sync.Mutex
	lastOK   time.Time
	accepted atomic.Int32
	rejected atomic.Int32
}

func (s *ceilingServer) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	now := time.Now()
	ok := s.lastOK.IsZero() || now.Sub(s.lastOK) >= s.gap
	if ok {
		s.lastOK = now
	}
	s.mu.Unlock()

	status := http.StatusOK
	if ok {
		s.accepted.Add(1)
	} else {
		status = http.StatusTooManyRequests
		s.rejected.Add(1)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

// TestIntuneExportLimiterConvergesBelowServerCeiling is the #709 regression: the
// configured intune-export rate sits ABOVE what the server enforces, so a fixed
// limiter 429s for as long as there is demand. The adaptive limiter must cut its
// rate on the first 429s and stop provoking them. Rates are scaled from per
// minute to per second so the run takes about two seconds.
func TestIntuneExportLimiterConvergesBelowServerCeiling(t *testing.T) {
	prev := workloadRates[WorkloadIntuneExport]
	spec := prev
	spec.every = rate.Every(25 * time.Millisecond) // 40/s configured
	workloadRates[WorkloadIntuneExport] = spec
	t.Cleanup(func() { workloadRates[WorkloadIntuneExport] = prev })

	srv := &ceilingServer{gap: 100 * time.Millisecond} // 10/s enforced
	rt := &rateLimitTransport{
		next:     srv,
		limiter:  NewWorkloadLimiter(),
		backoff:  &Backoff{Base: time.Millisecond, Max: time.Millisecond},
		tenantID: "tenant-a",
	}

	deadline := time.Now().Add(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				req, err := http.NewRequest(http.MethodPost, "https://graph.example/v1.0/deviceManagement/reports/exportJobs", nil)
				if err != nil {
					t.Errorf("build request: %v", err)
					return
				}
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Errorf("RoundTrip: %v", err)
					return
				}
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	// A fixed 40/s limiter against a 10/s ceiling draws roughly 60 429s in two
	// seconds. Converging costs a handful before the rate is cut below ceiling.
	if got := srv.rejected.Load(); got > 20 {
		t.Errorf("429s = %d (accepted %d), want <= 20: limiter did not adapt below the server ceiling", got, srv.accepted.Load())
	}
	if srv.accepted.Load() == 0 {
		t.Error("no request was accepted")
	}
	for _, h := range rt.limiter.Snapshot(time.Now()) {
		if h.Workload == WorkloadIntuneExport && h.LimitPerSec > 10 {
			t.Errorf("effective rate = %.1f/s, want <= the 10/s ceiling", h.LimitPerSec)
		}
	}
}

func newFakeClockLimiter() (*WorkloadLimiter, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewWorkloadLimiter()
	l.now = func() time.Time { return now }
	return l, &now
}

func TestAdaptiveLimiterHalvesToFloorAndIgnoresStale(t *testing.T) {
	l, now := newFakeClockLimiter()
	const tenant = "tenant-a"
	wl := WorkloadIntuneExport

	if got, ok := l.EffectiveRatePerMinute(tenant, wl); !ok || got < 23.99 || got > 24.01 {
		t.Fatalf("initial rate = %v ok=%v, want 24/min", got, ok)
	}
	issued := *now
	l.ObserveThrottle(tenant, wl, issued)
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got < 11.99 || got > 12.01 {
		t.Fatalf("after one 429 = %v/min, want 12", got)
	}
	// A 429 for a request issued before the decrease reflects the old rate.
	l.ObserveThrottle(tenant, wl, issued.Add(-time.Second))
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got < 11.99 || got > 12.01 {
		t.Fatalf("stale 429 changed the rate to %v/min, want 12", got)
	}
	for i := 0; i < 10; i++ {
		*now = now.Add(time.Second)
		l.ObserveThrottle(tenant, wl, *now)
	}
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got < 3.99 || got > 4.01 {
		t.Fatalf("floor = %v/min, want 4", got)
	}
	for _, h := range l.Snapshot(*now) {
		if h.Burst != 1 {
			t.Errorf("burst below base = %d, want 1", h.Burst)
		}
	}
}

func TestAdaptiveLimiterRecoversAdditivelyAfterQuiet(t *testing.T) {
	l, now := newFakeClockLimiter()
	const tenant = "tenant-a"
	wl := WorkloadIntuneExport
	l.ObserveThrottle(tenant, wl, *now) // 12/min

	// Not quiet long enough: no recovery.
	*now = now.Add(4 * time.Minute)
	if err := l.Wait(context.Background(), tenant, wl); err != nil {
		t.Fatal(err)
	}
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got > 12.01 {
		t.Fatalf("recovered after only 4 quiet minutes: %v/min", got)
	}
	// One quiet period regains 2/min.
	*now = now.Add(time.Minute)
	if err := l.Wait(context.Background(), tenant, wl); err != nil {
		t.Fatal(err)
	}
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got < 13.99 || got > 14.01 {
		t.Fatalf("after one quiet period = %v/min, want 14", got)
	}
	// Long quiet returns to base, not above it, and restores the burst.
	*now = now.Add(24 * time.Hour)
	if err := l.Wait(context.Background(), tenant, wl); err != nil {
		t.Fatal(err)
	}
	if got, _ := l.EffectiveRatePerMinute(tenant, wl); got < 23.99 || got > 24.01 {
		t.Fatalf("after long quiet = %v/min, want 24", got)
	}
	for _, h := range l.Snapshot(*now) {
		if h.Burst != 4 {
			t.Errorf("burst at base = %d, want 4", h.Burst)
		}
	}
}

func TestOtherWorkloadsAreNotAdaptive(t *testing.T) {
	l, now := newFakeClockLimiter()
	for _, wl := range []Workload{WorkloadReporting, WorkloadIPC, WorkloadIntuneGeneral, WorkloadTeamsPhone, WorkloadUnknown} {
		before := rate.Limit(0)
		if lim := l.limiterFor("t", wl); lim != nil {
			before = lim.Limit()
		}
		l.ObserveThrottle("t", wl, *now)
		if _, ok := l.EffectiveRatePerMinute("t", wl); ok {
			t.Errorf("%s reports an adaptive rate", wl)
		}
		if lim := l.limiterFor("t", wl); lim != nil && lim.Limit() != before {
			t.Errorf("%s rate changed on a 429: %v -> %v", wl, before, lim.Limit())
		}
	}
}

func TestEffectiveRateGaugePublishedForIntuneExportOnly(t *testing.T) {
	rec := telemetrytest.New()
	srv := &ceilingServer{gap: time.Hour} // first request ok, then 429
	rt := &rateLimitTransport{next: srv, limiter: NewWorkloadLimiter(), backoff: &Backoff{Base: time.Millisecond, Max: time.Millisecond}, tenantID: "tenant-a", emitter: rec.Emitter()}
	do := func(path string) {
		req, _ := http.NewRequest(http.MethodGet, "https://graph.example/v1.0"+path, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	do("/auditLogs/signIns")
	if pts := rec.MetricPoints(metricThrottleEffectiveRate); len(pts) != 0 {
		t.Fatalf("non-adaptive workload published %d effective-rate points", len(pts))
	}
	do("/deviceManagement/reports/exportJobs") // 429 (the server's one slot went to signIns): halves
	pts := rec.MetricPoints(metricThrottleEffectiveRate)
	if len(pts) == 0 {
		t.Fatal("no effective-rate gauge for intune-export")
	}
	last := pts[len(pts)-1]
	if last.Value < 11.99 || last.Value > 12.01 || last.Attrs[attrWorkload] != string(WorkloadIntuneExport) {
		t.Fatalf("last gauge = %+v, want 12/min for intune-export", last)
	}
}
