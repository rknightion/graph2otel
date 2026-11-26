package graphclient

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/time/rate"

	"github.com/rknightion/graph2otel/internal/telemetry"
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

func TestAdaptiveLimiterRecoversAdditivelyPerSuccessRun(t *testing.T) {
	l, now := newFakeClockLimiter()
	const tenant = "tenant-a"
	wl := WorkloadIntuneExport
	l.ObserveThrottle(tenant, wl, *now) // 12/min
	rate := func() float64 { r, _ := l.EffectiveRatePerMinute(tenant, wl); return r }
	succeed := func(n int) {
		for i := 0; i < n; i++ {
			l.ObserveSuccess(tenant, wl, *now)
		}
	}

	// Idle time alone never recovers.
	*now = now.Add(24 * time.Hour)
	if got := rate(); got > 12.01 {
		t.Fatalf("recovered to %v/min with no traffic", got)
	}
	// 49 successes: not yet a step. A 429 then restarts the count.
	succeed(49)
	l.ObserveThrottle(tenant, wl, *now) // 6/min
	succeed(49)
	if got := rate(); got < 5.99 || got > 6.01 {
		t.Fatalf("rate = %v/min after 49 successes following a 429, want 6", got)
	}
	// The 50th success is one additive step of 2/min.
	succeed(1)
	if got := rate(); got < 7.99 || got > 8.01 {
		t.Fatalf("after one run of 50 successes = %v/min, want 8", got)
	}
	// A success issued before the last decrease ran under the old rate: ignored.
	succeed(0)
	for i := 0; i < 100; i++ {
		l.ObserveSuccess(tenant, wl, now.Add(-time.Hour))
	}
	if got := rate(); got < 7.99 || got > 8.01 {
		t.Fatalf("stale successes changed the rate to %v/min", got)
	}
	// Long clean traffic returns to base, not above it, and restores the burst.
	succeed(5000)
	if got := rate(); got < 23.99 || got > 24.01 {
		t.Fatalf("after long clean traffic = %v/min, want 24", got)
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

// statusServer answers every request with the status chosen by next, after delay.
type statusServer struct {
	delay time.Duration
	next  func() int
}

func (s *statusServer) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return &http.Response{
		StatusCode: s.next(),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

const exportJobsURL = "https://graph.example/v1.0/deviceManagement/reports/exportJobs"

// fastExportRate scales intune-export's base rate for the test: 40/s (burst 4)
// unless a gap is given.
func fastExportRate(t *testing.T, every ...time.Duration) {
	t.Helper()
	gap := 25 * time.Millisecond
	if len(every) > 0 {
		gap = every[0]
	}
	prev := workloadRates[WorkloadIntuneExport]
	spec := prev
	spec.every = rate.Every(gap)
	workloadRates[WorkloadIntuneExport] = spec
	t.Cleanup(func() { workloadRates[WorkloadIntuneExport] = prev })
}

func doExport(t *testing.T, rt *rateLimitTransport) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, exportJobsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

// TestConcurrent429BurstHalvesOnce: seven requests issued together at 40/s burst
// 4 are all throttled. Three of them wait in the limiter for a slot that was
// fixed under the OLD rate, so their 429s say nothing about the new one. The
// rate must halve once (20/s), not collapse to the floor.
func TestConcurrent429BurstHalvesOnce(t *testing.T) {
	fastExportRate(t)
	rt := &rateLimitTransport{
		next:     &statusServer{delay: 10 * time.Millisecond, next: func() int { return http.StatusTooManyRequests }},
		limiter:  NewWorkloadLimiter(),
		backoff:  &Backoff{Base: time.Millisecond, Max: time.Millisecond},
		tenantID: "tenant-a",
	}
	var wg sync.WaitGroup
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); doExport(t, rt) }()
	}
	wg.Wait()
	got, _ := rt.limiter.EffectiveRatePerMinute("tenant-a", WorkloadIntuneExport)
	if want := 20.0 * 60; got < want-1 || got > want+1 {
		t.Fatalf("rate after a burst of 7 concurrent 429s = %.0f/min, want one halving to %.0f/min", got, want)
	}
}

func newFakeClockTransport(t *testing.T, status *int, rec *telemetrytest.Recorder) (*rateLimitTransport, *time.Time) {
	t.Helper()
	fastExportRate(t, time.Millisecond)
	l, now := newFakeClockLimiter()
	rt := &rateLimitTransport{
		next:     &statusServer{next: func() int { return *status }},
		limiter:  l,
		backoff:  &Backoff{Base: time.Millisecond, Max: time.Millisecond},
		tenantID: "tenant-a",
		emitter:  rec.Emitter(),
	}
	return rt, now
}

// TestAdaptiveRatePersistsAcrossIdleGap: export cycles are six hours apart, so a
// rate learned from a 429 must survive the idle gap instead of resetting to the
// configured base that was already proven to 429.
func TestAdaptiveRatePersistsAcrossIdleGap(t *testing.T) {
	status := http.StatusTooManyRequests
	rt, now := newFakeClockTransport(t, &status, telemetrytest.New())
	doExport(t, rt) // 429: halves
	halved, _ := rt.limiter.EffectiveRatePerMinute("tenant-a", WorkloadIntuneExport)

	*now = now.Add(6 * time.Hour)
	status = http.StatusOK
	doExport(t, rt)
	if got, _ := rt.limiter.EffectiveRatePerMinute("tenant-a", WorkloadIntuneExport); got > halved+0.01 {
		t.Fatalf("rate recovered from %.0f to %.0f/min across an idle gap with no successful traffic", halved, got)
	}
}

// TestAdaptiveRateRecoversOnSuccessfulRequestsAndGaugeFollows: recovery is paid
// for by successful requests, a 429 resets that count, and the published gauge
// is the current state after every step.
func TestAdaptiveRateRecoversOnSuccessfulRequestsAndGaugeFollows(t *testing.T) {
	status := http.StatusTooManyRequests
	rec := telemetrytest.New()
	rt, _ := newFakeClockTransport(t, &status, rec)
	doExport(t, rt)
	halved, _ := rt.limiter.EffectiveRatePerMinute("tenant-a", WorkloadIntuneExport)

	status = http.StatusOK
	for i := 0; i < 300; i++ {
		doExport(t, rt)
	}
	got, _ := rt.limiter.EffectiveRatePerMinute("tenant-a", WorkloadIntuneExport)
	if got <= halved {
		t.Fatalf("rate stayed at %.0f/min after 300 successful requests", got)
	}
	if got > 1000*60+0.01 {
		t.Fatalf("rate %.0f/min exceeds the 60000/min base", got)
	}
	pts := rec.MetricPoints(metricThrottleEffectiveRate)
	if last := pts[len(pts)-1].Value; last != got {
		t.Fatalf("last published gauge %.0f/min != current rate %.0f/min", last, got)
	}
}

// Gauge publication can be delayed after the rate is read. A recovery on a
// second transport sharing that bucket must not leave the older value exported.
func TestConcurrentRecoveryPublishesLatestEffectiveRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const tenant = "tenant-a"
		const wl = WorkloadIntuneExport
		l := NewWorkloadLimiter()
		l.ObserveThrottle(tenant, wl, time.Now()) // 24 -> 12/min
		// Make each success a recovery step without queuing 50 requests.
		l.adaptive[limiterKey{tenantID: tenant, workload: wl}].spec.recoverEvery = 1

		rec := telemetrytest.New()
		admitted := make(chan struct{})
		firstResponse, secondResponse := make(chan struct{}), make(chan struct{})
		olderPublishing, resumeOlder := make(chan struct{}), make(chan struct{})
		newTransport := func(response <-chan struct{}, emitter telemetry.Emitter) *rateLimitTransport {
			return &rateLimitTransport{
				next: &statusServer{next: func() int {
					admitted <- struct{}{}
					<-response
					return http.StatusOK
				}},
				limiter: l, tenantID: tenant, emitter: emitter,
			}
		}
		first := newTransport(firstResponse, gaugeBarrierEmitter{
			Emitter: rec.Emitter(),
			beforeRecord: func() {
				select {
				case <-firstResponse:
					close(olderPublishing)
					<-resumeOlder
				default: // Leave the pre-request publication alone.
				}
			},
		})
		second := newTransport(secondResponse, rec.Emitter())

		done := make(chan error, 2)
		export := func(rt *rateLimitTransport) {
			req, err := http.NewRequest(http.MethodPost, exportJobsURL, nil)
			if err == nil {
				var resp *http.Response
				resp, err = rt.RoundTrip(req)
				if err == nil {
					err = resp.Body.Close()
				}
			}
			done <- err
		}
		go export(first)
		<-admitted
		go export(second)
		<-admitted // Both requests are now in flight under the same rate.
		close(firstResponse)
		<-olderPublishing // First success raised the rate to 14; not yet recorded.
		close(secondResponse)
		synctest.Wait() // Second success raised it to 16 and attempted publication.
		close(resumeOlder)
		for range 2 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}

		got, ok := l.EffectiveRatePerMinute(tenant, wl)
		if !ok || got < 15.99 || got > 16.01 {
			t.Fatalf("effective rate = %v/min, adaptive = %t, want 16/min after two recoveries", got, ok)
		}
		pts := rec.MetricPoints("graph2otel.throttle.effective_rate_per_minute")
		if len(pts) != 1 || pts[0].Kind != "gauge" || pts[0].Unit != "{request}/min" ||
			len(pts[0].Attrs) != 2 || pts[0].Attrs["tenant_id"] != tenant || pts[0].Attrs["workload"] != string(wl) {
			t.Fatalf("effective-rate points = %+v, want one request/min gauge for the original tenant/workload series", pts)
		}
		if last := pts[0].Value; last != got {
			t.Fatalf("last published gauge %.0f/min != current rate %.0f/min", last, got)
		}
	})
}

type gaugeBarrierEmitter struct {
	telemetry.Emitter
	beforeRecord func()
}

func (e gaugeBarrierEmitter) Gauge(name, unit, desc string, value float64, attrs telemetry.Attrs) {
	if name == metricThrottleEffectiveRate {
		e.beforeRecord()
	}
	e.Emitter.Gauge(name, unit, desc, value, attrs)
}
