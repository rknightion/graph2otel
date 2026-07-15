package graphclient

import (
	"math/rand"
	"time"
)

// maxBackoffShift bounds the exponential shift so Base*2^attempt never
// overflows time.Duration for a pathological attempt count; well past this
// point the delay is already clamped to Max anyway.
const maxBackoffShift = 32

// Backoff computes the client-side delay to apply before a retried request,
// for the workloads (reporting, Identity Protection) that return 429 with no
// Retry-After header at all. When a Retry-After IS present, Delay honors it
// verbatim rather than computing its own value.
type Backoff struct {
	// Base is the delay for the first retry (attempt 0), before jitter.
	Base time.Duration
	// Max caps the computed delay (before jitter is added on top).
	Max time.Duration
	// jitter perturbs a computed delay; overridable so tests are deterministic.
	// Nil defaults to defaultJitter.
	jitter func(time.Duration) time.Duration
}

// NewBackoff returns a Backoff with sane defaults: 1s base, 60s cap, real
// random jitter.
func NewBackoff() *Backoff {
	return &Backoff{
		Base:   time.Second,
		Max:    60 * time.Second,
		jitter: defaultJitter,
	}
}

// Delay returns the delay to apply before the given retry attempt (0-based).
// If retryAfter is positive, it is returned as-is — a server-supplied
// Retry-After always wins over our own computed backoff. Otherwise Delay
// computes Base*2^attempt, capped at Max, then applies jitter.
func (b *Backoff) Delay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}

	base := b.Base
	if base <= 0 {
		base = time.Second
	}
	maxDelay := b.Max
	if maxDelay <= 0 {
		maxDelay = 60 * time.Second
	}
	if attempt < 0 {
		attempt = 0
	}

	delay := maxDelay
	if attempt < maxBackoffShift {
		if d := base * time.Duration(uint64(1)<<uint(attempt)); d > 0 && d < maxDelay {
			delay = d
		}
	}

	jitter := b.jitter
	if jitter == nil {
		jitter = defaultJitter
	}
	return jitter(delay)
}

// defaultJitter applies "equal jitter": half the delay is fixed, half is
// random, so retries stay spread out without ever landing below Base/2.
func defaultJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	//nolint:gosec // non-cryptographic jitter for backoff timing only
	return half + time.Duration(rand.Int63n(int64(half)+1))
}
