package graphclient

import (
	"testing"
	"time"
)

// noJitter is a deterministic jitter override for tests: returns the delay
// unchanged so the exponential sequence itself can be asserted exactly.
func noJitter(d time.Duration) time.Duration { return d }

func TestBackoffDelayIncreasesExponentially(t *testing.T) {
	b := NewBackoff()
	b.jitter = noJitter

	d0 := b.Delay(0, 0)
	d1 := b.Delay(1, 0)
	d2 := b.Delay(2, 0)

	if d0 != time.Second {
		t.Errorf("Delay(0,0) = %s, want %s", d0, time.Second)
	}
	if d1 != 2*time.Second {
		t.Errorf("Delay(1,0) = %s, want %s", d1, 2*time.Second)
	}
	if d2 != 4*time.Second {
		t.Errorf("Delay(2,0) = %s, want %s", d2, 4*time.Second)
	}
	if d0 >= d1 || d1 >= d2 {
		t.Errorf("delays are not strictly increasing: %s, %s, %s", d0, d1, d2)
	}
}

func TestBackoffDelayCapsAtMax(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: 3 * time.Second, jitter: noJitter}

	got := b.Delay(5, 0) // 1s * 2^5 = 32s, way past the 3s cap
	if got != 3*time.Second {
		t.Errorf("Delay(5,0) = %s, want capped at %s", got, 3*time.Second)
	}
}

func TestBackoffDelayHonorsRetryAfter(t *testing.T) {
	b := NewBackoff()
	b.jitter = noJitter

	for _, attempt := range []int{0, 1, 5, 20} {
		got := b.Delay(attempt, 7*time.Second)
		if got != 7*time.Second {
			t.Errorf("Delay(%d, 7s) = %s, want exactly 7s (Retry-After must win)", attempt, got)
		}
	}
}

func TestBackoffDelayNegativeAttemptClampsToZero(t *testing.T) {
	b := NewBackoff()
	b.jitter = noJitter

	got := b.Delay(-3, 0)
	if got != time.Second {
		t.Errorf("Delay(-3,0) = %s, want %s (treated as attempt 0)", got, time.Second)
	}
}

func TestBackoffDefaultJitterNeverExceedsDelay(t *testing.T) {
	b := NewBackoff() // real jitter this time

	for i := 0; i < 100; i++ {
		got := b.Delay(0, 0)
		if got < time.Second/2 || got > time.Second {
			t.Fatalf("jittered Delay(0,0) = %s, want within [%s, %s]", got, time.Second/2, time.Second)
		}
	}
}
