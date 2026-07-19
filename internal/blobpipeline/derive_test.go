package blobpipeline

import (
	"testing"
	"time"
)

func TestWithinWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		event  time.Time
		window time.Duration
		age    time.Duration
		ok     bool
	}{
		{"fresh", now.Add(-5 * time.Minute), 20 * time.Minute, 5 * time.Minute, true},
		{"exactly at window", now.Add(-20 * time.Minute), 20 * time.Minute, 20 * time.Minute, true},
		{"just past window", now.Add(-21 * time.Minute), 20 * time.Minute, 21 * time.Minute, false},
		{"backfill 2h", now.Add(-2 * time.Hour), 20 * time.Minute, 2 * time.Hour, false},
		{"future clock skew", now.Add(1 * time.Minute), 20 * time.Minute, -1 * time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			age, ok := withinWindow(tc.event, now, tc.window)
			if age != tc.age || ok != tc.ok {
				t.Fatalf("withinWindow = (%v, %v), want (%v, %v)", age, ok, tc.age, tc.ok)
			}
		})
	}
}
