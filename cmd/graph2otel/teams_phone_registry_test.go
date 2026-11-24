package main

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/collector"
	"github.com/rknightion/graph2otel/internal/collectors"
)

func TestTeamsPhoneWindowRegistration(t *testing.T) {
	for _, name := range []string{"teams.pstn_calls", "teams.direct_routing_calls"} {
		t.Run(name, func(t *testing.T) {
			for _, factory := range collectors.WindowAll() {
				rw := factory(collectors.WindowDeps{})
				if rw.Collector == nil || rw.Collector.Name() != name {
					continue
				}
				if got, _, err := collector.ProfilePolicy(rw.Collector); err != nil || got != collector.ProfileTeams {
					t.Fatalf("%s membership = %v (%v), want teams only", name, got, err)
				}
				return
			}
			t.Fatalf("%s missing from the window registry used by the CLI and collectordoc", name)
		})
	}
}
