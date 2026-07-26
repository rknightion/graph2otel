package admin

import "github.com/rknightion/graph2otel/internal/availability"

// BadgeClass maps every bounded availability state to the existing admin
// palette. Unknown future values remain visible with the neutral pending
// treatment; their typed state and reason text are still rendered verbatim.
func (a CollectorAvailability) BadgeClass() string {
	switch a.State {
	case availability.StateHealthyEmpty, availability.StateHealthy:
		return "ok"
	case availability.StateLimited, availability.StateDegraded:
		return "warn"
	case availability.StateBlocked, availability.StateFailed, availability.StateStartupFailed:
		return "err"
	case availability.StateCovered:
		return "info"
	case availability.StateDisabled:
		return "muted"
	case availability.StateStarting:
		return "pending"
	default:
		return "pending"
	}
}
