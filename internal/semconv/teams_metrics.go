package semconv

// WholeSeriesOverflow reports which synchronous metrics use one unattributed
// overflow series. For the Teams quality family, clipping one label while
// keeping the others would multiply overflow series and could leave a clipped
// observation looking like a real contribution to a named site's compliance.
func WholeSeriesOverflow(name string) bool {
	switch name {
	case "teams.calls", "teams.call.health_transitions", "teams.call.metrics_skipped",
		"teams.streams", "teams.stream.rtt", "teams.stream.jitter", "teams.stream.packet_loss",
		"teams.stream.transport", "teams.stream.feedback", "teams.call.failures":
		return true
	default:
		return false
	}
}
