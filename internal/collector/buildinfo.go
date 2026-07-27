package collector

import (
	"runtime"

	"github.com/rknightion/graph2otel/internal/semconv"
	"github.com/rknightion/graph2otel/internal/telemetry"
	"github.com/rknightion/graph2otel/internal/version"
)

// MetricBuildInfo is a constant-1 gauge carrying build metadata as attributes,
// so an operator can see which graph2otel version (and Go runtime) produced a
// given series. One series per process.
const MetricBuildInfo = "graph2otel.build_info"

// EmitBuildInfo records the graph2otel.build_info gauge once, with a "version"
// attribute (internal/version.String()) and a "go.version" attribute (the Go
// runtime version the binary was built with). Call once at process startup.
//
// internal/startupevent's graph2otel.startup marker carries the SAME two
// attributes from the SAME two sources, which is why both read the semconv
// constants rather than bare literals: a deploy annotation and this gauge
// disagreeing about which build is running would make both untrustworthy.
// TestEmittedVersionMatchesBuildInfo is the cross-check.
func EmitBuildInfo(e telemetry.Emitter) {
	attrs := telemetry.Attrs{
		semconv.AttrVersion:   version.String(),
		semconv.AttrGoVersion: runtime.Version(),
	}
	e.Gauge(MetricBuildInfo, semconv.UnitDimensionless,
		"Constant 1 build-info gauge; carries the graph2otel version and Go runtime version as attributes.",
		1, attrs)
}
