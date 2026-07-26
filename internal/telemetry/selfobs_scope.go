package telemetry

// selfObsScope is the identity contract for a metric emitted directly by the
// process-level Provider rather than through a tenant-decorated collector
// emitter.
type selfObsScope uint8

const selfObsScopeProcess selfObsScope = iota + 1

// providerSelfObsScopes is intentionally explicit. Provider.ReportSelfObs
// bypasses WithTenant because these cardinality values describe the single
// shared process: the configured limit, global total, and aggregate clipping
// across every tenant. Duplicating them once per tenant would create several
// identical-looking series that invite summing a process value N times.
//
// TestProviderProcessSelfObsScopeRegistryCoversEveryReportMetric is the drift
// gate: a new provider-level self-observability metric fails until its
// process-global semantics are recorded here. A tenant-specific metric must
// instead move behind a tenant-decorated emitter.
var providerSelfObsScopes = map[string]selfObsScope{
	seriesActiveMetric:  selfObsScopeProcess,
	seriesLimitMetric:   selfObsScopeProcess,
	seriesClippedMetric: selfObsScopeProcess,
	seriesTotalMetric:   selfObsScopeProcess,

	deliveryExportAttemptsMetric:     selfObsScopeProcess,
	deliveryExportSuccessesMetric:    selfObsScopeProcess,
	deliveryExportFailuresMetric:     selfObsScopeProcess,
	deliveryForceFlushFailuresMetric: selfObsScopeProcess,
	deliveryShutdownFailuresMetric:   selfObsScopeProcess,
	deliveryDegradedMetric:           selfObsScopeProcess,
}
