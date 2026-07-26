package telemetry

// selfObsScope is the identity contract for a metric emitted directly by the
// Provider rather than through a tenant-decorated collector emitter.
type selfObsScope uint8

const selfObsScopeProcess selfObsScope = iota + 1
const selfObsScopeTenantAttribution selfObsScope = selfObsScopeProcess + 1

// providerSelfObsScopes is intentionally explicit. Provider.ReportSelfObs
// emits through an undecorated path: genuinely process-wide values must omit
// tenant_id, while bounded capacity rows must carry their explicit tenant_id.
//
// TestProviderProcessSelfObsScopeRegistryCoversEveryReportMetric is the drift
// gate: a new provider-level self-observability metric fails until its scope
// semantics are recorded here.
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

	MetricOTLPTransmittedPayloadBytes: selfObsScopeProcess,
	MetricOTLPRetryAttempts:           selfObsScopeProcess,

	MetricIngestEmittedPoints: selfObsScopeTenantAttribution,
	MetricIngestCostProjected: selfObsScopeTenantAttribution,
}
