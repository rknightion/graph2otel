package telemetry

import (
	"sync"
	"time"

	"github.com/rknightion/graph2otel/internal/semconv"
)

const (
	MetricIngestEmittedPoints = "graph2otel.ingest.emitted_points"

	MetricOTLPTransmittedPayloadBytes = "graph2otel.otlp.transmitted_payload.bytes"
	MetricOTLPRetryAttempts           = "graph2otel.otlp.retry_attempts"

	MetricIngestCostProjected = "graph2otel.ingest.cost.projected"
)

// CostOptions configures optional OTLP cost-estimate telemetry. Rates and
// provenance come from validated operator config; graph2otel embeds no vendor
// prices. The budget remains an admin display input and is deliberately absent
// from the telemetry provider because this layer has no enforcement path.
type CostOptions struct {
	Enabled      bool
	Currency     string
	PriceVersion string
	Period       time.Duration
	Rates        CostRates
}

// capacityReportState holds the previous cumulative snapshots used to emit
// counter deltas on the provider self-observability cadence.
type capacityReportState struct {
	mu sync.Mutex

	lastVolume    map[Attribution]VolumeRow
	lastTransport OTLPTransportSnapshot
	startedAt     time.Time
}

func (p *Provider) reportCapacity() {
	if p == nil || p.selfObsEmitter == nil || p.volume == nil {
		return
	}
	now := time.Now()
	if p.capacityNow != nil {
		now = p.capacityNow()
	}

	p.capacityReport.mu.Lock()
	defer p.capacityReport.mu.Unlock()

	currentVolume := p.volume.Snapshot()
	currentTransport := p.Transport()
	deltaRows := capacityVolumeDelta(currentVolume, p.capacityReport.lastVolume)
	deltaTransport := capacityTransportDelta(
		currentTransport,
		p.capacityReport.lastTransport,
	)
	p.capacityReport.lastVolume = capacityVolumeMap(currentVolume)
	p.capacityReport.lastTransport = currentTransport

	for _, row := range deltaRows {
		const emittedPointsDescription = "Exact metric and log points emitted after cardinality limiting and handed to the OpenTelemetry SDK."
		base := Attrs{
			semconv.AttrTenantID:        row.TenantID,
			semconv.AttrCollector:       row.Collector,
			semconv.AttrIngestTransport: string(row.Transport),
			semconv.AttrTrafficClass:    string(row.TrafficClass),
		}
		if row.MetricPoints != 0 {
			attrs := cloneCapacityReportAttrs(base)
			attrs["signal"] = "metric"
			p.selfObsEmitter.Counter(
				MetricIngestEmittedPoints,
				"{point}",
				emittedPointsDescription,
				float64(row.MetricPoints),
				attrs,
			)
		}
		if row.LogPoints != 0 {
			attrs := cloneCapacityReportAttrs(base)
			attrs["signal"] = "log"
			p.selfObsEmitter.Counter(
				MetricIngestEmittedPoints,
				"{point}",
				emittedPointsDescription,
				float64(row.LogPoints),
				attrs,
			)
		}
	}

	reportTransportSignal(
		p.selfObsEmitter,
		"metrics",
		deltaTransport.Metrics,
	)
	reportTransportSignal(
		p.selfObsEmitter,
		"logs",
		deltaTransport.Logs,
	)

	projectionInterval := now.Sub(p.capacityReport.startedAt)
	if !p.cost.Enabled || projectionInterval <= 0 || p.cost.Period <= 0 {
		return
	}
	projection, err := ProjectCosts(
		currentVolume,
		currentTransport,
		p.cost.Rates,
		projectionInterval,
		p.cost.Period,
	)
	if err != nil {
		return
	}
	for _, row := range projection.Rows {
		if row.TrafficClass != string(TrafficClassSteadyState) {
			continue
		}
		p.selfObsEmitter.Gauge(
			MetricIngestCostProjected,
			"{microunit}",
			"Estimated recurring steady-state ingest cost projected from cumulative process-lifetime observations; payload-byte attribution is estimated, not an invoice.",
			float64(row.ProjectedMicrounits),
			Attrs{
				semconv.AttrTenantID:        row.TenantID,
				semconv.AttrCollector:       row.Collector,
				semconv.AttrIngestTransport: row.IngestTransport,
				"currency":                  p.cost.Currency,
				"price_version":             p.cost.PriceVersion,
				"attribution":               CostAttributionEstimated,
			},
		)
	}
}

func reportTransportSignal(e Emitter, signal string, delta OTLPTransportSignal) {
	attrs := Attrs{"signal": signal}
	if delta.PayloadBytes != 0 {
		e.Counter(
			MetricOTLPTransmittedPayloadBytes,
			"By",
			"Exact post-compression OTLP payload bytes accepted by the client transport; excludes protocol and network framing.",
			float64(delta.PayloadBytes),
			attrs,
		)
	}
	if delta.RetryAttempts != 0 {
		e.Counter(
			MetricOTLPRetryAttempts,
			"{retry}",
			"Exact second-and-later exporter retry-loop attempts; excludes redirects and transparent connection retries.",
			float64(delta.RetryAttempts),
			attrs,
		)
	}
}

func capacityVolumeMap(rows []VolumeRow) map[Attribution]VolumeRow {
	byAttribution := make(map[Attribution]VolumeRow, len(rows))
	for _, row := range rows {
		byAttribution[row.Attribution] = row
	}
	return byAttribution
}

func capacityVolumeDelta(
	current []VolumeRow,
	previous map[Attribution]VolumeRow,
) []VolumeRow {
	delta := make([]VolumeRow, 0, len(current))
	for _, row := range current {
		before := previous[row.Attribution]
		item := VolumeRow{
			Attribution:   row.Attribution,
			SourceRecords: monotonicDelta(row.SourceRecords, before.SourceRecords),
			MetricPoints:  monotonicDelta(row.MetricPoints, before.MetricPoints),
			LogPoints:     monotonicDelta(row.LogPoints, before.LogPoints),
		}
		if item.SourceRecords != 0 || item.MetricPoints != 0 || item.LogPoints != 0 {
			delta = append(delta, item)
		}
	}
	return delta
}

func capacityTransportDelta(
	current, previous OTLPTransportSnapshot,
) OTLPTransportSnapshot {
	return OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{
			PayloadBytes: monotonicDelta(
				current.Metrics.PayloadBytes,
				previous.Metrics.PayloadBytes,
			),
			RetryAttempts: monotonicDelta(
				current.Metrics.RetryAttempts,
				previous.Metrics.RetryAttempts,
			),
		},
		Logs: OTLPTransportSignal{
			PayloadBytes: monotonicDelta(
				current.Logs.PayloadBytes,
				previous.Logs.PayloadBytes,
			),
			RetryAttempts: monotonicDelta(
				current.Logs.RetryAttempts,
				previous.Logs.RetryAttempts,
			),
		},
	}
}

func monotonicDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func cloneCapacityReportAttrs(attrs Attrs) Attrs {
	cloned := make(Attrs, len(attrs)+1)
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}
