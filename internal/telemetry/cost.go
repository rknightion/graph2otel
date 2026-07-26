package telemetry

import (
	"cmp"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"time"
)

const (
	// CostAttributionEstimated is attached to every collector cost row because
	// process payload bytes are allocated by emitted-point share, not measured
	// per collector.
	CostAttributionEstimated = "estimated"
	// CostCollectorUnattributed retains process payload which has no emitted
	// point share to allocate against.
	CostCollectorUnattributed = "_unattributed"
	// CostTransportProcess identifies the process-level synthetic row without
	// broadening the bounded ingest Transport value set.
	CostTransportProcess = "process"
)

// ErrCostOverflow is returned when exact microunit arithmetic cannot be
// represented in uint64. Its wrapped diagnostics name only a bounded operation,
// never a tenant or collector value.
var ErrCostOverflow = errors.New("cost projection overflow")

// CostRates contains operator-supplied integer microunit rates. uint64 makes
// negative or fractional prices unrepresentable in the telemetry arithmetic
// layer; config owns parsing and metadata validation.
type CostRates struct {
	SourceRecordMicrounits           uint64
	MetricPointMicrounits            uint64
	LogRecordMicrounits              uint64
	TransmittedPayloadByteMicrounits uint64
}

// CostRow is one deterministic collector/transport/traffic-class estimate.
// The three logical-volume components are exact. Metric and log payload bytes
// are independently allocated from their same-signal emitted-point shares;
// AllocatedPayloadBytes is their checked sum. Payload cost remains estimated.
type CostRow struct {
	TenantID        string
	Collector       string
	IngestTransport string
	TrafficClass    string
	Attribution     string

	SourceRecordCostMicrounits  uint64
	MetricPointCostMicrounits   uint64
	LogRecordCostMicrounits     uint64
	AllocatedMetricPayloadBytes uint64
	AllocatedLogPayloadBytes    uint64
	AllocatedPayloadBytes       uint64
	PayloadCostMicrounits       uint64
	IntervalMicrounits          uint64
	ProjectedMicrounits         uint64
}

// CostProjection keeps the complete interval estimate across every traffic
// class, while ProjectedMicrounits is the integer recurring projection of
// steady-state rows only. Rows are sorted by bounded attribution labels and
// reconcile exactly to both process totals.
type CostProjection struct {
	Rows                []CostRow
	ObservedInterval    time.Duration
	Period              time.Duration
	IntervalMicrounits  uint64
	ProjectedMicrounits uint64
}

type costWorkRow struct {
	CostRow
	metricPoints        uint64
	logPoints           uint64
	allocationRemainder uint64
	projectionRemainder uint64
}

type costPayloadSignal uint8

const (
	costPayloadMetrics costPayloadSignal = iota
	costPayloadLogs
)

// ProjectCosts calculates one interval's collector estimates from exact volume
// deltas and the exact process OTLP transport delta. The caller owns cumulative
// snapshot differencing. Metrics payload is allocated only over metric points,
// and logs payload only over log points, each by deterministic largest
// remainder. Recurring projection includes steady-state rows only; exceptional
// interval cost stays visible but never becomes a budget burn rate. Retries
// remain exact transport telemetry and have no invented price.
func ProjectCosts(
	rows []VolumeRow,
	transport OTLPTransportSnapshot,
	rates CostRates,
	observedInterval, period time.Duration,
) (CostProjection, error) {
	if observedInterval <= 0 {
		return CostProjection{}, fmt.Errorf("cost projection: observed interval must be positive")
	}
	if period <= 0 {
		return CostProjection{}, fmt.Errorf("cost projection: period must be positive")
	}
	observedNanos := uint64(observedInterval)
	periodNanos := uint64(period)

	aggregated, err := aggregateVolumeRows(rows)
	if err != nil {
		return CostProjection{}, err
	}
	work := make([]costWorkRow, 0, len(aggregated)+1)
	var metricPoints, logPoints uint64
	for _, volume := range aggregated {
		row, buildErr := buildExactCostRow(volume, rates)
		if buildErr != nil {
			return CostProjection{}, buildErr
		}
		metricPoints, err = checkedAdd(
			metricPoints,
			volume.MetricPoints,
			"metric-point total",
		)
		if err != nil {
			return CostProjection{}, err
		}
		logPoints, err = checkedAdd(logPoints, volume.LogPoints, "log-point total")
		if err != nil {
			return CostProjection{}, err
		}
		work = append(work, costWorkRow{
			CostRow:      row,
			metricPoints: volume.MetricPoints,
			logPoints:    volume.LogPoints,
		})
	}

	work, err = allocatePayloadBytes(
		work,
		transport.Metrics.PayloadBytes,
		metricPoints,
		costPayloadMetrics,
	)
	if err != nil {
		return CostProjection{}, err
	}
	work, err = allocatePayloadBytes(
		work,
		transport.Logs.PayloadBytes,
		logPoints,
		costPayloadLogs,
	)
	if err != nil {
		return CostProjection{}, err
	}
	for i := range work {
		work[i].AllocatedPayloadBytes, err = checkedAdd(
			work[i].AllocatedMetricPayloadBytes,
			work[i].AllocatedLogPayloadBytes,
			"row allocated payload-byte total",
		)
		if err != nil {
			return CostProjection{}, err
		}
		work[i].PayloadCostMicrounits, err = checkedMul(
			work[i].AllocatedPayloadBytes,
			rates.TransmittedPayloadByteMicrounits,
			"payload-cost component",
		)
		if err != nil {
			return CostProjection{}, err
		}
		work[i].IntervalMicrounits, err = checkedAdd(
			work[i].IntervalMicrounits,
			work[i].PayloadCostMicrounits,
			"row interval total",
		)
		if err != nil {
			return CostProjection{}, err
		}
	}

	var intervalTotal uint64
	var steadyIntervalTotal uint64
	for i := range work {
		intervalTotal, err = checkedAdd(
			intervalTotal,
			work[i].IntervalMicrounits,
			"process interval total",
		)
		if err != nil {
			return CostProjection{}, err
		}
		if work[i].TrafficClass == string(TrafficClassSteadyState) {
			steadyIntervalTotal, err = checkedAdd(
				steadyIntervalTotal,
				work[i].IntervalMicrounits,
				"steady-state interval total",
			)
			if err != nil {
				return CostProjection{}, err
			}
		}
	}
	projectedTotal, _, err := checkedMulDiv(
		steadyIntervalTotal,
		periodNanos,
		observedNanos,
		true,
		"process period projection",
	)
	if err != nil {
		return CostProjection{}, err
	}
	if err := allocatePeriodProjection(work, projectedTotal, periodNanos, observedNanos); err != nil {
		return CostProjection{}, err
	}

	result := CostProjection{
		Rows:                make([]CostRow, len(work)),
		ObservedInterval:    observedInterval,
		Period:              period,
		IntervalMicrounits:  intervalTotal,
		ProjectedMicrounits: projectedTotal,
	}
	for i := range work {
		result.Rows[i] = work[i].CostRow
	}
	return result, nil
}

func aggregateVolumeRows(rows []VolumeRow) ([]VolumeRow, error) {
	byAttribution := make(map[Attribution]VolumeRow, len(rows))
	for _, input := range rows {
		row := byAttribution[input.Attribution]
		row.Attribution = input.Attribution
		var err error
		row.SourceRecords, err = checkedAdd(
			row.SourceRecords,
			input.SourceRecords,
			"source-record aggregation",
		)
		if err != nil {
			return nil, err
		}
		row.MetricPoints, err = checkedAdd(
			row.MetricPoints,
			input.MetricPoints,
			"metric-point aggregation",
		)
		if err != nil {
			return nil, err
		}
		row.LogPoints, err = checkedAdd(
			row.LogPoints,
			input.LogPoints,
			"log-record aggregation",
		)
		if err != nil {
			return nil, err
		}
		byAttribution[input.Attribution] = row
	}

	aggregated := make([]VolumeRow, 0, len(byAttribution))
	for _, row := range byAttribution {
		aggregated = append(aggregated, row)
	}
	slices.SortFunc(aggregated, compareVolumeRows)
	return aggregated, nil
}

func buildExactCostRow(volume VolumeRow, rates CostRates) (CostRow, error) {
	sourceCost, err := checkedMul(
		volume.SourceRecords,
		rates.SourceRecordMicrounits,
		"source-record cost",
	)
	if err != nil {
		return CostRow{}, err
	}
	metricCost, err := checkedMul(
		volume.MetricPoints,
		rates.MetricPointMicrounits,
		"metric-point cost",
	)
	if err != nil {
		return CostRow{}, err
	}
	logCost, err := checkedMul(
		volume.LogPoints,
		rates.LogRecordMicrounits,
		"log-record cost",
	)
	if err != nil {
		return CostRow{}, err
	}
	interval, err := checkedAdd(sourceCost, metricCost, "row logical-cost total")
	if err != nil {
		return CostRow{}, err
	}
	interval, err = checkedAdd(interval, logCost, "row logical-cost total")
	if err != nil {
		return CostRow{}, err
	}
	return CostRow{
		TenantID:                   volume.TenantID,
		Collector:                  volume.Collector,
		IngestTransport:            string(volume.Transport),
		TrafficClass:               string(volume.TrafficClass),
		Attribution:                CostAttributionEstimated,
		SourceRecordCostMicrounits: sourceCost,
		MetricPointCostMicrounits:  metricCost,
		LogRecordCostMicrounits:    logCost,
		IntervalMicrounits:         interval,
	}, nil
}

func allocatePayloadBytes(
	work []costWorkRow,
	payloadBytes, totalPoints uint64,
	signal costPayloadSignal,
) ([]costWorkRow, error) {
	if payloadBytes == 0 {
		return work, nil
	}
	if totalPoints == 0 {
		return appendUnattributed(work, payloadBytes, signal)
	}

	var allocated uint64
	order := make([]int, len(work))
	for i := range work {
		order[i] = i
		share, remainder, err := checkedMulDiv(
			costSignalPoints(work[i], signal),
			payloadBytes,
			totalPoints,
			false,
			"payload allocation",
		)
		if err != nil {
			return nil, err
		}
		if err := addSignalPayloadBytes(&work[i], share, signal); err != nil {
			return nil, err
		}
		work[i].allocationRemainder = remainder
		allocated, err = checkedAdd(allocated, share, "allocated payload-byte total")
		if err != nil {
			return nil, err
		}
	}
	if allocated > payloadBytes {
		return nil, overflowError("payload allocation reconciliation")
	}
	remaining := payloadBytes - allocated
	slices.SortFunc(order, func(a, b int) int {
		if n := cmp.Compare(
			work[b].allocationRemainder,
			work[a].allocationRemainder,
		); n != 0 {
			return n
		}
		return compareCostRows(work[a].CostRow, work[b].CostRow)
	})
	for _, index := range order {
		if remaining == 0 {
			break
		}
		if err := addSignalPayloadBytes(&work[index], 1, signal); err != nil {
			return nil, err
		}
		remaining--
	}
	if remaining > 0 {
		return appendUnattributed(work, remaining, signal)
	}
	slices.SortFunc(work, func(a, b costWorkRow) int {
		return compareCostRows(a.CostRow, b.CostRow)
	})
	return work, nil
}

func costSignalPoints(row costWorkRow, signal costPayloadSignal) uint64 {
	if signal == costPayloadLogs {
		return row.logPoints
	}
	return row.metricPoints
}

func addSignalPayloadBytes(
	row *costWorkRow,
	payloadBytes uint64,
	signal costPayloadSignal,
) error {
	var err error
	if signal == costPayloadLogs {
		row.AllocatedLogPayloadBytes, err = checkedAdd(
			row.AllocatedLogPayloadBytes,
			payloadBytes,
			"row allocated log payload-byte total",
		)
		return err
	}
	row.AllocatedMetricPayloadBytes, err = checkedAdd(
		row.AllocatedMetricPayloadBytes,
		payloadBytes,
		"row allocated metric payload-byte total",
	)
	return err
}

func appendUnattributed(
	work []costWorkRow,
	payloadBytes uint64,
	signal costPayloadSignal,
) ([]costWorkRow, error) {
	if payloadBytes == 0 {
		return work, nil
	}
	index := -1
	for i := range work {
		if work[i].Collector == CostCollectorUnattributed &&
			work[i].IngestTransport == CostTransportProcess {
			index = i
			break
		}
	}
	if index == -1 {
		work = append(work, costWorkRow{CostRow: CostRow{
			Collector:       CostCollectorUnattributed,
			IngestTransport: CostTransportProcess,
			Attribution:     CostAttributionEstimated,
		}})
		index = len(work) - 1
	}
	if err := addSignalPayloadBytes(&work[index], payloadBytes, signal); err != nil {
		return nil, err
	}
	slices.SortFunc(work, func(a, b costWorkRow) int {
		return compareCostRows(a.CostRow, b.CostRow)
	})
	return work, nil
}

func allocatePeriodProjection(
	work []costWorkRow,
	projectedTotal uint64,
	periodNanos, observedNanos uint64,
) error {
	var floorTotal uint64
	order := make([]int, 0, len(work))
	for i := range work {
		if work[i].TrafficClass != string(TrafficClassSteadyState) {
			work[i].ProjectedMicrounits = 0
			work[i].projectionRemainder = 0
			continue
		}
		order = append(order, i)
		floor, remainder, err := checkedMulDiv(
			work[i].IntervalMicrounits,
			periodNanos,
			observedNanos,
			false,
			"row period projection",
		)
		if err != nil {
			return err
		}
		work[i].ProjectedMicrounits = floor
		work[i].projectionRemainder = remainder
		floorTotal, err = checkedAdd(floorTotal, floor, "projected row floor total")
		if err != nil {
			return err
		}
	}
	if floorTotal > projectedTotal {
		return overflowError("period projection reconciliation")
	}
	remaining := projectedTotal - floorTotal
	slices.SortFunc(order, func(a, b int) int {
		if n := cmp.Compare(
			work[b].projectionRemainder,
			work[a].projectionRemainder,
		); n != 0 {
			return n
		}
		return compareCostRows(work[a].CostRow, work[b].CostRow)
	})
	for _, index := range order {
		if remaining == 0 {
			break
		}
		work[index].ProjectedMicrounits++
		remaining--
	}
	if remaining != 0 {
		return overflowError("period projection reconciliation")
	}
	slices.SortFunc(work, func(a, b costWorkRow) int {
		return compareCostRows(a.CostRow, b.CostRow)
	})
	return nil
}

func compareCostRows(a, b CostRow) int {
	if n := cmp.Compare(a.TenantID, b.TenantID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Collector, b.Collector); n != 0 {
		return n
	}
	if n := cmp.Compare(a.IngestTransport, b.IngestTransport); n != 0 {
		return n
	}
	return cmp.Compare(a.TrafficClass, b.TrafficClass)
}

func checkedAdd(a, b uint64, operation string) (uint64, error) {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, overflowError(operation)
	}
	return sum, nil
}

func checkedMul(a, b uint64, operation string) (uint64, error) {
	high, low := bits.Mul64(a, b)
	if high != 0 {
		return 0, overflowError(operation)
	}
	return low, nil
}

// checkedMulDiv returns floor(a*b/divisor) and its remainder without
// overflowing the intermediate product. When round is true, halves round up.
func checkedMulDiv(
	a, b, divisor uint64,
	round bool,
	operation string,
) (uint64, uint64, error) {
	if divisor == 0 {
		return 0, 0, fmt.Errorf("cost projection: zero divisor")
	}
	high, low := bits.Mul64(a, b)
	if high >= divisor {
		return 0, 0, overflowError(operation)
	}
	quotient, remainder := bits.Div64(high, low, divisor)
	if round && remainder >= divisor/2+divisor%2 {
		var err error
		quotient, err = checkedAdd(quotient, 1, operation)
		if err != nil {
			return 0, 0, err
		}
	}
	return quotient, remainder, nil
}

func overflowError(operation string) error {
	return fmt.Errorf("%w: %s", ErrCostOverflow, operation)
}
