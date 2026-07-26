package telemetry

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProjectCostsCalculatesExactComponentsAndReconciles(t *testing.T) {
	rows := []VolumeRow{
		{
			Attribution: Attribution{
				TenantID:     "tenant-a",
				Collector:    "collector-a",
				Transport:    TransportGraph,
				TrafficClass: TrafficClassSteadyState,
			},
			SourceRecords: 2,
			MetricPoints:  3,
		},
		{
			Attribution: Attribution{
				TenantID:     "tenant-a",
				Collector:    "collector-b",
				Transport:    TransportBlob,
				TrafficClass: TrafficClassColdStartBackfill,
			},
			SourceRecords: 1,
			LogPoints:     1,
		},
	}
	transport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 7, RetryAttempts: 9},
		Logs:    OTLPTransportSignal{PayloadBytes: 4, RetryAttempts: 11},
	}
	rates := CostRates{
		SourceRecordMicrounits:           10,
		MetricPointMicrounits:            20,
		LogRecordMicrounits:              30,
		TransmittedPayloadByteMicrounits: 2,
	}

	got, err := ProjectCosts(rows, transport, rates, 10*time.Second, 25*time.Second)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	want := CostProjection{
		ObservedInterval:    10 * time.Second,
		Period:              25 * time.Second,
		IntervalMicrounits:  142,
		ProjectedMicrounits: 235,
		Rows: []CostRow{
			{
				TenantID:                    "tenant-a",
				Collector:                   "collector-a",
				IngestTransport:             "graph",
				TrafficClass:                "steady_state",
				Attribution:                 CostAttributionEstimated,
				SourceRecordCostMicrounits:  20,
				MetricPointCostMicrounits:   60,
				AllocatedMetricPayloadBytes: 7,
				AllocatedPayloadBytes:       7,
				PayloadCostMicrounits:       14,
				IntervalMicrounits:          94,
				ProjectedMicrounits:         235,
			},
			{
				TenantID:                   "tenant-a",
				Collector:                  "collector-b",
				IngestTransport:            "blob",
				TrafficClass:               "cold_start_backfill",
				Attribution:                CostAttributionEstimated,
				SourceRecordCostMicrounits: 10,
				LogRecordCostMicrounits:    30,
				AllocatedLogPayloadBytes:   4,
				AllocatedPayloadBytes:      4,
				PayloadCostMicrounits:      8,
				IntervalMicrounits:         48,
				ProjectedMicrounits:        0,
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projection = %#v, want %#v", got, want)
	}
	assertCostProjectionReconciles(t, got)
}

func TestProjectCostsAllocatesPayloadWithinEachSignal(t *testing.T) {
	rows := []VolumeRow{
		{
			Attribution: Attribution{
				TenantID:     "tenant-a",
				Collector:    "metric-only",
				Transport:    TransportGraph,
				TrafficClass: TrafficClassSteadyState,
			},
			MetricPoints: 1,
		},
		{
			Attribution: Attribution{
				TenantID:     "tenant-a",
				Collector:    "log-only",
				Transport:    TransportBlob,
				TrafficClass: TrafficClassSteadyState,
			},
			LogPoints: 1,
		},
	}
	transport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 10},
		Logs:    OTLPTransportSignal{PayloadBytes: 1},
	}

	got, err := ProjectCosts(
		rows,
		transport,
		CostRates{TransmittedPayloadByteMicrounits: 1},
		time.Minute,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	metric := costRowByCollector(t, got, "metric-only")
	log := costRowByCollector(t, got, "log-only")
	if metric.AllocatedMetricPayloadBytes != 10 ||
		metric.AllocatedLogPayloadBytes != 0 ||
		metric.AllocatedPayloadBytes != 10 {
		t.Errorf("metric-only allocation = %+v, want 10 metric bytes only", metric)
	}
	if log.AllocatedMetricPayloadBytes != 0 ||
		log.AllocatedLogPayloadBytes != 1 ||
		log.AllocatedPayloadBytes != 1 {
		t.Errorf("log-only allocation = %+v, want 1 log byte only", log)
	}
	if got.IntervalMicrounits != 11 || got.ProjectedMicrounits != 11 {
		t.Fatalf("projection totals = (%d, %d), want (11, 11)", got.IntervalMicrounits, got.ProjectedMicrounits)
	}
	assertCostProjectionReconciles(t, got)
	assertPayloadSignalsReconcile(t, got, transport)
}

func TestProjectCostsKeepsSameSignalBytesWithoutShareUnattributed(t *testing.T) {
	rows := []VolumeRow{{
		Attribution: Attribution{
			TenantID:     "tenant-a",
			Collector:    "log-only",
			Transport:    TransportBlob,
			TrafficClass: TrafficClassSteadyState,
		},
		LogPoints: 1,
	}}
	transport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 5},
		Logs:    OTLPTransportSignal{PayloadBytes: 3},
	}

	got, err := ProjectCosts(
		rows,
		transport,
		CostRates{TransmittedPayloadByteMicrounits: 1},
		time.Minute,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	unattributed := costRowByCollector(t, got, CostCollectorUnattributed)
	log := costRowByCollector(t, got, "log-only")
	if unattributed.AllocatedMetricPayloadBytes != 5 ||
		unattributed.AllocatedLogPayloadBytes != 0 ||
		unattributed.AllocatedPayloadBytes != 5 ||
		unattributed.IntervalMicrounits != 5 {
		t.Errorf("unattributed metric payload = %+v, want 5 metric bytes/cost", unattributed)
	}
	if unattributed.ProjectedMicrounits != 0 {
		t.Errorf("unattributed projected = %d, want 0 non-recurring process cost", unattributed.ProjectedMicrounits)
	}
	if log.AllocatedMetricPayloadBytes != 0 ||
		log.AllocatedLogPayloadBytes != 3 ||
		log.AllocatedPayloadBytes != 3 ||
		log.IntervalMicrounits != 3 ||
		log.ProjectedMicrounits != 3 {
		t.Errorf("log-only row = %+v, want exact 3-log-byte recurring cost", log)
	}
	if got.IntervalMicrounits != 8 || got.ProjectedMicrounits != 3 {
		t.Fatalf("projection totals = (%d, %d), want (8, 3)", got.IntervalMicrounits, got.ProjectedMicrounits)
	}
	assertCostProjectionReconciles(t, got)
	assertPayloadSignalsReconcile(t, got, transport)
}

func TestProjectCostsLargestRemainderIsDeterministic(t *testing.T) {
	row := func(collector string) VolumeRow {
		return VolumeRow{
			Attribution: Attribution{
				TenantID:     "tenant-a",
				Collector:    collector,
				Transport:    TransportGraph,
				TrafficClass: TrafficClassSteadyState,
			},
			MetricPoints: 1,
		}
	}
	rates := CostRates{TransmittedPayloadByteMicrounits: 1}
	transport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 2},
	}

	first, err := ProjectCosts(
		[]VolumeRow{row("collector-c"), row("collector-a"), row("collector-b")},
		transport,
		rates,
		time.Minute,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("ProjectCosts first order: %v", err)
	}
	second, err := ProjectCosts(
		[]VolumeRow{row("collector-b"), row("collector-c"), row("collector-a")},
		transport,
		rates,
		time.Minute,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("ProjectCosts second order: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("input order changed projection:\nfirst=%#v\nsecond=%#v", first, second)
	}

	wantBytes := []uint64{1, 1, 0}
	for i, row := range first.Rows {
		if got := row.Collector; got != "collector-"+string(rune('a'+i)) {
			t.Fatalf("row[%d].collector = %q, want stable collector order", i, got)
		}
		if row.AllocatedPayloadBytes != wantBytes[i] {
			t.Errorf("row[%d].allocated payload bytes = %d, want %d", i, row.AllocatedPayloadBytes, wantBytes[i])
		}
	}
	assertCostProjectionReconciles(t, first)
}

func TestProjectCostsRetainsPayloadWithoutPointShareAsUnattributed(t *testing.T) {
	rows := []VolumeRow{{
		Attribution: Attribution{
			TenantID:     "tenant-a",
			Collector:    "source-only",
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		SourceRecords: 1,
	}}
	transport := OTLPTransportSnapshot{
		Metrics: OTLPTransportSignal{PayloadBytes: 3},
		Logs:    OTLPTransportSignal{PayloadBytes: 4},
	}
	rates := CostRates{
		SourceRecordMicrounits:           5,
		TransmittedPayloadByteMicrounits: 2,
	}

	got, err := ProjectCosts(rows, transport, rates, time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("rows = %d, want source row plus unattributed process row", len(got.Rows))
	}
	unattributed := got.Rows[0]
	if unattributed.Collector != CostCollectorUnattributed ||
		unattributed.IngestTransport != CostTransportProcess ||
		unattributed.Attribution != CostAttributionEstimated {
		t.Fatalf("unattributed row labels = %+v", unattributed)
	}
	if unattributed.AllocatedPayloadBytes != 7 || unattributed.PayloadCostMicrounits != 14 ||
		unattributed.IntervalMicrounits != 14 {
		t.Fatalf("unattributed row costs = %+v, want 7 bytes / 14 microunits", unattributed)
	}
	if unattributed.AllocatedMetricPayloadBytes != 3 ||
		unattributed.AllocatedLogPayloadBytes != 4 {
		t.Fatalf("unattributed signal bytes = %+v, want 3 metric / 4 log", unattributed)
	}
	if unattributed.ProjectedMicrounits != 0 {
		t.Errorf("unattributed projected = %d, want 0 non-recurring process cost", unattributed.ProjectedMicrounits)
	}
	if got.Rows[1].Collector != "source-only" || got.Rows[1].IntervalMicrounits != 5 {
		t.Fatalf("source row = %+v, want exact source cost", got.Rows[1])
	}
	if got.IntervalMicrounits != 19 || got.ProjectedMicrounits != 5 {
		t.Fatalf("projection totals = (%d, %d), want (19, 5)", got.IntervalMicrounits, got.ProjectedMicrounits)
	}
	assertCostProjectionReconciles(t, got)
	assertPayloadSignalsReconcile(t, got, transport)
}

func TestProjectCostsExceptionalOnlyRetainsIntervalAndProjectsZero(t *testing.T) {
	tests := []struct {
		name         string
		trafficClass TrafficClass
	}{
		{name: "cold start backfill", trafficClass: TrafficClassColdStartBackfill},
		{name: "manual replay", trafficClass: TrafficClassManualReplay},
		{name: "empty class", trafficClass: ""},
		{name: "unknown class", trafficClass: TrafficClass("future_class")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := costSourceRow("exceptional", 7)
			row.TrafficClass = tt.trafficClass

			got, err := ProjectCosts(
				[]VolumeRow{row},
				OTLPTransportSnapshot{},
				CostRates{SourceRecordMicrounits: 3},
				time.Minute,
				24*time.Hour,
			)
			if err != nil {
				t.Fatalf("ProjectCosts: %v", err)
			}
			if got.IntervalMicrounits != 21 {
				t.Errorf("interval total = %d, want visible exceptional cost 21", got.IntervalMicrounits)
			}
			if got.ProjectedMicrounits != 0 || got.Rows[0].ProjectedMicrounits != 0 {
				t.Errorf("exceptional projection = process %d row %d, want zero",
					got.ProjectedMicrounits, got.Rows[0].ProjectedMicrounits)
			}
			assertCostProjectionReconciles(t, got)
		})
	}
}

func TestProjectCostsMixedSteadyAndColdProjectsSteadyOnly(t *testing.T) {
	steady := costSourceRow("steady", 1)
	cold := costSourceRow("cold", 100)
	cold.TrafficClass = TrafficClassColdStartBackfill

	got, err := ProjectCosts(
		[]VolumeRow{cold, steady},
		OTLPTransportSnapshot{},
		CostRates{SourceRecordMicrounits: 1},
		time.Hour,
		2*time.Hour,
	)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	if got.IntervalMicrounits != 101 {
		t.Fatalf("interval total = %d, want all traffic classes 101", got.IntervalMicrounits)
	}
	if got.ProjectedMicrounits != 2 {
		t.Fatalf("projected total = %d, want steady-state-only 2", got.ProjectedMicrounits)
	}
	if projected := costRowByCollector(t, got, "cold").ProjectedMicrounits; projected != 0 {
		t.Errorf("cold projected = %d, want 0", projected)
	}
	if projected := costRowByCollector(t, got, "steady").ProjectedMicrounits; projected != 2 {
		t.Errorf("steady projected = %d, want 2", projected)
	}
	assertCostProjectionReconciles(t, got)
}

func TestProjectCostsPeriodRoundingReconcilesDeterministically(t *testing.T) {
	rows := []VolumeRow{
		costSourceRow("collector-c", 1),
		costSourceRow("collector-a", 1),
		costSourceRow("collector-b", 1),
	}
	rates := CostRates{SourceRecordMicrounits: 1}

	got, err := ProjectCosts(rows, OTLPTransportSnapshot{}, rates, 2*time.Second, time.Second)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	if got.ProjectedMicrounits != 2 {
		t.Fatalf("projected total = %d, want half-up rounded 2", got.ProjectedMicrounits)
	}
	wantProjected := []uint64{1, 1, 0}
	for i, row := range got.Rows {
		if row.ProjectedMicrounits != wantProjected[i] {
			t.Errorf("row[%d] projected = %d, want %d", i, row.ProjectedMicrounits, wantProjected[i])
		}
	}
	assertCostProjectionReconciles(t, got)
}

func TestProjectCostsAggregatesDuplicateAttribution(t *testing.T) {
	rows := []VolumeRow{
		costSourceRow("collector-a", 2),
		costSourceRow("collector-a", 3),
	}

	got, err := ProjectCosts(
		rows,
		OTLPTransportSnapshot{},
		CostRates{SourceRecordMicrounits: 7},
		time.Minute,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("ProjectCosts: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows = %d, want one aggregated attribution", len(got.Rows))
	}
	if got.Rows[0].SourceRecordCostMicrounits != 35 || got.Rows[0].IntervalMicrounits != 35 {
		t.Fatalf("aggregated row = %+v, want 35 microunits", got.Rows[0])
	}
}

func TestProjectCostsRejectsInvalidProjectionIntervals(t *testing.T) {
	tests := []struct {
		name     string
		observed time.Duration
		period   time.Duration
		want     string
	}{
		{name: "zero observed", period: time.Hour, want: "observed interval must be positive"},
		{name: "negative observed", observed: -time.Second, period: time.Hour, want: "observed interval must be positive"},
		{name: "zero period", observed: time.Second, want: "period must be positive"},
		{name: "negative period", observed: time.Second, period: -time.Hour, want: "period must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ProjectCosts(nil, OTLPTransportSnapshot{}, CostRates{}, tt.observed, tt.period)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ProjectCosts error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProjectCostsFailsClosedOnOverflow(t *testing.T) {
	secretRow := VolumeRow{
		Attribution: Attribution{
			TenantID:     "secret-tenant",
			Collector:    "secret-collector",
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		SourceRecords: math.MaxUint64,
	}
	tests := []struct {
		name      string
		rows      []VolumeRow
		transport OTLPTransportSnapshot
		rates     CostRates
		observed  time.Duration
		period    time.Duration
	}{
		{
			name:     "component multiplication",
			rows:     []VolumeRow{secretRow},
			rates:    CostRates{SourceRecordMicrounits: 2},
			observed: time.Second,
			period:   time.Second,
		},
		{
			name: "metric point total",
			rows: []VolumeRow{
				{Attribution: secretRow.Attribution, MetricPoints: math.MaxUint64},
				{Attribution: Attribution{Collector: "other"}, MetricPoints: 1},
			},
			observed: time.Second,
			period:   time.Second,
		},
		{
			name: "transport byte total",
			transport: OTLPTransportSnapshot{
				Metrics: OTLPTransportSignal{PayloadBytes: math.MaxUint64},
				Logs:    OTLPTransportSignal{PayloadBytes: 1},
			},
			observed: time.Second,
			period:   time.Second,
		},
		{
			name: "payload cost",
			transport: OTLPTransportSnapshot{
				Metrics: OTLPTransportSignal{PayloadBytes: math.MaxUint64},
			},
			rates:    CostRates{TransmittedPayloadByteMicrounits: 2},
			observed: time.Second,
			period:   time.Second,
		},
		{
			name:     "period projection",
			rows:     []VolumeRow{secretRow},
			rates:    CostRates{SourceRecordMicrounits: 1},
			observed: time.Nanosecond,
			period:   time.Duration(math.MaxInt64),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ProjectCosts(tt.rows, tt.transport, tt.rates, tt.observed, tt.period)
			if !errors.Is(err, ErrCostOverflow) {
				t.Fatalf("ProjectCosts error = %v, want ErrCostOverflow", err)
			}
			if len(err.Error()) > 96 {
				t.Errorf("overflow diagnostic length = %d, want bounded <= 96: %q", len(err.Error()), err)
			}
			if strings.Contains(err.Error(), "secret-") {
				t.Errorf("overflow diagnostic exposed attribution: %q", err)
			}
		})
	}
}

func costSourceRow(collector string, records uint64) VolumeRow {
	return VolumeRow{
		Attribution: Attribution{
			TenantID:     "tenant-a",
			Collector:    collector,
			Transport:    TransportGraph,
			TrafficClass: TrafficClassSteadyState,
		},
		SourceRecords: records,
	}
}

func costRowByCollector(t *testing.T, projection CostProjection, collector string) CostRow {
	t.Helper()
	for _, row := range projection.Rows {
		if row.Collector == collector {
			return row
		}
	}
	t.Fatalf("projection has no collector %q: %+v", collector, projection.Rows)
	return CostRow{}
}

func assertPayloadSignalsReconcile(
	t *testing.T,
	projection CostProjection,
	transport OTLPTransportSnapshot,
) {
	t.Helper()
	var metrics, logs, total uint64
	for _, row := range projection.Rows {
		metrics += row.AllocatedMetricPayloadBytes
		logs += row.AllocatedLogPayloadBytes
		total += row.AllocatedPayloadBytes
		if row.AllocatedMetricPayloadBytes+row.AllocatedLogPayloadBytes !=
			row.AllocatedPayloadBytes {
			t.Errorf("row signal allocations do not sum: %+v", row)
		}
	}
	if metrics != transport.Metrics.PayloadBytes {
		t.Errorf("allocated metric bytes = %d, process metric bytes = %d",
			metrics, transport.Metrics.PayloadBytes)
	}
	if logs != transport.Logs.PayloadBytes {
		t.Errorf("allocated log bytes = %d, process log bytes = %d",
			logs, transport.Logs.PayloadBytes)
	}
	if total != transport.Metrics.PayloadBytes+transport.Logs.PayloadBytes {
		t.Errorf("allocated total bytes = %d, process total bytes = %d",
			total, transport.Metrics.PayloadBytes+transport.Logs.PayloadBytes)
	}
}

func assertCostProjectionReconciles(t *testing.T, projection CostProjection) {
	t.Helper()
	var interval, projected uint64
	for _, row := range projection.Rows {
		interval += row.IntervalMicrounits
		projected += row.ProjectedMicrounits
		if row.Attribution != CostAttributionEstimated {
			t.Errorf("row attribution = %q, want %q", row.Attribution, CostAttributionEstimated)
		}
	}
	if interval != projection.IntervalMicrounits {
		t.Errorf("row interval sum = %d, process interval = %d", interval, projection.IntervalMicrounits)
	}
	if projected != projection.ProjectedMicrounits {
		t.Errorf("row projected sum = %d, process projected = %d", projected, projection.ProjectedMicrounits)
	}
}
