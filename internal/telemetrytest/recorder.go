// Package telemetrytest provides in-memory test helpers for asserting the
// OpenTelemetry output produced through the internal/telemetry Emitter.
//
// A Recorder wires a telemetry.Emitter to in-memory metric and log readers so
// collector tests can assert exactly which metric points and log records were
// emitted. The helpers return plain data structures; callers perform their own
// assertions (this package deliberately does not import the testing package).
package telemetrytest

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

// MetricPoint is a single recorded metric data point, flattened for assertions.
type MetricPoint struct {
	Name        string
	Unit        string
	Kind        string // "sum", "gauge", or "histogram"
	Description string
	Value       float64
	Monotonic   bool // only meaningful for sums
	Attrs       map[string]string
	// Histogram-only fields (set when Kind == "histogram"); Value holds the Sum.
	Count        uint64
	Bounds       []float64
	BucketCounts []uint64
}

// LogRecord is a single captured log record, flattened for assertions.
type LogRecord struct {
	Body         string
	SeverityText string
	EventName    string    // the OTLP LogRecord EventName field (log v0.20.0+)
	Timestamp    time.Time // the LogRecord Timestamp (zero when the emitter left it unset)
	Attrs        map[string]string

	// SeverityNumber is the OTEL wire severity (log.SeverityInfo=9,
	// SeverityWarn=13, SeverityError=17) — NOT this project's
	// telemetry.Severity enum (Info=0, Warn=1, Error=2). The two are different
	// scales, and conflating them is a live trap: `rec.SeverityNumber <
	// int(telemetry.SeverityWarn)` reads as "not at least a warning" but
	// evaluates 13 < 1, so it is false for EVERY record and the assertion can
	// never fail (#113).
	//
	// It is deliberately typed log.Severity rather than int so that comparison
	// is a COMPILE error instead of a silently-passing test. Assert on
	// SeverityText ("WARN"), or better, drive the collector's mapper directly
	// and compare telemetry.Severity values — see entra/securityincidents or
	// entra/risk for that idiom.
	SeverityNumber log.Severity
}

// Recorder wires a telemetry.Emitter to in-memory readers.
type Recorder struct {
	reader  *sdkmetric.ManualReader
	exp     *recordingLogExporter
	lp      *sdklog.LoggerProvider
	emitter telemetry.Emitter
}

// live accumulates every Recorder built in this test binary, so a package's
// TestMain can inspect the union of everything its tests emitted without any
// test having to opt in (#140).
//
// This is deliberately a package-level global, which is normally a smell. The
// justification: there are 364 telemetrytest.New() call sites across 57
// collector packages, so a design that requires each CALL SITE to register
// would be both a huge diff and — far worse — silently incomplete the moment
// someone adds a test and forgets. Self-registration at construction makes
// participation automatic and unforgettable, which is the only version of this
// worth having: a cardinality gate a new test can silently escape is not a gate.
//
// Retention is OPT-IN, via StartCapture, and that is not a detail — a Recorder
// holds every record it saw, so retaining one per test leaks by construction.
// internal/logpipeline's TestScalePollMemoryBoundedByWindowNotBacklog polls two
// large windows through a fresh Recorder each and asserts memory does not grow
// with the backlog; unconditional retention made that test fail, correctly, on
// the first run. Only packages that actually run the gate pay the cost, and
// there it is bounded by the package's test count.
var live struct {
	mu      sync.Mutex
	enabled bool
	recs    []*Recorder
}

// StartCapture makes subsequent New calls retain their Recorders for Live.
// signalcapture.Main calls this before running a package's tests; nothing else
// should. Without it, New retains nothing and Live is empty.
func StartCapture() {
	live.mu.Lock()
	live.enabled = true
	live.mu.Unlock()
}

// New returns a Recorder backed by an in-memory metric reader and log exporter.
func New() *Recorder {
	reader := sdkmetric.NewManualReader()
	// The SDK's own per-instrument cardinality limit is disabled here for the same
	// reason it is disabled in production (#235): graph2otel's limiter is the only
	// thing that bounds series count, and leaving the SDK's arrival-ordered 2000
	// underneath would silently truncate a test's fixture at a threshold no test
	// mentions.
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithCardinalityLimit(0))

	exp := &recordingLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))

	e := telemetry.NewEmitter(mp.Meter("test"), lp.Logger("test"))

	r := &Recorder{
		reader:  reader,
		exp:     exp,
		lp:      lp,
		emitter: e,
	}

	live.mu.Lock()
	if live.enabled {
		live.recs = append(live.recs, r)
	}
	live.mu.Unlock()

	return r
}

// Live returns every Recorder constructed so far in this test binary. It is for
// package-level gates that assert over the union of a package's emissions (see
// internal/signalcapture); ordinary tests should use their own Recorder.
func Live() []*Recorder {
	live.mu.Lock()
	defer live.mu.Unlock()
	return append([]*Recorder(nil), live.recs...)
}

// Emitter returns the telemetry.Emitter under test.
func (r *Recorder) Emitter() telemetry.Emitter { return r.emitter }

// MetricPoints collects current metrics and returns one MetricPoint per data
// point of the metric named name. Unknown names yield nil.
func (r *Recorder) MetricPoints(name string) []MetricPoint {
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		return nil
	}

	var out []MetricPoint
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			out = append(out, metricPoints(m)...)
		}
	}
	return out
}

// MetricNames collects current metrics and returns the sorted, de-duplicated
// names of every recorded metric.
func (r *Recorder) MetricNames() []string {
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if _, ok := seen[m.Name]; ok {
				continue
			}
			seen[m.Name] = struct{}{}
			names = append(names, m.Name)
		}
	}
	sort.Strings(names)
	return names
}

// LogRecords returns the captured log records, flattened for assertions.
func (r *Recorder) LogRecords() []LogRecord {
	recs := r.exp.all()
	out := make([]LogRecord, 0, len(recs))
	for i := range recs {
		out = append(out, flattenLogRecord(recs[i]))
	}
	return out
}

// metricPoints flattens a single metricdata.Metrics into MetricPoints, handling
// both float64 and int64 Sum/Gauge data plus float64 histograms.
func metricPoints(m metricdata.Metrics) []MetricPoint {
	switch d := m.Data.(type) {
	case metricdata.Sum[float64]:
		out := make([]MetricPoint, 0, len(d.DataPoints))
		for _, dp := range d.DataPoints {
			out = append(out, MetricPoint{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Kind:        "sum",
				Value:       dp.Value,
				Monotonic:   d.IsMonotonic,
				Attrs:       attrMap(dp.Attributes),
			})
		}
		return out
	case metricdata.Sum[int64]:
		out := make([]MetricPoint, 0, len(d.DataPoints))
		for _, dp := range d.DataPoints {
			out = append(out, MetricPoint{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Kind:        "sum",
				Value:       float64(dp.Value),
				Monotonic:   d.IsMonotonic,
				Attrs:       attrMap(dp.Attributes),
			})
		}
		return out
	case metricdata.Gauge[float64]:
		out := make([]MetricPoint, 0, len(d.DataPoints))
		for _, dp := range d.DataPoints {
			out = append(out, MetricPoint{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Kind:        "gauge",
				Value:       dp.Value,
				Attrs:       attrMap(dp.Attributes),
			})
		}
		return out
	case metricdata.Gauge[int64]:
		out := make([]MetricPoint, 0, len(d.DataPoints))
		for _, dp := range d.DataPoints {
			out = append(out, MetricPoint{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Kind:        "gauge",
				Value:       float64(dp.Value),
				Attrs:       attrMap(dp.Attributes),
			})
		}
		return out
	case metricdata.Histogram[float64]:
		out := make([]MetricPoint, 0, len(d.DataPoints))
		for _, dp := range d.DataPoints {
			out = append(out, MetricPoint{
				Name:         m.Name,
				Description:  m.Description,
				Unit:         m.Unit,
				Kind:         "histogram",
				Value:        dp.Sum,
				Count:        dp.Count,
				Bounds:       dp.Bounds,
				BucketCounts: dp.BucketCounts,
				Attrs:        attrMap(dp.Attributes),
			})
		}
		return out
	default:
		return nil
	}
}

// attrMap converts a metric attribute.Set to a string-keyed map.
func attrMap(set attribute.Set) map[string]string {
	out := map[string]string{}
	for it := set.Iter(); it.Next(); {
		kv := it.Attribute()
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// logValueString renders a log attribute value of ANY kind as a string.
//
// log.Value.AsString() returns "" for every kind except KindString — it does not
// convert, it asserts — so calling it directly captured bool, int64 and float64
// attributes as empty. Tests could then only assert that a numeric attribute was
// PRESENT, never that it was right, and an assertion against its value would
// have been comparing "" to "": vacuously true. Numeric log attributes are a
// large share of the signal surface (startup_impact_ms, battery_age_days, every
// score and count), so this was a hole under the whole log-twin test estate.
func logValueString(v log.Value) string {
	switch v.Kind() {
	case log.KindString:
		return v.AsString()
	case log.KindBool:
		return strconv.FormatBool(v.AsBool())
	case log.KindInt64:
		return strconv.FormatInt(v.AsInt64(), 10)
	case log.KindFloat64:
		return strconv.FormatFloat(v.AsFloat64(), 'g', -1, 64)
	case log.KindBytes:
		return string(v.AsBytes())
	case log.KindSlice:
		parts := make([]string, 0, len(v.AsSlice()))
		for _, e := range v.AsSlice() {
			parts = append(parts, logValueString(e))
		}
		return strings.Join(parts, ",")
	default:
		return v.String()
	}
}

// flattenLogRecord converts a captured sdklog.Record to a LogRecord.
func flattenLogRecord(rec sdklog.Record) LogRecord {
	attrs := map[string]string{}
	rec.WalkAttributes(func(kv log.KeyValue) bool {
		attrs[kv.Key] = logValueString(kv.Value)
		return true
	})
	return LogRecord{
		Body:           rec.Body().AsString(),
		SeverityText:   rec.SeverityText(),
		EventName:      rec.EventName(),
		SeverityNumber: rec.Severity(),
		Timestamp:      rec.Timestamp(),
		Attrs:          attrs,
	}
}

// recordingLogExporter captures emitted log records for later inspection. It
// implements the sdklog.Exporter interface.
type recordingLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *recordingLogExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range recs {
		e.records = append(e.records, recs[i].Clone())
	}
	return nil
}

func (e *recordingLogExporter) Shutdown(context.Context) error   { return nil }
func (e *recordingLogExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingLogExporter) all() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]sdklog.Record(nil), e.records...)
}
