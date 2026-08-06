package telemetry

import (
	"context"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// sizingLogExporter captures the full structured-metadata footprint of every
// exported record, measured the way Loki measures it: resource attributes,
// scope name, and record attributes all land in one entry's structured
// metadata, and the limit is the sum of every key's and value's length.
//
// It asserts at the EXPORTER boundary on purpose. The loss in #419 happens
// after the emitter facade, so a fake that only sees telemetry.Attrs would go
// green over a guard that measures a different set than the wire carries — the
// exact shape of blindness that let #417 sit undetected for eleven days.
type sizingLogExporter struct {
	mu    sync.Mutex
	sizes []int
}

func (s *sizingLogExporter) Export(_ context.Context, recs []sdklog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range recs {
		n := 0
		for _, kv := range rec.Resource().Attributes() {
			n += len(kv.Key) + len(kv.Value.String())
		}
		n += len("scope_name") + len(rec.InstrumentationScope().Name)
		rec.WalkAttributes(func(kv attribute.KeyValue) bool {
			n += len(kv.Key) + len(kv.Value.String())
			return true
		})
		s.sizes = append(s.sizes, n)
	}
	return nil
}

func (s *sizingLogExporter) ForceFlush(context.Context) error { return nil }
func (s *sizingLogExporter) Shutdown(context.Context) error   { return nil }

func (s *sizingLogExporter) exported() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.sizes...)
}

// productionShapedResource mirrors the resource graph2otel actually ships, whose
// attributes Loki counts against the same 64 KiB budget as the record's own.
// The values are the live-measured m7kni shapes (2026-08-06).
func productionShapedResource() *resource.Resource {
	return resource.NewSchemaless(
		attribute.String("service.name", "graph2otel"),
		attribute.String("service.version", "6215b4f"),
		attribute.String("host.name", "0d35aceb5c12"),
		attribute.String("os.type", "linux"),
		attribute.String("os.description",
			"Debian GNU/Linux Debian GNU/Linux 12 (bookworm) (Linux 0d35aceb5c12 "+
				"7.0.10-201.fc44.x86_64 #1 SMP PREEMPT_DYNAMIC Wed May 27 13:57:41 UTC 2026 x86_64)"),
		attribute.String("process.executable.name", "graph2otel"),
		attribute.String("process.pid", "1"),
		attribute.String("process.runtime.name", "go"),
		attribute.String("process.runtime.version", "go1.26.5-X:goroutineleakprofile"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.name", "opentelemetry"),
		attribute.String("telemetry.sdk.version", "1.45.0"),
		attribute.String("graph2otel.event_domain", "defender"),
	)
}

// TestAnOversizedRecordFitsLokisLimitOnTheWire drives a record through the real
// SDK log pipeline and measures what an exporter would ship, rather than what
// the facade was handed.
func TestAnOversizedRecordFitsLokisLimitOnTheWire(t *testing.T) {
	const lokiLimit = 65536

	exp := &sizingLogExporter{}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(productionShapedResource()),
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })

	base := newOtelEmitter(metricnoop.NewMeterProvider().Meter("t"), lp.Logger("github.com/rknightion/graph2otel"), nil)
	e := WithAttributeBudget(base, MaxAttributeBytes, "defender.device_event", "tenant-a", TransportBlob)

	// The observed #419 magnitudes: 135305 and 74478 bytes against a 65536 limit.
	e.LogEvent(Event{
		Name:  "defender.device_event",
		Body:  "oversized",
		Attrs: Attrs{"additional_fields": strings.Repeat("x", 135_305)},
	})

	sizes := exp.exported()
	if len(sizes) != 1 {
		t.Fatalf("got %d exported records, want 1 — the record must survive, clipped", len(sizes))
	}
	if sizes[0] >= lokiLimit {
		t.Fatalf("exported record carries %d bytes of structured metadata, limit is %d: "+
			"Loki would reject it and the record would be lost", sizes[0], lokiLimit)
	}
}
