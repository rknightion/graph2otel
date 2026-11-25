package collector

import (
	"fmt"
	"testing"
	"time"

	"github.com/rknightion/graph2otel/internal/telemetry"
)

type namedExport struct {
	transportReporterStub
	name string
}

func (n namedExport) Name() string { return n.name }

func exportEntry(name string) Entry {
	return Entry{Collector: namedExport{transportReporterStub{t: telemetry.TransportReportExport}, name}, Interval: 6 * time.Hour}
}

// TestExportCollectorsStartAtDeterministicSpreadOffsets: the ~22 intune export
// collectors must not all fire their first tick in the same second (#709), and
// an offset must be the same on every start.
func TestExportCollectorsStartAtDeterministicSpreadOffsets(t *testing.T) {
	s := NewScheduler(nil, nil, WithTenant("tenant-a"))
	other := NewScheduler(nil, nil, WithTenant("tenant-a"))

	buckets := map[int]int{}
	for i := 0; i < 24; i++ {
		name := fmt.Sprintf("intune.fixture_%02d", i)
		d := s.initialDelay(exportEntry(name))
		if d < 0 || d >= defaultExportStartSpread {
			t.Fatalf("%s offset %v outside [0,%v)", name, d, defaultExportStartSpread)
		}
		if again := other.initialDelay(exportEntry(name)); again != d {
			t.Fatalf("%s offset not deterministic: %v then %v", name, d, again)
		}
		buckets[int(d/time.Second)]++
	}
	// 24 collectors in the same second would be the startup stampede; a spread
	// over 90s puts them in many distinct seconds.
	if len(buckets) < 12 {
		t.Errorf("24 export collectors landed in only %d distinct seconds: %v", len(buckets), buckets)
	}
}

func TestExportStartSpreadLeavesOtherCollectorsOnShortStagger(t *testing.T) {
	s := NewScheduler(nil, nil)
	for i := 0; i < 50; i++ {
		if d := s.initialDelay(Entry{Collector: plainCollectorStub{}}); d >= defaultStaggerWindow {
			t.Fatalf("non-export collector delayed %v, want under %v", d, defaultStaggerWindow)
		}
	}
	zero := NewScheduler(nil, nil, WithStaggerWindow(0))
	if d := zero.initialDelay(exportEntry("intune.x")); d != 0 {
		t.Errorf("zero stagger window must disable the spread, got %v", d)
	}
	off := NewScheduler(nil, nil, WithExportStartSpread(0))
	if d := off.initialDelay(exportEntry("intune.x")); d != 0 {
		t.Errorf("zero spread must disable it, got %v", d)
	}
}
