package semconv

import "testing"

func TestSelfObsConstants(t *testing.T) {
	if AttrMetricName != "metric.name" {
		t.Errorf("AttrMetricName = %q, want %q", AttrMetricName, "metric.name")
	}
	if UnitSeries != "{series}" {
		t.Errorf("UnitSeries = %q, want %q", UnitSeries, "{series}")
	}
	if UnitDimensionless != "1" {
		t.Errorf("UnitDimensionless = %q, want %q", UnitDimensionless, "1")
	}
	if UnitRecords != "{record}" {
		t.Errorf("UnitRecords = %q, want %q", UnitRecords, "{record}")
	}
	if UnitRuns != "{run}" {
		t.Errorf("UnitRuns = %q, want %q", UnitRuns, "{run}")
	}
}

func TestCollectorConstants(t *testing.T) {
	if AttrCollector != "collector" {
		t.Errorf("AttrCollector = %q, want %q", AttrCollector, "collector")
	}
	if AttrCollectorTransport != "collector.transport" {
		t.Errorf("AttrCollectorTransport = %q, want %q", AttrCollectorTransport, "collector.transport")
	}
	if AttrState != "state" {
		t.Errorf("AttrState = %q, want %q", AttrState, "state")
	}
	if AttrReason != "reason" {
		t.Errorf("AttrReason = %q, want %q", AttrReason, "reason")
	}
	if AttrTenantID != "tenant_id" {
		t.Errorf("AttrTenantID = %q, want %q", AttrTenantID, "tenant_id")
	}
	if UnitSeconds != "s" {
		t.Errorf("UnitSeconds = %q, want %q", UnitSeconds, "s")
	}
}
