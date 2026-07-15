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
}
