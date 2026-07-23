package semconv_test

import (
	"testing"

	"github.com/rknightion/graph2otel/internal/semconv"
)

// TestAggregationKindDecidesAdditivityBeforeUnit pins the precedence.
//
// A sum and a histogram are additive by construction whatever they measure: a
// counter of seconds is a total of seconds, and a histogram's bucket counts add
// across series. Only a GAUGE has to be judged by what it measures, because a
// gauge is a last value and last values are only summable when the thing being
// measured is a count.
func TestAggregationKindDecidesAdditivityBeforeUnit(t *testing.T) {
	for _, unit := range []string{"s", "%", "1", "{score}", "{device}"} {
		for _, kind := range []string{"sum", "histogram"} {
			if !semconv.MetricAdditive(unit, kind) {
				t.Errorf("MetricAdditive(%q, %q) = false, want true — a %s aggregates by "+
					"addition whatever it measures", unit, kind, kind)
			}
		}
	}
}

// TestCountingGaugesAreAdditive covers the case #235 exists for: a gauge holding
// a count of things. intune.detected_apps.device_count is an observable gauge —
// non-additive by INSTRUMENT kind — carrying a very additive device count, which
// is exactly why the unit and not the kind is the discriminator for gauges.
func TestCountingGaugesAreAdditive(t *testing.T) {
	for _, unit := range []string{
		"{device}", "{user}", "{app}", "{policy}", "{crash}", "{signin}", "{certificate}",
		"By", "MB",
	} {
		if !semconv.MetricAdditive(unit, "gauge") {
			t.Errorf("MetricAdditive(%q, gauge) = false, want true — folding the tail of a "+
				"count into an `other` bucket is the correct aggregate", unit)
		}
	}
}

// TestQualityGaugesAreNotAdditive is the half that prevents a fabricated number.
//
// Summing a tail of scores, ratios, percentages or durations produces a value
// that was never measured and that no query can interpret. #235 fork 2: the tail
// of a non-additive metric is DROPPED with the dropped count reported, never
// summed.
func TestQualityGaugesAreNotAdditive(t *testing.T) {
	for _, unit := range []string{"1", "%", "s", "ms", "min", "h", "d", "{score}"} {
		if semconv.MetricAdditive(unit, "gauge") {
			t.Errorf("MetricAdditive(%q, gauge) = true, want false — summing this emits a "+
				"number that was never real", unit)
		}
	}
}

// TestAnnotationUnitsAreCountsUnlessTheyNameAQuality pins the open-ended half of
// the table, and why it is open-ended.
//
// UCUM annotation units ("{thing}") are unbounded by design — every new
// collector coins one for whatever it counts, and the tree already carries 40+.
// Requiring each to be enumerated would be friction people discharge by adding
// the entry without thinking, which is worse than a convention. So the
// convention is the rule: an annotation names a countable noun and is additive,
// UNLESS its inner word names a quality rather than a thing. The closed-ended
// axis — real UCUM units, of which there are few — stays enumerated.
func TestAnnotationUnitsAreCountsUnlessTheyNameAQuality(t *testing.T) {
	// Coined units this test has never seen must classify as counts, or a new
	// collector fails the gate for doing the ordinary thing.
	for _, unit := range []string{"{widget}", "{tenant}", "{mailbox}", "{alert}"} {
		if !semconv.MetricAdditive(unit, "gauge") {
			t.Errorf("MetricAdditive(%q, gauge) = false, want true — an unseen annotation "+
				"unit naming a thing must classify as a count without an explicit entry", unit)
		}
	}
	// Qualities must not, however they are spelled.
	for _, unit := range []string{
		"{score}", "{ratio}", "{percent}", "{percentage}", "{version}",
		"{level}", "{state}", "{status}", "{index}", "{rank}",
	} {
		if semconv.MetricAdditive(unit, "gauge") {
			t.Errorf("MetricAdditive(%q, gauge) = true, want false — this names a quality, "+
				"not a countable thing", unit)
		}
	}
}

// TestUnknownUnitIsUnclassifiedAndNonAdditive is the fail-safe. An unrecognized
// non-annotation unit must report as unclassified so the tree walk fails the
// build, AND must behave non-additively in the meantime, so the window between
// introducing it and classifying it cannot emit a fabricated aggregate.
func TestUnknownUnitIsUnclassifiedAndNonAdditive(t *testing.T) {
	for _, unit := range []string{"furlongs", "", "Cel", "kg"} {
		if semconv.UnitClassified(unit) {
			t.Errorf("UnitClassified(%q) = true, want false — an unenumerated non-annotation "+
				"unit must fail the gate rather than pick a behavior", unit)
		}
		if semconv.MetricAdditive(unit, "gauge") {
			t.Errorf("MetricAdditive(%q, gauge) = true, want false — unclassified must fail safe", unit)
		}
	}
	for _, unit := range []string{"{device}", "1", "%", "s", "By", "{score}"} {
		if !semconv.UnitClassified(unit) {
			t.Errorf("UnitClassified(%q) = false, want true", unit)
		}
	}
}

// TestUnclassifiedUnitOnASumStillFailsTheGate keeps the two questions separate.
//
// MetricAdditive can answer "sum" without consulting the unit at all, which
// would let an unknown unit ride into the tree unnoticed on a counter. Whether a
// unit is understood is a different question from how it aggregates, and the
// gate asks the first one.
func TestUnclassifiedUnitOnASumStillFailsTheGate(t *testing.T) {
	if semconv.UnitClassified("furlongs") {
		t.Fatal("precondition: furlongs must be unclassified")
	}
	if !semconv.MetricAdditive("furlongs", "sum") {
		t.Error("MetricAdditive(furlongs, sum) = false — a sum is additive whatever its unit")
	}
}
