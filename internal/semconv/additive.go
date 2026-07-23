package semconv

import "strings"

// Metric additivity: whether the series of a metric may legally be summed
// together, which is what decides how #235's cardinality limiter treats the tail
// it clips.
//
// # Why this is a unit question and not a kind question
//
// Kind almost answers it. A sum aggregates by addition and a histogram's buckets
// add across series, so both are additive whatever they measure. A GAUGE is a
// last value, and last values are only summable when the thing being measured is
// a count.
//
// Instrument kind cannot answer that, and gets it backwards exactly where it
// matters: intune.detected_apps.device_count is an OBSERVABLE GAUGE — the least
// additive instrument kind there is — carrying a device count, which is about as
// additive as a number gets. Meanwhile intune.uxa.app_health.os_version_score is
// the same instrument kind carrying a score, where a sum is meaningless. The
// unit is the only thing in the emit call that tells them apart, and it is
// already there on every call site.
//
// # What a wrong answer costs, in each direction
//
// Classifying a count as non-additive loses the tail's contribution: the `other`
// bucket is not emitted and the dropped-series count is reported instead. That
// is a smaller number than the truth, and it is visibly labeled as such.
//
// Classifying a quality as additive emits a NUMBER THAT WAS NEVER MEASURED —
// "the sum of 4,000 health scores" — under a metric name that looks legitimate,
// with nothing marking it as synthetic. Nobody querying it can tell. So the
// table errs toward non-additive, and an unrecognized unit is non-additive.
//
// # Why the annotation axis is a convention and the UCUM axis is a list
//
// UCUM annotation units ("{device}", "{signin}") are unbounded by design: every
// collector coins one for whatever it counts, and the tree already carries more
// than forty. Enumerating them would be friction discharged by adding the entry
// without thinking — a list everyone appends to and nobody reads. So annotations
// follow the convention that they name a countable noun, with a deny-list for
// the inner words that name a QUALITY instead. Real UCUM units are few and
// closed-ended, so those are enumerated, and one that is not on the list fails
// the build rather than picking a behavior.

// nonAdditiveUnits are the real (non-annotation) UCUM units whose gauges must
// never be summed. Durations dominate: these are ages, staleness and elapsed
// times measured per entity, where a total is not a quantity anyone wants.
var nonAdditiveUnits = map[string]struct{}{
	UnitDimensionless: {}, // "1" — flags, booleans and ratios; a sum changes the meaning
	"%":               {},
	UnitSeconds:       {},
	"ms":              {},
	"us":              {},
	"ns":              {},
	"min":             {},
	"h":               {},
	"d":               {},
}

// additiveUnits are the real (non-annotation) UCUM units whose gauges may be
// summed. Sizes only — bytes and their multiples are quantities of a substance,
// so a total is exactly what a tail fold should produce.
var additiveUnits = map[string]struct{}{
	"By": {}, "Bi": {},
	"kB": {}, "MB": {}, "GB": {}, "TB": {},
}

// nonCountableAnnotations are the inner words of an annotation unit that name a
// QUALITY rather than a countable thing. "{score}" is a measurement on a scale,
// not four hundred of something, so it does not follow the annotation
// convention. Matched against the text inside the braces, lowercased.
var nonCountableAnnotations = map[string]struct{}{
	"score": {}, "ratio": {}, "percent": {}, "percentage": {},
	"version": {}, "level": {}, "state": {}, "status": {},
	"index": {}, "rank": {}, "grade": {}, "age": {},
}

// annotationInner returns the text inside a UCUM annotation unit and whether the
// unit was one. "{device}" -> "device", true. "s" -> "", false.
func annotationInner(unit string) (string, bool) {
	if len(unit) >= 2 && strings.HasPrefix(unit, "{") && strings.HasSuffix(unit, "}") {
		return strings.ToLower(unit[1 : len(unit)-1]), true
	}
	return "", false
}

// UnitClassified reports whether this unit is one the additivity table
// understands. It is deliberately independent of MetricAdditive: a sum is
// additive whatever its unit, so asking MetricAdditive would let an unrecognized
// unit ride into the tree unnoticed on a counter. The build gate asks THIS
// question, so a new unit has to be classified even where its aggregation
// already determines the answer.
func UnitClassified(unit string) bool {
	if _, ok := annotationInner(unit); ok {
		return true
	}
	if _, ok := nonAdditiveUnits[unit]; ok {
		return true
	}
	_, ok := additiveUnits[unit]
	return ok
}

// MetricAdditive reports whether the series of a metric with this unit and this
// SDK aggregation kind ("sum", "gauge" or "histogram") may be summed together.
//
// #235's limiter uses it to decide the fate of the series it clips: an additive
// metric's tail is folded into a single `other` series carrying the tail's sum;
// a non-additive metric's tail is dropped, with the dropped count reported
// separately. It never fabricates an aggregate.
//
// An unrecognized unit answers false, so the window between introducing a unit
// and classifying it cannot emit an invented number.
func MetricAdditive(unit, kind string) bool {
	switch kind {
	case "sum", "histogram":
		return true
	}
	if inner, ok := annotationInner(unit); ok {
		_, quality := nonCountableAnnotations[inner]
		return !quality
	}
	_, ok := additiveUnits[unit]
	return ok
}
